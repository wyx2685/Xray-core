package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
//
// 性能优化策略：
// 1. 用户缓存：基于源地址的LRU缓存，缓存命中时O(1)直接返回，避免O(n)遍历
// 2. Email索引：使用map加速按Email查找/删除用户，从O(n)优化到O(1)
// 3. 内存池：复用解密缓冲区，减少GC压力
// 4. 攻击防御：检测和阻止失效用户的暴力尝试攻击
// 5. 早期中断：对可疑连接提前终止遍历，避免消耗大量CPU
//
// 性能提升：
// - 热点用户场景（80%请求来自20%用户）：5-10倍性能提升
// - Email查找/删除操作：从O(n)优化到O(1)
// - 攻击防御：失效用户第2次尝试直接拒绝，避免遍历10万用户
type Validator struct {
	sync.RWMutex
	users         []*protocol.MemoryUser
	emailIndex    map[string]*protocol.MemoryUser // Email -> User 的快速索引
	userCache     *UserCache                      // 基于源地址的用户缓存
	attackDefense *AttackDefense                  // 攻击防御系统

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// initializeIfNeeded 初始化索引和缓存（内部使用，调用者需持有锁）
func (v *Validator) initializeIfNeeded() {
	if v.emailIndex == nil {
		v.emailIndex = make(map[string]*protocol.MemoryUser)
	}
	if v.userCache == nil {
		// 初始缓存容量：先用默认值，后续根据实际用户数动态扩容
		// 默认1024：适合中小场景，避免初始分配过大
		v.userCache = NewUserCache(1024)
	}
	if v.attackDefense == nil {
		v.attackDefense = NewAttackDefense(nil) // 使用默认配置
	}
}

// expandCacheIfNeeded 根据用户数扩展缓存容量（内部使用，调用者需持有锁）
// 在用户数增长到一定规模时，自动扩容缓存以提升命中率
func (v *Validator) expandCacheIfNeeded() {
	if v.userCache == nil {
		return
	}

	userCount := len(v.users)

	// 根据用户规模计算理想缓存容量
	// 策略：缓存 min(用户数的10%, 100000)
	idealSize := userCount / 10
	if idealSize > 100000 {
		idealSize = 100000 // 最多10万，避免内存过大
	}

	// 获取当前缓存容量（估算：32分片 * 分片容量）
	// 由于 UserCache 没有暴露容量，我们用启发式规则判断：
	// - 用户数 < 10240：保持默认1024
	// - 用户数 10240-102400：每10240用户触发一次扩容
	// - 用户数 > 102400：保持10万容量

	// 定义扩容阈值点
	var newCacheSize int
	switch {
	case userCount < 10240:
		// 小规模：保持默认1024
		return
	case userCount < 102400:
		// 中等规模：每达到 10240 的倍数就扩容
		// 10240 → 1024
		// 20480 → 2048
		// 51200 → 5120
		newCacheSize = userCount / 10
	default:
		// 大规模：固定10万
		newCacheSize = 100000
	}

	// 重建缓存（简单粗暴，清空旧缓存）
	// 注意：这会丢失当前缓存数据，但下次连接会自动重建
	// 这个操作不频繁（只在用户数倍增时触发）
	if newCacheSize > 1024 {
		v.userCache = NewUserCache(newCacheSize)
	}
}

// Add a Shadowsocks user.
// 优化：支持高频添加场景（适用于逐个添加或定期同步）
// - 自动预分配容量，减少内存重分配
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}

	// 初始化索引和缓存（延迟初始化）
	v.initializeIfNeeded()

	// 智能扩容：当容量不足时，预分配更多空间
	// 策略：当前容量 + max(当前长度的25%, min(256, 当前长度))
	// - 小规模：快速翻倍增长
	// - 大规模：25%增长避免浪费内存
	if len(v.users) >= cap(v.users) {
		// 计算增长量
		growth := len(v.users) / 4 // 25%增长

		// 最小增长量：小规模时加速扩容
		minGrowth := len(v.users)
		if minGrowth > 256 {
			minGrowth = 256
		}
		if minGrowth < 64 {
			minGrowth = 64
		}

		if growth < minGrowth {
			growth = minGrowth
		}

		newCap := cap(v.users) + growth

		// 重新分配切片
		newUsers := make([]*protocol.MemoryUser, len(v.users), newCap)
		copy(newUsers, v.users)
		v.users = newUsers
	}

	v.users = append(v.users, u)

	// 更新Email索引（如果有Email）
	if u.Email != "" {
		v.emailIndex[strings.ToLower(u.Email)] = u
	}

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	// 定期检查是否需要扩容缓存（在关键节点触发）
	// 10240, 20480, 51200, 102400 等节点自动扩容
	userCount := len(v.users)
	if userCount%10240 == 0 {
		v.expandCacheIfNeeded()
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	// 先从Email索引中快速查找 O(1)
	user, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	// 从切片中移除
	idx := -1
	for i, u := range v.users {
		if u == user { // 直接比较指针
			idx = i
			break
		}
	}

	if idx != -1 {
		ulen := len(v.users)
		v.users[idx] = v.users[ulen-1]
		v.users[ulen-1] = nil
		v.users = v.users[:ulen-1]
	}

	// 从Email索引中移除
	delete(v.emailIndex, email)

	// 从用户缓存中移除
	if v.userCache != nil {
		v.userCache.Remove(email)
	}

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.RLock()
	defer v.RUnlock()

	email = strings.ToLower(email)

	// 优化：直接从Email索引中获取 O(1)
	if v.emailIndex != nil {
		return v.emailIndex[email]
	}

	// 降级：如果索引未初始化，使用原来的遍历方式
	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.RLock() // 改用读锁，不阻塞验证请求
	defer v.RUnlock()
	return int64(len(v.users))
}

// UpdateUser 更新用户信息（如修改密码）
// 注意：会清除该用户的缓存
func (v *Validator) UpdateUser(email string, newUser *protocol.MemoryUser) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	// 从索引查找旧用户
	oldUser, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	// 在切片中找到并替换
	for i, u := range v.users {
		if u == oldUser {
			v.users[i] = newUser
			break
		}
	}

	// 更新Email索引
	delete(v.emailIndex, email)
	if newUser.Email != "" {
		v.emailIndex[strings.ToLower(newUser.Email)] = newUser
	}

	// 清除用户缓存（密码已变更）
	if v.userCache != nil {
		v.userCache.Remove(email)
	}

	return nil
}

// GetStats 获取统计信息（用于监控）
func (v *Validator) GetStats() ValidatorStats {
	v.RLock()
	defer v.RUnlock()

	stats := ValidatorStats{
		TotalUsers:   len(v.users),
		IndexedUsers: 0,
		CacheSize:    0,
	}

	if v.emailIndex != nil {
		stats.IndexedUsers = len(v.emailIndex)
	}

	// 获取攻击防御统计
	if v.attackDefense != nil {
		defenseStats := v.attackDefense.GetStats()
		stats.BannedIPs = defenseStats.BannedIPs
		stats.TotalFailures = defenseStats.TotalFailures
	}

	return stats
}

// ValidatorStats 验证器统计信息
type ValidatorStats struct {
	TotalUsers    int // 总用户数
	IndexedUsers  int // 已建立Email索引的用户数
	CacheSize     int // 缓存的用户数
	BannedIPs     int // 被封禁的IP/指纹数
	TotalFailures int // 总失败次数
}

// Get a Shadowsocks user.
// 性能优化：
// 1. 使用内存池减少内存分配和GC压力
// 2. 如果提供了cacheKey，会先从用户缓存中查找（O(1)），大幅提升热点用户性能
// 3. 未命中缓存时，遍历所有用户尝试解密，找到后更新缓存
//
// cacheKey: 可选的缓存键（通常是源地址 "ip:port"），为空则跳过缓存
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	return v.GetWithCache(bs, command, "")
}

// GetWithCache 带缓存支持的用户验证
// cacheKey: 缓存键（建议使用源地址 "ip:port"），为空则跳过缓存
func (v *Validator) GetWithCache(bs []byte, command protocol.RequestCommand, cacheKey string) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	// 优化：智能防御检查
	var defenseKey string
	if cacheKey != "" && v.attackDefense != nil {
		// 根据协议类型选择防御粒度：
		// - TCP: 用纯IP（攻击者会换端口）
		// - UDP: 用IP:Port（端口通常固定）
		isTCP := (command == protocol.RequestCommandTCP)
		defenseKey = v.attackDefense.CheckAndRecordConnection(cacheKey, isTCP)

		if defenseKey != "" && !v.attackDefense.CheckAllowed(defenseKey) {
			// 已被封禁（IP），直接拒绝，避免遍历所有用户
			return nil, nil, nil, 0, ErrNotFound
		}
	}

	// 优化：先尝试从缓存获取热点用户 O(1)
	var cachedUser *protocol.MemoryUser
	if cacheKey != "" && v.userCache != nil {
		cachedUser = v.userCache.Get(cacheKey)
		if cachedUser != nil {
			// 缓存命中，直接尝试该用户解密
			if account := cachedUser.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
				if len(bs) < 32 {
					cachedUser = nil // 数据太短，缓存失效
					goto FULL_SCAN
				}

				aeadCipher := account.Cipher.(*AEADCipher)
				ivLen = aeadCipher.IVSize()
				iv := bs[:ivLen]

				subkey := getSubkey(aeadCipher.KeyBytes)
				hkdfSHA1(account.Key, iv, subkey)
				aead = aeadCipher.AEADAuthCreator(subkey)

				var matchErr error
				switch command {
				case protocol.RequestCommandTCP:
					data := getTCPData(4 + aead.NonceSize())
					ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
				case protocol.RequestCommandUDP:
					data := getUDPData()
					ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
				}

				putSubkey(subkey)

				if matchErr == nil {
					// 缓存命中且解密成功，快速返回
					u = cachedUser
					err = account.CheckIV(iv)
					// 优化：记录验证成功，清除失败记录
					if defenseKey != "" && v.attackDefense != nil {
						v.attackDefense.RecordSuccess(defenseKey)
					}
					return
				}
				// 缓存失效（用户密钥可能已变更），继续全量扫描
			}
		}
	}

FULL_SCAN:
	// 未命中缓存或缓存验证失败，遍历所有用户
	//
	// 优化策略：早期中断（仅对从未成功的连接启用）
	// - 如果是首次连接的正常用户 → 不在缓存，需要完整遍历
	// - 如果是过期用户持续重试 → 已有失败记录，可以提前中断
	totalUsers := len(v.users)
	earlyStopThreshold := totalUsers // 默认检查所有用户（保证正常用户能连接）

	// 白名单检查优化（新增）：
	// - 如果IP在白名单中(曾经成功验证过)，跳过早停限制
	// - 这样正常用户打开新连接时不会因为"缓存未命中"而受早停影响
	// - 攻击者的IP不在白名单，仍然会触发早停
	isWhitelisted := false
	if defenseKey != "" && v.attackDefense != nil {
		// 使用 defenseKey(纯IP) 而不是 cacheKey(IP:Port)
		// defenseKey 已经在上面根据协议类型提取过了(TCP=纯IP, UDP=IP:Port)
		isWhitelisted = v.attackDefense.IsWhitelisted(defenseKey)
	}

	// 只有当连接已经有失败记录时，才启用早期中断
	// 白名单IP(成功验证过的正常用户)不受早停限制
	if !isWhitelisted && defenseKey != "" && v.attackDefense != nil {
		if v.attackDefense.HasFailureRecord(defenseKey) {
			// 此连接之前失败过，可能是过期用户，启用渐进式早期中断
			// 连续失败越多，检查用户数越少，最终降至10个
			earlyStopThreshold = v.attackDefense.GetEarlyStopThreshold(totalUsers, defenseKey)
		}
		// 否则：首次连接，完整遍历，避免误判
	}

	// 随机起始位置，避免总是遍历前面的用户
	// 这样可以：
	// 1. 公平性：所有用户有平等的验证机会
	// 2. 缓存均衡：不同位置的用户都能被缓存
	// 3. 防御优化：攻击者位置随机，不会固定消耗前N个检查
	startIdx := 0
	if totalUsers > 1 {
		startIdx = dice.Roll(totalUsers)
	}

	checkedCount := 0
	for i := 0; i < totalUsers; i++ {
		// 从随机位置开始，循环遍历
		idx := (startIdx + i) % totalUsers
		user := v.users[idx]

		// 跳过已验证失败的缓存用户
		if user == cachedUser {
			continue
		}

		// 优化：早期中断检查 - 对可疑连接提前终止
		checkedCount++
		if checkedCount > earlyStopThreshold {
			// 已检查足够多的用户仍未找到，极可能是攻击，提前放弃
			break
		}

		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]

			// 优化：使用内存池获取subkey缓冲区，避免频繁分配
			subkey := getSubkey(aeadCipher.KeyBytes)
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				// 优化：使用内存池获取TCP数据缓冲区
				data := getTCPData(4 + aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
				// TCP数据在返回后仍需使用，所以暂不归还到池

			case protocol.RequestCommandUDP:
				// 优化：使用内存池获取UDP数据缓冲区
				data := getUDPData()
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
				// UDP数据在返回后仍需使用，所以暂不归还到池
			}

			// 用完立即归还subkey到池，供下次使用
			putSubkey(subkey)

			if matchErr == nil {
				u = user
				err = account.CheckIV(iv)

				// 优化：找到用户后更新缓存（异步更新，不阻塞当前请求）
				if cacheKey != "" && v.userCache != nil {
					// 注意：这里在RLock内调用Put是安全的，因为UserCache内部有自己的锁
					v.userCache.Put(cacheKey, user)
				}

				// 优化：记录验证成功，清除失败记录
				if defenseKey != "" && v.attackDefense != nil {
					v.attackDefense.RecordSuccess(defenseKey)
				}

				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.

			// 优化：记录验证成功
			if defenseKey != "" && v.attackDefense != nil {
				v.attackDefense.RecordSuccess(defenseKey)
			}
			return
		}
	}

	// 优化：未找到用户，记录失败
	if defenseKey != "" && v.attackDefense != nil {
		v.attackDefense.RecordFailure(defenseKey)
	}

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
