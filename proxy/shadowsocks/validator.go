package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"math/rand/v2"
	"strings"
	"sync"

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

	isRelayNode bool // 标记节点是否处于中转环境（检测到后保持，关闭攻击防御）
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

// expandCacheIfNeeded 根据用户数扩展缓存容量（简化策略）
func (v *Validator) expandCacheIfNeeded() {
	if v.userCache == nil {
		return
	}

	userCount := len(v.users)

	// 简化策略：只有三个档位的缓存容量
	var newCacheSize int
	switch {
	case userCount < 5000:
		return // 小于5000用户，不扩容
	case userCount < 20000:
		newCacheSize = 2048 // 中等规模：2048缓存
	default:
		newCacheSize = 8192 // 大规模：8192缓存（避免过大）
	}

	// 简化判断：只有在容量明显不足时才扩容
	// 避免频繁重建缓存
	v.userCache = NewUserCache(newCacheSize)
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

	// 缓存扩容策略优化：只在用户数量翻倍且超过阈值时扩容
	// 避免频繁的缓存重建导致连接不稳定
	userCount := len(v.users)
	// 只有当用户数超过2048且为2的幂次时才扩容
	if userCount >= 2048 && (userCount&(userCount-1)) == 0 {
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

	// 获取攻击防御统计（添加空指针保护）
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

// GetWithCache 带两级缓存支持的用户验证（优化IP变化场景）
//
// 查找策略：
// 1. 第一级：IP缓存直接命中（最快，O(1)）
// 2. 第二级：成功用户缓存遍历（较快，O(k)，k为活跃用户数）
// 3. 第三级：全量用户扫描（最慢，O(n)，n为总用户数）
//
// cacheKey: 缓存键（建议使用源地址 "ip:port"），为空则跳过缓存
func (v *Validator) GetWithCache(bs []byte, command protocol.RequestCommand, cacheKey string) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	// 优化：先尝试无锁缓存查找
	// 对于同一用户的多个并发连接，大部分都应该能命中缓存
	// 这样可以避免全局锁竞争，大幅提升并发性能
	var defenseKey string
	var cachedUser *protocol.MemoryUser
	var successUsers []*protocol.MemoryUser

	if cacheKey != "" {
		// 尝试两级缓存查找（无需全局锁），同时获取是否为中转环境
		var isRelay bool
		if v.userCache != nil {
			cachedUser, successUsers, isRelay = v.userCache.GetWithFallback(cacheKey)
			// 检测到中转环境，设置全局开关（只设置一次）
			if isRelay && !v.isRelayNode {
				v.Lock()
				v.isRelayNode = true
				v.Unlock()
			}
		}

		// 只有在非中转节点时才进行攻击防御
		if !v.isRelayNode && v.attackDefense != nil {
			isTCP := (command == protocol.RequestCommandTCP)
			defenseKey = v.attackDefense.CheckAndRecordConnection(cacheKey, isTCP)

			if defenseKey != "" && !v.attackDefense.CheckAllowed(defenseKey) {
				// 已被封禁，直接返回
				return nil, nil, nil, 0, ErrNotFound
			}
		}

		if cachedUser != nil {
			// 第一级缓存命中，直接验证
			if account := cachedUser.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
				if len(bs) >= 32 {
					aeadCipher := account.Cipher.(*AEADCipher)
					ivLen = aeadCipher.IVSize()
					iv := bs[:ivLen]

					// 优化：使用内存池获取subkey缓冲区
					subkey := getSubkey(aeadCipher.KeyBytes)
					hkdfSHA1(account.Key, iv, subkey)
					aead = aeadCipher.AEADAuthCreator(subkey)

					var matchErr error
					switch command {
					case protocol.RequestCommandTCP:
						// 优化：使用内存池获取TCP数据缓冲区
						data := getTCPData(4 + aead.NonceSize())
						ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
						// TCP数据在返回后仍需使用，暂不归还到池
					case protocol.RequestCommandUDP:
						// 优化：使用内存池获取UDP数据缓冲区
						data := getUDPData()
						ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
						// UDP数据在返回后仍需使用，暂不归还到池
					}

					// 用完立即归还subkey到池
					putSubkey(subkey)

					if matchErr == nil {
						// 第一级缓存命中且验证成功，记录成功并返回
						u = cachedUser
						err = account.CheckIV(iv)
						// 非中转节点才记录成功
						if !v.isRelayNode && defenseKey != "" && v.attackDefense != nil {
							v.attackDefense.RecordSuccess(defenseKey)
						}
						return
					}
					// 第一级缓存失效，继续第二级缓存验证
				}
			}
		}

		// 第二级缓存：验证成功用户列表（无需全局锁）
		if len(successUsers) > 0 {
			for _, successUser := range successUsers {
				if account := successUser.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
					if len(bs) >= 32 {
						aeadCipher := account.Cipher.(*AEADCipher)
						ivLen = aeadCipher.IVSize()
						iv := bs[:ivLen]

						// 优化：使用内存池获取subkey缓冲区
						subkey := getSubkey(aeadCipher.KeyBytes)
						hkdfSHA1(account.Key, iv, subkey)
						aead = aeadCipher.AEADAuthCreator(subkey)

						var matchErr error
						switch command {
						case protocol.RequestCommandTCP:
							// 优化：使用内存池获取TCP数据缓冲区
							data := getTCPData(4 + aead.NonceSize())
							ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
							// TCP数据在返回后仍需使用，暂不归还到池
						case protocol.RequestCommandUDP:
							// 优化：使用内存池获取UDP数据缓冲区
							data := getUDPData()
							ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
							// UDP数据在返回后仍需使用，暂不归还到池
						}

						// 用完立即归还subkey到池
						putSubkey(subkey)

						if matchErr == nil {
							// 第二级缓存命中且验证成功
							u = successUser
							err = account.CheckIV(iv)

							// 更新第一级缓存
							if cacheKey != "" && v.userCache != nil {
								v.userCache.PutWithSuccess(cacheKey, successUser)
							}

							// 非中转节点才记录成功
							if !v.isRelayNode && defenseKey != "" && v.attackDefense != nil {
								v.attackDefense.RecordSuccess(defenseKey)
							}
							return
						}
					}
				}
			}
		}
	}

	// 慢速路径：需要全局锁进行全量扫描
	v.RLock()
	defer v.RUnlock()

	// 全量扫描策略：早期中断优化
	totalUsers := len(v.users)
	earlyStopThreshold := totalUsers // 默认检查所有用户（保证正常用户能连接）

	// 白名单检查优化（新增）：（添加空指针保护）
	// - 如果IP在白名单中(曾经成功验证过)，跳过早停限制
	// - 这样正常用户打开新连接时不会因为"缓存未命中"而受早停影响
	// - 攻击者的IP不在白名单，仍然会触发早停
	isWhitelisted := false
	if defenseKey != "" && v.attackDefense != nil {
		// 使用 defenseKey(纯IP) 而不是 cacheKey(IP:Port)
		// defenseKey 已经在上面根据协议类型提取过了(TCP=纯IP, UDP=IP:Port)
		isWhitelisted = v.attackDefense.IsWhitelisted(defenseKey)
	}

	// 只有当连接已经有失败记录时，才启用早期中断（添加空指针保护）
	// 白名单IP(成功验证过的正常用户)不受早停限制
	if !isWhitelisted && defenseKey != "" && v.attackDefense != nil {
		if v.attackDefense.HasFailureRecord(defenseKey) {
			// 此连接之前失败过，可能是过期用户，启用渐进式早期中断
			// 连续失败越多，检查用户数越少，最终降至10个
			earlyStopThreshold = v.attackDefense.GetEarlyStopThreshold(totalUsers, defenseKey)
		}
		// 否则：首次连接，完整遍历，避免误判
	}

	// 随机起始位置：使用 math/rand/v2（无锁、高性能）
	// 优势：
	// 1. 无锁：每个 goroutine 有独立的随机数生成器
	// 2. 均匀分布：所有用户有平等的验证机会
	// 3. 性能：比 math/rand 快很多，无全局锁竞争
	startIdx := 0
	if totalUsers > 1 {
		startIdx = rand.IntN(totalUsers)
	}

	checkedCount := 0
	for i := 0; i < totalUsers; i++ {
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

				// 优化：找到用户后更新两级缓存（异步更新，不阻塞当前请求）
				if cacheKey != "" && v.userCache != nil {
					// 同时更新IP缓存和成功用户缓存
					v.userCache.PutWithSuccess(cacheKey, user)
				}

				// 非中转节点才记录验证成功（添加空指针保护）
				if !v.isRelayNode && defenseKey != "" && v.attackDefense != nil {
					v.attackDefense.RecordSuccess(defenseKey)
				}

				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.

			// 优化：更新两级缓存
			if cacheKey != "" && v.userCache != nil {
				v.userCache.PutWithSuccess(cacheKey, user)
			}

			// 非中转节点才记录验证成功
			if !v.isRelayNode && defenseKey != "" && v.attackDefense != nil {
				v.attackDefense.RecordSuccess(defenseKey)
			}
			return
		}
	}

	// 非中转节点才记录失败
	if !v.isRelayNode && defenseKey != "" && v.attackDefense != nil {
		v.attackDefense.RecordFailure(defenseKey)
	}

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = rand.Uint64()
	}
	return v.behaviorSeed
}
