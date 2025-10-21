package shadowsocks

import (
	"sync"
	"time"
)

// AttackDefense 攻击防御系统
// 主要用于多用户场景的性能优化，而非安全防御
//
// 真实场景分析：
// - "攻击"通常来自过期用户（已Del但客户端仍在连接）
// - 过期用户失败是正常现象，不应严格封禁
//
// 优化策略：
// 1. IP:Port防御：递进式封禁（5分钟→10分钟→20分钟→30分钟）
//   - 不同端口=不同连接，不会误伤
//
// 2. 早期中断：对重复失败的连接，渐进式减少检查用户数
//   - 1-2次失败：检查100%用户（避免误伤）
//   - 3-5次失败：检查50%用户
//   - 21+次失败：检查5%用户（明确是假用户）
type AttackDefense struct {
	shards [32]*defenseShardDB // 32个分片，降低锁竞争
	config DefenseConfig
}

// DefenseConfig 防御配置
type DefenseConfig struct {
	MaxFailures      int           // 最大失败次数（建议20+，过期用户会持续重试）
	BanDuration      time.Duration // 封禁时长（建议5分钟，递进式增长）
	CleanupInterval  time.Duration // 清理过期记录的间隔
	EarlyStopPercent int           // 早期中断基础百分比（最终会根据失败次数动态调整）
}

// defenseShardDB 防御分片数据库
type defenseShardDB struct {
	mu        sync.RWMutex
	records   map[string]*failureRecord // key: "ip:port" - 失败记录
	whitelist map[string]time.Time      // key: "ip" - 白名单(成功验证的IP及过期时间)
}

// failureRecord 失败记录
type failureRecord struct {
	failures  int       // 失败次数
	firstFail time.Time // 第一次失败时间
	lastFail  time.Time // 最后一次失败时间
	banned    bool      // 是否已被封禁
	banUntil  time.Time // 封禁到期时间
	banCount  int       // 被封禁次数（用于递进式封禁）

	// 新增:连续失败次数（用于渐进式限制）
	consecutiveFails int // 连续失败次数（成功后重置）
}

// NewAttackDefense 创建攻击防御系统
func NewAttackDefense(config *DefenseConfig) *AttackDefense {
	if config == nil {
		config = &DefenseConfig{
			MaxFailures:      20,              // 两级缓存优化后，可以适当收紧到20次
			BanDuration:      3 * time.Minute, // 缩短到3分钟（快速恢复+性能优化）
			CleanupInterval:  5 * time.Minute, // 适中的清理频率
			EarlyStopPercent: 30,              // 收紧到30%（性能释放，两级缓存补偿）
		}
	}

	// 确保配置有效
	if config.MaxFailures <= 0 {
		config.MaxFailures = 15
	}
	if config.BanDuration <= 0 {
		config.BanDuration = 10 * time.Minute
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	d := &AttackDefense{
		config: *config,
	}

	// 初始化32个分片
	for i := 0; i < 32; i++ {
		d.shards[i] = &defenseShardDB{
			records:   make(map[string]*failureRecord),
			whitelist: make(map[string]time.Time),
		}
	}

	// 启动清理协程
	go d.cleanupLoop()

	return d
}

// CheckAllowed 检查IP是否被允许
// 返回 true 表示允许继续验证，false 表示应该直接拒绝
func (d *AttackDefense) CheckAllowed(addr string) bool {
	if addr == "" {
		return true // 没有地址信息，允许通过
	}

	shard := d.getShard(addr)
	shard.mu.RLock()
	record, exists := shard.records[addr]
	shard.mu.RUnlock()

	if !exists {
		return true // 首次连接，允许
	}

	now := time.Now()

	// 检查是否在封禁期内
	if record.banned && now.Before(record.banUntil) {
		return false // 仍在封禁期，拒绝
	}

	// 检查失败次数和时间窗口
	if record.failures >= d.config.MaxFailures {
		// 超过最大失败次数，检查是否需要解禁
		if now.Sub(record.lastFail) > d.config.BanDuration {
			// 已过封禁期，重置记录
			shard.mu.Lock()
			delete(shard.records, addr)
			shard.mu.Unlock()
			return true
		}
		return false // 仍在封禁期，拒绝
	}

	return true
}

// IsWhitelisted 检查IP是否在白名单中（成功验证过的IP）
// 参数 addr: 防御键(TCP=纯IP, UDP=IP:Port)
func (d *AttackDefense) IsWhitelisted(addr string) bool {
	if addr == "" {
		return false
	}

	// 提取纯IP（UDP的defenseKey包含端口，需要提取；TCP的defenseKey已经是纯IP）
	ip := addr
	if colonIdx := len(addr) - 1; colonIdx > 0 {
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				ip = addr[:i]
				break
			}
		}
	}

	shard := d.getShard(ip) // 使用纯IP计算分片(与RecordSuccess一致)
	shard.mu.RLock()
	expireTime, exists := shard.whitelist[ip]
	shard.mu.RUnlock()

	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().After(expireTime) {
		// 过期了,异步清理(避免持锁)
		go func() {
			shard.mu.Lock()
			delete(shard.whitelist, ip)
			shard.mu.Unlock()
		}()
		return false
	}

	return true
}

// HasFailureRecord 检查是否有失败记录
// 用于判断是否应该启用早期中断优化
func (d *AttackDefense) HasFailureRecord(addr string) bool {
	if addr == "" {
		return false
	}

	shard := d.getShard(addr)
	shard.mu.RLock()
	_, exists := shard.records[addr]
	shard.mu.RUnlock()

	return exists
}

// RecordFailure 记录验证失败
func (d *AttackDefense) RecordFailure(addr string) {
	if addr == "" {
		return
	}

	now := time.Now()
	shard := d.getShard(addr)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	record, exists := shard.records[addr]
	if !exists {
		record = &failureRecord{
			failures:         1,
			firstFail:        now,
			lastFail:         now,
			consecutiveFails: 1, // 新增
		}
		shard.records[addr] = record
	} else {
		record.failures++
		record.consecutiveFails++ // 累加连续失败
		record.lastFail = now

		// 检查是否需要封禁
		if record.failures >= d.config.MaxFailures {
			record.banned = true
			record.banCount++

			// 递进式封禁：每次封禁时长翻倍
			// 1次: 5分钟
			// 2次: 10分钟
			// 3次: 20分钟
			// 4次+: 30分钟（上限）
			banDuration := d.config.BanDuration
			for i := 1; i < record.banCount && i < 3; i++ {
				banDuration *= 2
			}
			if banDuration > 30*time.Minute {
				banDuration = 30 * time.Minute
			}

			record.banUntil = now.Add(banDuration)
			// 重置失败计数，为下次解封做准备
			record.failures = 0
		}
	}
}

// RecordSuccess 记录验证成功（清除失败记录+加入白名单）
// 参数 addr: 防御键(TCP=纯IP, UDP=IP:Port)
func (d *AttackDefense) RecordSuccess(addr string) {
	if addr == "" {
		return
	}

	// 提取纯IP（UDP的defenseKey包含端口，需要提取；TCP的defenseKey已经是纯IP）
	ip := addr
	if colonIdx := len(addr) - 1; colonIdx > 0 {
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				ip = addr[:i]
				break
			}
		}
	}

	// 注意：失败记录用完整 defenseKey(addr)，白名单用纯IP
	// - TCP: addr=IP, 两者相同
	// - UDP: addr=IP:Port, 需要区分
	shard := d.getShard(addr) // 用 addr 查找失败记录的分片
	shard.mu.Lock()

	// 清除失败记录(使用完整 defenseKey)
	delete(shard.records, addr)

	shard.mu.Unlock()

	// 加入白名单(使用纯IP，1小时过期)
	// 注意：白名单用IP的分片(与IsWhitelisted一致)
	ipShard := d.getShard(ip)
	ipShard.mu.Lock()
	ipShard.whitelist[ip] = time.Now().Add(1 * time.Hour)
	ipShard.mu.Unlock()
}

// CheckAndRecordConnection 检查并记录连接
// 返回防御标识符（TCP用纯IP，UDP用IP:Port）
//
// 防御粒度分析：
//   - TCP攻击：客户端端口是临时的，每次连接都不同
//     → 必须用纯IP防御，否则攻击者换端口就绕过
//   - UDP攻击：客户端端口通常固定（同一个socket）
//     → 可以用IP:Port防御，避免误伤同IP的其他用户
//
// 参数：
// - addr: 源地址 "ip:port"
// - isTCP: true=TCP连接，false=UDP包
func (d *AttackDefense) CheckAndRecordConnection(addr string, isTCP bool) string {
	if addr == "" {
		return ""
	}

	// TCP连接：只用IP（攻击者会不断换端口）
	if isTCP {
		// 提取纯IP（去掉端口）
		ip := addr
		if colonIdx := len(addr) - 1; colonIdx > 0 {
			for i := len(addr) - 1; i >= 0; i-- {
				if addr[i] == ':' {
					ip = addr[:i]
					break
				}
			}
		}
		return ip
	}

	// UDP包：使用完整地址（端口通常固定）
	return addr
}

// GetEarlyStopThreshold 获取早期中断阈值（两级缓存优化版）
// 配合20次失败阈值和3分钟封禁，以及两级缓存机制，实现性能和安全的平衡
//
// 两级缓存优化策略：
// - 正常用户：第一级IP缓存命中（O(1)）或第二级成功用户缓存（O(k)，k<<n）
// - 攻击用户：无法命中缓存，需要全量扫描，此时早期中断生效
// - 1-5次失败：检查100%用户（给正常用户充足机会）
// - 6-12次失败：检查50%用户（开始限制可疑连接）
// - 13-19次失败：检查30%用户（严格限制）
// - 20+次失败：启用封禁（确认为攻击）
func (d *AttackDefense) GetEarlyStopThreshold(totalUsers int, addr string) int {
	if d.config.EarlyStopPercent <= 0 {
		return totalUsers // 不启用早期中断
	}

	// 获取连续失败次数
	consecutiveFails := d.getConsecutiveFailures(addr)

	var percent int
	switch {
	case consecutiveFails <= 5:
		// 1-5次失败：检查所有用户（给正常用户充足机会）
		return totalUsers
	case consecutiveFails <= 12:
		// 6-12次失败：检查50%（开始限制可疑连接，两级缓存补偿）
		percent = 50
	case consecutiveFails <= 19:
		// 13-19次失败：检查30%（严格限制，接近封禁）
		percent = 30
	default:
		// 20+次失败：检查20%（最小检查，即将封禁）
		percent = 20
	}

	threshold := totalUsers * percent / 100

	// 大规模场景优化：针对10K-300K用户规模调整最小阈值
	// 正常用户命中两级缓存，攻击者才需要全量扫描+早期中断
	minThreshold := 200 // 大规模场景：最少检查200用户
	if totalUsers < 1000 {
		minThreshold = totalUsers / 10 // 中小规模：至少10%
	} else if totalUsers < 10000 {
		minThreshold = totalUsers / 20 // 中等规模：至少5%
	} else {
		minThreshold = totalUsers / 50 // 大规模：至少2%，但不少于200
		if minThreshold < 200 {
			minThreshold = 200
		}
	}

	if minThreshold > totalUsers {
		minThreshold = totalUsers
	}

	if threshold < minThreshold {
		threshold = minThreshold
	}

	return threshold
}

// getConsecutiveFailures 获取连续失败次数
func (d *AttackDefense) getConsecutiveFailures(addr string) int {
	if addr == "" {
		return 0
	}

	shard := d.getShard(addr)
	shard.mu.RLock()
	record, exists := shard.records[addr]
	shard.mu.RUnlock()

	if !exists {
		return 0
	}

	return record.consecutiveFails
}

// getShard 根据地址计算分片索引
// 使用完整字符串hash，保证相同地址总是映射到同一分片
func (d *AttackDefense) getShard(addr string) *defenseShardDB {
	hash := uint32(0)
	// 使用完整字符串计算hash，保证分布均匀且一致
	for i := 0; i < len(addr); i++ {
		hash = hash*31 + uint32(addr[i])
	}
	return d.shards[hash%32]
}

// cleanupLoop 定期清理过期记录
func (d *AttackDefense) cleanupLoop() {
	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		d.cleanup()
	}
}

// cleanup 清理过期记录（优化：分批清理，减少持锁时间）
func (d *AttackDefense) cleanup() {
	now := time.Now()

	// 分批清理，避免持锁时间过长
	// 场景：100万条记录，每个分片3万条，一次性清理持锁5ms
	// 优化：每批1000条，分30批，每批持锁~200μs，批次间释放锁
	const batchSize = 1000
	const maxRecordsPerShard = 100000 // 每个分片最多10万条记录，32分片共320万条

	for i := 0; i < 32; i++ {
		shard := d.shards[i]

		// 分批清理失败记录
		for {
			toDelete := make([]string, 0, batchSize)

			shard.mu.Lock()

			// 紧急清理：如果记录数超过最大限制，强制清理最旧的
			// 防御场景：持续的大规模DDoS攻击导致内存无限增长
			if len(shard.records) > maxRecordsPerShard {
				// 强制删除最旧的记录
				count := 0
				for addr := range shard.records {
					toDelete = append(toDelete, addr)
					count++
					if count >= batchSize {
						break
					}
				}
			} else {
				// 正常清理：删除过期记录
				count := 0
				for addr, record := range shard.records {
					// 清理超过封禁时长2倍的记录
					if now.Sub(record.lastFail) > d.config.BanDuration*2 {
						toDelete = append(toDelete, addr)
						count++
						if count >= batchSize {
							break // 达到批次大小，停止收集
						}
					}
				}
			}

			// 批量删除失败记录
			for _, addr := range toDelete {
				delete(shard.records, addr)
			}

			// 清理过期的白名单
			toDeleteWhitelist := make([]string, 0, batchSize)
			count := 0
			for ip, expireTime := range shard.whitelist {
				if now.After(expireTime) {
					toDeleteWhitelist = append(toDeleteWhitelist, ip)
					count++
					if count >= batchSize {
						break
					}
				}
			}
			for _, ip := range toDeleteWhitelist {
				delete(shard.whitelist, ip)
			}

			recordCount := len(shard.records)

			shard.mu.Unlock()

			// 如果记录数已经降到安全范围，且这批未满，说明清理完毕
			if recordCount <= maxRecordsPerShard && len(toDelete) < batchSize {
				break
			}

			// 批次间短暂休眠，让其他goroutine有机会获取锁
			// 避免清理过程霸占锁，阻塞正常请求
			time.Sleep(time.Microsecond * 100)
		}
	}
}

// GetStats 获取防御统计信息
func (d *AttackDefense) GetStats() DefenseStats {
	stats := DefenseStats{}

	for i := 0; i < 32; i++ {
		shard := d.shards[i]
		shard.mu.RLock()

		for _, record := range shard.records {
			stats.TotalRecords++
			if record.banned {
				stats.BannedIPs++
			}
			stats.TotalFailures += record.failures
		}

		shard.mu.RUnlock()
	}

	return stats
}

// DefenseStats 防御统计信息
type DefenseStats struct {
	TotalRecords  int // 总记录数
	BannedIPs     int // 被封禁的IP数
	TotalFailures int // 总失败次数
}
