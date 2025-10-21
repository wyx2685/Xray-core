package antireplay

import (
	"hash/crc32"
	"sync"

	ss_bloomring "github.com/v2fly/ss-bloomring"
)

const (
	// DefaultShardCount 默认分片数量，平衡性能和内存开销
	// 优化：调整为64，在性能和内存之间取得平衡
	// 64分片可以有效降低锁竞争，同时不会过度消耗内存
	DefaultShardCount = 64
	// DefaultCapacityPerShard 每个分片的默认容量
	DefaultCapacityPerShard = 16000 // 总容量 1M / 64 分片
	// DefaultFPR 默认误判率
	DefaultFPR = 1e-6
	// DefaultSlot 默认时间槽数量
	DefaultSlot = 10
)

// ShardedBloomRing 分片布隆环，通过多个分片降低锁争用，提升并发性能
type ShardedBloomRing struct {
	shards    []*bloomRingShard
	numShards uint32
}

// bloomRingShard 单个分片，包含独立的布隆环和锁
type bloomRingShard struct {
	ring *ss_bloomring.BloomRing
	lock sync.Mutex
}

// NewShardedBloomRing 创建分片布隆环
// shardCount: 分片数量，建议32-128之间，过少无法充分降低争用，过多增加内存开销
// capacity: 总容量，会平均分配到各个分片
// fpr: 误判率
// slotCount: 时间槽数量
func NewShardedBloomRing(shardCount int, capacity int, fpr float64, slotCount int) *ShardedBloomRing {
	if shardCount <= 0 {
		shardCount = DefaultShardCount
	}
	if capacity <= 0 {
		capacity = int(1e6)
	}
	if fpr <= 0 {
		fpr = DefaultFPR
	}
	if slotCount <= 0 {
		slotCount = DefaultSlot
	}

	sbr := &ShardedBloomRing{
		shards:    make([]*bloomRingShard, shardCount),
		numShards: uint32(shardCount),
	}

	// 每个分片的容量 = 总容量 / 分片数
	shardCapacity := capacity / shardCount
	if shardCapacity < 1000 {
		shardCapacity = 1000 // 最小容量保护
	}

	// 初始化所有分片
	for i := 0; i < shardCount; i++ {
		sbr.shards[i] = &bloomRingShard{
			ring: ss_bloomring.NewBloomRing(slotCount, shardCapacity, fpr),
		}
	}

	return sbr
}

// NewDefaultShardedBloomRing 使用默认参数创建分片布隆环
// 默认配置: 64分片，总容量1M，误判率1e-6，10个时间槽
func NewDefaultShardedBloomRing() *ShardedBloomRing {
	return NewShardedBloomRing(
		DefaultShardCount,
		int(1e6),
		DefaultFPR,
		DefaultSlot,
	)
}

// Interval 实现 GeneralizedReplayFilter 接口
func (s *ShardedBloomRing) Interval() int64 {
	return 9999999
}

// Check 检查并添加IV，实现重放攻击检测
// 使用 CRC32 哈希将 IV 映射到不同分片，实现负载均衡
// 只锁定对应的单个分片，其他分片可以并发处理
func (s *ShardedBloomRing) Check(sum []byte) bool {
	// 使用 CRC32 哈希选择分片，快速且分布均匀
	shardIdx := crc32.ChecksumIEEE(sum) % s.numShards
	shard := s.shards[shardIdx]

	// 只锁定当前分片，不影响其他分片的并发处理
	shard.lock.Lock()
	defer shard.lock.Unlock()

	// 检查是否已存在（重放攻击）
	if shard.ring.Test(sum) {
		return false // 检测到重放
	}

	// 添加到布隆环
	shard.ring.Add(sum)
	return true // 通过检查
}
