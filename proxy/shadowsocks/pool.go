package shadowsocks

import (
	"sync"
)

// 内存池，用于减少频繁的内存分配和GC压力
// 在高并发场景下，频繁的内存分配会导致：
// 1. CPU 时间浪费在内存分配上
// 2. GC 压力增大，导致 STW (Stop The World) 暂停
// 3. 内存碎片化

var (
	// subkeyPool HKDF派生密钥的缓冲池 (32字节)
	// 每次用户验证都需要一个subkey，使用池可以避免重复分配
	subkeyPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32)
		},
	}

	// tcpSmallDataPool TCP AEAD 小数据缓冲池 (128字节)
	// TCP 握手验证时使用，数据量较小
	tcpSmallDataPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 128)
		},
	}

	// udpDataPool UDP AEAD 数据缓冲池 (8192字节)
	// UDP 包通常较大，需要更大的缓冲区
	udpDataPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8192)
		},
	}
)

// getSubkey 从池中获取 subkey 缓冲区（优化：减少大小检查）
func getSubkey(size int32) []byte {
	// 优化：大部分 shadowsocks 密钥都是32字节，直接从池获取
	// 这样避免了频繁的大小检查和分支判断
	buf := subkeyPool.Get().([]byte)
	if int32(cap(buf)) >= size {
		return buf[:size]
	}
	// 罕见情况：需要更大的缓冲区，直接分配（不回池）
	subkeyPool.Put(buf) // 归还标准大小的缓冲区
	return make([]byte, size)
}

// putSubkey 归还 subkey 缓冲区到池（优化：简化检查）
func putSubkey(buf []byte) {
	// 优化：只检查容量，不检查当前长度
	// 因为我们总是将缓冲区重置为完整容量
	if cap(buf) == 32 {
		// 重用缓冲区，避免分配
		buf = buf[:32]
		subkeyPool.Put(buf)
	}
	// 非标准大小的缓冲区直接丢弃，由GC回收
}

// getTCPData 从池中获取 TCP 数据缓冲区
// size: 需要的大小
func getTCPData(size int) []byte {
	if size <= 128 {
		buf := tcpSmallDataPool.Get().([]byte)
		return buf[:size]
	}
	// 超过池大小，直接分配
	return make([]byte, size)
}

// getUDPData 从池中获取 UDP 数据缓冲区
func getUDPData() []byte {
	return udpDataPool.Get().([]byte)
}
