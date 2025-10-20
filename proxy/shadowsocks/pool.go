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

// getSubkey 从池中获取 subkey 缓冲区
// size: 需要的大小，如果超过32字节则新分配
func getSubkey(size int32) []byte {
	if size > 32 {
		// 超过池大小，直接分配
		return make([]byte, size)
	}
	buf := subkeyPool.Get().([]byte)
	return buf[:size]
}

// putSubkey 归还 subkey 缓冲区到池
// 注意：只有标准大小(32字节)的缓冲区才放回池中
func putSubkey(buf []byte) {
	if cap(buf) == 32 {
		// 重置为完整容量后放回池
		subkeyPool.Put(buf[:32])
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

// putTCPData 归还 TCP 数据缓冲区到池
func putTCPData(buf []byte) {
	if cap(buf) == 128 {
		tcpSmallDataPool.Put(buf[:128])
	}
}

// getUDPData 从池中获取 UDP 数据缓冲区
func getUDPData() []byte {
	return udpDataPool.Get().([]byte)
}

// putUDPData 归还 UDP 数据缓冲区到池
func putUDPData(buf []byte) {
	if cap(buf) == 8192 {
		udpDataPool.Put(buf[:8192])
	}
}
