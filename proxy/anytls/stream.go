package anytls

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

type stream struct {
	sid  uint32
	link *transport.Link

	done     chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	err      error
	dieHook  func()

	dispatchCtx  context.Context
	isUDP        bool
	udpTarget    *xnet.Destination
	udpIsConnect bool
	// udpReqParsed indicates the one-shot UoT request header has been consumed.
	udpReqParsed bool
	// udpBuf accumulates raw UoT bytes across PSH frames so datagrams can be
	// reassembled regardless of how the stream is chunked into frames.
	udpBuf []byte
	// udpLastActive holds the unix-nano timestamp of the most recent UDP traffic
	// in either direction; the idle watchdog uses it to reap dead associations.
	udpLastActive atomic.Int64
	// udpIdleTimer is the per-UDP-stream inactivity watchdog (server side).
	udpIdleTimer *time.Timer
}

func newStream(sid uint32, link *transport.Link) *stream {
	return &stream{
		sid:  sid,
		link: link,
		done: make(chan struct{}),
	}
}

func (st *stream) close(err error) {
	if st.done == nil {
		if st.link != nil {
			// link.Reader is a *pipe.Reader, which has no Close() method, so
			// common.Close on it is a silent no-op. A UoT downlink pump blocked
			// on link.Reader.ReadMultiBuffer therefore never wakes up (UDP
			// outbounds never EOF on their own). Interrupt closes the pipe's
			// done channel and unblocks the read, which is what actually reaps
			// the pump. Close the writer to signal EOF to the outbound.
			common.Interrupt(st.link.Reader)
			common.Close(st.link.Writer)
		}
		return
	}
	st.doneOnce.Do(func() {
		st.errMu.Lock()
		st.err = err
		st.errMu.Unlock()
		if st.link != nil {
			// link.Reader is a *pipe.Reader, which has no Close() method, so
			// common.Close on it is a silent no-op. A UoT downlink pump blocked
			// on link.Reader.ReadMultiBuffer therefore never wakes up (UDP
			// outbounds never EOF on their own). Interrupt closes the pipe's
			// done channel and unblocks the read, which is what actually reaps
			// the pump. Close the writer to signal EOF to the outbound.
			common.Interrupt(st.link.Reader)
			common.Close(st.link.Writer)
		}
		close(st.done)
		if st.dieHook != nil {
			st.dieHook()
		}
	})
}

func (st *stream) result() error {
	st.errMu.Lock()
	defer st.errMu.Unlock()
	return st.err
}
