package anytls

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

func (s *Server) handlePSH(ctx context.Context, sid uint32, body buf.MultiBuffer, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	if body.IsEmpty() {
		return nil
	}

	smu.Lock()
	st := (*streams)[sid]
	smu.Unlock()

	if st == nil {
		return s.handleLazyConnect(ctx, sid, body, streams, smu, dispatcher, sendFrame)
	}

	// Handle UDP-over-TCP v2 stream
	if st.isUDP {
		return s.handleUDPStream(ctx, sid, body, st, streams, smu, dispatcher, sendFrame)
	}

	// Normal TCP stream, forward data
	if st.link == nil {
		buf.ReleaseMulti(body)
		return errors.New("anytls: TCP stream link is nil")
	}
	if err := st.link.Writer.WriteMultiBuffer(body); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleLazyConnect(ctx context.Context, sid uint32, body buf.MultiBuffer, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	peekLen := int(body.Len())
	if peekLen > 259 {
		peekLen = 259
	}
	peek := make([]byte, peekLen)
	body.Copy(peek)
	dest, consumed, err := parseSocksAddr(peek)
	if err != nil {
		buf.ReleaseMulti(body)
		// Ignore parse errors for unknown streams (likely cleanup data after connection close)
		return nil
	}

	// Check for UDP-over-TCP v2 magic domain in lazy connect
	if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		// Mark as UDP stream and ignore any extra data in this frame
		smu.Lock()
		(*streams)[sid] = &stream{isUDP: true}
		smu.Unlock()

		// Send SYNACK for UDP stream
		if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
			errors.LogWarning(ctx, "anytls: lazy UDP SYNACK send error, streamId=", sid, " err=", err)
			buf.ReleaseMulti(body)
			return err
		}

		if consumed < int(body.Len()) {
			errors.LogWarning(ctx, "anytls: lazy connect PSH contains extra data, streamId=", sid)
		}
		buf.ReleaseMulti(body)
		return nil
	}

	l, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: lazy connect dispatcher error, streamId=", sid, " err=", err)
		buf.ReleaseMulti(body)
		return nil
	}
	smu.Lock()
	(*streams)[sid] = &stream{link: l}
	smu.Unlock()

	// Send SYNACK
	if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
		errors.LogWarning(ctx, "anytls: lazy connect SYNACK send error, streamId=", sid, " err=", err)
		buf.ReleaseMulti(body)
		return err
	}

	// If there's remaining data after SOCKS address, warn and discard it
	if consumed < int(body.Len()) {
		errors.LogWarning(ctx, "anytls: lazy connect PSH contains extra data, streamId=", sid)
	}
	buf.ReleaseMulti(body)

	// Start downlink pump
	go s.pumpDownlink(ctx, sid, l, streams, smu, sendFrame)
	return nil
}

func (s *Server) handleUDPStream(ctx context.Context, sid uint32, body buf.MultiBuffer, st *stream, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	// First PSH in UDP stream contains: uot.Request (IsConnect + Destination) + first UDP packet
	// Format: IsConnect(1) + SOCKS_ATYP(1) + Address(variable) + Port(2) + [SOCKS_ATYP + Address + Port + Length(2) + Data]
	if st.link == nil {
		if int(body.Len()) < 11 {
			errors.LogWarning(ctx, "anytls: UDP packet too short")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			buf.ReleaseMulti(body)
			return nil
		}

		peekLen := int(body.Len())
		if peekLen > 520 {
			peekLen = 520
		}
		peek := make([]byte, peekLen)
		body.Copy(peek)
		offset := 0

		// Parse uot.Request: IsConnect(1) + Destination(SOCKS format)
		isConnect := peek[offset] != 0
		offset++

		// Parse Request destination (SOCKS format: ATYP uses values 1/3/4)
		_, consumed, err := parseSocksAddr(peek[offset:])
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP failed to parse request destination:", err)
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			buf.ReleaseMulti(body)
			return nil
		}
		offset += consumed

		// Now parse first UDP packet: SOCKS_ATYP + Address + Port + Length + Data
		if len(peek) <= offset+1 {
			errors.LogWarning(ctx, "anytls: UDP no packet data after Request")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			buf.ReleaseMulti(body)
			return nil
		}

		// Parse packet destination (uot ATYP format: 0=IPv4, 1=IPv6, 2=Domain)
		// Try uot format first, fall back to SOCKS format if that fails
		packetDest, packetConsumed, err := parseUotAddr(peek[offset:])
		if err != nil {
			// Try SOCKS format as fallback
			packetDest, packetConsumed, err = parseSocksAddr(peek[offset:])
			if err != nil {
				errors.LogWarning(ctx, "anytls: UDP failed to parse packet destination:", err)
				_ = sendFrame(cmdFIN, sid, nil)
				smu.Lock()
				delete(*streams, sid)
				smu.Unlock()
				buf.ReleaseMulti(body)
				return nil
			}
		}
		offset += packetConsumed

		// Parse packet length (2 bytes)
		if len(peek) < offset+2 {
			errors.LogWarning(ctx, "anytls: UDP packet length missing")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			buf.ReleaseMulti(body)
			return nil
		}
		_ = binary.BigEndian.Uint16(peek[offset : offset+2]) // packetLen - not validated for multi-frame support
		offset += 2

		// Create UDP socket using dispatcher
		link, err := dispatcher.Dispatch(ctx, packetDest)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", sid, " err=", err)
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			buf.ReleaseMulti(body)
			return nil
		}

		// Save to stream
		st.link = link
		st.udpTarget = &packetDest
		st.isConnect = isConnect

		// Start UDP relay goroutine (downlink: UDP -> TCP stream)
		go s.pumpDownlink(ctx, sid, link, streams, smu, sendFrame)

		// Forward all available UDP payload data
		// Note: UDP packets may be split across multiple ANYTLS frames
		// The first frame contains: AddrPort + Length + partial_data
		// Subsequent frames contain: continuation_data
		udpPayload, consumedMb := buf.SplitSize(body, int32(offset))
		buf.ReleaseMulti(consumedMb)
		if len(udpPayload) > 0 {
			if err := st.link.Writer.WriteMultiBuffer(udpPayload); err != nil {
				errors.LogWarning(ctx, "anytls: UDP first payload write error, streamId=", sid, " err=", err)
			}
		}
		return nil
	}

	// Subsequent PSH: relay continuation UDP data to link
	// These frames contain the rest of the UDP packet data
	if st.link == nil {
		errors.LogWarning(ctx, "anytls: UDP stream link is nil, streamId=", sid)
		_ = sendFrame(cmdFIN, sid, nil)
		smu.Lock()
		delete(*streams, sid)
		smu.Unlock()
		buf.ReleaseMulti(body)
		return nil
	}
	if err := st.link.Writer.WriteMultiBuffer(body); err != nil {
		errors.LogWarning(ctx, "anytls: UDP uplink write error, streamId=", sid, " err=", err)
		_ = sendFrame(cmdFIN, sid, nil)
		smu.Lock()
		common.Close(st.link.Writer)
		delete(*streams, sid)
		smu.Unlock()
	}
	return nil
}

func (s *Server) pumpDownlink(ctx context.Context, sid uint32, link *transport.Link, streams *map[uint32]*stream, smu *sync.Mutex, sendFrame func(byte, uint32, []byte) error) {
	defer func() {
		smu.Lock()
		st := (*streams)[sid]
		delete(*streams, sid)
		smu.Unlock()
		if st != nil && st.link != nil {
			common.Close(st.link.Writer)
			common.Close(st.link.Reader)
		}
		_ = sendFrame(cmdFIN, sid, nil)
	}()

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		// Optimization: send all buffers in the batch
		// The sendFrame function will flush each time, but this is necessary
		// to ensure data is sent promptly. The OS will batch the writes.
		for _, b := range mb {
			if err := sendFrame(cmdPSH, sid, b.Bytes()); err != nil {
				b.Release()
				buf.ReleaseMulti(mb)
				return
			}
			b.Release()
		}
	}
}
