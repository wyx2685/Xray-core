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

func (s *Server) handleSYN(ctx context.Context, sid uint32, body []byte, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	if len(body) == 0 {
		// Empty SYN indicates lazy connect mode: client will send target in first PSH
		// Don't send SYNACK yet, wait for PSH with target address
		return nil
	}
	dest, _, err := parseSocksAddr(body)
	if err != nil {
		errors.LogWarning(ctx, "anytls: invalid target address, streamId=", sid)
		_ = sendFrame(cmdSYNACK, sid, []byte("invalid target address"))
		return nil
	}

	// Check for UDP-over-TCP v2 magic domain
	if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		// Check capacity and duplicates
		smu.Lock()
		if len(*streams) >= 64 {
			smu.Unlock()
			_ = sendFrame(cmdSYNACK, sid, []byte("too many streams"))
			return nil
		}
		if _, ok := (*streams)[sid]; ok {
			smu.Unlock()
			_ = sendFrame(cmdSYNACK, sid, []byte("duplicate stream"))
			return nil
		}
		// Mark as UDP stream
		(*streams)[sid] = &stream{isUDP: true}
		smu.Unlock()

		// Send SYNACK immediately for UDP-over-TCP
		if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
			return err
		}
		return nil
	}

	// TCP handling
	// check capacity and duplicates
	smu.Lock()
	if len(*streams) >= 64 {
		smu.Unlock()
		_ = sendFrame(cmdSYNACK, sid, []byte("too many streams"))
		return nil
	}
	if _, ok := (*streams)[sid]; ok {
		smu.Unlock()
		_ = sendFrame(cmdSYNACK, sid, []byte("duplicate stream"))
		return nil
	}
	smu.Unlock()

	l, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: dispatch failed, streamId=", sid, " err=", err)
		_ = sendFrame(cmdSYNACK, sid, []byte(err.Error()))
		return nil
	}
	smu.Lock()
	(*streams)[sid] = &stream{link: l}
	smu.Unlock()
	if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
		errors.LogWarning(ctx, "anytls: failed to send SYNACK, streamId=", sid, " err=", err)
		return err
	}

	// start downlink pump for this stream
	go s.pumpDownlink(ctx, sid, l, streams, smu, sendFrame)
	return nil
}

func (s *Server) handlePSH(ctx context.Context, sid uint32, body []byte, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	if len(body) == 0 {
		return nil
	}

	smu.Lock()
	st := (*streams)[sid]
	smu.Unlock()

	if st == nil {
		// Lazy connect: first PSH contains SOCKS address
		return s.handleLazyConnect(ctx, sid, body, streams, smu, dispatcher, sendFrame)
	}

	// Handle UDP-over-TCP v2 stream
	if st.isUDP {
		return s.handleUDPStream(ctx, sid, body, st, streams, smu, dispatcher, sendFrame)
	}

	// Normal TCP stream, forward data
	if err := st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(body)}); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleFIN(ctx context.Context, sid uint32, streams *map[uint32]*stream, smu *sync.Mutex, bw *buf.BufferedWriter) {
	smu.Lock()
	st := (*streams)[sid]
	smu.Unlock()
	if st != nil {
		common.Close(st.link.Writer)
		_ = bw.Flush()
	}
}

func (s *Server) handleLazyConnect(ctx context.Context, sid uint32, body []byte, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	dest, consumed, err := parseSocksAddr(body)
	if err != nil {
		// Ignore parse errors for unknown streams (likely cleanup data after connection close)
		return nil
	}

	// Check for UDP-over-TCP v2 magic domain in lazy connect
	if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		// Mark as UDP stream and immediately process remaining data as uot.Request
		smu.Lock()
		(*streams)[sid] = &stream{isUDP: true}
		smu.Unlock()

		// Send SYNACK for UDP stream
		if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
			errors.LogWarning(ctx, "anytls: lazy UDP SYNACK send error, streamId=", sid, " err=", err)
			return err
		}

		// If there's remaining data after SOCKS address, process it as uot.Request
		if consumed < len(body) {
			remainingData := body[consumed:]
			smu.Lock()
			st := (*streams)[sid]
			smu.Unlock()
			return s.handleUDPStream(ctx, sid, remainingData, st, streams, smu, dispatcher, sendFrame)
		}
		return nil
	}

	l, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: lazy connect dispatcher error, streamId=", sid, " err=", err)
		return nil
	}
	smu.Lock()
	(*streams)[sid] = &stream{link: l}
	smu.Unlock()

	// Send SYNACK
	if err := sendFrame(cmdSYNACK, sid, nil); err != nil {
		errors.LogWarning(ctx, "anytls: lazy connect SYNACK send error, streamId=", sid, " err=", err)
		return err
	}

	// If there's remaining data after SOCKS address, forward it to the target
	if consumed < len(body) {
		remainingData := body[consumed:]
		if err := l.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(remainingData)}); err != nil {
			return err
		}
	}

	// Start downlink pump
	go s.pumpDownlink(ctx, sid, l, streams, smu, sendFrame)
	return nil
}

func (s *Server) handleUDPStream(ctx context.Context, sid uint32, body []byte, st *stream, streams *map[uint32]*stream, smu *sync.Mutex, dispatcher routing.Dispatcher, sendFrame func(byte, uint32, []byte) error) error {
	// First PSH in UDP stream contains: uot.Request (IsConnect + Destination) + first UDP packet
	// Format: IsConnect(1) + SOCKS_ATYP(1) + Address(variable) + Port(2) + [SOCKS_ATYP + Address + Port + Length(2) + Data]
	if st.link == nil {
		// Minimum: IsConnect(1) + SOCKS header + packet header
		if len(body) < 11 {
			errors.LogWarning(ctx, "anytls: UDP packet too short")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			return nil
		}

		offset := 0

		// Parse uot.Request: IsConnect(1) + Destination(SOCKS format)
		isConnect := body[offset] != 0
		offset++

		// Parse Request destination (SOCKS format: ATYP uses values 1/3/4)
		_, consumed, err := parseSocksAddr(body[offset:])
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP failed to parse request destination:", err)
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			return nil
		}
		offset += consumed

		// Now parse first UDP packet: SOCKS_ATYP + Address + Port + Length + Data
		if len(body) <= offset+1 {
			errors.LogWarning(ctx, "anytls: UDP no packet data after Request")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			return nil
		}

		// Parse packet destination (uot ATYP format: 0=IPv4, 1=IPv6, 2=Domain)
		// Try uot format first, fall back to SOCKS format if that fails
		packetDest, packetConsumed, err := parseUotAddr(body[offset:])
		if err != nil {
			// Try SOCKS format as fallback
			packetDest, packetConsumed, err = parseSocksAddr(body[offset:])
			if err != nil {
				errors.LogWarning(ctx, "anytls: UDP failed to parse packet destination:", err)
				_ = sendFrame(cmdFIN, sid, nil)
				smu.Lock()
				delete(*streams, sid)
				smu.Unlock()
				return nil
			}
		}
		offset += packetConsumed

		// Parse packet length (2 bytes)
		if len(body) < offset+2 {
			errors.LogWarning(ctx, "anytls: UDP packet length missing")
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
			return nil
		}
		_ = binary.BigEndian.Uint16(body[offset : offset+2]) // packetLen - not validated for multi-frame support
		offset += 2

		// Create UDP socket using dispatcher
		link, err := dispatcher.Dispatch(ctx, packetDest)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", sid, " err=", err)
			_ = sendFrame(cmdFIN, sid, nil)
			smu.Lock()
			delete(*streams, sid)
			smu.Unlock()
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
		udpPayload := body[offset:]
		if len(udpPayload) > 0 {
			if err := st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(udpPayload)}); err != nil {
				errors.LogWarning(ctx, "anytls: UDP first payload write error, streamId=", sid, " err=", err)
			}
		}
		return nil
	}

	// Subsequent PSH: relay continuation UDP data to link
	// These frames contain the rest of the UDP packet data
	if err := st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(body)}); err != nil {
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
