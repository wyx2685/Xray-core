package anytls

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type session struct {
	isClient bool
	conn     stat.Connection
	br       *buf.BufferedReader
	bw       *buf.BufferedWriter
	fw       *frameWriter

	writeMu sync.Mutex

	streamsMu sync.Mutex
	streams   map[uint32]*stream

	peerVersion byte
	errCh       chan error
	closed      atomic.Bool
	seq         uint64

	server           *Server
	dispatcher       routing.Dispatcher
	handshakeDone    bool
	clientPaddingMD5 string
	noTLS            bool

	client       *Client
	nextSID      atomic.Uint32
	pktCounter   atomic.Uint32
	settingsSent bool

	schemeMu      sync.RWMutex
	paddingScheme *paddingScheme

	synAckMu sync.Mutex
	synAckCh map[uint32]chan error

	activeStreams atomic.Int32
	idleSinceNano atomic.Int64
	inIdlePool    atomic.Bool
	dieHook       func()
}

func (s *session) dispatchContext(ctx context.Context, st *stream) context.Context {
	if st.dispatchCtx != nil {
		return st.dispatchCtx
	}
	dispatchCtx := sessionctx.SubContextFromMuxInbound(ctx)
	if s.noTLS {
		if content := sessionctx.ContentFromContext(dispatchCtx); content != nil {
			content.SetAttribute("anytls", "notls")
		}
	}
	st.dispatchCtx = dispatchCtx
	return dispatchCtx
}

func (s *session) handleNewStream(ctx context.Context, st *stream, body buf.MultiBuffer) error {
	var first *buf.Buffer
	body, first = buf.SplitFirst(body)
	if first == nil {
		return errors.New("anytls: missing destination address in PSH")
	}

	addr, err := M.SocksaddrSerializer.ReadAddrPort(first)
	if err != nil {
		first.Release()
		return err
	}
	if !first.IsEmpty() {
		body = append(buf.MultiBuffer{first}, body...)
		first = nil
	} else {
		first.Release()
	}
	dest, err := singbridge.ToDestination(addr, net.Network_TCP)
	if err != nil {
		buf.ReleaseMulti(body)
		return errors.New("anytls: invalid destination address in SYN")
	}

	dispatchCtx := s.dispatchContext(ctx, st)

	if dest.Address.String() == "sp.v2.udp-over-tcp.arpa" {
		st.isUDP = true
		if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
			errors.LogWarning(ctx, "anytls: UDP SYNACK send error, streamId=", st.sid, " err=", err)
			return err
		}
		if !body.IsEmpty() {
			return s.feedUDP(dispatchCtx, st, body)
		}
		return nil
	} else if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		errors.LogWarning(ctx, "anytls: unsupported UDP destination: "+dest.Address.String())
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		s.finishStream(st.sid, nil)
		return nil
	}

	l, err := s.dispatcher.Dispatch(dispatchCtx, dest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: new stream dispatcher error, streamId=", st.sid, " err=", err)
		return nil
	}
	st.link = l

	if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
		errors.LogWarning(ctx, "anytls: new stream SYNACK send error, streamId=", st.sid, " err=", err)
		return err
	}
	if !body.IsEmpty() {
		if err := st.link.Writer.WriteMultiBuffer(body); err != nil {
			return err
		}
	}

	go s.pumpDownlink(st.sid, l)
	return nil
}

// isIncompleteRead reports whether err is the result of a short/truncated read,
// i.e. the UoT stream simply has not delivered enough bytes yet (as opposed to a
// genuinely malformed frame). Such reads must be retried once more data arrives.
func isIncompleteRead(err error) bool {
	return stderrors.Is(err, io.EOF) || stderrors.Is(err, io.ErrUnexpectedEOF)
}

// failUDP tears down a single UDP stream after an unrecoverable protocol error
// without killing the whole session (matching the previous behaviour).
func (s *session) failUDP(ctx context.Context, st *stream, msg string, err error) error {
	errors.LogWarning(ctx, "anytls: "+msg, ", streamId=", st.sid, " err=", err)
	_ = s.sendFrame(newFrame(cmdFIN, st.sid))
	s.finishStream(st.sid, nil)
	return nil
}

// writeUDPDatagram forwards exactly one UDP datagram to the dispatched link.
// Each datagram is written as a single buffer so the outbound treats it as one
// packet, and b.UDP carries the explicit destination.
func (s *session) writeUDPDatagram(st *stream, dest net.Destination, payload []byte) error {
	b := buf.NewWithSize(int32(len(payload)))
	if len(payload) > 0 {
		if _, err := b.Write(payload); err != nil {
			b.Release()
			return err
		}
	}
	d := dest
	b.UDP = &d
	return st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

// feedUDP is the unified UoT uplink handler. UoT is a continuous byte stream
// ([request][addr?][len][payload]...) whose datagram boundaries are independent
// of how the data is split into PSH frames. It therefore accumulates the raw
// bytes and extracts every complete datagram, keeping any partial tail for the
// next frame.
func (s *session) feedUDP(ctx context.Context, st *stream, body buf.MultiBuffer) error {
	// Any PSH frame for this stream is uplink activity; refresh the idle clock.
	st.udpLastActive.Store(time.Now().UnixNano())
	for _, b := range body {
		if b != nil && !b.IsEmpty() {
			st.udpBuf = append(st.udpBuf, b.Bytes()...)
		}
	}
	buf.ReleaseMulti(body)

	off := 0
	for off < len(st.udpBuf) {
		slice := st.udpBuf[off:]
		r := bytes.NewReader(slice)

		// The UoT request header is present exactly once, at the very start.
		if !st.udpReqParsed {
			request, err := uot.ReadRequest(r)
			if err != nil {
				if isIncompleteRead(err) {
					break
				}
				return s.failUDP(ctx, st, "UDP failed to parse request", err)
			}
			requestDest, derr := singbridge.ToDestination(request.Destination, net.Network_UDP)
			if derr != nil {
				return s.failUDP(ctx, st, "UDP invalid destination", derr)
			}
			link, lerr := s.dispatcher.Dispatch(s.dispatchContext(ctx, st), requestDest)
			if lerr != nil {
				return s.failUDP(ctx, st, "UDP dispatcher error", lerr)
			}
			st.link = link
			st.udpTarget = &requestDest
			st.udpIsConnect = request.IsConnect
			st.udpReqParsed = true
			// Arm the idle watchdog before starting the pump so its cleanup
			// always sees a non-nil timer.
			s.armUDPIdle(st)
			go s.pumpUoTDownlink(st, link, request.IsConnect, request.Destination)
			off += len(slice) - r.Len()
			continue
		}

		// Per-packet destination is only present in non-connect (full-cone) mode.
		pktDest := *st.udpTarget
		if !st.udpIsConnect {
			addr, err := uot.AddrParser.ReadAddrPort(r)
			if err != nil {
				if isIncompleteRead(err) {
					break
				}
				return s.failUDP(ctx, st, "UDP packet missing destination address", err)
			}
			d, derr := singbridge.ToDestination(addr, net.Network_UDP)
			if derr != nil {
				return s.failUDP(ctx, st, "UDP packet has invalid destination address", derr)
			}
			pktDest = d
		}

		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			// length header not fully arrived yet; wait for the next frame.
			break
		}
		headerLen := len(slice) - r.Len()
		if headerLen+int(length) > len(slice) {
			// payload not fully arrived yet; keep the partial tail.
			break
		}
		payload := slice[headerLen : headerLen+int(length)]

		// Full-cone (non-connect) traffic to many destinations all flows over
		// the single link dispatched when the UoT request was parsed; the
		// per-packet destination is carried via b.UDP (set in writeUDPDatagram)
		// and honoured by the outbound. We must NOT re-dispatch / spawn a new
		// downlink pump per destination: that both deviates from how xray
		// handles full-cone UDP and leaks pump goroutines (a pump whose stream
		// was already removed from s.streams never gets its link closed and
		// blocks forever on Read).
		if err := s.writeUDPDatagram(st, pktDest, payload); err != nil {
			return err
		}
		off += headerLen + int(length)
	}

	// Drop consumed bytes, retaining only the not-yet-complete tail.
	if off > 0 {
		st.udpBuf = append(st.udpBuf[:0], st.udpBuf[off:]...)
	}
	return nil
}

func (s *session) pumpDownlink(sid uint32, link *transport.Link) {
	defer func() {
		s.streamsMu.Lock()
		st := s.streams[sid]
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		if st != nil && st.link != nil {
			common.Close(st.link.Writer)
			common.Interrupt(st.link.Reader)
		}
		if !s.isClosed() {
			_ = s.sendFrame(newFrame(cmdFIN, sid))
		}
	}()

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		if err := s.sendStreamData(sid, mb, 0); err != nil {
			return
		}
	}
}

// anytlsUDPIdleTimeout reaps UoT streams with no traffic in either direction
// for this long. UDP outbounds never EOF on their own and many clients never
// FIN idle UDP associations (DNS, abandoned QUIC, TUN short flows); without an
// explicit reaper the per-stream downlink pump blocks on the pipe forever and
// the goroutine leaks. This timeout is independent of (and may be shorter
// than) the outbound ConnectionIdle policy: it only fires after full
// bidirectional silence, so genuinely active associations are never dropped.
// 120s matches common UDP NAT association timeouts.
const anytlsUDPIdleTimeout = 120 * time.Second

// armUDPIdle starts a self-rescheduling inactivity watchdog for a UDP stream.
// time.AfterFunc keeps no goroutine parked while waiting; it only runs when it
// fires, at which point it either reaps a truly idle stream or reschedules.
func (s *session) armUDPIdle(st *stream) {
	st.udpIdleTimer = time.AfterFunc(anytlsUDPIdleTimeout, func() {
		s.streamsMu.Lock()
		_, alive := s.streams[st.sid]
		s.streamsMu.Unlock()
		if !alive {
			return // stream already gone; stop rescheduling
		}
		idle := time.Duration(time.Now().UnixNano() - st.udpLastActive.Load())
		if idle >= anytlsUDPIdleTimeout {
			// No traffic for the whole window: close the stream, which unblocks
			// and ends the downlink pump.
			s.finishStream(st.sid, nil)
			return
		}
		st.udpIdleTimer.Reset(anytlsUDPIdleTimeout - idle)
	})
}

func (s *session) pumpUoTDownlink(st *stream, link *transport.Link, isConnect bool, dest M.Socksaddr) {
	sid := st.sid
	defer func() {
		if st.udpIdleTimer != nil {
			st.udpIdleTimer.Stop()
		}
		s.streamsMu.Lock()
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		if !s.isClosed() {
			_ = s.sendFrame(newFrame(cmdFIN, sid))
		}
	}()

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		// Downlink data arrived; refresh the idle clock.
		st.udpLastActive.Store(time.Now().UnixNano())
		// Each buffer is one UDP datagram. Frame every datagram independently so
		// the peer's stream parser sees correct UoT packet boundaries; merging
		// them under a single length header would corrupt the stream.
		for _, b := range mb {
			if b == nil {
				continue
			}
			hdr := buf.New()
			if !isConnect {
				src := dest
				if b.UDP != nil {
					src = singbridge.ToSocksaddr(*b.UDP)
				}
				if err := uot.AddrParser.WriteAddrPort(hdr, src); err != nil {
					hdr.Release()
					b.Release()
					continue
				}
			}
			p := hdr.Extend(2)
			binary.BigEndian.PutUint16(p, uint16(b.Len()))
			if err := s.sendStreamData(sid, buf.MultiBuffer{hdr, b}, 0); err != nil {
				return
			}
		}
	}
}

func (s *session) isClosed() bool {
	return s.closed.Load()
}

func (s *session) close(err error) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if err != nil {
		select {
		case s.errCh <- err:
		default:
		}
	}
	_ = s.conn.Close()

	s.streamsMu.Lock()
	streams := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*stream)
	s.streamsMu.Unlock()

	for _, st := range streams {
		st.close(err)
	}
	if s.dieHook != nil {
		s.dieHook()
	}
}

func (s *session) finishStream(sid uint32, err error) {
	s.streamsMu.Lock()
	st := s.streams[sid]
	if st != nil {
		delete(s.streams, sid)
	}
	s.streamsMu.Unlock()

	if st == nil {
		return
	}

	if s.client != nil {
		s.activeStreams.Add(-1)
	}
	st.close(err)
}

func (s *session) sendFrame(f *frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.fw.writeFrame(f); err != nil {
		return err
	}
	return s.fw.flush()
}

func (s *session) sendStreamData(sid uint32, data buf.MultiBuffer, packetIndex uint32) error {
	defer buf.ReleaseMulti(data)
	for !data.IsEmpty() {
		var chunk buf.MultiBuffer
		data, chunk = buf.SplitSize(data, maxFramePayload)
		if packetIndex > 0 {
			b := buf.New()
			p := b.Extend(7)
			p[0] = cmdPSH
			binary.BigEndian.PutUint32(p[1:5], sid)
			binary.BigEndian.PutUint16(p[5:7], uint16(chunk.Len()))
			merge, _ := buf.MergeMulti(buf.MultiBuffer{b}, chunk)
			s.writeMu.Lock()
			if err := s.writePacketWithPadding(packetIndex, merge); err != nil {
				return err
			}
			s.writeMu.Unlock()
		} else {
			s.writeMu.Lock()
			err := s.fw.writeMultiBuffer(cmdPSH, sid, chunk)
			if err == nil {
				err = s.fw.flush()
			}
			s.writeMu.Unlock()
			if err != nil {
				buf.ReleaseMulti(data)
				return err
			}
		}

	}
	return nil
}

// serverKeepAlive periodically pings the client with a heartbeat frame. A live
// client (even one only holding an idle multiplexed stream) replies, which
// resets the readLoop idle deadline and keeps the session alive. A dead /
// half-open client never replies, so the idle deadline eventually fires and the
// session — together with all of its streams and goroutines — is reaped. This
// is the cure for the connection-accumulation leak. Server-side only.
func (s *session) serverKeepAlive(stop <-chan struct{}) {
	ticker := time.NewTicker(anytlsServerHeartInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if s.isClosed() {
				return
			}
			// Heartbeats are a v2 feature. Only ping peers that negotiated
			// v2 so we never send an unknown command to a legacy v1 client.
			if s.peerVersion < 2 {
				continue
			}
			if err := s.sendFrame(newFrame(cmdHeartRequest, 0)); err != nil {
				return
			}
		}
	}
}

func (s *session) readLoop(ctx context.Context) error {
	var head [7]byte
	for {
		// On the server, enforce an idle read deadline. Any inbound frame
		// (data, heartbeat response, etc.) refreshes it on the next iteration,
		// so only truly silent/dead connections time out and get cleaned up.
		if !s.isClient {
			_ = s.conn.SetReadDeadline(time.Now().Add(anytlsServerIdleTimeout))
		}
		_, err := io.ReadFull(s.br, head[:])
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}

		cmd := head[0]
		sid := binary.BigEndian.Uint32(head[1:5])
		length := int(binary.BigEndian.Uint16(head[5:7]))
		//errors.LogDebug(ctx, "anytls: received frame cmd=", cmd, " streamId=", sid, " length=", length)
		switch cmd {
		case cmdWaste:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSettings:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected cmdSettings from server")
			}
			text, err := readText(s.br, length)
			if err != nil {
				return err
			}
			if s.handshakeDone {
				continue
			}
			if text != "" {
				lines := strings.Split(text, "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					switch kv[0] {
					case "v":
						if v, err := strconv.Atoi(kv[1]); err == nil {
							s.peerVersion = byte(v)
						}
					case "padding-md5":
						s.clientPaddingMD5 = strings.ToLower(kv[1])
					}
				}
			}
			if err := s.sendFrame(&frame{cmd: cmdServerSettings, sid: 0, data: []byte("v=2")}); err != nil {
				return err
			}
			if s.server != nil && s.server.paddingScheme != "" && s.clientPaddingMD5 != "" {
				sum := md5.Sum([]byte(s.server.paddingScheme))
				if strings.ToLower(hex.EncodeToString(sum[:])) != s.clientPaddingMD5 {
					if err := s.sendFrame(&frame{cmd: cmdUpdatePaddingScheme, sid: 0, data: []byte(s.server.paddingScheme)}); err != nil {
						return err
					}
				}
			}
			s.handshakeDone = true
		case cmdHeartRequest:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			if err := s.sendFrame(newFrame(cmdHeartResponse, 0)); err != nil {
				return err
			}
		case cmdHeartResponse:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSYN:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYN from server")
			} else {
				if !s.handshakeDone {
					alert := newFrame(cmdAlert, 0)
					alert.data = []byte("client did not send its settings")
					_ = s.sendFrame(alert)
					return errors.New("anytls: client did not send its settings")
				}
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
					errors.LogWarning(ctx, "anytls: unexpected data in SYN, streamId=", sid)
					if err := s.sendFrame(&frame{cmd: cmdSYNACK, sid: sid, data: []byte("unexpected syn body")}); err != nil {
						return err
					}
					continue
				}
				s.streamsMu.Lock()
				if _, ok := s.streams[sid]; !ok {
					s.streams[sid] = &stream{sid: sid}
				}
				s.streamsMu.Unlock()
			}
		case cmdPSH:
			if length <= 0 {
				err := errors.New("anytls: PSH frame with empty payload, streamId=", sid)
				s.finishStream(sid, err)
				return err
			}
			body, err := readMultiBufferExact(s.br, length)
			if err != nil {
				return err
			}
			s.streamsMu.Lock()
			st := s.streams[sid]
			s.streamsMu.Unlock()
			if st == nil {
				err := errors.New("anytls: received PSH for unknown stream, streamId=", sid)
				buf.ReleaseMulti(body)
				s.finishStream(sid, err)
				return nil
			} else if st.isUDP {
				if err := s.feedUDP(ctx, st, body); err != nil {
					return err
				}
				continue
			} else if st.link == nil {
				if err := s.handleNewStream(ctx, st, body); err != nil {
					return err
				}
				continue
			}
			if err := st.link.Writer.WriteMultiBuffer(body); err != nil {
				return err
			}
		case cmdFIN:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			s.finishStream(sid, nil)
		case cmdSYNACK:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYNACK from client")
			}
			s.synAckMu.Lock()
			ch := s.synAckCh[sid]
			s.synAckMu.Unlock()
			if length == 0 {
				if ch != nil {
					ch <- nil
				}
			} else {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				errors.LogWarning(ctx, "anytls: stream handshake rejected, streamId=", sid, " err=", bodyText)
				s.finishStream(sid, errors.New(bodyText))
				if ch != nil {
					ch <- errors.New(bodyText)
				}
			}
		case cmdServerSettings:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected ServerSettings from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				lines := strings.Split(bodyText, "\n")
				for _, line := range lines {
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					if kv[0] != "v" {
						continue
					}
					if v, err := strconv.Atoi(kv[1]); err == nil {
						s.peerVersion = byte(v)
					}
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty ServerSettings from server")
			}
		case cmdUpdatePaddingScheme:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected UpdatePaddingScheme from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				scheme, perr := parsePaddingScheme(bodyText)
				if perr == nil && scheme != nil {
					s.schemeMu.Lock()
					s.paddingScheme = scheme
					s.schemeMu.Unlock()
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty UpdatePaddingScheme from server")
			}
		case cmdAlert:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected Alert from client")
			}
			var bodyText string
			if length > 0 {
				bodyText, err = readText(s.br, length)
				if err != nil {
					return err
				}
			}
			alertText := "anytls: server alert"
			if bodyText != "" {
				alertText += ": " + bodyText
			}
			return errors.New(alertText)
		default:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			errors.LogWarning(ctx, "anytls: unknown cmd=", cmd, " streamId=", sid)
			return errors.New("anytls: unknown cmd")
		}
	}
}
