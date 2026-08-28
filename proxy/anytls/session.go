package anytls

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
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
			return s.handleUDPFrame(dispatchCtx, st, body)
		}
		return nil
	} else if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		errors.LogWarning(ctx, "anytls: unsupported UDP destination: "+dest.Address.String())
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		s.finishStream(st.sid, nil)
		return nil
	}
	accessMessage := &log.AccessMessage{
		From:   s.conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
	}
	if inbound := sessionctx.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		accessMessage.Email = inbound.User.Email
	}
	dispatchCtx = log.ContextWithAccessMessage(dispatchCtx, accessMessage)

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

func (s *session) handleUDPFrame(ctx context.Context, st *stream, body buf.MultiBuffer) error {
	st.uotInput = appendMultiBuffer(st.uotInput, body)
	if st.uotRequest == nil {
		reader := bytes.NewReader(st.uotInput)
		request, err := uot.ReadRequest(reader)
		if err != nil {
			return s.rejectUDPStream(ctx, st, errors.New("anytls: UDP failed to parse request").Base(err))
		}
		st.uotRequest = request
		st.udpIsConnect = request.IsConnect
		st.consumeUoTInput(len(st.uotInput) - reader.Len())

		requestDest, err := singbridge.ToDestination(request.Destination, net.Network_UDP)
		if err != nil {
			return s.rejectUDPStream(ctx, st, errors.New("anytls: UDP invalid destination").Base(err))
		}
		dispatchCtx := s.dispatchContext(ctx, st)
		accessMessage := &log.AccessMessage{
			From:   s.conn.RemoteAddr(),
			To:     requestDest,
			Status: log.AccessAccepted,
		}
		if inbound := sessionctx.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
			accessMessage.Email = inbound.User.Email
		}
		dispatchCtx = log.ContextWithAccessMessage(dispatchCtx, accessMessage)
		link, err := s.dispatcher.Dispatch(dispatchCtx, requestDest)
		if err != nil {
			return s.rejectUDPStream(ctx, st, errors.New("anytls: UDP dispatcher error").Base(err))
		}
		st.link = link
		go s.pumpUoTDownlink(st.sid, st, link, request.IsConnect, request.Destination)
	}

	for {
		if len(st.uotInput) == 0 {
			return nil
		}
		dest := st.uotRequest.Destination
		offset := 0
		if !st.udpIsConnect {
			reader := bytes.NewReader(st.uotInput)
			var err error
			dest, err = uot.AddrParser.ReadAddrPort(reader)
			if err != nil {
				return s.rejectUDPStream(ctx, st, errors.New("anytls: UDP packet has invalid destination address").Base(err))
			}
			offset = len(st.uotInput) - reader.Len()
		}
		if len(st.uotInput) < offset+2 {
			return nil
		}
		length := int(binary.BigEndian.Uint16(st.uotInput[offset : offset+2]))
		if len(st.uotInput) < offset+2+length {
			return nil
		}
		if err := s.writeUoTPacket(ctx, st, dest, st.uotInput[offset+2:offset+2+length]); err != nil {
			return err
		}
		st.consumeUoTInput(offset + 2 + length)
	}
}

func appendMultiBuffer(dst []byte, mb buf.MultiBuffer) []byte {
	for _, b := range mb {
		if b != nil {
			dst = append(dst, b.Bytes()...)
		}
	}
	buf.ReleaseMulti(mb)
	return dst
}

func (st *stream) consumeUoTInput(length int) {
	remaining := len(st.uotInput) - length
	if remaining == 0 {
		st.uotInput = st.uotInput[:0]
		return
	}
	copy(st.uotInput, st.uotInput[length:])
	st.uotInput = st.uotInput[:remaining]
}

func (s *session) writeUoTPacket(ctx context.Context, st *stream, addr M.Socksaddr, payload []byte) error {
	dest, err := singbridge.ToDestination(addr, net.Network_UDP)
	if err != nil {
		return s.rejectUDPStream(ctx, st, errors.New("anytls: UDP invalid destination").Base(err))
	}
	if st.link == nil {
		return errors.New("anytls: UDP stream without link")
	}

	b := buf.NewWithSize(int32(len(payload)))
	if len(payload) > 0 {
		copy(b.Extend(int32(len(payload))), payload)
	}
	b.UDP = &dest
	return st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

func (s *session) rejectUDPStream(ctx context.Context, st *stream, err error) error {
	errors.LogWarning(ctx, err, ", streamId=", st.sid)
	_ = s.sendFrame(newFrame(cmdFIN, st.sid))
	s.finishStream(st.sid, nil)
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

func (s *session) pumpUoTDownlink(sid uint32, st *stream, link *transport.Link, isConnect bool, dest M.Socksaddr) {
	defer func() {
		s.streamsMu.Lock()
		current := s.streams[sid]
		active := current == st && st.link == link
		if active {
			delete(s.streams, sid)
		}
		s.streamsMu.Unlock()
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		if !active {
			return
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
		for {
			var b *buf.Buffer
			mb, b = buf.SplitFirst(mb)
			if b == nil {
				break
			}
			length := b.Len()
			if length > maxFramePayload {
				b.Release()
				continue
			}
			packetDest := dest
			if !isConnect && b.UDP != nil {
				packetDest = singbridge.ToSocksaddr(*b.UDP)
			}
			header := buf.New()
			if !isConnect {
				if err := uot.AddrParser.WriteAddrPort(header, packetDest); err != nil {
					header.Release()
					b.Release()
					buf.ReleaseMulti(mb)
					return
				}
			}
			p := header.Extend(2)
			binary.BigEndian.PutUint16(p, uint16(length))
			if err := s.sendStreamData(sid, buf.MultiBuffer{header, b}, 0); err != nil {
				buf.ReleaseMulti(mb)
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

func (s *session) readLoop(ctx context.Context) error {
	var head [7]byte
	for {
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
				if err := s.handleUDPFrame(ctx, st, body); err != nil {
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
