package anytls

import (
	"bufio"
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
		s.startUoTStream(dispatchCtx, st)
		if !body.IsEmpty() {
			s.feedUoTUplink(st, body)
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

func (s *session) startUoTStream(ctx context.Context, st *stream) {
	st.udpCh = make(chan *buf.Buffer, 256)
	st.udpDone = make(chan struct{})
	go s.serveUoTStream(ctx, st)
}

func (s *session) feedUoTUplink(st *stream, body buf.MultiBuffer) {
	if st.udpCh == nil || st.udpDone == nil {
		buf.ReleaseMulti(body)
		return
	}
	for _, b := range body {
		if b == nil || b.IsEmpty() {
			if b != nil {
				b.Release()
			}
			continue
		}
		select {
		case st.udpCh <- b:
		case <-st.udpDone:
			b.Release()
		default:
			b.Release()
		}
	}
}

type uotFrameReader struct {
	ch   chan *buf.Buffer
	done chan struct{}
	cur  *buf.Buffer
}

func (r *uotFrameReader) Read(p []byte) (int, error) {
	for r.cur == nil || r.cur.IsEmpty() {
		if r.cur != nil {
			r.cur.Release()
			r.cur = nil
		}
		select {
		case b := <-r.ch:
			r.cur = b
		case <-r.done:
			return 0, io.EOF
		}
	}
	n := copy(p, r.cur.Bytes())
	r.cur.Advance(int32(n))
	return n, nil
}

func (r *uotFrameReader) release() {
	if r.cur != nil {
		r.cur.Release()
		r.cur = nil
	}
	for {
		select {
		case b := <-r.ch:
			b.Release()
		default:
			return
		}
	}
}

func (s *session) serveUoTStream(ctx context.Context, st *stream) {
	reader := &uotFrameReader{ch: st.udpCh, done: st.udpDone}
	buffered := bufio.NewReader(reader)
	defer func() {
		if st.link == nil && !s.isClosed() {
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		}
		s.finishStream(st.sid, nil)
		reader.release()
	}()

	request, err := uot.ReadRequest(buffered)
	if err != nil {
		errors.LogWarning(ctx, "anytls: UDP failed to parse request:", err)
		return
	}
	st.udpIsConnect = request.IsConnect
	requestDest, err := singbridge.ToDestination(request.Destination, net.Network_UDP)
	if err != nil {
		errors.LogWarning(ctx, "anytls: UDP invalid destination, streamId=", st.sid, " err=", err)
		return
	}
	st.udpTarget = &requestDest

	for {
		destination := request.Destination
		if !request.IsConnect {
			destination, err = uot.AddrParser.ReadAddrPort(buffered)
			if err != nil {
				return
			}
		}

		var length uint16
		if err = binary.Read(buffered, binary.BigEndian, &length); err != nil {
			return
		}

		payload := buf.NewWithSize(int32(length))
		if _, err = io.ReadFull(buffered, payload.Extend(int32(length))); err != nil {
			payload.Release()
			return
		}

		packetDest, err := singbridge.ToDestination(destination, net.Network_UDP)
		if err != nil {
			payload.Release()
			return
		}
		payload.UDP = &packetDest

		if st.link == nil {
			link, dispatchErr := s.dispatcher.Dispatch(s.dispatchContext(ctx, st), packetDest)
			if dispatchErr != nil {
				payload.Release()
				errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", dispatchErr)
				return
			}
			st.link = link
			go s.pumpUoTDownlink(st.sid, link, request.IsConnect, request.Destination)
		}

		if err = st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			return
		}
	}
}

func (s *session) handleFirstUDPFrame(ctx context.Context, st *stream, body buf.MultiBuffer) error {
	if st.link == nil {
		request, body, err := readUoTRequest(body)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP failed to parse request:", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}
		st.udpIsConnect = request.IsConnect
		requestDest, err := singbridge.ToDestination(request.Destination, net.Network_UDP)
		if err != nil {
			buf.ReleaseMulti(body)
			errors.LogWarning(ctx, "anytls: UDP invalid destination, streamId=", st.sid, " err=", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}
		link, err := s.dispatcher.Dispatch(s.dispatchContext(ctx, st), requestDest)
		if err != nil {
			buf.ReleaseMulti(body)
			errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}

		st.link = link
		st.udpTarget = &requestDest

		if !body.IsEmpty() {
			if err := s.writeUoTFrameToLink(ctx, st, body, request.Destination); err != nil {
				return err
			}
		}

		go s.pumpUoTDownlink(st.sid, link, request.IsConnect, request.Destination)
		return nil
	}

	fallback := M.Socksaddr{}
	if st.udpTarget != nil {
		fallback = singbridge.ToSocksaddr(*st.udpTarget)
	}
	return s.writeUoTFrameToLink(ctx, st, body, fallback)
}

func (s *session) handleUDPFrame(ctx context.Context, st *stream, body buf.MultiBuffer) error {
	if st.link == nil {
		errors.LogWarning(ctx, "anytls: UDP stream without link, streamId=", st.sid)
		buf.ReleaseMulti(body)
		return errors.New("anytls: UDP stream without link")
	}
	fallback := M.Socksaddr{}
	if st.udpTarget != nil {
		fallback = singbridge.ToSocksaddr(*st.udpTarget)
	}
	return s.writeUoTFrameToLink(ctx, st, body, fallback)
}

func readUoTRequest(body buf.MultiBuffer) (*uot.Request, buf.MultiBuffer, error) {
	if body.IsEmpty() {
		return nil, nil, errors.New("anytls: UDP missing request data")
	}
	reader := &buf.MultiBufferContainer{MultiBuffer: body}
	request, err := uot.ReadRequest(reader)
	if err != nil {
		_ = reader.Close()
		return nil, nil, err
	}
	return request, reader.MultiBuffer, nil
}

func readUoTPacket(body buf.MultiBuffer, isConnect bool, fallback M.Socksaddr) (*buf.Buffer, net.Destination, error) {
	reader := &buf.MultiBufferContainer{MultiBuffer: body}
	defer reader.Close()

	destination := fallback
	if !isConnect {
		dest, err := uot.AddrParser.ReadAddrPort(reader)
		if err != nil {
			return nil, net.Destination{}, errors.New("anytls: UDP packet missing destination address").Base(err)
		}
		destination = dest
	}

	var length uint16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, net.Destination{}, errors.New("anytls: UDP packet too short").Base(err)
	}

	payload := buf.NewWithSize(int32(length))
	if _, err := payload.ReadFullFrom(reader, int32(length)); err != nil {
		payload.Release()
		return nil, net.Destination{}, errors.New("anytls: UDP packet payload too short").Base(err)
	}
	if !reader.MultiBuffer.IsEmpty() {
		payload.Release()
		return nil, net.Destination{}, errors.New("anytls: UDP packet has trailing data")
	}

	packetDest, err := singbridge.ToDestination(destination, net.Network_UDP)
	if err != nil {
		payload.Release()
		return nil, net.Destination{}, errors.New("anytls: UDP packet has invalid destination address").Base(err)
	}
	payload.UDP = &packetDest
	return payload, packetDest, nil
}

func (s *session) writeUoTFrameToLink(ctx context.Context, st *stream, body buf.MultiBuffer, fallback M.Socksaddr) error {
	payload, _, err := readUoTPacket(body, st.udpIsConnect, fallback)
	if err != nil {
		errors.LogWarning(ctx, "anytls: UDP failed to parse packet, streamId=", st.sid, " err=", err)
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		s.finishStream(st.sid, nil)
		return nil
	}
	return st.link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload})
}

func (s *session) pumpDownlink(sid uint32, link *transport.Link) {
	defer func() {
		s.streamsMu.Lock()
		st := s.streams[sid]
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		if st != nil && st.link != nil {
			common.Close(st.link.Writer)
			common.Close(st.link.Reader)
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

func (s *session) pumpUoTDownlink(sid uint32, link *transport.Link, isConnect bool, dest M.Socksaddr) {
	defer func() {
		s.streamsMu.Lock()
		st := s.streams[sid]
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		if st != nil && st.link != nil {
			common.Close(st.link.Writer)
			common.Close(st.link.Reader)
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
		for _, b := range mb {
			if b == nil {
				continue
			}
			destination := dest
			if b.UDP != nil {
				destination = singbridge.ToSocksaddr(*b.UDP)
			}
			packet, err := buildUoTPacket(buf.MultiBuffer{b}, isConnect, destination)
			if err != nil {
				buf.ReleaseMulti(mb)
				return
			}
			if err := s.sendStreamDataFrame(sid, packet); err != nil {
				buf.ReleaseMulti(mb)
				return
			}
		}
	}
}

func buildUoTPacket(payload buf.MultiBuffer, isConnect bool, destination M.Socksaddr) (buf.MultiBuffer, error) {
	length := payload.Len()
	headerLen := int32(2)
	if !isConnect {
		headerLen += int32(uot.AddrParser.AddrPortLen(destination))
	}
	if length > maxFramePayload || headerLen+length > maxFramePayload {
		buf.ReleaseMulti(payload)
		return nil, errors.New("anytls: UDP packet too large")
	}

	header := buf.NewWithSize(headerLen)
	if !isConnect {
		if err := uot.AddrParser.WriteAddrPort(header, destination); err != nil {
			header.Release()
			buf.ReleaseMulti(payload)
			return nil, err
		}
	}
	p := header.Extend(2)
	binary.BigEndian.PutUint16(p, uint16(length))
	return append(buf.MultiBuffer{header}, payload...), nil
}

func (s *session) sendStreamDataFrame(sid uint32, data buf.MultiBuffer) error {
	if data.IsEmpty() {
		return nil
	}
	if data.Len() > maxFramePayload {
		buf.ReleaseMulti(data)
		return errors.New("anytls: frame payload too large")
	}
	defer buf.ReleaseMulti(data)
	s.writeMu.Lock()
	err := s.fw.writeMultiBuffer(cmdPSH, sid, data)
	if err == nil {
		err = s.fw.flush()
	}
	s.writeMu.Unlock()
	return err
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
				buf.ReleaseMulti(body)
				_ = s.sendFrame(newFrame(cmdFIN, sid))
				continue
			} else if st.isUDP {
				s.feedUoTUplink(st, body)
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
