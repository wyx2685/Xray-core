package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	stderrors "errors"
	"io"
	stdnet "net"
	"runtime"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

type serverOptions struct {
	Context           context.Context
	TLSConfig         *tls.Config
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	UDPTimeout        time.Duration
	Authenticator     Authenticator
	Handler           internet.ConnHandler
	LocalAddr         stdnet.Addr
}

type serverService struct {
	ctx               context.Context
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	congestionControl string
	authTimeout       time.Duration
	udpTimeout        time.Duration
	authenticator     Authenticator
	handler           internet.ConnHandler
	localAddr         stdnet.Addr
	listener          io.Closer
	tr                *quic.Transport
}

func newServerService(options serverOptions) (*serverService, error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.UDPTimeout == 0 {
		options.UDPTimeout = 60 * time.Second
	}
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, errors.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &serverService{
		ctx:       options.Context,
		tlsConfig: options.TLSConfig,
		quicConfig: &quic.Config{
			DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
			EnableDatagrams:                true,
			Allow0RTT:                      options.ZeroRTTHandshake,
			MaxIncomingStreams:             1 << 60,
			MaxIncomingUniStreams:          1 << 60,
			MaxDatagramFrameSize:           1200,
			AssumePeerMaxDatagramFrameSize: 1200,
			DisablePathManager:             true,
		},
		congestionControl: options.CongestionControl,
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		authenticator:     options.Authenticator,
		handler:           options.Handler,
		localAddr:         options.LocalAddr,
	}, nil
}

func (s *serverService) Start(conn stdnet.PacketConn) error {
	s.tr = &quic.Transport{Conn: conn}
	var listener interface {
		Accept(context.Context) (*quic.Conn, error)
		Close() error
	}
	var err error
	if s.quicConfig.Allow0RTT {
		listener, err = s.tr.ListenEarly(s.tlsConfig, s.quicConfig)
	} else {
		listener, err = s.tr.Listen(s.tlsConfig, s.quicConfig)
	}
	if err != nil {
		return err
	}
	s.listener = listener
	go s.acceptLoop(listener)
	return nil
}

func (s *serverService) CloseWithError() error {
	var errs []error
	if s.listener != nil {
		errs = append(errs, s.listener.Close())
	}
	if s.tr != nil {
		errs = append(errs, s.tr.Close())
	}
	return stderrors.Join(errs...)
}

func (s *serverService) acceptLoop(listener interface {
	Accept(context.Context) (*quic.Conn, error)
}) {
	for {
		conn, err := listener.Accept(s.ctx)
		if err != nil {
			if !stderrors.Is(err, quic.ErrServerClosed) && !stderrors.Is(err, context.Canceled) {
				errors.LogWarning(s.ctx, "TUIC accept error: ", err)
			}
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *serverService) handleConnection(conn *quic.Conn) {
	s.setCongestion(conn)
	session := &serverSession{
		serverService: s,
		ctx:           s.ctx,
		quicConn:      conn,
		connDone:      make(chan struct{}),
		authDone:      make(chan struct{}),
		udpConnMap:    make(map[uint16]*udpPacketConn),
	}
	session.handle()
}

func (s *serverService) setCongestion(conn *quic.Conn) {
	if s.congestionControl != "bbr" {
		return
	}
	congestion.UseBBR(conn, bbr.ProfileStandard)
}

type serverSession struct {
	*serverService
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authAccess sync.Mutex
	authDone   chan struct{}
	authUser   *protocol.MemoryUser
	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn
}

func (s *serverSession) handle() {
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.handleAuthTimeout()
}

func (s *serverSession) loopUniStreams() {
	for {
		stream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			if err := s.handleUniStream(stream); err != nil {
				s.closeWithError(errors.New("handle uni stream").Base(err))
			}
		}()
	}
}

func (s *serverSession) handleUniStream(stream *quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		return err
	}
	if buffer[0] != tuicVersion {
		return errors.New("unknown version ", buffer[0])
	}
	switch buffer[1] {
	case commandAuthenticate:
		authPayload := make([]byte, authenticateLen-2)
		if _, err := io.ReadFull(stream, authPayload); err != nil {
			return err
		}
		var userUUID [16]byte
		copy(userUUID[:], authPayload[:16])
		if s.authenticator == nil {
			return errors.New("missing TUIC authenticator")
		}
		user, ok := s.authenticator.Authenticate(s.ctx, userUUID, authPayload[16:48], s.quicConn.ConnectionState().TLS)
		if !ok {
			return errors.New("token mismatch")
		}
		s.authAccess.Lock()
		defer s.authAccess.Unlock()
		select {
		case <-s.authDone:
			return errors.New("multiple authentication requests")
		default:
		}
		s.authUser = user
		close(s.authDone)
		return nil
	case commandPacket:
		if err := s.waitAuth(); err != nil {
			return err
		}
		message := new(udpMessage)
		if err := readUDPMessage(message, io.MultiReader(bytes.NewReader(buffer[2:]), stream)); err != nil {
			return err
		}
		s.handleUDPMessage(message, true)
		return nil
	case commandDissociate:
		if err := s.waitAuth(); err != nil {
			return err
		}
		var sessionID uint16
		if err := binary.Read(stream, binary.BigEndian, &sessionID); err != nil {
			return err
		}
		s.udpAccess.RLock()
		udpConn := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if udpConn != nil {
			udpConn.closeWithError(io.ErrClosedPipe)
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil
	default:
		return errors.New("unknown command ", buffer[1])
	}
}

func (s *serverSession) handleAuthTimeout() {
	timer := time.NewTimer(s.authTimeout)
	defer timer.Stop()
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-timer.C:
		s.closeWithError(errors.New("authentication timeout"))
	}
}

func (s *serverSession) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			if err := s.handleStream(stream); err != nil {
				stream.CancelRead(0)
				_ = stream.Close()
				errors.LogWarning(s.ctx, "TUIC stream error: ", err)
			}
		}()
	}
}

func (s *serverSession) handleStream(stream *quic.Stream) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(stream, header); err != nil {
		return err
	}
	if header[0] != tuicVersion {
		return errors.New("unknown version ", header[0])
	}
	if header[1] != commandConnect {
		return errors.New("unsupported stream command ", header[1])
	}
	destination, err := readDestination(stream, xnet.Network_TCP)
	if err != nil {
		return err
	}
	if err := s.waitAuth(); err != nil {
		return err
	}
	conn := &serverConn{
		Stream:      stream,
		local:       s.localAddr,
		remote:      s.quicConn.RemoteAddr(),
		destination: destination,
		user:        s.authUser,
	}
	s.handler(conn)
	return nil
}

func (s *serverSession) loopMessages() {
	if err := s.waitAuth(); err != nil {
		return
	}
	for {
		data, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(err)
			return
		}
		if err := s.handleMessage(data); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *serverSession) handleMessage(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid message")
	}
	if data[0] != tuicVersion {
		return errors.New("unknown version ", data[0])
	}
	switch data[1] {
	case commandPacket:
		message := new(udpMessage)
		if err := decodeUDPMessage(message, data[2:]); err != nil {
			return err
		}
		s.handleUDPMessage(message, false)
		return nil
	case commandHeartbeat:
		return nil
	default:
		return errors.New("unknown command ", data[1])
	}
}

func (s *serverSession) handleUDPMessage(message *udpMessage, udpStream bool) {
	s.udpAccess.RLock()
	udpConn := s.udpConnMap[message.sessionID]
	s.udpAccess.RUnlock()
	if udpConn == nil || udpConn.done() {
		newUDPConn := newUDPPacketConn(s.ctx, s.quicConn, udpStream, true, s.authUser, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, message.sessionID)
			s.udpAccess.Unlock()
		})
		newUDPConn.sessionID = message.sessionID
		s.udpAccess.Lock()
		udpConn = s.udpConnMap[message.sessionID]
		if udpConn == nil || udpConn.done() {
			udpConn = newUDPConn
			s.udpConnMap[message.sessionID] = udpConn
		} else {
			newUDPConn.closeWithError(io.ErrClosedPipe)
		}
		s.udpAccess.Unlock()
	}
	destination := message.destination
	shouldStart := udpConn.markStarted(destination)
	udpConn.inputPacket(message)
	if !shouldStart {
		return
	}
	go func() {
		s.handler(udpConn)
	}()
}

func (s *serverSession) waitAuth() error {
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
		return nil
	}
}

func (s *serverSession) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if err != nil && !stderrors.Is(err, context.Canceled) && !stderrors.Is(err, quic.ErrServerClosed) {
		errors.LogWarning(s.ctx, "TUIC connection closed: ", err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	local       stdnet.Addr
	remote      stdnet.Addr
	destination xnet.Destination
	user        *protocol.MemoryUser
}

func (c *serverConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *serverConn) Destination() xnet.Destination {
	return c.destination
}

func (c *serverConn) LocalAddr() stdnet.Addr {
	return c.local
}

func (c *serverConn) RemoteAddr() stdnet.Addr {
	return c.remote
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
