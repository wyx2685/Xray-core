package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	tuictransport "github.com/xtls/xray-core/transport/internet/tuic"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Inbound struct {
	userMap sync.Map // uuid.UUID -> *protocol.MemoryUser

	config *ServerConfig
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	_ = ctx
	inbound := &Inbound{
		config: config,
	}
	for _, user := range config.Users {
		if user.Account == nil {
			continue
		}
		memUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get TUIC user").Base(err).AtError()
		}
		acc, ok := memUser.Account.(*MemoryAccount)
		if !ok {
			return nil, errors.New("invalid TUIC account").AtError()
		}
		inbound.userMap.Store(acc.UUID, memUser)
	}
	return inbound, nil
}

func (i *Inbound) Authenticate(ctx context.Context, userUUID [16]byte, token []byte, tlsState tls.ConnectionState) (*protocol.MemoryUser, bool) {
	rawUser, loaded := i.userMap.Load(uuid.UUID(userUUID))
	if !loaded {
		return nil, false
	}
	user := rawUser.(*protocol.MemoryUser)
	acc, ok := user.Account.(*MemoryAccount)
	if !ok {
		return nil, false
	}
	expected, err := tlsState.ExportKeyingMaterial(string(userUUID[:]), []byte(acc.Password), 32)
	if err != nil {
		return nil, false
	}
	if !bytes.Equal(expected, token) {
		return nil, false
	}
	return user, true
}

func (i *Inbound) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (i *Inbound) TUICInboundAuthenticator() tuictransport.Authenticator {
	return i
}

func (i *Inbound) TUICInboundSettings() tuictransport.ServerSettings {
	return tuictransport.ServerSettings{
		CongestionControl: i.config.GetCongestionControl(),
		AuthTimeout:       seconds(i.config.GetAuthTimeout()),
		ZeroRTTHandshake:  i.config.GetZeroRttHandshake(),
		Heartbeat:         seconds(i.config.GetHeartbeat()),
		UDPTimeout:        seconds(i.config.GetUdpTimeout()),
	}
}

func seconds(value uint32) time.Duration {
	if value == 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = "tuic"
	inbound.CanSpliceCopy = 3

	iConn := stat.TryUnwrapStatsConn(connection)
	type userConn interface{ User() *protocol.MemoryUser }
	if v, ok := iConn.(userConn); ok && v.User() != nil {
		inbound.User = v.User()
	}

	if packetConn, ok := iConn.(tuictransport.PacketConn); ok {
		return i.processUDP(ctx, connection, packetConn, dispatcher)
	}
	return i.processTCP(ctx, connection, dispatcher)
}

func (i *Inbound) processTCP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	destination, err := i.parseTUICStreamDestination(conn)
	if err != nil {
		errors.LogDebug(ctx, "TUIC TCP stream destination parse failed: ", err)
		return errors.New("missing TUIC TCP destination").Base(err)
	}
	if !destination.IsValid() {
		errors.LogDebug(ctx, "TUIC TCP destination invalid: ", destination)
		return errors.New("invalid TUIC TCP destination")
	}

	email := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		email = inbound.User.Email
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Email:  email,
	})
	errors.LogDebug(ctx, "accepted TUIC TCP connection to ", destination, " user: ", email)

	reader := buf.NewReader(conn)
	writer := buf.NewWriter(conn)

	return dispatcher.DispatchLink(ctx, destination, &transport.Link{
		Reader: reader,
		Writer: writer,
	})
}

func (i *Inbound) processUDP(ctx context.Context, conn stat.Connection, packetConn tuictransport.PacketConn, dispatcher routing.Dispatcher) error {
	firstPacket, firstDestination, err := packetConn.ReadPacket()
	if err != nil {
		errors.LogDebug(ctx, "TUIC UDP first packet read failed: ", err)
		return errors.New("failed to read TUIC UDP first packet").Base(err)
	}
	if !firstDestination.IsValid() {
		errors.LogDebug(ctx, "TUIC UDP first packet has invalid destination: ", firstDestination)
		return errors.New("invalid TUIC UDP destination")
	}
	destination := firstDestination
	if !destination.IsValid() {
		errors.LogDebug(ctx, "TUIC UDP destination invalid after assignment: ", destination)
		return errors.New("invalid TUIC UDP destination")
	}
	email := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		email = inbound.User.Email
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Email:  email,
	})
	errors.LogDebug(ctx, "accepted TUIC UDP connection to ", destination, " user: ", email)

	return dispatcher.DispatchLink(ctx, destination, &transport.Link{
		Reader: &udpPacketReader{
			conn:             packetConn,
			firstPacket:      firstPacket,
			firstDestination: firstDestination,
			hasFirstPacket:   true,
		},
		Writer: &udpPacketWriter{
			conn:        packetConn,
			destination: firstDestination,
		},
	})
}

type udpPacketReader struct {
	conn             tuictransport.PacketConn
	firstPacket      []byte
	firstDestination net.Destination
	hasFirstPacket   bool
}

func (r *udpPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.hasFirstPacket {
		packet := r.firstPacket
		destination := r.firstDestination
		r.firstPacket = nil
		r.firstDestination = net.Destination{}
		r.hasFirstPacket = false
		return packetToMultiBuffer(packet, destination)
	}

	packet, destination, err := r.conn.ReadPacket()
	if err != nil {
		return nil, err
	}
	return packetToMultiBuffer(packet, destination)
}

type udpPacketWriter struct {
	conn        tuictransport.PacketConn
	destination net.Destination
}

func (w *udpPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, buffer := range mb {
		destination := w.destination
		if buffer.UDP != nil {
			destination = *buffer.UDP
		}
		if !destination.IsValid() {
			buffer.Release()
			continue
		}
		if err := w.conn.WritePacket(buffer.Bytes(), destination); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		buffer.Release()
	}
	return nil
}

func packetToMultiBuffer(packet []byte, destination net.Destination) (buf.MultiBuffer, error) {
	if !destination.IsValid() {
		errors.LogDebug(context.Background(), "TUIC packetToMultiBuffer invalid destination: ", destination)
		return nil, errors.New("invalid TUIC UDP packet destination")
	}
	var buffer *buf.Buffer
	if len(packet) > buf.Size {
		buffer = buf.NewWithSize(int32(len(packet)))
	} else {
		buffer = buf.New()
	}
	if _, err := buffer.Write(packet); err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.UDP = &destination
	return buf.MultiBuffer{buffer}, nil
}

func (i *Inbound) parseTUICStreamDestination(conn net.Conn) (net.Destination, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return net.Destination{}, err
	}
	if header[0] != tuictransport.TUICVersion {
		return net.Destination{}, errors.New("unknown TUIC version ", header[0])
	}
	if header[1] != tuictransport.TUICCommandConnect {
		return net.Destination{}, errors.New("unsupported TUIC stream command ", header[1])
	}
	return tuictransport.ReadDestination(conn, net.Network_TCP)
}

func (i *Inbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if acc, ok := u.Account.(*MemoryAccount); ok {
		i.userMap.Store(acc.UUID, u)
	}
	return nil
}

func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty")
	}
	var uuidToRemove uuid.UUID
	i.userMap.Range(func(key, value any) bool {
		u := value.(*protocol.MemoryUser)
		if u.Email == email {
			uuidToRemove = key.(uuid.UUID)
			return false
		}
		return true
	})
	if uuidToRemove == (uuid.UUID{}) {
		return errors.New("User not found: ", email)
	}
	i.userMap.Delete(uuidToRemove)
	return nil
}

func (i *Inbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	var found *protocol.MemoryUser
	i.userMap.Range(func(key, value any) bool {
		u := value.(*protocol.MemoryUser)
		if u.Email == email {
			found = u
			return false
		}
		return true
	})
	return found
}

func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	i.userMap.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

func (i *Inbound) GetUsersCount(ctx context.Context) int64 {
	var count int64
	i.userMap.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

var _ tuictransport.Authenticator = (*Inbound)(nil)
