package tuic

import (
	"context"
	"crypto/tls"
	gonet "net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/auth"
	singBufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Inbound is the TUIC inbound handler
type Inbound struct {
	userMap sync.Map // uuid.UUID -> *protocol.MemoryUser
	// Fast-path structures
	uMu          sync.RWMutex
	uuidList     [][16]byte
	passwordList []string
	uuidIndex    map[uuid.UUID]int
	// Coalesced update machinery
	updateCh      chan struct{}
	stopCh        chan struct{}
	debounce      time.Duration
	policyManager policy.Manager
	config        *ServerConfig
	ctx           context.Context
	tag           string
	localaddr     gonet.Addr
	service       *tuic.Service[[16]byte]
	cancel        context.CancelFunc
}

// NewServer creates a new TUIC inbound handler
func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	v := core.MustFromContext(ctx)

	inbound := &Inbound{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
		ctx:           ctx,
		uuidIndex:     make(map[uuid.UUID]int),
		updateCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		debounce:      200 * time.Millisecond,
	}

	// Build users from config
	for _, user := range config.Users {
		if user.Account == nil {
			continue
		}
		if memUser, err := user.ToMemoryUser(); err == nil {
			if acc, ok := memUser.Account.(*MemoryAccount); ok {
				inbound.userMap.Store(acc.UUID, memUser)
				// Initialize fast-path lists
				inbound.uuidList = append(inbound.uuidList, acc.UUID)
				inbound.passwordList = append(inbound.passwordList, acc.Password)
				inbound.uuidIndex[acc.UUID] = len(inbound.uuidList) - 1
			}
		}
	}

	return inbound, nil
}

// StartService starts the TUIC service with provided settings
func (i *Inbound) StartService(ctx context.Context, tag string, packetConn gonet.PacketConn, tlsConfig *tls.Config) error {
	if i.service != nil {
		return errors.New("TUIC service already started")
	}
	i.tag = tag
	i.localaddr = packetConn.LocalAddr()
	ctx, cancel := context.WithCancel(ctx)
	i.cancel = cancel

	// Get congestion control from config
	congestionControl := i.config.CongestionControl
	if congestionControl == "" {
		congestionControl = "cubic"
	}

	// Get timeouts from config
	authTimeout := time.Duration(i.config.AuthTimeout) * time.Second
	if authTimeout == 0 {
		authTimeout = 3 * time.Second
	}

	heartbeat := time.Duration(i.config.Heartbeat) * time.Second
	if heartbeat == 0 {
		heartbeat = 10 * time.Second
	}

	udpTimeout := time.Duration(i.config.UdpTimeout) * time.Second
	if udpTimeout == 0 {
		udpTimeout = 60 * time.Second
	}

	// Create user/password maps for TUIC service
	i.uMu.RLock()
	userList := make([][16]byte, len(i.uuidList))
	copy(userList, i.uuidList)
	passwordList := make([]string, len(i.passwordList))
	copy(passwordList, i.passwordList)
	i.uMu.RUnlock()

	userMap := make(map[[16]byte][16]byte)
	passwordMap := make(map[[16]byte]string)
	for idx, uuid := range userList {
		userMap[uuid] = uuid
		passwordMap[uuid] = passwordList[idx]
	}

	serviceOptions := tuic.ServiceOptions{
		Context:           ctx,
		Logger:            singbridge.NewLogger(errors.New),
		TLSConfig:         singbridge.NewTLSConfig(tlsConfig),
		CongestionControl: congestionControl,
		AuthTimeout:       authTimeout,
		ZeroRTTHandshake:  i.config.ZeroRttHandshake,
		Heartbeat:         heartbeat,
		UDPTimeout:        udpTimeout,
		Handler:           i,
	}

	// Create TUIC service
	service, err := tuic.NewService[[16]byte](serviceOptions)
	if err != nil {
		cancel()
		return errors.New("Failed to create TUIC service").Base(err)
	}

	// Update users
	service.UpdateUsers(userList, userList, passwordList)

	i.service = service

	// Start service in background
	go func() {
		if err := service.Start(packetConn); err != nil {
			errors.LogWarning(ctx, "TUIC service error: ", err)
		}
	}()

	// Start user updater loop
	go i.userUpdaterLoop()

	errors.LogInfo(ctx, "TUIC service started")
	return nil
}

// Close closes the TUIC service
func (i *Inbound) Close() error {
	if i.stopCh != nil {
		close(i.stopCh)
		i.stopCh = nil
	}
	if i.cancel != nil {
		i.cancel()
	}
	if i.service != nil {
		return common.Close(i.service)
	}
	return nil
}

// Network implements proxy.Inbound.Network()
func (i *Inbound) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.Process()
func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	return errors.New("TUIC.Process should not be called - connections are handled by ServerHandler")
}

// NewConnectionEx handles new TCP connection with full metadata
func (i *Inbound) NewConnectionEx(ctx context.Context, conn gonet.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(errors.New("connection closed"))
	}

	// Get user from auth context
	var user *protocol.MemoryUser
	if userUUID, ok := auth.UserFromContext[[16]byte](ctx); ok {
		uuid := uuid.UUID(userUUID)
		if u, exists := i.userMap.Load(uuid); exists {
			user = u.(*protocol.MemoryUser)
		}
	}

	email := ""
	if user != nil {
		email = user.Email
	}

	// Build session inbound
	inbound := &session.Inbound{
		Name:    "tuic",
		User:    user,
		Source:  singbridge.ToDestination(source, net.Network_TCP),
		Local:   net.DestinationFromAddr(i.localaddr),
		Gateway: net.DestinationFromAddr(i.localaddr),
		Tag:     i.tag,
	}

	inbound.CanSpliceCopy = 3
	sessionCtx := session.ContextWithInbound(ctx, inbound)

	// Convert destination
	var targetDest net.Destination
	if destination.IsValid() {
		targetDest = singbridge.ToDestination(destination, net.Network_TCP)
	} else {
		targetDest = net.TCPDestination(net.LocalHostIP, net.Port(443))
	}

	if !targetDest.IsValid() {
		errors.LogWarning(sessionCtx, "invalid destination")
		return
	}

	sessionCtx = log.ContextWithAccessMessage(sessionCtx, &log.AccessMessage{
		From:   source,
		To:     targetDest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	errors.LogDebug(sessionCtx, "accepted tuic tcp connection to ", targetDest, " user: ", email)

	// Get dispatcher
	dispatcher := session.DispatcherFromContext(sessionCtx)
	if dispatcher == nil {
		errors.LogWarning(sessionCtx, "dispatcher missing in context")
		return
	}

	// Dispatch connection
	link, err := dispatcher.Dispatch(sessionCtx, targetDest)
	if err != nil {
		errors.LogWarning(sessionCtx, "failed to dispatch request: ", err)
		return
	}

	// Copy data
	if err := singbridge.CopyConn(sessionCtx, nil, link, conn); err != nil {
		errors.LogWarning(sessionCtx, "connection copy error: ", err)
	}
}

// NewPacketConnectionEx handles new UDP connection with full metadata
func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(errors.New("connection closed"))
	}

	// Get user from auth context
	var user *protocol.MemoryUser
	if userUUID, ok := auth.UserFromContext[[16]byte](ctx); ok {
		uuid := uuid.UUID(userUUID)
		if u, exists := i.userMap.Load(uuid); exists {
			user = u.(*protocol.MemoryUser)
		}
	}

	email := ""
	if user != nil {
		email = user.Email
	}

	// Build session inbound
	inbound := &session.Inbound{
		Name:    "tuic",
		User:    user,
		Source:  singbridge.ToDestination(source, net.Network_UDP),
		Local:   net.DestinationFromAddr(i.localaddr),
		Gateway: net.DestinationFromAddr(i.localaddr),
		Tag:     i.tag,
	}

	inbound.CanSpliceCopy = 3
	sessionCtx := session.ContextWithInbound(ctx, inbound)

	// Convert destination
	var targetDest net.Destination
	if destination.IsValid() {
		targetDest = singbridge.ToDestination(destination, net.Network_UDP)
	} else {
		targetDest = net.UDPDestination(net.LocalHostIP, net.Port(443))
	}

	if !targetDest.IsValid() {
		errors.LogWarning(sessionCtx, "invalid udp destination")
		return
	}

	sessionCtx = log.ContextWithAccessMessage(sessionCtx, &log.AccessMessage{
		From:   inbound.Source,
		To:     targetDest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	errors.LogDebug(sessionCtx, "accepted tuic udp connection to ", targetDest, " user: ", email)

	// Get dispatcher
	dispatcher := session.DispatcherFromContext(sessionCtx)
	if dispatcher == nil {
		errors.LogWarning(sessionCtx, "dispatcher missing in context")
		return
	}

	// Dispatch UDP connection
	link, err := dispatcher.Dispatch(sessionCtx, targetDest)
	if err != nil {
		errors.LogWarning(sessionCtx, "failed to dispatch udp request: ", err)
		return
	}

	// Use singbridge PacketConnWrapper for UDP
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   targetDest,
	}

	// Copy UDP packets
	if err := singBufio.CopyPacketConn(sessionCtx, conn, outConn); err != nil {
		errors.LogWarning(sessionCtx, "udp connection copy error: ", err)
	}
}

// Update service users
func (i *Inbound) updateServiceUsers() {
	if i.service == nil {
		return
	}
	i.uMu.RLock()
	users := make([][16]byte, len(i.uuidList))
	copy(users, i.uuidList)
	pwds := make([]string, len(i.passwordList))
	copy(pwds, i.passwordList)
	i.uMu.RUnlock()
	i.service.UpdateUsers(users, users, pwds)
}

// AddUser implements proxy.UserManager.AddUser()
func (i *Inbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if acc, ok := u.Account.(*MemoryAccount); ok {
		i.userMap.Store(acc.UUID, u)
		i.uMu.Lock()
		if _, exists := i.uuidIndex[acc.UUID]; !exists {
			i.uuidList = append(i.uuidList, acc.UUID)
			i.passwordList = append(i.passwordList, acc.Password)
			i.uuidIndex[acc.UUID] = len(i.uuidList) - 1
		} else {
			i.passwordList[i.uuidIndex[acc.UUID]] = acc.Password
		}
		i.uMu.Unlock()
		i.scheduleUserUpdate()
	}
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser()
func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty")
	}

	// Find and remove user
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

	// Remove from fast-path lists
	i.uMu.Lock()
	if idx, ok := i.uuidIndex[uuidToRemove]; ok {
		last := len(i.uuidList) - 1
		if idx != last {
			i.uuidList[idx] = i.uuidList[last]
			i.passwordList[idx] = i.passwordList[last]
			i.uuidIndex[uuid.UUID(i.uuidList[idx])] = idx
		}
		i.uuidList = i.uuidList[:last]
		i.passwordList = i.passwordList[:last]
		delete(i.uuidIndex, uuidToRemove)
	}
	i.uMu.Unlock()
	i.scheduleUserUpdate()

	return nil
}

// GetUser implements proxy.UserManager.GetUser()
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

// GetUsers implements proxy.UserManager.GetUsers()
func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	i.userMap.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount()
func (i *Inbound) GetUsersCount(ctx context.Context) int64 {
	var count int64
	i.userMap.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// scheduleUserUpdate coalesces UpdateUsers calls
func (i *Inbound) scheduleUserUpdate() {
	select {
	case i.updateCh <- struct{}{}:
	default:
	}
}

// userUpdaterLoop batches rapid user updates
func (i *Inbound) userUpdaterLoop() {
	var timer *time.Timer
	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}
		select {
		case <-i.stopCh:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-i.updateCh:
			if timer == nil {
				timer = time.NewTimer(i.debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(i.debounce)
			}
		case <-timerC:
			timer.Stop()
			timer = nil
			i.updateServiceUsers()
		}
	}
}
