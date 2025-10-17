package hysteria2

import (
	"context"
	"crypto/tls"
	gonet "net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
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

// Inbound is an inbound connection handler that handles Hysteria2 protocol
type Inbound struct {
	userMap sync.Map // email -> *protocol.MemoryUser
	// Fast-path structures to avoid full map scan on every update
	uMu          sync.RWMutex
	userList     []string
	passwordList []string
	emailIndex   map[string]int // email -> index in userList/passwordList
	// Coalesced update machinery for massive AddUser bursts
	updateCh      chan struct{}
	stopCh        chan struct{}
	debounce      time.Duration
	policyManager policy.Manager
	config        *ServerConfig
	ctx           context.Context
	tag           string
	localaddr     gonet.Addr
	service       *hysteria2.Service[string]
	cancel        context.CancelFunc
}

// NewServer creates a new Hysteria2 inbound handler
func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	v := core.MustFromContext(ctx)

	inbound := &Inbound{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
		ctx:           ctx,
		emailIndex:    make(map[string]int),
		updateCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		debounce:      200 * time.Millisecond,
	}

	// Build users from config
	for _, user := range config.Users {
		if user.Account == nil {
			continue
		}

		// Get typed message and convert to Account
		typedAccount, err := user.Account.GetInstance()
		if err != nil {
			return nil, errors.New("Failed to get account instance").Base(err)
		}

		account, ok := typedAccount.(protocol.AsAccount)
		if !ok {
			return nil, errors.New("Account does not implement AsAccount interface")
		}

		memAccount, err := account.AsAccount()
		if err != nil {
			return nil, errors.New("Failed to parse account").Base(err)
		}

		if acc, ok := memAccount.(*MemoryAccount); ok {
			memUser := &protocol.MemoryUser{
				Email:   user.Email,
				Level:   user.Level,
				Account: memAccount,
			}
			inbound.userMap.Store(memUser.Email, memUser)
			// initialize fast-path lists
			inbound.userList = append(inbound.userList, memUser.Email)
			inbound.passwordList = append(inbound.passwordList, acc.Password)
			inbound.emailIndex[memUser.Email] = len(inbound.userList) - 1
		}
	}

	return inbound, nil
}

// createMasqueradeHandler creates an HTTP handler for masquerade
func (i *Inbound) createMasqueradeHandler() http.Handler {
	if i.config.Masquerade == nil {
		return nil
	}

	m := i.config.Masquerade

	// Handle simple config (URL string)
	if m.SimpleConfig != "" {
		if strings.HasPrefix(m.SimpleConfig, "file://") {
			directory := strings.TrimPrefix(m.SimpleConfig, "file://")
			return http.FileServer(http.Dir(directory))
		} else if strings.HasPrefix(m.SimpleConfig, "http://") || strings.HasPrefix(m.SimpleConfig, "https://") {
			return &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = "http"
					if strings.HasPrefix(m.SimpleConfig, "https://") {
						req.URL.Scheme = "https"
					}
					req.URL.Host = strings.TrimPrefix(strings.TrimPrefix(m.SimpleConfig, "http://"), "https://")
				},
			}
		}
	}

	// Handle structured config
	switch m.Type {
	case "file":
		if m.Directory != "" {
			return http.FileServer(http.Dir(m.Directory))
		}
	case "proxy":
		if m.Url != "" {
			return &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					targetURL := m.Url
					if strings.HasPrefix(targetURL, "https://") {
						req.URL.Scheme = "https"
						req.URL.Host = strings.TrimPrefix(targetURL, "https://")
					} else {
						req.URL.Scheme = "http"
						req.URL.Host = strings.TrimPrefix(targetURL, "http://")
					}
					if m.RewriteHost {
						req.Host = req.URL.Host
					}
				},
			}
		}
	case "string":
		content := []byte(m.Content)
		if m.Content == "" {
			content = []byte("404 Not Found")
		}
		statusCode := int(m.StatusCode)
		if statusCode == 0 {
			statusCode = 404
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range m.Headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(statusCode)
			w.Write(content)
		})
	}

	return nil
}

// StartService starts the Hysteria2 service with provided settings
// ctx should already carry dispatcher via session.ContextWithDispatcher
func (i *Inbound) StartService(ctx context.Context, tag string, packetConn gonet.PacketConn, tlsConfig *tls.Config) error {
	if i.service != nil {
		return errors.New("Hysteria2 service already started")
	}
	i.tag = tag
	i.localaddr = packetConn.LocalAddr()
	// Use the provided context (from worker/transport) so dispatcher and other values propagate
	ctx, cancel := context.WithCancel(ctx)
	i.cancel = cancel

	// Calculate bandwidth from config
	sendBPS := uint64(0)    // unlimited by default
	receiveBPS := uint64(0) // unlimited by default

	if i.config.UpMbps > 0 {
		sendBPS = i.config.UpMbps * 125000 // convert Mbps to Bps
	}
	if i.config.DownMbps > 0 {
		receiveBPS = i.config.DownMbps * 125000 // convert Mbps to Bps
	}

	// Salamander obfuscation password
	salamanderPassword := ""
	if i.config.Obfs != nil && i.config.Obfs.Type == "salamander" && i.config.Obfs.Password != "" {
		salamanderPassword = i.config.Obfs.Password
		errors.LogInfo(ctx, "Hysteria2 salamander obfuscation enabled")
	}

	// Masquerade handler
	masqueradeHandler := i.createMasqueradeHandler()
	if masqueradeHandler != nil {
		errors.LogInfo(ctx, "Hysteria2 masquerade enabled")
	}

	serviceOptions := hysteria2.ServiceOptions{
		Context:               ctx,
		Logger:                singbridge.NewLogger(errors.New),
		BrutalDebug:           i.config.BrutalDebug,
		SendBPS:               sendBPS,
		ReceiveBPS:            receiveBPS,
		IgnoreClientBandwidth: i.config.IgnoreClientBandwidth,
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             singbridge.NewTLSConfig(tlsConfig),
		UDPDisabled:           false,
		UDPTimeout:            60 * time.Second,
		Handler:               i, // Use self as ServerHandler
		MasqueradeHandler:     masqueradeHandler,
	}

	// Create Hysteria2 service
	service, err := hysteria2.NewService[string](serviceOptions)
	if err != nil {
		cancel()
		return errors.New("Failed to create Hysteria2 service").Base(err)
	}

	// Initialize users into service from fast-path lists
	i.uMu.RLock()
	initUsers := append([]string(nil), i.userList...)
	initPwds := append([]string(nil), i.passwordList...)
	i.uMu.RUnlock()
	service.UpdateUsers(initUsers, initPwds)

	i.service = service

	// Start service in background
	go func() {
		if err := service.Start(packetConn); err != nil {
			errors.LogWarning(ctx, "Hysteria2 service error: ", err)
		}
	}()

	// Start coalesced user updater loop
	go i.userUpdaterLoop()

	errors.LogInfo(ctx, "Hysteria2 service started")
	return nil
}

// Close closes the Hysteria2 service
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
// For Hysteria2, connections are handled through ServerHandler callbacks
func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	return errors.New("Hysteria2.Process should not be called - connections are handled by ServerHandler")
}

// GetConfig returns the server configuration
func (i *Inbound) GetConfig() *ServerConfig {
	return i.config
}

// NewConnectionEx handles new TCP connection with full metadata
func (i *Inbound) NewConnectionEx(ctx context.Context, conn gonet.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(errors.New("connection closed"))
	}

	// Get user from auth context (hot path: use RLock)
	var user *protocol.MemoryUser
	if userID, ok := auth.UserFromContext[string](ctx); ok && userID != "" {
		if u, exists := i.userMap.Load(userID); exists {
			user = u.(*protocol.MemoryUser)
		}
	}
	email := ""
	if user != nil {
		email = user.Email
	}

	// Build session inbound with tag
	// Note: Even though Hysteria2 uses QUIC/UDP transport, the stream connections are TCP semantics
	inbound := &session.Inbound{
		Name:    "hysteria2",
		User:    user,
		Source:  singbridge.ToDestination(source, net.Network_TCP),
		Local:   net.DestinationFromAddr(i.localaddr),
		Gateway: net.DestinationFromAddr(i.localaddr),
		Tag:     i.tag,
	}

	inbound.CanSpliceCopy = 3
	sessionCtx := session.ContextWithInbound(ctx, inbound)
	// Convert sing metadata to Xray destination
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

	errors.LogInfo(sessionCtx, "accepted hysteria2 tcp connection to ", targetDest, " user: ", email)

	// Get dispatcher from context or core
	dispatcher := session.DispatcherFromContext(sessionCtx)
	if dispatcher == nil {
		errors.LogWarning(sessionCtx, "dispatcher missing in context")
		return
	}

	// Dispatch connection
	link, err := dispatcher.Dispatch(sessionCtx, targetDest)
	if err != nil {
		// Notify client of handshake failure if the connection supports it
		if hs, ok := conn.(interface{ HandshakeFailure(error) error }); ok {
			_ = hs.HandshakeFailure(err)
		}
		errors.LogWarning(sessionCtx, "failed to dispatch request: ", err)
		return
	}

	// Notify client of handshake success
	if hs, ok := conn.(interface{ HandshakeSuccess() error }); ok {
		if err := hs.HandshakeSuccess(); err != nil {
			errors.LogWarning(sessionCtx, "failed to send handshake success: ", err)
			return
		}
	}

	// Use singbridge to copy data between connections
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

	// Get user from auth context (hot path: use RLock)
	var user *protocol.MemoryUser
	if userID, ok := auth.UserFromContext[string](ctx); ok && userID != "" {
		if u, exists := i.userMap.Load(userID); exists {
			user = u.(*protocol.MemoryUser)
		}
	}
	email := ""
	if user != nil {
		email = user.Email
	}

	// Build session inbound with tag
	inbound := &session.Inbound{
		Name:    "hysteria2",
		User:    user,
		Source:  singbridge.ToDestination(source, net.Network_UDP),
		Local:   net.DestinationFromAddr(i.localaddr),
		Gateway: net.DestinationFromAddr(i.localaddr),
		Tag:     i.tag,
	}

	inbound.CanSpliceCopy = 3
	sessionCtx := session.ContextWithInbound(ctx, inbound)
	// Convert sing metadata to Xray destination
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

	errors.LogInfo(sessionCtx, "accepted hysteria2 udp connection to ", targetDest, " user: ", email)

	// Get dispatcher from context or core
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

// Update service Users
func (i *Inbound) updateServiceUsers() {
	if i.service == nil {
		return
	}
	// snapshot lists to avoid holding lock during service update
	i.uMu.RLock()
	users := append([]string(nil), i.userList...)
	pwds := append([]string(nil), i.passwordList...)
	i.uMu.RUnlock()
	i.service.UpdateUsers(users, pwds)
}

// AddUser implements proxy.UserManager.AddUser().
func (i *Inbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.userMap.Store(u.Email, u)
	// update fast-path lists and coalesce service update
	if acc, ok := u.Account.(*MemoryAccount); ok {
		i.uMu.Lock()
		if _, exists := i.emailIndex[u.Email]; !exists {
			i.userList = append(i.userList, u.Email)
			i.passwordList = append(i.passwordList, acc.Password)
			i.emailIndex[u.Email] = len(i.userList) - 1
		} else {
			// overwrite password if changed
			i.passwordList[i.emailIndex[u.Email]] = acc.Password
		}
		i.uMu.Unlock()
		i.scheduleUserUpdate()
	} else {
		// fallback: rebuild from map once
		i.scheduleUserUpdate()
	}
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	i.userMap.Delete(email)
	// swap-delete in arrays for O(1)
	i.uMu.Lock()
	if idx, ok := i.emailIndex[email]; ok {
		last := len(i.userList) - 1
		if idx != last {
			i.userList[idx] = i.userList[last]
			i.passwordList[idx] = i.passwordList[last]
			i.emailIndex[i.userList[idx]] = idx
		}
		i.userList = i.userList[:last]
		i.passwordList = i.passwordList[:last]
		delete(i.emailIndex, email)
	}
	i.uMu.Unlock()
	i.scheduleUserUpdate()

	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (i *Inbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	if u, exists := i.userMap.Load(email); exists {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	i.userMap.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (i *Inbound) GetUsersCount(ctx context.Context) int64 {
	var count int64
	i.userMap.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// scheduleUserUpdate coalesces UpdateUsers calls to reduce overhead during bulk updates.
func (i *Inbound) scheduleUserUpdate() {
	// try send signal (droppable if already pending)
	select {
	case i.updateCh <- struct{}{}:
	default:
	}
}

// userUpdaterLoop batches rapid user updates with a trailing-edge debounce window.
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
