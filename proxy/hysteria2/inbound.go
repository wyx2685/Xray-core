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
	sync.Mutex
	policyManager policy.Manager
	config        *ServerConfig
	ctx           context.Context
	tag           string
	localaddr     gonet.Addr
	service       *hysteria2.Service[string]
	cancel        context.CancelFunc
	users         []*protocol.MemoryUser          // user list
	userMap       map[string]*protocol.MemoryUser // password -> user
}

// NewServer creates a new Hysteria2 inbound handler
func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	v := core.MustFromContext(ctx)

	inbound := &Inbound{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
		ctx:           ctx,
		userMap:       make(map[string]*protocol.MemoryUser),
	}

	// Build user map from config
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

		if hy2Account, ok := memAccount.(*MemoryAccount); ok {
			memUser := &protocol.MemoryUser{
				Email:   user.Email,
				Level:   user.Level,
				Account: memAccount,
			}
			inbound.userMap[hy2Account.Password] = memUser
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

	// Update users with passwords from userMap
	if len(i.userMap) > 0 {
		userList := make([]string, 0, len(i.userMap))
		passwordList := make([]string, 0, len(i.userMap))

		for password, user := range i.userMap {
			userList = append(userList, user.Email)
			passwordList = append(passwordList, password)
		}

		service.UpdateUsers(userList, passwordList)
		errors.LogInfo(ctx, "Loaded ", len(i.userMap), " Hysteria2 users")
	} else {
		// No users configured, use empty list (will reject all connections)
		errors.LogWarning(ctx, "No users configured for Hysteria2")
	}

	i.service = service

	// Start service in background
	go func() {
		if err := service.Start(packetConn); err != nil {
			errors.LogWarning(ctx, "Hysteria2 service error: ", err)
		}
	}()

	errors.LogInfo(ctx, "Hysteria2 service started")
	return nil
}

// Close closes the Hysteria2 service
func (i *Inbound) Close() error {
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

	// Get user from auth context
	var user *protocol.MemoryUser
	if userID, ok := auth.UserFromContext[string](ctx); ok && userID != "" {
		if foundUser, exists := i.userMap[userID]; exists {
			user = foundUser
		} else {
			user = &protocol.MemoryUser{
				Email: userID,
				Level: 0,
			}
		}
	} else {
		user = &protocol.MemoryUser{
			Email: "anonymous",
			Level: 0,
		}
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
		Email:  user.Email,
	})

	errors.LogInfo(sessionCtx, "accepted hysteria2 tcp connection to ", targetDest, " user: ", user.Email)

	// Get dispatcher from context or core
	dispatcher := session.DispatcherFromContext(sessionCtx)

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

	// Get user from auth context
	var user *protocol.MemoryUser
	if userID, ok := auth.UserFromContext[string](ctx); ok && userID != "" {
		if foundUser, exists := i.userMap[userID]; exists {
			user = foundUser
		} else {
			user = &protocol.MemoryUser{
				Email: userID,
				Level: 0,
			}
		}
	} else {
		user = &protocol.MemoryUser{
			Email: "anonymous",
			Level: 0,
		}
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
		Email:  user.Email,
	})

	errors.LogInfo(sessionCtx, "accepted hysteria2 udp connection to ", targetDest, " user: ", user.Email)

	// Get dispatcher from context or core
	dispatcher := session.DispatcherFromContext(sessionCtx)

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

// updateServiceUsers updates the hysteria2 service with current user list
func (i *Inbound) updateServiceUsers() {
	if i.service == nil {
		return
	}

	userList := make([]string, 0, len(i.users))
	passwordList := make([]string, 0, len(i.users))

	for _, user := range i.users {
		if hy2Account, ok := user.Account.(*MemoryAccount); ok {
			userList = append(userList, user.Email)
			passwordList = append(passwordList, hy2Account.Password)
		}
	}

	i.service.UpdateUsers(userList, passwordList)
}

// AddUser implements proxy.UserManager.AddUser().
func (i *Inbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.Lock()
	defer i.Unlock()

	if u.Email != "" {
		for _, user := range i.users {
			if user.Email == u.Email {
				return errors.New("User ", u.Email, " already exists.")
			}
		}
	}

	// Validate account type
	hy2Account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("Invalid account type for Hysteria2")
	}

	// Add to users list and userMap
	i.users = append(i.users, u)
	i.userMap[hy2Account.Password] = u

	// Update service
	i.updateServiceUsers()

	errors.LogInfo(ctx, "Hysteria2: Added user ", u.Email)
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	i.Lock()
	defer i.Unlock()

	idx := -1
	var password string
	for ii, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			idx = ii
			if hy2Account, ok := u.Account.(*MemoryAccount); ok {
				password = hy2Account.Password
			}
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}

	// Remove from users list
	ulen := len(i.users)
	i.users[idx] = i.users[ulen-1]
	i.users[ulen-1] = nil
	i.users = i.users[:ulen-1]

	// Remove from userMap
	if password != "" {
		delete(i.userMap, password)
	}

	// Update service
	i.updateServiceUsers()

	errors.LogInfo(ctx, "Hysteria2: Removed user ", email)
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (i *Inbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	i.Lock()
	defer i.Unlock()

	for _, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	i.Lock()
	defer i.Unlock()

	dst := make([]*protocol.MemoryUser, len(i.users))
	copy(dst, i.users)
	return dst
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (i *Inbound) GetUsersCount(ctx context.Context) int64 {
	i.Lock()
	defer i.Unlock()

	return int64(len(i.users))
}
