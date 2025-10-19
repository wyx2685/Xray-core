package anytls

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	cmdWaste               byte = 0
	cmdSYN                 byte = 1
	cmdPSH                 byte = 2
	cmdFIN                 byte = 3
	cmdSettings            byte = 4
	cmdAlert               byte = 5
	cmdUpdatePaddingScheme byte = 6
	cmdSYNACK              byte = 7
	cmdHeartRequest        byte = 8
	cmdHeartResponse       byte = 9
	cmdServerSettings      byte = 10
)

type Server struct {
	policyManager policy.Manager
	// lock-free read via atomic snapshot; writers use wmu and COW
	store atomic.Value // *userStoreSnapshot
	wmu   sync.Mutex
	// coalesced updates
	pendingAdds    map[string]*protocol.MemoryUser
	pendingRemoves map[string]struct{}
	pendingMu      sync.Mutex
	updateCh       chan struct{}
	stopCh         chan struct{}
	debounce       time.Duration
	paddingScheme  string
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager:  v.GetFeature(policy.ManagerType()).(policy.Manager),
		updateCh:       make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		debounce:       200 * time.Millisecond,
		pendingAdds:    make(map[string]*protocol.MemoryUser),
		pendingRemoves: make(map[string]struct{}),
		paddingScheme:  config.PaddingScheme,
	}
	users := make(map[[32]byte]*protocol.MemoryUser)
	emailIndex := make(map[string][32]byte)
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("anytls: bad user").Base(err)
		}
		acc, ok := mu.Account.(*MemoryAccount)
		if !ok {
			return nil, errors.New("anytls: user account type")
		}
		sum := sha256.Sum256([]byte(acc.Password))
		users[sum] = mu
		emailIndex[mu.Email] = sum
	}
	s.store.Store(&userStoreSnapshot{users: users, emailIndex: emailIndex})
	// start updater loop
	go s.userUpdaterLoop()
	return s, nil
}

func (s *Server) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPol := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPol.Timeouts.Handshake))

	br := &buf.BufferedReader{Reader: buf.NewReader(conn)}
	// auth header: 32B sha256(password) + 2B padlen
	h := make([]byte, 34)
	if _, err := io.ReadFull(br, h); err != nil {
		return errors.New("anytls: read auth").Base(err)
	}
	var sum [32]byte
	copy(sum[:], h[:32])
	snap := s.loadStore()
	user := snap.users[sum]
	if user == nil {
		return errors.New("anytls: invalid user")
	}
	padlen := binary.BigEndian.Uint16(h[32:34])
	if padlen > 0 {
		if _, err := io.ReadFull(br, make([]byte, padlen)); err != nil {
			return errors.New("anytls: read padding0").Base(err)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	inb := session.InboundFromContext(ctx)
	inb.Name = protocolName
	inb.User = user
	inb.CanSpliceCopy = 3

	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	// serialize all writes to the underlying connection
	var writeMu sync.Mutex
	streams := make(map[uint32]*stream)
	var smu sync.Mutex

	// Frame operations
	fr := newFrameReader(br, ctx)
	fw := newFrameWriter(bw)

	readFrame := func() (cmd byte, sid uint32, data []byte, err error) {
		return fr.read()
	}

	sendFrame := func(cmd byte, sid uint32, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := fw.write(cmd, sid, data); err != nil {
			return err
		}
		return fw.flush()
	}

	// settings handshake: expect cmdSettings first
	var clientVersion int = 1
	var clientPaddingMD5 string
	for {
		c, _, data, err := readFrame()
		if err != nil {
			return err
		}
		if c == cmdWaste {
			continue
		}
		if c != cmdSettings {
			return errors.New("anytls: expect settings first")
		}
		// parse settings key=value per line
		if len(data) > 0 {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				kv := strings.SplitN(line, "=", 2)
				if len(kv) != 2 {
					continue
				}
				k := kv[0]
				v := kv[1]
				switch k {
				case "v":
					if v == "2" {
						clientVersion = 2
					}
				case "padding-md5":
					clientPaddingMD5 = strings.ToLower(v)
				}
			}
		}
		// For v>=2 client, send server settings v=2
		if clientVersion >= 2 {
			if err := sendFrame(cmdServerSettings, 0, []byte("v=2")); err != nil {
				return err
			}
		}
		// If server has paddingScheme and md5 mismatches, request update
		if s.paddingScheme != "" && clientPaddingMD5 != "" {
			sum := md5.Sum([]byte(s.paddingScheme))
			localMD5 := strings.ToLower(hex.EncodeToString(sum[:]))
			if localMD5 != clientPaddingMD5 {
				if err := sendFrame(cmdUpdatePaddingScheme, 0, []byte(s.paddingScheme)); err != nil {
					return err
				}
			}
		}
		break
	}

	for {
		cmd, sid, body, err := readFrame()
		if err != nil {
			return err
		}

		switch cmd {
		case cmdWaste:
			continue
		case cmdHeartRequest:
			if err := sendFrame(cmdHeartResponse, 0, nil); err != nil {
				return err
			}
		case cmdSYN:
			if err := s.handleSYN(ctx, sid, body, &streams, &smu, dispatcher, sendFrame); err != nil {
				return err
			}
		case cmdPSH:
			if err := s.handlePSH(ctx, sid, body, &streams, &smu, dispatcher, sendFrame); err != nil {
				return err
			}
		case cmdFIN:
			s.handleFIN(ctx, sid, &streams, &smu, bw)
		default:
			errors.LogWarning(ctx, "anytls: unknown cmd=", cmd, " streamId=", sid)
			return errors.New("anytls: unknown cmd")
		}
	}
}
