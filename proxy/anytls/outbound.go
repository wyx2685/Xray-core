package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutbound(ctx, config.(*ClientConfig))
	}))
}

// Outbound is the anytls outbound proxy handler
type Outbound struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewOutbound(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("anytls: no server specified")
	}

	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	v := core.MustFromContext(ctx)
	outbound := &Outbound{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	return outbound, nil
}

// Process implements OutboundHandler.Process()
// Supports both TCP and UDP proxying:
// - TCP: direct stream forwarding
// - UDP: uses UDP-over-TCP (UoT) protocol with special destination sp.v2.udp-over-tcp.arpa
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	server := o.server
	dest := server.Destination

	// Get user account
	if server.User == nil {
		return errors.New("anytls: no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return errors.New("anytls: invalid account type")
	}
	password := account.Password

	// 获取默认 padding scheme 以确定 padding0 大小
	// 根据官方默认 scheme: 0=30-30，包0 的 padding 应该是 30 字节
	defaultScheme := getDefaultPaddingScheme()
	padding := getPadding0Size(defaultScheme)

	// Establish TCP connection with exponential backoff retry
	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("anytls: failed to find an available destination").AtWarning().Base(err)
	}

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", dest.NetAddr())
	defer conn.Close()

	// 认证：sha256(password) + padding
	sum := sha256.Sum256([]byte(password))
	auth := make([]byte, 34)
	copy(auth[:32], sum[:])
	binary.BigEndian.PutUint16(auth[32:34], padding)
	if _, err := conn.Write(auth); err != nil {
		return errors.New("anytls: write auth failed").Base(err)
	}
	if padding > 0 {
		pad := make([]byte, padding)
		if _, err := conn.Write(pad); err != nil {
			return errors.New("anytls: write padding failed").Base(err)
		}
	}

	// 帧协议收发
	br := &buf.BufferedReader{Reader: buf.NewReader(conn)}
	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	fw := newFrameWriter(bw)
	var writeMu sync.Mutex

	// 包计数器（用于 padding scheme）
	// 包0 = 认证阶段的 padding0
	// 包1 = cmdSettings + cmdSYN（合并发送）
	// 包2+ = 后续数据包
	var pktCounter uint32 = 1 // 从 1 开始，因为包0已在认证阶段
	var pktMu sync.Mutex

	// padding scheme state
	paddingScheme := getDefaultPaddingScheme()
	schemeMu := sync.RWMutex{}

	// 缓冲区用于合并 cmdSettings + cmdSYN 作为包1
	var frameBuffer []byte

	// helper to send control frames immediately
	sendFrame := func(cmd byte, sid uint32, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := fw.write(cmd, sid, data); err != nil {
			return err
		}
		return fw.flush()
	}

	// helper to send data frames without immediate flush
	sendDataFrame := func(sid uint32, data buf.MultiBuffer) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return fw.writeMultiBuffer(cmdPSH, sid, data)
	}

	// helper to send byte slice data frames without immediate flush
	sendDataFrameBytes := func(sid uint32, data []byte) error {
		return sendDataFrame(sid, buf.MultiBuffer{buf.FromBytes(data)})
	}

	// buffered frame writer - 用于合并 cmdSettings + cmdSYN
	writeFrameBuffered := func(cmd byte, sid uint32, data []byte) {
		// 计算帧大小: 1(cmd) + 4(sid) + 2(len) + data
		frameSize := 7 + len(data)
		frame := make([]byte, frameSize)
		frame[0] = cmd
		binary.BigEndian.PutUint32(frame[1:5], sid)
		binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
		copy(frame[7:], data)
		frameBuffer = append(frameBuffer, frame...)
	}

	// flush buffered frames with padding
	flushFrameBuffer := func() error {
		if len(frameBuffer) == 0 {
			return nil
		}

		writeMu.Lock()
		defer writeMu.Unlock()

		// 应用包1的 padding 规则 (1=100-400)
		schemeMu.RLock()
		scheme := paddingScheme
		schemeMu.RUnlock()

		dataToSend := frameBuffer
		if scheme != nil && scheme.stop > 1 {
			// 使用官方简洁 API 生成包1的大小
			pktSizes := scheme.GenerateRecordPayloadSizes(1)
			if len(pktSizes) > 0 && pktSizes[0] != CheckMark {
				targetSize := pktSizes[0]

				// 如果当前数据不足目标大小，添加 cmdWaste 填充
				currentSize := len(frameBuffer)
				if currentSize < targetSize {
					paddingSize := targetSize - currentSize
					// 创建 cmdWaste 帧
					wasteFrame := make([]byte, 7+paddingSize)
					wasteFrame[0] = cmdWaste
					binary.BigEndian.PutUint32(wasteFrame[1:5], 0)
					binary.BigEndian.PutUint16(wasteFrame[5:7], uint16(paddingSize))
					// 数据部分填充0
					dataToSend = append(frameBuffer, wasteFrame...)
				}
				// 如果currentSize >= targetSize，直接发送（cmdSettings + cmdSYN 的内容是必须的）
			}
		}

		// 写入数据
		if _, err := conn.Write(dataToSend); err != nil {
			return err
		}

		frameBuffer = nil
		return nil
	}

	// 1) send settings frame (buffered)
	// 按照 anytls-go 官方协议，发送 v=2 和 client 标识
	clientSettings := "v=2\nclient=xray\npadding-md5=" + paddingScheme.md5

	// 缓冲 cmdSettings（不立即发送）
	writeFrameBuffered(cmdSettings, 0, []byte(clientSettings))

	// manage streams: use sid allocation
	var sid uint32 = 1
	sidMu := sync.Mutex{}
	allocSid := func() uint32 {
		sidMu.Lock()
		defer sidMu.Unlock()
		s := sid
		sid++
		return s
	}

	// helper to serialize destination into SOCKS addr bytes
	makeSocksAddr := func(d net.Destination) []byte {
		// SOCKS ATYP: 1=IPv4, 3=Domain, 4=IPv6
		var out []byte
		if d.Address.Family().IsIP() {
			ip := d.Address.IP()
			if ip.To4() != nil {
				out = append(out, 1)
				out = append(out, ip.To4()...)
			} else {
				out = append(out, 4)
				out = append(out, ip.To16()...)
			}
		} else {
			s := d.Address.String()
			out = append(out, 3)
			out = append(out, byte(len(s)))
			out = append(out, []byte(s)...)
		}
		portb := make([]byte, 2)
		binary.BigEndian.PutUint16(portb, uint16(d.Port))
		out = append(out, portb...)
		return out
	}

	// streams and synAck channels
	synAckCh := make(map[uint32]chan error)
	synAckMu := sync.Mutex{}

	// start read loop (downlink handler)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var head [7]byte
		for {
			_, err := io.ReadFull(br, head[:])
			if err != nil {
				return
			}
			cmd := head[0]
			rsid := binary.BigEndian.Uint32(head[1:5])
			length := int(binary.BigEndian.Uint16(head[5:7]))

			switch cmd {
			case cmdPSH:
				var data buf.MultiBuffer
				if length > 0 {
					var b *buf.Buffer
					if length <= buf.Size {
						b = buf.New()
					} else {
						b = buf.NewWithSize(int32(length))
					}
					p := b.Extend(int32(length))
					if _, err := io.ReadFull(br, p); err != nil {
						b.Release()
						return
					}
					data = buf.MultiBuffer{b}
				}
				if !data.IsEmpty() {
					_ = link.Writer.WriteMultiBuffer(data)
				}
			case cmdFIN:
				if length > 0 {
					discard := make([]byte, length)
					if _, err := io.ReadFull(br, discard); err != nil {
						return
					}
				}
				common.Close(link.Writer)
				return
			case cmdSYNACK:
				var body []byte
				if length > 0 {
					body = make([]byte, length)
					if _, err := io.ReadFull(br, body); err != nil {
						return
					}
				}
				synAckMu.Lock()
				ch := synAckCh[rsid]
				synAckMu.Unlock()
				if ch != nil {
					if len(body) > 0 {
						ch <- errors.New(string(body))
					} else {
						ch <- nil
					}
				}
			case cmdWaste:
				if length > 0 {
					discard := make([]byte, length)
					if _, err := io.ReadFull(br, discard); err != nil {
						return
					}
				}
				continue
			case cmdServerSettings:
				if length > 0 {
					discard := make([]byte, length)
					if _, err := io.ReadFull(br, discard); err != nil {
						return
					}
				}
				// ignore for now
			case cmdUpdatePaddingScheme:
				if length > 0 {
					body := make([]byte, length)
					if _, err := io.ReadFull(br, body); err != nil {
						return
					}
					scheme, perr := parsePaddingScheme(string(body))
					if perr == nil && scheme != nil {
						schemeMu.Lock()
						paddingScheme = scheme
						schemeMu.Unlock()
					}
				}
			case cmdHeartRequest:
				if length > 0 {
					discard := make([]byte, length)
					if _, err := io.ReadFull(br, discard); err != nil {
						return
					}
				}
				_ = sendFrame(cmdHeartResponse, 0, nil)
			default:
				if length > 0 {
					discard := make([]byte, length)
					if _, err := io.ReadFull(br, discard); err != nil {
						return
					}
				}
				errors.LogWarning(ctx, "anytls: unknown cmd=", cmd, " streamId=", rsid)
				return
			}
		}
	}()

	// uplink: read from link.Reader and establish stream via SYN
	lbr := &buf.BufferedReader{Reader: link.Reader}
	mySid := allocSid()

	// Check if target is UDP, use UoT special destination
	isUDP := destination.Network == net.Network_UDP
	var actualDest net.Destination

	if isUDP {
		// UDP-over-TCP: use special domain sp.v2.udp-over-tcp.arpa
		actualDest = net.Destination{
			Network: net.Network_TCP,
			Address: net.ParseAddress("sp.v2.udp-over-tcp.arpa"),
			Port:    0,
		}
	} else {
		actualDest = destination
	}

	// prepare SYN body: target address in SOCKS format if available
	synBody := []byte{}
	if len(outbounds) > 0 {
		ob := outbounds[len(outbounds)-1]
		if ob.Target.IsValid() {
			synBody = makeSocksAddr(actualDest)
		}
	}

	// 缓冲 cmdSYN（与 cmdSettings 合并）
	writeFrameBuffered(cmdSYN, mySid, synBody)

	// 立即 flush 缓冲区，发送 cmdSettings + cmdSYN 作为包1
	if err := flushFrameBuffer(); err != nil {
		return errors.New("anytls: send settings+syn failed").Base(err)
	}

	// wait for SYNACK
	ch := make(chan error, 1)
	synAckMu.Lock()
	synAckCh[mySid] = ch
	synAckMu.Unlock()
	select {
	case serr := <-ch:
		if serr != nil {
			return errors.New("anytls: SYN rejected").Base(serr)
		}
	case <-time.After(5 * time.Second):
		return errors.New("anytls: SYNACK timeout")
	}
	// remove channel
	synAckMu.Lock()
	delete(synAckCh, mySid)
	synAckMu.Unlock()

	// For UDP: send UoT request header immediately after stream establishment
	if isUDP {
		// Construct UoT request
		uotReq := uot.Request{
			Destination: M.Socksaddr{
				Fqdn: destination.Address.String(),
				Port: destination.Port.Value(),
			},
		}

		// Write UoT request header to stream
		reqBuf := buf.New()
		if err := uot.WriteRequest(reqBuf, uotReq); err != nil {
			return errors.New("anytls: write UoT request failed").Base(err)
		}
		if err := sendDataFrameBytes(mySid, reqBuf.Bytes()); err != nil {
			reqBuf.Release()
			return errors.New("anytls: send UoT request failed").Base(err)
		}
		reqBuf.Release()
	}

	// start uplink pump: read from link and send PSH for mySid
	// 应用 padding scheme 进行数据分片和填充
	// 注意：包1 已经在 cmdSettings+cmdSYN 中处理，这里从包2开始
	go func(sid uint32) {
		for {
			mb, err := lbr.ReadMultiBuffer()
			if !mb.IsEmpty() {
				// 获取当前包序号
				pktMu.Lock()
				packetIndex := int(pktCounter)
				pktCounter++
				pktMu.Unlock()

				// 检查是否需要应用 padding scheme
				schemeMu.RLock()
				scheme := paddingScheme
				schemeMu.RUnlock()

				if scheme != nil && uint32(packetIndex) < scheme.stop {
					pktSizes := scheme.GenerateRecordPayloadSizes(uint32(packetIndex))
					if len(pktSizes) > 0 {
						for _, size := range pktSizes {
							if size == CheckMark {
								if mb.IsEmpty() {
									break
								}
								continue
							}

							remaining := int(mb.Len())
							if remaining <= 0 {
								wastePad := make([]byte, size)
								if werr := sendFrame(cmdWaste, 0, wastePad); werr != nil {
									_ = sendFrame(cmdFIN, sid, nil)
									return
								}
								continue
							}

							if remaining >= size {
								var chunk buf.MultiBuffer
								mb, chunk = buf.SplitSize(mb, int32(size))
								if werr := sendDataFrame(sid, chunk); werr != nil {
									buf.ReleaseMulti(mb)
									return
								}
								continue
							}

							var chunk buf.MultiBuffer
							mb, chunk = buf.SplitSize(mb, int32(remaining))
							pad := buf.NewWithSize(int32(size - remaining))
							pad.Extend(int32(size - remaining))
							chunk = append(chunk, pad)
							if werr := sendDataFrame(sid, chunk); werr != nil {
								buf.ReleaseMulti(mb)
								return
							}
						}

						if !mb.IsEmpty() {
							if werr := sendDataFrame(sid, mb); werr != nil {
								return
							}
						}
						continue
					}
				}

				if err := sendDataFrame(sid, mb); err != nil {
					_ = sendFrame(cmdFIN, sid, nil)
					return
				}
			}
			if err != nil {
				_ = sendFrame(cmdFIN, sid, nil)
				return
			}
		}
	}(mySid)

	// wait for downlink goroutine to finish
	<-done

	return nil
}
