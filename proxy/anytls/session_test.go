package anytls

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func TestReadUoTRequestLeavesPacketBody(t *testing.T) {
	requestDest := M.Socksaddr{Fqdn: "initial.example", Port: 443}
	packetDest := M.Socksaddr{Fqdn: "packet.example", Port: 53}

	requestBuffer := buf.New()
	if err := uot.WriteRequest(requestBuffer, uot.Request{
		IsConnect:   false,
		Destination: requestDest,
	}); err != nil {
		t.Fatal(err)
	}

	payload := buf.New()
	if _, err := payload.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	packet, err := buildUoTPacket(buf.MultiBuffer{payload}, false, packetDest)
	if err != nil {
		t.Fatal(err)
	}

	request, rest, err := readUoTRequest(append(buf.MultiBuffer{requestBuffer}, packet...))
	if err != nil {
		t.Fatal(err)
	}
	if request.IsConnect {
		t.Fatal("request unexpectedly used connect mode")
	}
	if request.Destination.Fqdn != requestDest.Fqdn || request.Destination.Port != requestDest.Port {
		t.Fatalf("request destination = %v, want %v", request.Destination, requestDest)
	}

	parsedPayload, parsedDest, err := readUoTPacket(rest, false, request.Destination)
	if err != nil {
		t.Fatal(err)
	}
	defer parsedPayload.Release()
	if string(parsedPayload.Bytes()) != "ping" {
		t.Fatalf("payload = %q, want ping", string(parsedPayload.Bytes()))
	}
	if parsedDest.Address.String() != packetDest.Fqdn || parsedDest.Port != net.Port(packetDest.Port) {
		t.Fatalf("packet destination = %v, want %v", parsedDest, packetDest)
	}
}

func TestReadLoopDropsUnknownPSHAndContinues(t *testing.T) {
	serverConn, clientConn := stdnet.Pipe()
	defer clientConn.Close()

	s := &session{
		conn:    serverConn,
		br:      &buf.BufferedReader{Reader: buf.NewReader(serverConn)},
		bw:      buf.NewBufferedWriter(buf.NewWriter(serverConn)),
		streams: make(map[uint32]*stream),
		errCh:   make(chan error, 1),
	}
	s.fw = newFrameWriter(s.bw)

	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readLoop(context.Background())
	}()
	defer s.close(nil)

	writeFrameForTest(t, clientConn, cmdPSH, 99, []byte("late"))
	cmd, sid, body := readFrameForTest(t, clientConn)
	if cmd != cmdFIN || sid != 99 || len(body) != 0 {
		t.Fatalf("first response = cmd %d sid %d len %d, want FIN sid 99", cmd, sid, len(body))
	}

	writeFrameForTest(t, clientConn, cmdHeartRequest, 0, nil)
	cmd, sid, body = readFrameForTest(t, clientConn)
	if cmd != cmdHeartResponse || sid != 0 || len(body) != 0 {
		t.Fatalf("second response = cmd %d sid %d len %d, want HeartResponse", cmd, sid, len(body))
	}

	select {
	case err := <-readErr:
		t.Fatalf("readLoop exited after unknown PSH: %v", err)
	default:
	}
}

func TestFeedUoTUplinkDropsWhenQueueFull(t *testing.T) {
	st := &stream{
		udpCh:   make(chan *buf.Buffer, 1),
		udpDone: make(chan struct{}),
	}
	queued := buf.New()
	st.udpCh <- queued
	defer queued.Release()

	body := buf.New()
	if _, err := body.Write([]byte("drop")); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		(&session{}).feedUoTUplink(st, buf.MultiBuffer{body})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("feedUoTUplink blocked on full UDP queue")
	}
}

func writeFrameForTest(t *testing.T, w io.Writer, cmd byte, sid uint32, body []byte) {
	t.Helper()
	var head [7]byte
	head[0] = cmd
	binary.BigEndian.PutUint32(head[1:5], sid)
	binary.BigEndian.PutUint16(head[5:7], uint16(len(body)))
	if _, err := w.Write(head[:]); err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
}

func readFrameForTest(t *testing.T, r io.Reader) (byte, uint32, []byte) {
	t.Helper()
	var head [7]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint16(head[5:7])
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatal(err)
		}
	}
	return head[0], binary.BigEndian.Uint32(head[1:5]), body
}

func TestBuildUoTPacketUsesDatagramDestination(t *testing.T) {
	packetDest := M.Socksaddr{Fqdn: "reply.example", Port: 5353}
	payload := buf.New()
	if _, err := payload.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}

	packet, err := buildUoTPacket(buf.MultiBuffer{payload}, false, packetDest)
	if err != nil {
		t.Fatal(err)
	}

	parsedPayload, parsedDest, err := readUoTPacket(packet, false, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer parsedPayload.Release()
	if string(parsedPayload.Bytes()) != "pong" {
		t.Fatalf("payload = %q, want pong", string(parsedPayload.Bytes()))
	}
	if parsedDest.Address.String() != packetDest.Fqdn || parsedDest.Port != net.Port(packetDest.Port) {
		t.Fatalf("packet destination = %v, want %v", parsedDest, packetDest)
	}
}
