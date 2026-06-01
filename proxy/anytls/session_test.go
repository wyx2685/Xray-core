package anytls

import (
	"testing"

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
