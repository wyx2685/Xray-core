package anytls

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	sessionctx "github.com/xtls/xray-core/common/session"
)

func TestDispatchContextAccessMessage(t *testing.T) {
	source := net.TCPDestination(net.ParseAddress("192.0.2.1"), 1234)
	ctx := sessionctx.ContextWithInbound(context.Background(), &sessionctx.Inbound{
		Source: source,
		User:   &protocol.MemoryUser{Email: "user@example.com"},
	})
	ctx = sessionctx.ContextWithContent(ctx, &sessionctx.Content{})

	s := &session{noTLS: true}
	st := newStream(1, nil)
	firstDest := net.TCPDestination(net.ParseAddress("example.com"), 443)
	firstCtx := s.dispatchContext(ctx, st, firstDest)
	first := log.AccessMessageFromContext(firstCtx)
	if first == nil {
		t.Fatal("missing access message")
	}
	if serial.ToString(first.From) != serial.ToString(source) || serial.ToString(first.To) != serial.ToString(firstDest) {
		t.Fatalf("unexpected access endpoints: from=%v to=%v", first.From, first.To)
	}
	if first.Status != log.AccessAccepted || first.Reason != "" || first.Email != "user@example.com" {
		t.Fatalf("unexpected access message: %+v", first)
	}
	if content := sessionctx.ContentFromContext(firstCtx); content == nil || content.Attribute("anytls") != "notls" {
		t.Fatal("missing AnyTLS no-TLS dispatch attribute")
	}
	if log.AccessMessageFromContext(st.dispatchCtx) != nil {
		t.Fatal("base dispatch context must not retain an access message")
	}

	secondDest := net.UDPDestination(net.ParseAddress("8.8.8.8"), 53)
	second := log.AccessMessageFromContext(s.dispatchContext(ctx, st, secondDest))
	if second == nil {
		t.Fatal("missing second access message")
	}
	if second == first {
		t.Fatal("dispatches must not reuse access messages")
	}
	if serial.ToString(second.To) != serial.ToString(secondDest) || serial.ToString(first.To) != serial.ToString(firstDest) {
		t.Fatalf("access destinations were reused: first=%v second=%v", first.To, second.To)
	}
}
