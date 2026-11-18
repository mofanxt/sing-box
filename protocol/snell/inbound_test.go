package snell

import (
	"context"
	"net"
	"testing"

	snellprotocol "github.com/mofanxt/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recordingRouter struct {
	adapter.ConnectionRouterEx
	last adapter.InboundContext
}

func (r *recordingRouter) RouteConnectionEx(_ context.Context, _ net.Conn, m adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.last = m
}
func TestFingerprintSource(t *testing.T) {
	r := new(recordingRouter)
	h := &Inbound{logger: logger.NOP(), router: r}
	outer := &snellprotocol.TCPFingerprint{Window: 100}
	inner := &snellprotocol.TCPFingerprint{Window: 200}
	physical := adapter.InboundContext{TCPFingerprint: outer}
	ctx := adapter.WithContext(context.Background(), &physical)
	for _, tc := range []struct {
		managed      bool
		sample, want *snellprotocol.TCPFingerprint
	}{
		{false, nil, outer}, {true, inner, inner}, {true, nil, nil}, {false, nil, outer},
	} {
		h.managedFingerprint = tc.managed
		h.NewConnectionEx(snellprotocol.ContextWithTCPFingerprint(ctx, tc.sample), nil, M.Socksaddr{}, M.Socksaddr{}, nil)
		got := r.last.TCPFingerprint
		if (got == nil) != (tc.want == nil) || (got != nil && got.Window != tc.want.Window) || r.last.TCPFingerprintAuthoritative != tc.managed {
			t.Fatalf("managed=%v sample=%v got=%v", tc.managed, tc.sample, got)
		}
	}
}
