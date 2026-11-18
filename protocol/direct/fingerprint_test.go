package direct_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func TestFingerprintBridgeNetworks(t *testing.T) {
	b, err := box.New(box.Options{Context: include.Context(context.Background()), Options: option.Options{
		Outbounds: []option.Outbound{{Type: "direct", Tag: "bridge", Options: &option.DirectOutboundOptions{FingerprintProxyProtocol: true}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	o, ok := b.Outbound().Outbound("bridge")
	if !ok || !slices.Equal(o.Network(), []string{N.NetworkTCP}) {
		t.Fatal("unexpected bridge networks")
	}
	f := o.(adapter.FlowOutbound)
	for _, network := range []string{N.NetworkUDP, N.NetworkICMP} {
		if f.PreMatchFlow(network, netip.MustParseAddr("127.0.0.1")) != adapter.PreMatchReject {
			t.Fatal("accepted", network)
		}
	}
}
