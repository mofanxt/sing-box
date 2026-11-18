package dialer

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/tcpfingerprint"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRouteStrategyConflictsWithFingerprint(t *testing.T) {
	d := DefaultDialer{fingerprint: new(tcpfingerprint.Manager)}
	strategy := C.NetworkStrategyDefault
	_, err := d.DialParallelInterface(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:1"), &strategy, nil, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "network_strategy") {
		t.Fatalf("expected strategy conflict: %v", err)
	}
}
