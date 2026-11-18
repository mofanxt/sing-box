package listener

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRawListenerRejectsFingerprintOptions(t *testing.T) {
	for _, o := range []option.ListenOptions{{FingerprintOriginalDestination: true}, {FingerprintProxyProtocol: &option.FingerprintProxyProtocolOptions{TrustedSources: []string{"127.0.0.1/32"}}}} {
		l := New(Options{Listen: o})
		if conn, err := l.ListenTCP(); err == nil {
			conn.Close()
			t.Fatal("unmanaged listener accepted fingerprint options")
		}
	}
}
