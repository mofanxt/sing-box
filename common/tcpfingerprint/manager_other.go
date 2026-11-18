//go:build !linux

package tcpfingerprint

import (
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"syscall"
)

func (m *Manager) start() error { return fmt.Errorf("TCP fingerprint capture/rewrite requires Linux") }
func (m *Manager) Control(*snell.TCPFingerprint) (func(string, string, syscall.RawConn) error, func()) {
	return nil, nil
}
