//go:build !linux

package tcpfingerprint

import (
	"fmt"
	"syscall"

	snell "github.com/mofanxt/sing-snell"
)

func (m *Manager) start() error { return fmt.Errorf("TCP fingerprint capture/rewrite requires Linux") }
func (m *Manager) Control(*snell.TCPFingerprint) (func(string, string, syscall.RawConn) error, func()) {
	return nil, nil
}
