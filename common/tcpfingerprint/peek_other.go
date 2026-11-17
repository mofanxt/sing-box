//go:build !linux

package tcpfingerprint

import (
	"fmt"
	"net"
)

func PeekProxyHeader(conn net.Conn) (bool, error) {
	return false, fmt.Errorf("optional proxy header requires Linux")
}
