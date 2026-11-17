//go:build linux

package tcpfingerprint

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"syscall"
	"time"
)

// PeekProxyHeader不消费协议字节，避免旧SS2022服务将回放短读误判为坏头。
func PeekProxyHeader(conn net.Conn) (bool, error) {
	c, ok := conn.(syscall.Conn)
	if !ok {
		return false, fmt.Errorf("optional proxy header requires a raw TCP connection")
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	deadline := time.Now().Add(3 * time.Second)
	var prefix [12]byte
	for {
		var n int
		var readErr error
		if err = raw.Control(func(fd uintptr) { n, _, readErr = unix.Recvfrom(int(fd), prefix[:], unix.MSG_PEEK|unix.MSG_DONTWAIT) }); err != nil {
			return false, err
		}
		if readErr == nil {
			if n == 0 {
				return false, io.EOF
			}
			if !bytes.Equal(prefix[:n], proxySignature[:n]) {
				return false, nil
			}
			if n == len(prefix) {
				return true, nil
			}
		} else if readErr != unix.EAGAIN && readErr != unix.EINTR {
			return false, readErr
		}
		if time.Now().After(deadline) {
			return false, fmt.Errorf("optional proxy header timeout")
		}
		time.Sleep(time.Millisecond)
	}
}
