//go:build linux

package tcpfingerprint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// PeekProxyHeader不消费协议字节，避免旧SS2022服务将回放短读误判为坏头。
func PeekProxyHeader(conn net.Conn) (bool, error) {
	return peekProxyHeader(conn, 3*time.Second)
}

func peekProxyHeader(conn net.Conn, timeout time.Duration) (bool, error) {
	c, ok := conn.(syscall.Conn)
	if !ok {
		return false, fmt.Errorf("optional proxy header requires a raw TCP connection")
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	// 先借助 netpoll 等首字节。静默到期按原协议交回，保留其后才到的首包。
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}
	defer conn.SetReadDeadline(time.Time{})
	var deadline time.Time
	var prefix [12]byte
	for {
		var n int
		var readErr error
		if err = raw.Read(func(fd uintptr) bool {
			for {
				n, _, readErr = unix.Recvfrom(int(fd), prefix[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
				if readErr != unix.EINTR {
					return readErr != unix.EAGAIN
				}
			}
		}); err != nil {
			if deadline.IsZero() && errors.Is(err, os.ErrDeadlineExceeded) {
				return false, nil
			}
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
		if deadline.IsZero() {
			deadline = time.Now().Add(timeout)
			if err := conn.SetReadDeadline(deadline); err != nil {
				return false, err
			}
		}
		if time.Now().After(deadline) {
			return false, fmt.Errorf("optional proxy header timeout")
		}
		time.Sleep(time.Millisecond)
	}
}
