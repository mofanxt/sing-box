//go:build linux

package tcpfingerprint

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	snell "github.com/sagernet/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func (m *Manager) start() error {
	if m.options.Rewrite {
		if err := m.calibrateWindowBuffers(); err != nil {
			return err
		}
	}
	for _, name := range m.options.CaptureInterfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
		if err != nil {
			return err
		}
		m.closers = append(m.closers, func() error { return unix.Close(fd) })
		if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(unix.ETH_P_IP)}); err != nil {
			return err
		}
		// 内核只上送IPv4 SYN，避免每个业务数据包进入用户态。
		filter := []unix.SockFilter{{Code: 0x28, K: 12}, {Code: 0x15, Jt: 0, Jf: 7, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jt: 0, Jf: 5, K: 6}, {Code: 0xb1, K: 14}, {Code: 0x50, K: 27}, {Code: 0x54, K: 0x12}, {Code: 0x15, Jt: 0, Jf: 1, K: 2}, {Code: 0x06, K: 128}, {Code: 0x06, K: 0}}
		if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
			return err
		}
		if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000}); err != nil {
			return err
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			b := make([]byte, 128)
			for {
				n, _, err := unix.Recvfrom(fd, b, 0)
				if err != nil {
					select {
					case <-m.ctx.Done():
						return
					default:
					}
					if err == unix.EAGAIN || err == unix.EINTR {
						continue
					}
					return
				}
				if n < 54 {
					continue
				}
				p := b[14:n]
				f, err := FromIPv4(p)
				if err != nil {
					continue
				}
				s := M.SocksaddrFrom(netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(p[20:22]))
				d := M.SocksaddrFrom(netip.AddrFrom4([4]byte(p[16:20])), binary.BigEndian.Uint16(p[22:24]))
				m.remember(s, d, f)
			}
		}()
	}
	if !m.options.Rewrite {
		return nil
	}
	q, err := nfqueue.Open(&nfqueue.Config{NfQueue: m.options.Queue, AfFamily: unix.AF_INET, MaxPacketLen: 65531, MaxQueueLen: 4096, Copymode: nfqueue.NfQnlCopyPacket, Flags: nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO, WriteTimeout: time.Second})
	if err != nil {
		return err
	}
	m.closers = append(m.closers, q.Close)
	err = q.RegisterWithErrorFunc(m.ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		var output []byte
		if a.Mark != nil && a.Payload != nil && (a.CapLen == nil || int(*a.CapLen) == len(*a.Payload)) {
			m.mu.Lock()
			f := m.templates[*a.Mark].Clone()
			m.mu.Unlock()
			if f != nil {
				output, _ = Rewrite(*a.Payload, f)
			}
		}
		m.mu.Lock()
		if output != nil {
			m.rewritten++
		} else {
			m.skipped++
		}
		m.mu.Unlock()
		var verdictErr error
		if output != nil {
			verdictErr = q.SetVerdictWithOption(*a.PacketID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(output))
		} else {
			verdictErr = q.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		if verdictErr != nil {
			m.logger.Error("tcp fingerprint verdict: ", verdictErr)
		}
		return 0
	}, func(err error) int {
		if m.ctx.Err() == nil {
			m.logger.Error("tcp fingerprint queue: ", err)
		}
		return 0
	})
	if err != nil {
		return err
	}
	rules := fmt.Sprintf("create table inet %s\nadd chain inet %s post { type filter hook postrouting priority 110; policy accept; }\nadd rule inet %s post ip protocol tcp tcp flags & (syn | ack) == syn meta mark & 0x%x == 0x%x counter queue num %d bypass\n", tableName, tableName, tableName, markMask, markPrefix, m.options.Queue)
	cmd := exec.CommandContext(m.ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tcp fingerprint nft: %w: %s", err, out)
	}
	m.rulesOwned = true
	m.closers = append(m.closers, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableName).Run()
	})
	m.logger.Info("tcp fingerprint: queue ready ", m.options.Queue)
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (m *Manager) Control(f *snell.TCPFingerprint) func(string, string, syscall.RawConn) error {
	if m == nil || !m.options.Rewrite || f == nil || f.Validate() != nil {
		return nil
	}
	opts := parseOptions(f.Options)
	var scale byte
	if ws := opts[3]; ws != nil {
		scale = ws[2]
	}
	// 使用本机握手校准值，避免不同tcp_rmem下缓冲大小与缩放比例不一致。
	requested, ok := m.windowBuffers[scale]
	if !ok {
		m.mu.Lock()
		m.skipped++
		m.mu.Unlock()
		return nil
	}
	mark := m.templateMark(f)
	if mark == 0 {
		return nil
	}
	return func(network, address string, raw syscall.RawConn) error {
		if strings.HasSuffix(network, "6") {
			return nil
		}
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, requested)
			if inner != nil {
				return
			}
			actual, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			if e != nil {
				inner = e
				return
			}
			// 小缓冲转发机使用逐socket权限接口，避免修改整机rmem_max。
			if actual < requested*2 {
				inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, requested)
				if inner != nil {
					return
				}
			}
			inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return inner
	}
}

// 启动时仅连接本机回环，最多申请16MiB的逐socket缓冲；不修改全局sysctl。
func (m *Manager) calibrateWindowBuffers() error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("calibrate TCP window: %w", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	m.windowBuffers = make(map[byte]int)
	for requested := 1 << 15; requested <= 1<<24; requested <<= 1 {
		d := net.Dialer{Timeout: time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var setErr error
			if err := raw.Control(func(fd uintptr) {
				setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, requested)
			}); err != nil {
				return err
			}
			return setErr
		}}
		conn, err := d.DialContext(m.ctx, "tcp4", listener.Addr().String())
		if err != nil {
			return fmt.Errorf("calibrate TCP window: %w", err)
		}
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			conn.Close()
			return err
		}
		var info *unix.TCPInfo
		var infoErr error
		err = raw.Control(func(fd uintptr) { info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
		conn.Close()
		if err != nil {
			return err
		}
		if infoErr != nil {
			return infoErr
		}
		// TCP_INFO的第6字节为内核位域，x/sys结构体没有公开该字段。
		bits := (*[8]byte)(unsafe.Pointer(info))[6]
		scale := bits >> 4
		if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
			scale = bits & 15
		}
		if _, exists := m.windowBuffers[scale]; !exists {
			m.windowBuffers[scale] = requested
		}
	}
	m.logger.Info("tcp fingerprint: calibrated window scales ", fmt.Sprint(m.windowBuffers))
	return nil
}
