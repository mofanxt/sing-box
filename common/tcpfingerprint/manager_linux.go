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

	nfqueue "github.com/florianl/go-nfqueue/v2"
	snell "github.com/mofanxt/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

func (m *Manager) start() error {
	if m.options.Rewrite {
		// 抽象 socket 随进程退出释放，覆盖 NFQUEUE 取消与 nft 清理之间的窗口。
		owner, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "@" + m.tableName(), Net: "unixgram"})
		if err != nil {
			return fmt.Errorf("claim fingerprint queue %d: %w", m.queue(), err)
		}
		m.closers = append(m.closers, owner.Close)
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
			for m.ctx.Err() == nil {
				n, _, err := unix.Recvfrom(fd, b, 0)
				if err != nil {
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
			var f *snell.TCPFingerprint
			if t := m.templates[*a.Mark]; t != nil {
				f = t.fingerprint
			}
			m.mu.Unlock()
			if f != nil {
				output, _ = Rewrite(*a.Payload, f)
			}
		}
		var verdictErr error
		if output != nil {
			verdictErr = q.SetVerdictWithOption(*a.PacketID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(output))
		} else {
			verdictErr = q.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		if verdictErr != nil {
			m.logger.Error("tcp fingerprint verdict: ", verdictErr)
			return 0
		}
		m.mu.Lock()
		if output != nil {
			m.rewritten++
		} else {
			m.skipped++
		}
		m.mu.Unlock()
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
	rules := fmt.Sprintf("create table inet %s\nadd chain inet %s post { type filter hook postrouting priority 110; policy accept; }\nadd rule inet %s post ip protocol tcp tcp flags & (syn | ack) == syn meta mark & 0x%x == 0x%x counter queue num %d bypass\n", m.tableName(), m.tableName(), m.tableName(), markMask, m.markPrefix(), m.options.Queue)
	cmd := exec.CommandContext(m.ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		// 已经独占此 netns 的 NFQUEUE。只接管与旧版完全匹配的遗留规则。
		if !m.ownsRules(m.ctx) {
			return fmt.Errorf("tcp fingerprint nft: %w: %s", err, out)
		}
	}
	m.closers = append(m.closers, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if !m.ownsRules(ctx) {
			return fmt.Errorf("tcp fingerprint: cannot verify table %s before cleanup", m.tableName())
		}
		return exec.CommandContext(ctx, "nft", "delete", "table", "inet", m.tableName()).Run()
	})
	m.logger.Info("tcp fingerprint: queue ready ", m.options.Queue)
	return nil
}

// 使用无计数值、数值优先级的输出。接受 nft 新旧两种 queue 拼写，
// 任意额外对象、链策略、匹配条件或 verdict 都不属于本实例。
func (m *Manager) ownsRules(ctx context.Context) bool {
	listed, err := exec.CommandContext(ctx, "nft", "-s", "-y", "list", "table", "inet", m.tableName()).Output()
	if err != nil {
		return false
	}
	actual := strings.Join(strings.Fields(string(listed)), " ")
	prefix := fmt.Sprintf("table inet %s { chain post { type filter hook postrouting priority 110; policy accept; ip protocol tcp tcp flags & (syn | ack) == syn meta mark & 0xffff0000 == 0x%08x counter queue ", m.tableName(), m.markPrefix())
	return actual == fmt.Sprintf("%sflags bypass to %d } }", prefix, m.queue()) ||
		actual == fmt.Sprintf("%snum %d bypass } }", prefix, m.queue())
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func (m *Manager) Control(f *snell.TCPFingerprint) (func(string, string, syscall.RawConn) error, func()) {
	if m == nil || !m.options.Rewrite || f == nil || f.Validate() != nil {
		return nil, nil
	}
	// 使用协商缩放能表示的最大窗口，保留 Linux 接收缓冲自动调优。
	var maxWindow int
	if ws := parseOptions(f.Options)[3]; ws != nil {
		maxWindow = 65535 << ws[2]
	}
	mark := m.templateMark(f)
	if mark == 0 {
		return nil, nil
	}
	return func(network, address string, raw syscall.RawConn) error {
		if strings.HasSuffix(network, "6") {
			return nil
		}
		var inner error
		err := raw.Control(func(fd uintptr) {
			if maxWindow != 0 {
				clamp, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP)
				if e == nil && (clamp == 0 || clamp > maxWindow) {
					e = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, maxWindow)
				}
				if e != nil {
					m.mu.Lock()
					m.skipped++
					m.mu.Unlock()
					return
				}
			}
			inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return inner
	}, func() { m.releaseMark(mark) }
}
