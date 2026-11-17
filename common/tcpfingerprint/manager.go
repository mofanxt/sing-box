package tcpfingerprint

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const markMask uint32 = 0xffff0000
const tableName = "sbox_tcp_fingerprint"

type entry struct {
	at          time.Time
	fingerprint *snell.TCPFingerprint
}

// 同一网络命名空间的多个核心用不同队列隔离模板、socket标记和规则表。
func (m *Manager) queue() uint16 {
	if m.options.Queue == 0 {
		return 19518
	}
	return m.options.Queue
}
func (m *Manager) markPrefix() uint32 { return uint32(m.queue()) << 16 }
func (m *Manager) tableName() string  { return fmt.Sprintf("%s_%d", tableName, m.queue()) }

func (m *Manager) Name() string { return "tcp-fingerprint" }

type Manager struct {
	ctx                                   context.Context
	cancel                                context.CancelFunc
	options                               option.TCPFingerprintOptions
	logger                                logger.ContextLogger
	mu                                    sync.Mutex
	cache                                 map[string]entry
	templates                             map[uint32]*snell.TCPFingerprint
	marks                                 map[string]uint32
	windowBuffers                         map[byte]int
	next                                  uint32
	closers                               []func() error
	rulesOwned                            bool
	wg                                    sync.WaitGroup
	captured, matched, rewritten, skipped uint64
}

func New(ctx context.Context, options option.TCPFingerprintOptions, log logger.ContextLogger) (*Manager, error) {
	if len(options.CaptureInterfaces) == 0 && !options.Rewrite {
		return nil, fmt.Errorf("tcp fingerprint: neither capture nor rewrite enabled")
	}
	if options.Queue == 0 {
		options.Queue = 19518
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{ctx: ctx, cancel: cancel, options: options, logger: log, cache: make(map[string]entry), templates: make(map[uint32]*snell.TCPFingerprint), marks: make(map[string]uint32)}, nil
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := m.start(); err != nil {
		m.Close()
		return err
	}
	scope.Add(m.Close)
	return nil
}

func (m *Manager) Close() error {
	m.cancel()
	for i := len(m.closers) - 1; i >= 0; i-- {
		_ = m.closers[i]()
	}
	m.closers = nil
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger.Info("tcp fingerprint: captured=", m.captured, " matched=", m.matched, " rewritten=", m.rewritten, " skipped=", m.skipped)
	return nil
}

func (m *Manager) RewriteEnabled() bool { return m.options.Rewrite }

func cacheKey(s, d M.Socksaddr) string { return s.String() + "|" + d.String() }

func (m *Manager) remember(s, d M.Socksaddr, f *snell.TCPFingerprint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if len(m.cache) >= 8192 {
		for k, e := range m.cache {
			if now.Sub(e.at) > 30*time.Second {
				delete(m.cache, k)
			}
		}
		if len(m.cache) >= 8192 {
			m.skipped++
			return
		}
	}
	m.cache[cacheKey(s, d)] = entry{now, f.Clone()}
	m.captured++
}

// Lookup只按完整原始四元组匹配；无法关联时不用来源IP猜测设备。
func (m *Manager) Lookup(s, d M.Socksaddr) *snell.TCPFingerprint {
	if m == nil || len(m.options.CaptureInterfaces) == 0 || !s.IsIPv4() || !d.IsIPv4() {
		return nil
	}
	for i := 0; i < 5; i++ {
		m.mu.Lock()
		e, ok := m.cache[cacheKey(s, d)]
		if ok {
			delete(m.cache, cacheKey(s, d))
		}
		if ok && time.Since(e.at) < 30*time.Second {
			m.matched++
			m.mu.Unlock()
			return e.fingerprint.Clone()
		}
		m.mu.Unlock()
		select {
		case <-m.ctx.Done():
			return nil
		case <-time.After(time.Millisecond):
		}
	}
	return nil
}

func (m *Manager) templateMark(f *snell.TCPFingerprint) uint32 {
	b, err := f.MarshalBinary()
	if err != nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if mark, ok := m.marks[string(b)]; ok {
		return mark
	}
	if len(m.templates) >= 256 {
		m.skipped++
		return 0
	}
	m.next++
	mark := m.markPrefix() | m.next
	m.marks[string(b)] = mark
	m.templates[mark] = f.Clone()
	return mark
}

func parseOptions(b []byte) map[byte][]byte {
	result := make(map[byte][]byte)
	for i := 0; i < len(b); {
		if b[i] == 0 {
			break
		}
		if b[i] == 1 {
			i++
			continue
		}
		if i+2 > len(b) || b[i+1] < 2 || i+int(b[i+1]) > len(b) {
			return nil
		}
		if _, exists := result[b[i]]; exists {
			return nil
		}
		result[b[i]] = b[i : i+int(b[i+1])]
		i += int(b[i+1])
	}
	return result
}

// FromIPv4接收普通SYN及RFC 3168的ECN协商SYN；ECN仍由出口内核协商。
func FromIPv4(p []byte) (*snell.TCPFingerprint, error) {
	if len(p) < 40 || p[0] != 0x45 || p[9] != 6 || binary.BigEndian.Uint16(p[6:8]) != 0x4000 || (p[33] != 2 && p[33] != 0xc2) {
		return nil, fmt.Errorf("unsupported SYN")
	}
	n := int(p[32]>>4) * 4
	if n < 20 || n > 60 || len(p) < 20+n || int(binary.BigEndian.Uint16(p[2:4])) != 20+n {
		return nil, fmt.Errorf("SYN with payload or invalid length")
	}
	f := &snell.TCPFingerprint{Window: binary.BigEndian.Uint16(p[34:36]), ZeroIPID: binary.BigEndian.Uint16(p[4:6]) == 0, Options: append([]byte(nil), p[40:20+n]...)}
	for _, ttl := range []byte{32, 64, 128, 255} {
		if p[8] <= ttl {
			f.TTL = ttl
			break
		}
	}
	opts := parseOptions(f.Options)
	if opts == nil {
		return nil, fmt.Errorf("invalid options")
	}
	if ts := opts[8]; len(ts) == 10 {
		clear(ts[2:])
	}
	return f, f.Validate()
}

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, b := range parts {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Rewrite保留本次内核生成的序列号和时间戳，且不扩大原始MSS。
func Rewrite(p []byte, f *snell.TCPFingerprint) ([]byte, error) {
	if _, err := FromIPv4(p); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	old := parseOptions(p[40 : 20+int(p[32]>>4)*4])
	opts := append([]byte(nil), f.Options...)
	desired := parseOptions(opts)
	for _, k := range []byte{2, 3, 4, 8} {
		v, ok := desired[k]
		if !ok {
			continue
		}
		u, available := old[k]
		if !available || len(v) != len(u) {
			return nil, fmt.Errorf("kernel did not offer option %d", k)
		}
		switch k {
		case 2:
			if binary.BigEndian.Uint16(v[2:]) > binary.BigEndian.Uint16(u[2:]) {
				copy(v[2:], u[2:])
			}
		case 3:
			if v[2] != u[2] {
				return nil, fmt.Errorf("kernel window scale mismatch")
			}
		case 8:
			copy(v[2:6], u[2:6])
			clear(v[6:])
		}
	}
	out := make([]byte, 40+len(opts))
	copy(out, p[:40])
	copy(out[40:], opts)
	out[8] = f.TTL
	if f.ZeroIPID {
		out[4], out[5] = 0, 0
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[10], out[11] = 0, 0
	out[32] = (byte((20+len(opts))/4) << 4) | (out[32] & 15)
	binary.BigEndian.PutUint16(out[34:36], f.Window)
	out[36], out[37] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	pseudo := make([]byte, 12)
	copy(pseudo, out[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(out)-20))
	binary.BigEndian.PutUint16(out[36:38], checksum(pseudo, out[20:]))
	return out, nil
}
