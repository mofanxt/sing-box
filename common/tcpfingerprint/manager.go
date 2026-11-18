package tcpfingerprint

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	snell "github.com/mofanxt/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const markMask uint32 = 0xffff0000
const tableName = "sbox_tcp_fingerprint"

type entry struct {
	key         string
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

type template struct {
	fingerprint *snell.TCPFingerprint
	key         string
	dials       int
}

type Manager struct {
	order                                 list.List
	ctx                                   context.Context
	cancel                                context.CancelFunc
	options                               option.TCPFingerprintOptions
	logger                                logger.ContextLogger
	mu                                    sync.Mutex
	cache                                 map[string]*list.Element
	templates                             map[uint32]*template
	marks                                 map[string]uint32
	next                                  uint32
	closers                               []func() error
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
	return &Manager{ctx: ctx, cancel: cancel, options: options, logger: log, cache: make(map[string]*list.Element), templates: make(map[uint32]*template), marks: make(map[string]uint32)}, nil
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := m.start(); err != nil {
		return errors.Join(err, m.Close())
	}
	scope.Add(m.Close)
	return nil
}

func (m *Manager) Close() error {
	m.cancel()
	// 等读取协程退出后再释放 fd，避免描述符编号被复用。
	m.wg.Wait()
	var closeErr error
	for i := len(m.closers) - 1; i >= 0; i-- {
		closeErr = errors.Join(closeErr, m.closers[i]())
	}
	m.closers = nil
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger.Info("tcp fingerprint: captured=", m.captured, " matched=", m.matched, " rewritten=", m.rewritten, " skipped=", m.skipped)
	return closeErr
}

func (m *Manager) RewriteEnabled() bool { return m.options.Rewrite }

func cacheKey(s, d M.Socksaddr) string { return s.String() + "|" + d.String() }

func (m *Manager) remember(s, d M.Socksaddr, f *snell.TCPFingerprint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	key := cacheKey(s, d)
	if elem := m.cache[key]; elem != nil {
		m.order.Remove(elem)
	} else if len(m.cache) >= 8192 {
		oldest := m.order.Front()
		if now.Sub(oldest.Value.(entry).at) < 30*time.Second {
			m.skipped++
			return
		}
		delete(m.cache, oldest.Value.(entry).key)
		m.order.Remove(oldest)
	}
	m.cache[key] = m.order.PushBack(entry{key, now, f.Clone()})
	m.captured++
}

// Lookup只按完整原始四元组匹配；无法关联时不用来源IP猜测设备。
func (m *Manager) Lookup(s, d M.Socksaddr) *snell.TCPFingerprint {
	if m == nil || len(m.options.CaptureInterfaces) == 0 || !s.IsIPv4() || !d.IsIPv4() {
		return nil
	}
	for i := 0; i < 5; i++ {
		m.mu.Lock()
		elem, ok := m.cache[cacheKey(s, d)]
		if ok {
			delete(m.cache, cacheKey(s, d))
			m.order.Remove(elem)
			e := elem.Value.(entry)
			if time.Since(e.at) < 30*time.Second {
				m.matched++
				m.mu.Unlock()
				return e.fingerprint.Clone()
			}
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
	// 编码的前六字节为模板头。入口 MSS 不参与出口模板的身份判断。
	clear(parseOptions(b[6:])[2][2:])
	key := string(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if mark, ok := m.marks[key]; ok {
		m.templates[mark].dials++
		return mark
	}
	if len(m.templates) >= 256 {
		m.skipped++
		return 0
	}
	// 低16位循环分配，跳过仍有拨号或重传在使用的标记。
	var mark uint32
	for {
		m.next = m.next%65535 + 1
		mark = m.markPrefix() | m.next
		if m.templates[mark] == nil {
			break
		}
	}
	m.marks[key] = mark
	m.templates[mark] = &template{fingerprint: f.Clone(), key: key, dials: 1}
	return mark
}

func (m *Manager) releaseMark(mark uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.templates[mark]
	t.dials--
	if t.dials == 0 {
		delete(m.marks, t.key)
		delete(m.templates, mark)
	}
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

// captureOptions移除只对原服务器有效的TFO cookie；其余选项仍严格校验。
func captureOptions(raw []byte) ([]byte, bool, error) {
	out := make([]byte, 0, len(raw))
	tfo := false
	for i := 0; i < len(raw); {
		k := raw[i]
		if k == 0 {
			out = append(out, raw[i:]...)
			break
		}
		if k == 1 {
			out = append(out, k)
			i++
			continue
		}
		if i+2 > len(raw) || raw[i+1] < 2 || i+int(raw[i+1]) > len(raw) {
			return nil, false, fmt.Errorf("invalid TCP option length")
		}
		n := int(raw[i+1])
		if k == 34 {
			if tfo || (n != 2 && (n < 6 || n > 18 || n%2 != 0)) {
				return nil, false, fmt.Errorf("invalid TFO option")
			}
			tfo = true
		} else {
			out = append(out, raw[i:i+n]...)
		}
		i += n
	}
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out, tfo, nil
}

// FromIPv4接收普通SYN及RFC 3168的ECN协商SYN；ECN仍由出口内核协商。
func FromIPv4(p []byte) (*snell.TCPFingerprint, error) {
	if len(p) < 40 || p[0] != 0x45 || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&^uint16(0x4000) != 0 || (p[33] != 2 && p[33] != 0xc2) {
		return nil, fmt.Errorf("unsupported SYN")
	}
	n := int(p[32]>>4) * 4
	if n < 20 || n > 60 || len(p) < 20+n || int(binary.BigEndian.Uint16(p[2:4])) < 20+n {
		return nil, fmt.Errorf("SYN with payload or invalid length")
	}
	options, tfo, err := captureOptions(p[40 : 20+n])
	if err != nil {
		return nil, err
	}
	// 仅TFO连接允许初始数据；采集器只取首部，绝不传递或保存数据。
	if int(binary.BigEndian.Uint16(p[2:4])) != 20+n && !tfo {
		return nil, fmt.Errorf("SYN payload without TFO")
	}
	f := &snell.TCPFingerprint{Window: binary.BigEndian.Uint16(p[34:36]), ZeroIPID: binary.BigEndian.Uint16(p[4:6]) == 0, Options: options}
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

// Rewrite保留本次内核的序列号、时间戳及出口MSS；代理两侧独立协商路径限制。
func Rewrite(p []byte, f *snell.TCPFingerprint) ([]byte, error) {
	// 输出改写只处理无负载SYN，不能丢弃内核TFO中的真实应用数据。
	if len(p) < 40 || int(binary.BigEndian.Uint16(p[2:4])) != 20+int(p[32]>>4)*4 {
		return nil, fmt.Errorf("cannot rewrite SYN payload")
	}
	if _, err := FromIPv4(p); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	old := parseOptions(p[40 : 20+int(p[32]>>4)*4])
	opts := append([]byte(nil), f.Options...)
	desired := parseOptions(opts)
	if old[3] != nil && desired[3] == nil {
		return nil, fmt.Errorf("kernel window scale mismatch")
	}
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
			// MSS依赖本段路径，不能把手机到入口的隧道MTU当作出口路径限制。
			// 此值始终等于出口内核原值，绝不高于该socket的路径能力。
			copy(v[2:], u[2:])
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
	// 允许分片的出站保留本机 IPID，以免后续分片重组冲突。
	if f.ZeroIPID && p[6]&0x40 != 0 {
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
