package tcpfingerprint

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	snell "github.com/sagernet/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
)

func linuxSYN() []byte {
	p := make([]byte, 60)
	p[0] = 0x45
	p[8] = 63
	p[9] = 6
	p[6] = 0x40
	p[32] = 0xa0
	p[33] = 2
	binary.BigEndian.PutUint16(p[2:4], 60)
	binary.BigEndian.PutUint16(p[34:36], 64240)
	copy(p[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	copy(p[40:], []byte{2, 4, 5, 180, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 6})
	return p
}

func appleFP() *snell.TCPFingerprint {
	return &snell.TCPFingerprint{TTL: 64, Window: 65535, ZeroIPID: true, Options: []byte{2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 0, 0}}
}

func TestCaptureAndRewrite(t *testing.T) {
	p := linuxSYN()
	f, err := FromIPv4(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.TTL != 64 {
		t.Fatal("TTL not normalized")
	}
	if binary.BigEndian.Uint32(parseOptions(f.Options)[8][2:]) != 0 {
		t.Fatal("raw timestamp retained")
	}
	out, err := Rewrite(p, appleFP())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 64 || out[32] != 0xb0 || binary.BigEndian.Uint16(out[34:36]) != 65535 {
		t.Fatal("shape mismatch")
	}
	if checksum(out[:20]) != 0 {
		t.Fatal("IP checksum invalid")
	}
	pseudo := make([]byte, 12)
	copy(pseudo, out[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], 44)
	if checksum(pseudo, out[20:]) != 0 {
		t.Fatal("TCP checksum invalid")
	}
	if binary.BigEndian.Uint32(parseOptions(out[40:])[8][2:]) != 0x01020304 {
		t.Fatal("kernel timestamp lost")
	}
	if binary.BigEndian.Uint16(p[34:36]) != 64240 {
		t.Fatal("original mutated")
	}
	p = linuxSYN()
	p[43] = 120
	out, err = Rewrite(p, appleFP())
	if err != nil || binary.BigEndian.Uint16(out[42:44]) != 1400 {
		t.Fatal("MSS increased")
	}
	p = linuxSYN()
	p[59] = 7
	if _, err = Rewrite(p, appleFP()); err == nil {
		t.Fatal("accepted kernel window mismatch")
	}
	p = linuxSYN()
	p[33] |= 0xc0
	if _, err = FromIPv4(p); err == nil {
		t.Fatal("ECN unsupported case accepted")
	}
}

func TestCacheIsolationAndBounds(t *testing.T) {
	m := &Manager{cache: make(map[string]entry), templates: make(map[uint32]*snell.TCPFingerprint), marks: make(map[string]uint32)}
	s := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 12345)
	d := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.2"), 443)
	m.remember(s, d, appleFP())
	if len(m.cache) != 1 {
		t.Fatal("missing sample")
	}
	other := d
	other.Port = 80
	if _, ok := m.cache[cacheKey(s, other)]; ok {
		t.Fatal("cross destination collision")
	}
	for i := 0; i < 256; i++ {
		f := appleFP()
		f.Window = uint16(i + 1)
		if m.templateMark(f) == 0 {
			t.Fatal("premature table full")
		}
	}
	f := appleFP()
	f.Window = 1000
	if m.templateMark(f) != 0 {
		t.Fatal("unbounded template table")
	}
	if m.templateMark(appleFP()) != 0 { /* 表满时未知模板按设计跳过 */
	}
	m.cache[cacheKey(s, d)] = entry{time.Now().Add(-time.Minute), appleFP()}
	for i := 0; i < 8192; i++ {
		m.cache[string(rune(i))] = entry{time.Now(), appleFP()}
	}
	m.remember(s, d, appleFP())
	if len(m.cache) > 8192 {
		t.Fatal("unbounded capture cache")
	}
}

func FuzzCapture(f *testing.F) {
	f.Add(linuxSYN())
	f.Fuzz(func(t *testing.T, p []byte) {
		sample, err := FromIPv4(p)
		if err == nil {
			if sample.Validate() != nil {
				t.Fatal("invalid sample")
			}
			_, _ = Rewrite(p, sample)
		}
	})
}

func TestQueueIsolation(t *testing.T) {
	newManager := func(queue uint16) *Manager {
		return &Manager{options: option.TCPFingerprintOptions{Queue: queue}, templates: make(map[uint32]*snell.TCPFingerprint), marks: make(map[string]uint32)}
	}
	a, b := newManager(19518), newManager(19519)
	if a.tableName() == b.tableName() || a.templateMark(appleFP()) == b.templateMark(appleFP()) {
		t.Fatal("independent cores share packet ownership")
	}
	if a.markPrefix()&markMask == b.markPrefix()&markMask {
		t.Fatal("queue marks overlap")
	}
}
