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
	if _, err = FromIPv4(p); err != nil {
		t.Fatal("ECN SYN should retain its fingerprint:", err)
	}
	out, err = Rewrite(p, appleFP())
	if err != nil || out[33] != 0xc2 {
		t.Fatal("rewrite must preserve kernel ECN negotiation flags")
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

// 来自6001真实iPhone的SYN形状：64字节、DF、零IPID、ECN和Apple选项。
func TestIPhoneECNCapture(t *testing.T) {
	p := make([]byte, 64)
	p[0], p[6], p[8], p[9], p[32], p[33] = 0x45, 0x40, 64, 6, 0xb0, 0xc2
	binary.BigEndian.PutUint16(p[2:4], 64)
	binary.BigEndian.PutUint16(p[34:36], 65535)
	copy(p[40:], []byte{2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 0x8a, 0xb5, 0xa9, 0x89, 0, 0, 0, 0, 4, 2, 0, 0})
	fp, err := FromIPv4(p)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Window != 65535 || fp.TTL != 64 || !fp.ZeroIPID || parseOptions(fp.Options)[3][2] != 6 {
		t.Fatal("iPhone shape lost")
	}
	encoded, err := fp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("empty metadata")
	}
	for _, flags := range []byte{0x12, 0x42, 0x82, 0x03, 0x06, 0x22} {
		p[33] = flags
		if _, err = FromIPv4(p); err == nil {
			t.Fatalf("accepted unsupported flags %x", flags)
		}
	}
}

// Shadowrocket的外层连接携带TFO请求，不能因私有cookie而丢弃整份设备特征。
func TestShadowrocketTFOCapture(t *testing.T) {
	for _, cookie := range []int{0, 4, 16} {
		options := append([]byte(nil), appleFP().Options[:22]...)
		options = append(options, 34, byte(cookie+2))
		for i := 0; i < cookie; i++ {
			options = append(options, 0xab)
		}
		for len(options)%4 != 0 {
			options = append(options, 0)
		}
		p := make([]byte, 40+len(options))
		copy(p, linuxSYN()[:40])
		p[8] = 251
		p[32] = byte((20+len(options))/4) << 4
		p[33] = 0xc2
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		binary.BigEndian.PutUint16(p[34:36], 65535)
		copy(p[40:], options)
		f, err := FromIPv4(p)
		if err != nil {
			t.Fatal(err)
		}
		if f.TTL != 255 || f.Window != 65535 || parseOptions(f.Options)[3][2] != 6 || len(f.Options) != 24 {
			t.Fatal("outer fingerprint lost")
		}
		if _, exists := parseOptions(f.Options)[34]; exists {
			t.Fatal("server-specific cookie leaked")
		}
		encoded, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = snell.ParseTCPFingerprint(encoded); err != nil {
			t.Fatal(err)
		}
		// 抓包只保存首部；即使TFO已经发送数据也仍能采集，但出口改写必须拒绝。
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+20))
		if _, err = FromIPv4(p); err != nil {
			t.Fatal("TFO data header capture failed", err)
		}
		if _, err = Rewrite(p, f); err == nil {
			t.Fatal("rewrite accepted application payload")
		}
	}
	for _, n := range []byte{3, 4, 5, 7, 19} {
		if _, _, err := captureOptions([]byte{34, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
			t.Fatalf("accepted invalid TFO length %d", n)
		}
	}
}
