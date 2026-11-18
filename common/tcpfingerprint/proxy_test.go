package tcpfingerprint

import (
	"bytes"
	"reflect"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestProxyHeaderIsolation(t *testing.T) {
	s, d := M.ParseSocksaddr("192.0.2.1:1234"), M.ParseSocksaddr("192.0.2.2:443")
	b, err := ProxyHeader(s, d, appleFP())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("encrypted-application-data")
	r := bytes.NewReader(append(append([]byte{}, b...), payload...))
	gotS, gotD, gotF, err := ReadProxyHeader(r)
	if err != nil || gotS != s || gotD != d || !reflect.DeepEqual(gotF, appleFP()) {
		t.Fatalf("bad proxy header: %v", err)
	}
	left := make([]byte, r.Len())
	r.Read(left)
	if !bytes.Equal(left, payload) {
		t.Fatal("header consumed application data")
	}
	for i := 0; i < len(b); i++ {
		if _, _, _, err = ReadProxyHeader(bytes.NewReader(b[:i])); err == nil {
			t.Fatalf("accepted truncated proxy header %d", i)
		}
	}
	b[14], b[15] = 255, 255
	if _, _, _, err = ReadProxyHeader(bytes.NewReader(b)); err == nil {
		t.Fatal("accepted oversized header")
	}
}

// HAProxy为未采集到样本的连接输出空TLV，不能拒绝正常旧客户端。
func TestEmptyProxyFingerprint(t *testing.T) {
	s, d := M.ParseSocksaddr("192.0.2.1:1234"), M.ParseSocksaddr("192.0.2.2:443")
	b, err := ProxyHeader(s, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, 0xe0, 0, 0)
	b[15] += 3
	_, _, f, err := ReadProxyHeader(bytes.NewReader(b))
	if err != nil || f != nil {
		t.Fatalf("missing sample rejected: %v", err)
	}
	b = append(b, 0xe0, 0, 0)
	b[15] += 3
	if _, _, _, err = ReadProxyHeader(bytes.NewReader(b)); err == nil {
		t.Fatal("duplicate empty TLV accepted")
	}
}

func TestProxyIPv6WithoutFingerprint(t *testing.T) {
	s, d := M.ParseSocksaddr("[2001:db8::1]:3456"), M.ParseSocksaddr("[2001:db8::2]:443")
	b, err := ProxyHeader(s, d, appleFP())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 52 || b[13] != 0x21 {
		t.Fatalf("invalid INET6 header %x", b)
	}
	r := bytes.NewReader(append(b, 42))
	src, dst, f, err := ReadProxyHeader(r)
	if err != nil || src != s || dst != d || f != nil || r.Len() != 1 {
		t.Fatalf("IPv6 round trip %v %v %v %v", src, dst, f, err)
	}
	for _, n := range []int{0, 12, 35} {
		b[15] = byte(n)
		if _, _, _, err = ReadProxyHeader(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted %d-byte IPv6 header", n)
		}
	}
}
