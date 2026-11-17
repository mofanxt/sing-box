package tcpfingerprint

import (
	"bytes"
	M "github.com/sagernet/sing/common/metadata"
	"reflect"
	"testing"
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
