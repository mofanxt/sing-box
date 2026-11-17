package tcpfingerprint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	snell "github.com/sagernet/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
)

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ProxyHeader仅在显式配置的受管内部跳点使用，0xE0为应用私有TLV。
func ProxyHeader(source, destination M.Socksaddr, f *snell.TCPFingerprint) ([]byte, error) {
	if !source.IsIPv4() || !destination.IsIPv4() {
		return nil, fmt.Errorf("fingerprint proxy header requires IPv4 endpoints")
	}
	b := make([]byte, 28)
	copy(b, proxySignature)
	b[12] = 0x21
	b[13] = 0x11
	copy(b[16:20], source.Addr.AsSlice())
	copy(b[20:24], destination.Addr.AsSlice())
	binary.BigEndian.PutUint16(b[24:26], source.Port)
	binary.BigEndian.PutUint16(b[26:28], destination.Port)
	if f != nil {
		data, err := f.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, 0xe0, byte(len(data)>>8), byte(len(data)))
		b = append(b, data...)
	}
	binary.BigEndian.PutUint16(b[14:16], uint16(len(b)-16))
	return b, nil
}

func ReadProxyHeader(r io.Reader) (source, destination M.Socksaddr, f *snell.TCPFingerprint, err error) {
	h := make([]byte, 16)
	if _, err = io.ReadFull(r, h); err != nil {
		return
	}
	if !bytes.Equal(h[:12], proxySignature) || h[12] != 0x21 || h[13] != 0x11 {
		err = fmt.Errorf("unsupported fingerprint proxy header")
		return
	}
	n := int(binary.BigEndian.Uint16(h[14:]))
	if n < 12 || n > 1024 {
		err = fmt.Errorf("fingerprint proxy header length out of bounds")
		return
	}
	b := make([]byte, n)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	source = M.SocksaddrFrom(netip.AddrFrom4([4]byte(b[:4])), binary.BigEndian.Uint16(b[8:10]))
	destination = M.SocksaddrFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[10:12]))
	for b = b[12:]; len(b) > 0; {
		if len(b) < 3 {
			err = io.ErrUnexpectedEOF
			return
		}
		kind := b[0]
		n = int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if n > len(b) {
			err = io.ErrUnexpectedEOF
			return
		}
		if kind == 0xe0 {
			if f != nil {
				err = fmt.Errorf("duplicate fingerprint proxy TLV")
				return
			}
			f, err = snell.ParseTCPFingerprint(b[:n])
			if err != nil {
				return
			}
		}
		b = b[n:]
	}
	return
}
