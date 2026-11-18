package tcpfingerprint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"

	snell "github.com/mofanxt/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
)

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ProxyHeader仅在显式配置的受管内部跳点使用，0xE0为应用私有TLV。
func ProxyHeader(source, destination M.Socksaddr, f *snell.TCPFingerprint) ([]byte, error) {
	source, destination = source.Unwrap(), destination.Unwrap()
	var family byte
	switch {
	case source.IsIPv4() && destination.IsIPv4():
		family = 0x11
	case source.IsIPv6() && destination.IsIPv6():
		family = 0x21
		f = nil
	default:
		return nil, fmt.Errorf("fingerprint proxy header requires IP endpoints of the same family")
	}
	b := make([]byte, 16, 52)
	copy(b, proxySignature)
	b[12], b[13] = 0x21, family
	b = append(b, source.Addr.AsSlice()...)
	b = append(b, destination.Addr.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, source.Port)
	b = binary.BigEndian.AppendUint16(b, destination.Port)
	if f != nil {
		data, err := f.MarshalBinary()
		if err != nil {
			return nil, err
		}
		// HAProxy的TLV格式器遇NUL截断，内部头使用有版本的ASCII编码。
		encoded := []byte("v1:" + hex.EncodeToString(data))
		b = append(b, 0xe0, byte(len(encoded)>>8), byte(len(encoded)))
		b = append(b, encoded...)
	}
	binary.BigEndian.PutUint16(b[14:16], uint16(len(b)-16))
	return b, nil
}

func ReadProxyHeader(r io.Reader) (source, destination M.Socksaddr, f *snell.TCPFingerprint, err error) {
	h := make([]byte, 16)
	if _, err = io.ReadFull(r, h); err != nil {
		return
	}
	if !bytes.Equal(h[:12], proxySignature) || h[12] != 0x21 || (h[13] != 0x11 && h[13] != 0x21) {
		err = fmt.Errorf("unsupported fingerprint proxy header")
		return
	}
	n := int(binary.BigEndian.Uint16(h[14:]))
	addressSize := 4
	if h[13] == 0x21 {
		addressSize = 16
	}
	ports := 2 * addressSize
	if n < ports+4 || n > 1024 {
		err = fmt.Errorf("fingerprint proxy header length out of bounds")
		return
	}
	b := make([]byte, n)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	src, _ := netip.AddrFromSlice(b[:addressSize])
	dst, _ := netip.AddrFromSlice(b[addressSize:ports])
	source = M.SocksaddrFrom(src, binary.BigEndian.Uint16(b[ports:]))
	destination = M.SocksaddrFrom(dst, binary.BigEndian.Uint16(b[ports+2:]))
	seenFingerprint := false
	for b = b[ports+4:]; len(b) > 0; {
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
			if seenFingerprint {
				err = fmt.Errorf("duplicate fingerprint proxy TLV")
				return
			}
			seenFingerprint = true
			// HAProxy转发缺失样本时生成空TLV，空值表示未采集到指纹。
			if n == 0 {
				continue
			}
			data := b[:n]
			if bytes.HasPrefix(data, []byte("v1:")) {
				if n > 95 {
					err = fmt.Errorf("oversized fingerprint TLV")
					return
				}
				data, err = hex.DecodeString(string(data[3:]))
				if err != nil {
					return
				}
			}
			f, err = snell.ParseTCPFingerprint(data)
			if err != nil {
				return
			}
		}
		b = b[n:]
	}
	if h[13] == 0x21 {
		f = nil
	}
	return
}
