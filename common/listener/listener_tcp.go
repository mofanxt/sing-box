package listener

import (
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/redir"
	"github.com/sagernet/sing-box/common/tcpfingerprint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/database64128/tfo-go/v2"
)

func (l *Listener) ListenTCP() (net.Listener, error) {
	if cfg := l.listenOptions.FingerprintProxyProtocol; cfg != nil {
		if len(cfg.TrustedSources) == 0 {
			return nil, E.New("fingerprint proxy requires trusted_sources")
		}
		for _, s := range cfg.TrustedSources {
			if _, err := netip.ParsePrefix(s); err != nil {
				return nil, err
			}
		}
	}
	//nolint:staticcheck
	if l.listenOptions.ProxyProtocol || l.listenOptions.ProxyProtocolAcceptNoHeader {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	var err error
	bindAddr := M.SocksaddrFrom(l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), l.listenOptions.ListenPort)
	var (
		listenConfig    net.ListenConfig
		followInterface func(conn syscall.Conn)
	)
	if l.listenOptions.BindInterface != "" {
		var bindFunc control.Func
		bindFunc, followInterface = l.followBindInterface()
		listenConfig.Control = control.Append(listenConfig.Control, bindFunc)
	}
	if l.listenOptions.RoutingMark != 0 {
		listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
	}
	if l.listenOptions.ReuseAddr {
		listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	}
	if l.listenOptions.DisableTCPKeepAlive {
		listenConfig.KeepAlive = -1
		listenConfig.KeepAliveConfig.Enable = false
	} else {
		keepIdle := time.Duration(l.listenOptions.TCPKeepAlive)
		if keepIdle == 0 {
			keepIdle = C.TCPKeepAliveInitial
		}
		keepInterval := time.Duration(l.listenOptions.TCPKeepAliveInterval)
		if keepInterval == 0 {
			keepInterval = C.TCPKeepAliveInterval
		}
		listenConfig.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepIdle,
			Interval: keepInterval,
		}
	}
	if l.listenOptions.TCPMultiPath {
		listenConfig.SetMultipathTCP(true)
	}
	if l.tproxy {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return redir.TProxy(fd, !strings.HasSuffix(network, "4"), false)
			})
		})
	}
	tcpListener, err := ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		if l.listenOptions.TCPFastOpen {
			var tfoConfig tfo.ListenConfig
			tfoConfig.ListenConfig = listenConfig
			return tfoConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		} else {
			return listenConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		}
	})
	if err != nil {
		return nil, err
	}
	if followInterface != nil {
		followInterface(tcpListener.(syscall.Conn))
	}
	l.logger.Info("tcp server started at ", tcpListener.Addr())
	l.tcpListener = tcpListener
	return tcpListener, err
}

func (l *Listener) loopTCPIn() {
	tcpListener := l.tcpListener
	var (
		metadata    adapter.InboundContext
		acceptDelay time.Duration
	)
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay = min(2*acceptDelay, time.Second)
				}
				l.logger.Error(err, ", retrying in ", acceptDelay)
				time.Sleep(acceptDelay)
				continue
			}
			l.tcpListener.Close()
			l.logger.Error("tcp listener closed: ", err)
			return
		}
		acceptDelay = 0
		//nolint:staticcheck
		metadata.InboundDetour = l.listenOptions.Detour
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
		go l.handleFingerprintConnection(conn, metadata)

	}
}

// 元数据头在独立连接协程读取，慢连接不会阻塞监听器接受下一条连接。
func (l *Listener) handleFingerprintConnection(conn net.Conn, metadata adapter.InboundContext) {
	metadata.TCPFingerprint = nil
	if l.listenOptions.FingerprintOriginalDestination {
		// DNAT入口用conntrack原始目标关联网卡上改写前的SYN，不按来源IP猜测。
		if original, err := control.GetOriginalDestination(conn); err == nil && original.IsValid() {
			metadata.OriginDestination = M.SocksaddrFromNetIP(original)
		}
	}
	if cfg := l.listenOptions.FingerprintProxyProtocol; cfg != nil {
		realSource := metadata.Source.Addr
		trusted := false
		for _, s := range cfg.TrustedSources {
			p, _ := netip.ParsePrefix(s)
			if p.Contains(realSource) {
				trusted = true
				break
			}
		}
		if !trusted && !cfg.Optional {
			conn.Close()
			return
		}
		if trusted {
			hasHeader := true
			if cfg.Optional {
				var err error
				hasHeader, err = tcpfingerprint.PeekProxyHeader(conn)
				if err != nil {
					conn.Close()
					return
				}
			}
			if hasHeader {
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				source, destination, f, err := tcpfingerprint.ReadProxyHeader(conn)
				if err != nil {
					conn.Close()
					l.logger.Debug("invalid fingerprint proxy header: ", err)
					return
				}
				metadata.Source = source
				metadata.OriginDestination = destination
				metadata.TCPFingerprint = f
			}
			conn.SetReadDeadline(time.Time{})
		}
	}
	if metadata.TCPFingerprint == nil {
		if manager := service.FromContext[*tcpfingerprint.Manager](l.ctx); manager != nil {
			metadata.TCPFingerprint = manager.Lookup(metadata.Source, metadata.OriginDestination)
		}
	}
	ctx := log.ContextWithNewID(l.ctx)
	if metadata.TCPFingerprint != nil {
		ctx = adapter.WithContext(ctx, &metadata)
	}
	l.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	l.connHandler.NewConnection(ctx, conn, metadata, nil)
}
