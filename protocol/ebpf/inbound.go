//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const defaultListenPort = 65532

var defaultRedirectIPv4 = netip.MustParsePrefix("127.128.0.0/9")

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx               context.Context
	router            adapter.ConnectionRouterEx
	logger            log.ContextLogger
	networkManager    adapter.NetworkManager
	listenOptions     option.ListenOptions
	listener4         *listener.Listener
	listener6         *listener.Listener
	udpNat            *udpnat.Service
	backend           *ECommon.Backend
	protectRegistered bool
	listenPort        uint16
	enableTCP         bool
	enableUDP         bool
	redirectIPv4      netip.Prefix
	redirectIPv6      netip.Prefix
	policy            ECommon.Policy
	localRoutes       []*localRoute

	bindingAccess sync.RWMutex
	bindings      map[udpBindingKey]netip.Addr
	connectedUDP  map[netip.AddrPort]bool
}

type udpBindingKey struct {
	client      netip.AddrPort
	destination netip.AddrPort
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	listenOptions, err := normalizeListenOptions(options.ListenOptions)
	if err != nil {
		return nil, err
	}
	redirectIPv4, redirectIPv6, err := normalizeRedirectAddresses(options.RedirectAddress)
	if err != nil {
		return nil, err
	}
	includeUID, err := parseUIDRanges(options.IncludeUID, options.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUID, err := parseUIDRanges(options.ExcludeUID, options.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		networkManager: networkManager,
		listenOptions:  listenOptions,
		bindings:       make(map[udpBindingKey]netip.Addr),
		connectedUDP:   make(map[netip.AddrPort]bool),
		listenPort:     listenOptions.ListenPort,
		enableTCP:      enableTCP,
		enableUDP:      enableUDP,
		redirectIPv4:   redirectIPv4,
		redirectIPv6:   redirectIPv6,
		policy: ECommon.Policy{
			IncludeUID: includeUID,
			ExcludeUID: excludeUID,
		},
	}
	udpTimeout := C.UDPTimeout
	if listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(listenOptions.UDPTimeout)
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	if redirectIPv4.IsValid() {
		inbound.listener4 = inbound.newListener(network, false)
	}
	if redirectIPv6.IsValid() {
		inbound.listener6 = inbound.newListener(network, true)
	}
	return inbound, nil
}

func (i *Inbound) newListener(network []string, ipv6 bool) *listener.Listener {
	listenOptions := i.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6 {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	return listener.New(listener.Options{
		Context:             i.ctx,
		Logger:              i.logger,
		Network:             network,
		Listen:              listenOptions,
		ConnectionHandler:   i,
		OOBPacketHandler:    i,
		DisablePacketOutput: true,
		SocketControl:       i.socketControl(ipv6),
	})
}

func normalizeListenOptions(options option.ListenOptions) (option.ListenOptions, error) {
	if options.Listen != nil {
		listenAddress := netip.Addr(*options.Listen)
		if !listenAddress.IsValid() || !listenAddress.IsUnspecified() {
			return option.ListenOptions{}, E.New("eBPF inbound listen address must be unspecified")
		}
	}
	if options.ProxyProtocol || options.ProxyProtocolAcceptNoHeader {
		return option.ListenOptions{}, E.New("proxy_protocol is not supported by eBPF inbound")
	}
	options.Listen = common.Ptr(badoption.Addr(netip.IPv4Unspecified()))
	if options.ListenPort == 0 {
		options.ListenPort = defaultListenPort
	}
	return options, nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			if address.Bits() < 8 || address.Bits() > 10 {
				return netip.Prefix{}, netip.Prefix{}, E.New("IPv4 eBPF redirect address must use a prefix between /8 and /10")
			}
			if address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
				return netip.Prefix{}, netip.Prefix{}, E.New("invalid IPv4 eBPF redirect address: ", address)
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			if address.Bits() != 64 {
				return netip.Prefix{}, netip.Prefix{}, E.New("IPv6 eBPF redirect address must use a /64 prefix")
			}
			if address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
				return netip.Prefix{}, netip.Prefix{}, E.New("invalid IPv6 eBPF redirect address: ", address)
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		backend, err := ECommon.Prepare("", i.listenPort,
			i.enableTCP, i.enableUDP, i.redirectIPv4, i.redirectIPv6, i.policy)
		if err != nil {
			return err
		}
		i.backend = backend
		if err = i.networkManager.RegisterSocketProtectFunc(backend.ProtectFunc()); err != nil {
			_ = backend.Close()
			i.backend = nil
			return err
		}
		i.protectRegistered = true
	case adapter.StartStateStart:
		if i.backend == nil {
			return E.New("eBPF backend is not initialized")
		}
		if err := i.setupLocalRoutes(); err != nil {
			i.cleanupStartFailure()
			return E.Cause(err, "configure eBPF redirect routes")
		}
		if err := i.startListeners(); err != nil {
			i.cleanupStartFailure()
			return err
		}
		if err := i.backend.Attach(); err != nil {
			i.cleanupStartFailure()
			return err
		}
		i.logger.Info(
			"eBPF inbound attached: cgroup=", i.backend.CgroupPath(),
			", redirect_address=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
			", programs=[", strings.Join(i.backend.AttachedPrograms(), ", "), "]",
		)
	}
	return nil
}

func (i *Inbound) Close() error {
	i.unregisterSocketProtector()
	var backendErr error
	if i.backend != nil {
		backendErr = i.backend.Close()
		i.backend = nil
	}
	i.udpNat.Purge()
	return E.Errors(backendErr, i.closeListeners(), i.removeLocalRoutes())
}

func (i *Inbound) startListeners() error {
	if i.listener4 != nil {
		if err := i.listener4.Start(); err != nil {
			return err
		}
	}
	if i.listener6 != nil {
		if err := i.listener6.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (i *Inbound) closeListeners() error {
	var listener4Err error
	var listener6Err error
	if i.listener4 != nil {
		listener4Err = i.listener4.Close()
	}
	if i.listener6 != nil {
		listener6Err = i.listener6.Close()
	}
	return E.Errors(listener4Err, listener6Err)
}

func (i *Inbound) cleanupStartFailure() {
	_ = i.closeListeners()
	_ = i.removeLocalRoutes()
	i.unregisterSocketProtector()
	if i.backend != nil {
		_ = i.backend.Close()
		i.backend = nil
	}
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4.IsValid() {
		addresses = append(addresses, i.redirectIPv4.String())
	}
	if i.redirectIPv6.IsValid() {
		addresses = append(addresses, i.redirectIPv6.String())
	}
	return addresses
}

func (i *Inbound) unregisterSocketProtector() {
	if !i.protectRegistered {
		return
	}
	i.networkManager.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if i.backend == nil {
		conn.Close()
		return
	}
	original, err := i.backend.LookupOriginal(
		ECommon.ProtocolTCP,
		M.SocksaddrFromNet(conn.LocalAddr()).AddrPort(),
	)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	i.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if i.backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.logger.Warn("read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listenPort)
	original, err := i.backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
	if err != nil {
		i.logger.Warn("lookup UDP original destination: ", err)
		return
	}
	i.bindingAccess.Lock()
	i.bindings[udpBindingKey{client: client, destination: original.Destination}] = redirectAddress
	i.bindingAccess.Unlock()
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = i.listenOptions.Detour
	i.bindingAccess.RLock()
	metadata.UDPConnect = i.connectedUDP[source.AddrPort()]
	i.bindingAccess.RUnlock()
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	i.bindingAccess.Lock()
	i.connectedUDP[client] = connectedUDP
	i.bindingAccess.Unlock()
	writer := &udpPacketWriter{
		inbound: i,
		client:  client,
	}
	return true, ctx, writer, func(error) {
		i.deleteBindings(writer.client)
	}
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
				return nil
			})
		}
		switch network {
		case "udp4":
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		default:
			return nil
		}
	}
}

func (i *Inbound) redirectAddressFor(client netip.AddrPort, destination netip.AddrPort) (netip.Addr, bool) {
	i.bindingAccess.RLock()
	redirectAddress, loaded := i.bindings[udpBindingKey{client: client, destination: destination}]
	i.bindingAccess.RUnlock()
	return redirectAddress, loaded
}

func (i *Inbound) deleteBindings(client netip.AddrPort) {
	i.bindingAccess.Lock()
	for key := range i.bindings {
		if key.client == client {
			delete(i.bindings, key)
		}
	}
	delete(i.connectedUDP, client)
	i.bindingAccess.Unlock()
}

type udpPacketWriter struct {
	inbound *Inbound
	client  netip.AddrPort
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	redirectAddress, loaded := w.inbound.redirectAddressFor(w.client, destination.AddrPort())
	if !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.inbound.listener4 == nil {
			return E.New("IPv4 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.inbound.listener6 == nil {
			return E.New("IPv6 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage4 ipv4.ControlMessage
	if err := controlMessage4.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage4.Dst); loaded && address.Is4() {
			return address.Unmap(), nil
		}
	}
	var controlMessage6 ipv6.ControlMessage
	if err := controlMessage6.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage6.Dst); loaded && address.Is6() && !address.Is4In6() {
			return address, nil
		}
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
