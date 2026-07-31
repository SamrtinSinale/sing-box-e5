//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

func TestNormalizeListenOptionsDefaults(t *testing.T) {
	options, err := normalizeListenOptions(option.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if options.Listen == nil || netip.Addr(*options.Listen) != netip.IPv4Unspecified() {
		t.Fatalf("unexpected listen address: %v", options.Listen)
	}
	if options.ListenPort != defaultListenPort {
		t.Fatalf("unexpected listen port: %d", options.ListenPort)
	}
}

func TestNormalizeListenOptionsPreservesFields(t *testing.T) {
	listenAddress := badoption.Addr(netip.IPv6Unspecified())
	options, err := normalizeListenOptions(option.ListenOptions{
		Listen:     &listenAddress,
		ListenPort: 12345,
		ReuseAddr:  true,
		Detour:     "detour-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Listen == nil || netip.Addr(*options.Listen) != netip.IPv4Unspecified() {
		t.Fatalf("unexpected normalized listen address: %v", options.Listen)
	}
	if options.ListenPort != 12345 || !options.ReuseAddr || options.Detour != "detour-in" {
		t.Fatalf("listen fields were not preserved: %+v", options)
	}
}

func TestNormalizeListenOptionsRejectsSpecificAddress(t *testing.T) {
	listenAddress := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	_, err := normalizeListenOptions(option.ListenOptions{Listen: &listenAddress})
	if err == nil {
		t.Fatal("expected a specific listen address to be rejected")
	}
}

func TestNormalizeListenOptionsRejectsProxyProtocol(t *testing.T) {
	_, err := normalizeListenOptions(option.ListenOptions{ProxyProtocol: true})
	if err == nil {
		t.Fatal("expected proxy protocol to be rejected")
	}
}

func TestNormalizeRedirectAddresses(t *testing.T) {
	tests := []struct {
		name      string
		addresses []netip.Prefix
		ipv4      string
		ipv6      string
	}{
		{
			name: "default",
			ipv4: "127.128.0.0/9",
		},
		{
			name:      "ipv4 only",
			addresses: []netip.Prefix{netip.MustParsePrefix("10.42.0.1/9")},
			ipv4:      "10.0.0.0/9",
		},
		{
			name:      "ipv6 only",
			addresses: []netip.Prefix{netip.MustParsePrefix("fd53:696e:672d:626f::1/64")},
			ipv6:      "fd53:696e:672d:626f::/64",
		},
		{
			name: "dual stack",
			addresses: []netip.Prefix{
				netip.MustParsePrefix("127.128.0.0/10"),
				netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
			},
			ipv4: "127.128.0.0/10",
			ipv6: "fd53:696e:672d:626f::/64",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipv4Prefix, ipv6Prefix, err := normalizeRedirectAddresses(test.addresses)
			if err != nil {
				t.Fatal(err)
			}
			if prefixString(ipv4Prefix) != test.ipv4 || prefixString(ipv6Prefix) != test.ipv6 {
				t.Fatalf("unexpected prefixes: IPv4=%v IPv6=%v", ipv4Prefix, ipv6Prefix)
			}
		})
	}
}

func TestNormalizeRedirectAddressesRejectsInvalid(t *testing.T) {
	tests := [][]netip.Prefix{
		{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
			netip.MustParsePrefix("fd00::/64"),
		},
		{netip.MustParsePrefix("127.0.0.0/7")},
		{netip.MustParsePrefix("127.0.0.0/11")},
		{netip.MustParsePrefix("fd53:696e:672d:626f::/96")},
		{netip.MustParsePrefix("0.0.0.0/8")},
		{netip.MustParsePrefix("ff00::/64")},
	}
	for _, addresses := range tests {
		if _, _, err := normalizeRedirectAddresses(addresses); err == nil {
			t.Fatalf("expected redirect addresses to be rejected: %v", addresses)
		}
	}
}

func TestRedirectAddressFromOOB(t *testing.T) {
	ipv4Address := netip.MustParseAddr("127.23.45.67")
	ipv4OOB := ipv4PacketInfo(ipv4Address)
	parsedIPv4, err := redirectAddressFromOOB(ipv4OOB)
	if err != nil {
		t.Fatal(err)
	}
	if parsedIPv4 != ipv4Address {
		t.Fatalf("unexpected IPv4 redirect address: %v", parsedIPv4)
	}

	ipv6Address := netip.MustParseAddr("fd53:696e:672d:626f::1234")
	ipv6OOB := ipv6PacketInfo(ipv6Address)
	parsedIPv6, err := redirectAddressFromOOB(ipv6OOB)
	if err != nil {
		t.Fatal(err)
	}
	if parsedIPv6 != ipv6Address {
		t.Fatalf("unexpected IPv6 redirect address: %v", parsedIPv6)
	}
}

func TestIPv6ListenerControlAllowsSharedPort(t *testing.T) {
	var listenConfig net.ListenConfig
	listenConfig.Control = (&Inbound{}).socketControl(true)
	listener6, err := listenConfig.Listen(context.Background(), "tcp", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 TCP is unavailable: %v", err)
	}
	defer listener6.Close()
	tcpPort := listener6.Addr().(*net.TCPAddr).Port
	listener4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: tcpPort})
	if err != nil {
		t.Fatalf("IPv6 TCP listener also occupied the IPv4 port: %v", err)
	}
	listener4.Close()

	packetConn6, err := listenConfig.ListenPacket(context.Background(), "udp", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 UDP is unavailable: %v", err)
	}
	defer packetConn6.Close()
	udpPort := packetConn6.LocalAddr().(*net.UDPAddr).Port
	packetConn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: udpPort})
	if err != nil {
		t.Fatalf("IPv6 UDP listener also occupied the IPv4 port: %v", err)
	}
	packetConn4.Close()
}

func ipv4PacketInfo(address netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	packetInfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	packetInfo.Addr = address.As4()
	return oob
}

func ipv6PacketInfo(address netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IPV6
	header.Type = unix.IPV6_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	packetInfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	packetInfo.Addr = address.As16()
	return oob
}

func prefixString(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}
