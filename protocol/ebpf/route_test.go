//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"
)

func TestRoutePrefixContains(t *testing.T) {
	tests := []struct {
		destination *net.IPNet
		prefix      netip.Prefix
		contains    bool
	}{
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.0.0.0/8"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("fd53:696e:672d:626f::/48")),
			prefix:      netip.MustParsePrefix("fd53:696e:672d:626f::1/64"),
			contains:    true,
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("10.0.0.0/8")),
			prefix:      netip.MustParsePrefix("127.0.0.0/8"),
		},
		{
			destination: prefixIPNet(netip.MustParsePrefix("127.128.0.0/10")),
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
		},
		{
			destination: nil,
			prefix:      netip.MustParsePrefix("127.128.0.0/9"),
		},
	}
	for _, test := range tests {
		if routePrefixContains(test.destination, test.prefix) != test.contains {
			t.Fatalf("unexpected comparison for %v and %v", test.destination, test.prefix)
		}
	}
}
