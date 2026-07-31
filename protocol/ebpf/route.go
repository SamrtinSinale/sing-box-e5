//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/common/listener"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type localRoute struct {
	route netlink.Route
}

func (i *Inbound) setupLocalRoutes() error {
	prefixes := make([]netip.Prefix, 0, 2)
	if i.redirectIPv4.IsValid() {
		prefixes = append(prefixes, i.redirectIPv4)
	}
	if i.redirectIPv6.IsValid() {
		prefixes = append(prefixes, i.redirectIPv6)
	}
	routes, err := listener.ListenNetworkNamespace(i.ctx, i.listenOptions.NetNs, func() ([]*localRoute, error) {
		return addLocalRoutes(prefixes)
	})
	if err != nil {
		return err
	}
	i.localRoutes = routes
	return nil
}

func (i *Inbound) removeLocalRoutes() error {
	if len(i.localRoutes) == 0 {
		return nil
	}
	routes := i.localRoutes
	_, err := listener.ListenNetworkNamespace(i.ctx, i.listenOptions.NetNs, func() (struct{}, error) {
		var routeErr error
		for index := len(routes) - 1; index >= 0; index-- {
			err := netlink.RouteDel(&routes[index].route)
			if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
				routeErr = E.Errors(routeErr, err)
			}
		}
		return struct{}{}, routeErr
	})
	if err == nil {
		i.localRoutes = nil
	}
	return err
}

func addLocalRoutes(prefixes []netip.Prefix) ([]*localRoute, error) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback interface")
	}
	ownedRoutes := make([]*localRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		route, owned, routeErr := addLocalRoute(loopback.Attrs().Index, prefix)
		if routeErr != nil {
			for index := len(ownedRoutes) - 1; index >= 0; index-- {
				_ = netlink.RouteDel(&ownedRoutes[index].route)
			}
			return nil, routeErr
		}
		if owned {
			ownedRoutes = append(ownedRoutes, &localRoute{route: route})
		}
	}
	return ownedRoutes, nil
}

func addLocalRoute(loopbackIndex int, prefix netip.Prefix) (netlink.Route, bool, error) {
	family := unix.AF_INET
	if prefix.Addr().Is6() {
		family = unix.AF_INET6
	}
	route := netlink.Route{
		LinkIndex: loopbackIndex,
		Family:    family,
		Dst:       prefixIPNet(prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
	}
	exists, err := localRouteExists(family, prefix)
	if err != nil {
		return netlink.Route{}, false, err
	}
	if exists {
		return route, false, nil
	}
	if err = netlink.RouteAdd(&route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			exists, listErr := localRouteExists(family, prefix)
			if listErr == nil && exists {
				return route, false, nil
			}
		}
		return netlink.Route{}, false, E.Cause(err, "add local route for ", prefix)
	}
	return route, true, nil
}

func localRouteExists(family int, prefix netip.Prefix) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: unix.RT_TABLE_LOCAL},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, E.Cause(err, "list local routes")
	}
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL && routePrefixContains(route.Dst, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func routePrefixContains(destination *net.IPNet, prefix netip.Prefix) bool {
	if destination == nil {
		return false
	}
	bits, addressBits := destination.Mask.Size()
	address, loaded := netip.AddrFromSlice(destination.IP)
	if !loaded {
		return false
	}
	address = address.Unmap()
	prefix = prefix.Masked()
	if bits < 0 || address.BitLen() != addressBits || address.BitLen() != prefix.Addr().BitLen() || bits > prefix.Bits() {
		return false
	}
	return netip.PrefixFrom(address, bits).Masked().Contains(prefix.Addr())
}
