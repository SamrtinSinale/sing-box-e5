//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_shared_network_prepare(
	const uint8_t *object,
	size_t object_size,
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	uint32_t map_capacity,
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_prepare(
		object,
		object_size,
		bypass_ipv4_map_fd,
		bypass_ipv6_map_fd,
		map_capacity,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_shared_network_close(
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

//go:embed native/shared_network.bpf.o
var sharedNetworkObject []byte

type sharedNetworkControl struct {
	Enabled        uint32
	Flags          uint32
	BridgePort     uint16
	Reserved       uint16
	IPv4Prefix     [4]byte
	IPv4PrefixBits uint8
	IPv6PrefixBits uint8
	Reserved2      [2]byte
	IPv6Prefix     [16]byte
}

type sharedNetworkRedirectKey struct {
	Family       uint8
	Protocol     uint8
	RedirectPort uint16
	RedirectAddr [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type sharedNetworkOriginalKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	OriginalPort   uint16
	Reserved       uint16
	ClientAddr     [16]byte
	OriginalAddr   [16]byte
}

type sharedNetworkTokenValue struct {
	TokenAddr [16]byte
}

type sharedNetworkReverseKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	TokenPort      uint16
	Reserved       uint16
	ClientAddr     [16]byte
	TokenAddr      [16]byte
}

type sharedNetworkRedirectValue struct {
	Family         uint8
	Protocol       uint8
	Port           uint16
	Addr           [16]byte
	InterfaceIndex uint32
	Reserved       uint32
}

type SharedNetworkFlow struct {
	originalKey sharedNetworkOriginalKey
	reverseKey  sharedNetworkReverseKey
	redirectKey sharedNetworkRedirectKey
}

const (
	sharedNetworkFlagIPv4 = 1 << iota
	sharedNetworkFlagIPv6
	sharedNetworkFlagTCP
	sharedNetworkFlagUDP
	sharedNetworkFlagDNSHijack
)

type SharedNetworkBackend struct {
	access   sync.RWMutex
	runtime  *C.struct_sb_ebpf_shared_network_runtime
	control  sharedNetworkControl
	hostIPv4 []netip.Prefix
	hostIPv6 []netip.Prefix
}

func PrepareSharedNetwork(
	parent *Backend,
	bridgePort uint16,
	enableTCP bool,
	enableUDP bool,
	redirectIPv4 netip.Prefix,
	redirectIPv6 netip.Prefix,
) (*SharedNetworkBackend, error) {
	return PrepareSharedNetworkWithMapCapacity(
		parent,
		bridgePort,
		enableTCP,
		enableUDP,
		redirectIPv4,
		redirectIPv6,
		SharedNetworkMapCapacity,
	)
}

func PrepareSharedNetworkWithMapCapacity(
	parent *Backend,
	bridgePort uint16,
	enableTCP bool,
	enableUDP bool,
	redirectIPv4 netip.Prefix,
	redirectIPv6 netip.Prefix,
	mapCapacity uint32,
) (*SharedNetworkBackend, error) {
	if parent == nil {
		return nil, osErrClosed
	}
	if mapCapacity == 0 || mapCapacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid shared-network map capacity: ", mapCapacity)
	}
	if bridgePort == 0 {
		return nil, E.New("missing shared-network listener port")
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing shared-network redirect address")
	}
	if len(sharedNetworkObject) == 0 {
		return nil, E.New("missing embedded shared-network eBPF object")
	}

	runtimeState := (*C.struct_sb_ebpf_shared_network_runtime)(C.calloc(
		1,
		C.size_t(C.sizeof_struct_sb_ebpf_shared_network_runtime),
	))
	if runtimeState == nil {
		return nil, E.New("allocate shared-network token runtime")
	}
	parent.access.RLock()
	if parent.runtime == nil {
		parent.access.RUnlock()
		C.free(unsafe.Pointer(runtimeState))
		return nil, osErrClosed
	}
	hijackDNS := parent.hijackDNS
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkObject[0])),
		C.size_t(len(sharedNetworkObject)),
		C.int(parent.bypassIPv4CIDRMap),
		C.int(parent.bypassIPv6CIDRMap),
		C.uint32_t(mapCapacity),
		runtimeState,
		&savedErrno,
	)
	parent.access.RUnlock()
	if result != 0 {
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFOperationError(
			"prepare shared-network programs",
			syscall.Errno(savedErrno),
		)
	}

	backend := &SharedNetworkBackend{runtime: runtimeState}
	backend.control.BridgePort = bridgePort
	if enableTCP {
		backend.control.Flags |= sharedNetworkFlagTCP
	}
	if enableUDP {
		backend.control.Flags |= sharedNetworkFlagUDP
	}
	if hijackDNS {
		backend.control.Flags |= sharedNetworkFlagDNSHijack
	}
	if redirectIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv4
		backend.control.IPv4Prefix = redirectIPv4.Addr().As4()
		backend.control.IPv4PrefixBits = uint8(redirectIPv4.Bits())
	}
	if redirectIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv6
		backend.control.IPv6Prefix = redirectIPv6.Addr().As16()
		backend.control.IPv6PrefixBits = uint8(redirectIPv6.Bits())
	}
	if err := backend.updateControl(false); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "initialize shared-network control")
	}
	return backend, nil
}

func (b *SharedNetworkBackend) updateControl(enabled bool) error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	control := b.control
	if enabled {
		control.Enabled = 1
	}
	key := uint32(0)
	return updateMap(
		int(b.runtime.control_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&control),
	)
}

func (b *SharedNetworkBackend) Enable() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.updateControl(true)
}

func (b *SharedNetworkBackend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	return b.updateControl(false)
}

func (b *SharedNetworkBackend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.ingress_prog_fd)
}

func (b *SharedNetworkBackend) EgressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.egress_prog_fd)
}

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (OriginalDestination, error) {
	original, _, err := b.LookupFlow(protocol, client, redirect)
	return original, err
}

func (b *SharedNetworkBackend) LookupFlow(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (OriginalDestination, *SharedNetworkFlow, error) {
	if b == nil {
		return OriginalDestination{}, nil, osErrClosed
	}
	key, err := makeSharedNetworkRedirectKey(protocol, client, redirect)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, nil, osErrClosed
	}
	var value sharedNetworkRedirectValue
	if err = lookupMap(
		int(b.runtime.redirect_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return OriginalDestination{}, nil, E.Cause(err, "lookup shared-network original destination")
	}
	address, err := sharedNetworkOriginalAddress(value)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	flow := makeSharedNetworkFlow(key, value)
	return OriginalDestination{
		Destination: netip.AddrPortFrom(address, value.Port),
	}, &flow, nil
}

func makeSharedNetworkRedirectKey(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (sharedNetworkRedirectKey, error) {
	var key sharedNetworkRedirectKey
	key.Protocol = protocol
	key.RedirectPort = redirect.Port()
	key.ClientPort = client.Port()
	if err := putAddress(&key.Family, &key.RedirectAddr, redirect.Addr()); err != nil {
		return sharedNetworkRedirectKey{}, E.Cause(err, "invalid shared-network redirect address")
	}
	var clientFamily uint8
	if err := putAddress(&clientFamily, &key.ClientAddr, client.Addr()); err != nil {
		return sharedNetworkRedirectKey{}, E.Cause(err, "invalid shared-network client address")
	}
	if clientFamily != key.Family {
		return sharedNetworkRedirectKey{}, E.New("shared-network client and redirect address families do not match")
	}
	return key, nil
}

func sharedNetworkOriginalAddress(value sharedNetworkRedirectValue) (netip.Addr, error) {
	switch value.Family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(value.Addr[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(value.Addr), nil
	default:
		return netip.Addr{}, E.New("invalid original destination family: ", value.Family)
	}
}

func makeSharedNetworkFlow(key sharedNetworkRedirectKey, value sharedNetworkRedirectValue) SharedNetworkFlow {
	return SharedNetworkFlow{
		originalKey: sharedNetworkOriginalKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			OriginalPort:   value.Port,
			ClientAddr:     key.ClientAddr,
			OriginalAddr:   value.Addr,
		},
		reverseKey: sharedNetworkReverseKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			TokenPort:      key.RedirectPort,
			ClientAddr:     key.ClientAddr,
			TokenAddr:      key.RedirectAddr,
		},
		redirectKey: key,
	}
}

func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlow) error {
	if b == nil || flow == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	return E.Errors(
		deleteMapIfExists(int(b.runtime.original_to_token_map_fd), unsafe.Pointer(&flow.originalKey)),
		deleteMapIfExists(int(b.runtime.redirect_map_fd), unsafe.Pointer(&flow.redirectKey)),
		deleteMapIfExists(int(b.runtime.token_to_original_map_fd), unsafe.Pointer(&flow.reverseKey)),
	)
}

func deleteMapIfExists(mapFD int, key unsafe.Pointer) error {
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *SharedNetworkBackend) DeleteRedirect(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeSharedNetworkRedirectKey(protocol, client, redirect)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return osErrClosed
	}
	err = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return osErrClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if len(ipv4) > 256 || len(ipv6) > 256 {
		return E.New("shared-network host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if !slices.Equal(b.hostIPv6, ipv6) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv6_map_fd),
			b.hostIPv6,
			ipv6,
		); err != nil {
			return E.Cause(err, "update shared-network IPv6 host map")
		}
	}
	if !slices.Equal(b.hostIPv4, ipv4) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv4_map_fd),
			b.hostIPv4,
			ipv4,
		); err != nil {
			if !slices.Equal(b.hostIPv6, ipv6) {
				_ = replaceBypassCIDRPolicyMap(
					int(b.runtime.host_ipv6_map_fd),
					ipv6,
					b.hostIPv6,
				)
			}
			return E.Cause(err, "update shared-network IPv4 host map")
		}
	}
	b.hostIPv4 = ipv4
	b.hostIPv6 = ipv6
	return nil
}

func compileSharedHostPrefixes(addresses []netip.Addr) ([]netip.Prefix, []netip.Prefix) {
	ipv4Set := make(map[netip.Prefix]struct{})
	ipv6Set := make(map[netip.Prefix]struct{})
	for _, address := range addresses {
		address = address.Unmap()
		switch {
		case address.Is4():
			ipv4Set[netip.PrefixFrom(address, 32)] = struct{}{}
		case address.Is6():
			ipv6Set[netip.PrefixFrom(address, 128)] = struct{}{}
		}
	}
	ipv4 := make([]netip.Prefix, 0, len(ipv4Set))
	for prefix := range ipv4Set {
		ipv4 = append(ipv4, prefix)
	}
	ipv6 := make([]netip.Prefix, 0, len(ipv6Set))
	for prefix := range ipv6Set {
		ipv6 = append(ipv6, prefix)
	}
	slices.SortFunc(ipv4, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	slices.SortFunc(ipv6, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	return ipv4, ipv6
}

func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	_ = b.updateControl(false)
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_close(b.runtime, &savedErrno)
	if b.runtime.control_map_fd < 0 &&
		b.runtime.ingress_prog_fd < 0 &&
		b.runtime.egress_prog_fd < 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.hostIPv4 = nil
		b.hostIPv6 = nil
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close shared-network runtime")
	}
	return nil
}

func (b *SharedNetworkBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
