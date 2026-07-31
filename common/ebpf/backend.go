//go:build with_ebpf && (linux || android) && cgo && (386 || amd64 || arm || arm64)

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_inbound_prepare(
	const char *cgroup_path,
	uint16_t listen_port,
	bool enable_tcp,
	bool enable_udp,
	bool enable_ipv4,
	const uint8_t *redirect_ipv4,
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t *redirect_ipv6,
	uint32_t redirect_ipv6_prefix_bits,
	uint32_t include_uid_entries,
	uint32_t exclude_uid_entries,
	struct sb_ebpf_inbound_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_inbound_prepare(
		cgroup_path,
		listen_port,
		enable_tcp,
		enable_udp,
		enable_ipv4,
		redirect_ipv4,
		redirect_ipv4_prefix_bits,
		enable_ipv6,
		redirect_ipv6,
		redirect_ipv6_prefix_bits,
		include_uid_entries,
		exclude_uid_entries,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_inbound_attach(
	struct sb_ebpf_inbound_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_inbound_attach(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	bpfMapCreate     = 0
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfMapTypeArray  = 2
)

type Backend struct {
	runtime     *C.struct_sb_ebpf_inbound_runtime
	redirectMap int
	cookieMap   int
	cgroupPath  string
	enableUDP   bool
}

type mapElementAttr struct {
	MapFD uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

type mapCreateAttr struct {
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

func Prepare(
	cgroupPath string,
	listenPort uint16,
	enableTCP bool,
	enableUDP bool,
	redirectIPv4 netip.Prefix,
	redirectIPv6 netip.Prefix,
	policy Policy,
) (*Backend, error) {
	if redirectIPv4.IsValid() &&
		(!redirectIPv4.Addr().Is4() || redirectIPv4.Bits() < 8 || redirectIPv4.Bits() > 10) {
		return nil, E.New("invalid IPv4 eBPF redirect address: ", redirectIPv4)
	}
	if redirectIPv6.IsValid() &&
		(!redirectIPv6.Addr().Is6() || redirectIPv6.Addr().Is4In6() || redirectIPv6.Bits() != 64) {
		return nil, E.New("invalid IPv6 eBPF redirect address: ", redirectIPv6)
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing eBPF redirect address")
	}
	includeUIDEntries, err := compileUIDPolicy("include_uid", policy.IncludeUID)
	if err != nil {
		return nil, err
	}
	excludeUIDEntries, err := compileUIDPolicy("exclude_uid", policy.ExcludeUID)
	if err != nil {
		return nil, err
	}
	if cgroupPath == "" {
		cgroupPath, err = DetectCgroup2Mount()
		if err != nil {
			return nil, err
		}
	}
	memlockErr := raiseMemlockLimit()
	if err := checkKernelCapabilities(cgroupPath); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	runtimeState := (*C.struct_sb_ebpf_inbound_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_sb_ebpf_inbound_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF runtime")
	}
	var cgroupPathCString *C.char
	if cgroupPath != "" {
		cgroupPathCString = C.CString(cgroupPath)
		defer C.free(unsafe.Pointer(cgroupPathCString))
	}
	var savedErrno C.int
	var redirectIPv4Bytes [4]byte
	var redirectIPv4Pointer *C.uint8_t
	var redirectIPv4Bits C.uint32_t
	if redirectIPv4.IsValid() {
		redirectIPv4Bytes = redirectIPv4.Addr().As4()
		redirectIPv4Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv4Bytes[0]))
		redirectIPv4Bits = C.uint32_t(redirectIPv4.Bits())
	}
	var redirectIPv6Bytes [16]byte
	var redirectIPv6Pointer *C.uint8_t
	var redirectIPv6Bits C.uint32_t
	if redirectIPv6.IsValid() {
		redirectIPv6Bytes = redirectIPv6.Addr().As16()
		redirectIPv6Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv6Bytes[0]))
		redirectIPv6Bits = C.uint32_t(redirectIPv6.Bits())
	}
	if C.singbox_ebpf_inbound_prepare(
		cgroupPathCString,
		C.uint16_t(listenPort),
		C.bool(enableTCP),
		C.bool(enableUDP),
		C.bool(redirectIPv4.IsValid()),
		redirectIPv4Pointer,
		redirectIPv4Bits,
		C.bool(redirectIPv6.IsValid()),
		redirectIPv6Pointer,
		redirectIPv6Bits,
		C.uint32_t(len(includeUIDEntries)),
		C.uint32_t(len(excludeUIDEntries)),
		runtimeState,
		&savedErrno,
	) != 0 {
		prepareErrno := syscall.Errno(savedErrno)
		var prepareErr error = prepareErrno
		if memlockErr != nil && (prepareErrno == unix.ENOMEM || prepareErrno == unix.EPERM) {
			prepareErr = E.Cause(prepareErr, "memlock limit could not be removed: ", memlockErr)
		}
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFOperationError("prepare eBPF inbound", prepareErr)
	}
	backend := &Backend{
		runtime:     runtimeState,
		redirectMap: int(runtimeState.redirect_map_fd),
		cookieMap:   int(runtimeState.bypass_socket_cookie_map_fd),
		cgroupPath:  cgroupPath,
		enableUDP:   enableUDP,
	}
	if err = populateUIDPolicyMap(int(runtimeState.include_uid_map_fd), includeUIDEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate include_uid eBPF map")
	}
	if err = populateUIDPolicyMap(int(runtimeState.exclude_uid_map_fd), excludeUIDEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate exclude_uid eBPF map")
	}
	return backend, nil
}

func compileUIDPolicy(name string, uidRanges []UIDRange) ([]uidLPMKey, error) {
	for _, uidRange := range uidRanges {
		if uidRange.Start > uidRange.End {
			return nil, E.New("invalid ", name, " range: ", uidRange.Start, ":", uidRange.End)
		}
	}
	entries := compileUIDRanges(uidRanges)
	if len(entries) > maxUIDPolicyEntries {
		return nil, E.New(name, " compiles to too many eBPF map entries: ", len(entries), " > ", maxUIDPolicyEntries)
	}
	return entries, nil
}

func populateUIDPolicyMap(mapFD int, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	value := uint8(1)
	for entryIndex := range entries {
		if err := updateMap(mapFD, unsafe.Pointer(&entries[entryIndex]), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}
	return nil
}

func raiseMemlockLimit() error {
	unlimited := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	unlimitedErr := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unlimited)
	if unlimitedErr == nil {
		return nil
	}

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return E.Errors(unlimitedErr, E.Cause(err, "read memlock limit"))
	}
	if limit.Cur < limit.Max {
		limit.Cur = limit.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			return E.Errors(unlimitedErr, E.Cause(err, "raise soft memlock limit"))
		}
	}
	return unlimitedErr
}

func checkKernelCapabilities(cgroupPath string) error {
	var fileSystem unix.Statfs_t
	if err := unix.Statfs(cgroupPath, &fileSystem); err != nil {
		return E.Cause(err, "check eBPF cgroup2 mount")
	}
	if fileSystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return E.New("eBPF inbound is not supported: ", cgroupPath, " is not a cgroup2 mount")
	}

	attribute := mapCreateAttr{
		MapType:    bpfMapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	if errno != 0 {
		return eBPFOperationError("probe BPF_MAP_CREATE", errno)
	}
	if err := unix.Close(int(fd)); err != nil {
		return E.Cause(err, "close eBPF capability probe map")
	}
	return nil
}

func eBPFOperationError(operation string, err error) error {
	if errno, isErrno := err.(syscall.Errno); isErrno {
		switch errno {
		case unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP:
			return E.Cause(errno, "eBPF inbound is not supported by this kernel: ", operation)
		case unix.EPERM, unix.EACCES:
			return E.Cause(errno, "eBPF inbound is not permitted on this device: ", operation)
		}
	}
	return E.Cause(err, operation)
}

func (b *Backend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *Backend) AttachedPrograms() []string {
	if b == nil || b.runtime == nil {
		return nil
	}
	programs := make([]string, 0, 9)
	if b.runtime.connect4_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_conn4 (cgroup/connect4)")
	}
	if b.enableUDP && b.runtime.udp4_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_udp4 (cgroup/sendmsg4)")
	}
	if b.enableUDP && b.runtime.udp4_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_urcv4 (cgroup/recvmsg4)")
	}
	if b.runtime.connect6_v4mapped_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_c6v4m (cgroup/connect6)")
	}
	if b.runtime.connect6_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_conn6 (cgroup/connect6)")
	}
	if b.enableUDP && b.runtime.udp6_v4mapped_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_u6v4m (cgroup/sendmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_udp6 (cgroup/sendmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_v4mapped_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_ur6v4m (cgroup/recvmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_urcv6 (cgroup/recvmsg6)")
	}
	return programs
}

func (b *Backend) Attach() error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	var savedErrno C.int
	if C.singbox_ebpf_inbound_attach(b.runtime, &savedErrno) != 0 {
		return eBPFOperationError("attach eBPF inbound", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *Backend) Close() error {
	if b == nil || b.runtime == nil {
		return nil
	}
	C.sb_ebpf_inbound_close(b.runtime)
	C.free(unsafe.Pointer(b.runtime))
	b.runtime = nil
	b.redirectMap = -1
	b.cookieMap = -1
	return nil
}

func (b *Backend) ProtectFunc() control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		return control.Raw(rawConn, func(fd uintptr) error {
			cookie, err := socketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			value := uint8(1)
			if err = updateMap(b.cookieMap, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
				return E.Cause(err, "register eBPF bypass socket")
			}
			return nil
		})
	}
}

func (b *Backend) LookupOriginal(protocol uint8, redirect netip.AddrPort) (OriginalDestination, error) {
	key, err := makeRedirectKey(protocol, redirect, netip.AddrPort{})
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestination
	err = lookupMap(b.redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&1 != 0,
	}, nil
}

func lookupMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapLookupElem, mapFD, key, value)
}

func updateMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapUpdateElem, mapFD, key, value)
}

func mapOperation(command uintptr, mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if mapFD < 0 {
		return osErrClosed
	}
	attribute := mapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(key)),
		Value: uint64(uintptr(value)),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}

func socketCookie(fd uintptr) (uint64, error) {
	var cookie uint64
	length := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		fd,
		unix.SOL_SOCKET,
		unix.SO_COOKIE,
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return cookie, nil
}

var osErrClosed = syscall.EBADF
