//go:build with_ebpf && (linux || android) && cgo && !386 && !amd64 && !arm && !arm64

package ebpf

import (
	"net/netip"
	"runtime"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type Backend struct{}

func unsupportedArchitectureError() error {
	return E.New("eBPF inbound is not supported on ", runtime.GOOS, "/", runtime.GOARCH)
}

func Prepare(string, uint16, bool, bool, netip.Prefix, netip.Prefix) (*Backend, error) {
	return nil, unsupportedArchitectureError()
}

func (b *Backend) Attach() error {
	return unsupportedArchitectureError()
}

func (b *Backend) Close() error {
	return nil
}

func (b *Backend) CgroupPath() string {
	return ""
}

func (b *Backend) AttachedPrograms() []string {
	return nil
}

func (b *Backend) ProtectFunc() control.Func {
	return nil
}

func (b *Backend) LookupOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, unsupportedArchitectureError()
}
