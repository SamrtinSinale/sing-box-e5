# eBPF inbound backend

This package implements the native eBPF backend used by the sing-box eBPF
inbound.

The Go and `cgo_*.c` files in this directory form the cgo boundary. cgo only
compiles C files located directly in the package directory, so each wrapper
includes one implementation file from `native/`:

- `native/connect_prog.c` builds and manages the inbound maps and programs.
- `native/bpf_util.c` contains the BPF syscall, loader, attach, and cleanup
  helpers.
- `native/singbox_ebpf.h` is the private ABI shared with the Go backend.

Small helpers used only by the program builder are kept static in
`connect_prog.c` instead of being exposed as separate translation units.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and
has been adapted for direct integration as a sing-box inbound, without a SOCKS
bridge.

The derived native source remains available under GPL-3.0. See
[`native/LICENSE`](native/LICENSE).
