//go:build with_ebpf && (linux || android) && cgo && (386 || amd64 || arm || arm64)

#include "native/bpf_util.c"
