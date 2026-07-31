//go:build with_ebpf && (linux || android) && cgo && (386 || amd64 || arm || arm64)

#include "native/shared_network_loader.c"
#include "native/shared_network_runtime.c"
