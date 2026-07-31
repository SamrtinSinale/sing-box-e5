//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestCompileUIDRanges(t *testing.T) {
	if size := unsafe.Sizeof(uidLPMKey{}); size != 8 {
		t.Fatalf("unexpected UID LPM key size: %d", size)
	}
	entries := compileUIDRanges([]UIDRange{
		{Start: 0, End: 0},
		{Start: 1000, End: 99999},
	})
	for _, uid := range []uint32{0, 1000, 50000, 99999} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is not covered", uid)
		}
	}
	for _, uid := range []uint32{1, 999, 100000} {
		if uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is unexpectedly covered", uid)
		}
	}
}

func TestCompileFullUIDRange(t *testing.T) {
	entries := compileUIDRanges([]UIDRange{{Start: 0, End: ^uint32(0)}})
	if len(entries) != 1 || entries[0].PrefixLength != 0 {
		t.Fatalf("unexpected full UID range: %+v", entries)
	}
}

func uidMatchesPrefixes(uid uint32, entries []uidLPMKey) bool {
	for _, entry := range entries {
		prefix := binary.BigEndian.Uint32(entry.UID[:])
		if entry.PrefixLength == 0 || uid>>(32-entry.PrefixLength) == prefix>>(32-entry.PrefixLength) {
			return true
		}
	}
	return false
}
