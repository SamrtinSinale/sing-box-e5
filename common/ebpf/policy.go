//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"math/bits"
	"sort"
)

const maxUIDPolicyEntries = 4096

type Policy struct {
	IncludeUID []UIDRange
	ExcludeUID []UIDRange
}

type UIDRange struct {
	Start uint32
	End   uint32
}

type uidLPMKey struct {
	PrefixLength uint32
	UID          [4]byte
}

func compileUIDRanges(uidRanges []UIDRange) []uidLPMKey {
	entries := make(map[uidLPMKey]struct{})
	for _, uidRange := range uidRanges {
		start := uint64(uidRange.Start)
		end := uint64(uidRange.End)
		for start <= end {
			var blockSize uint64
			if start == 0 {
				blockSize = uint64(1) << 32
			} else {
				blockSize = uint64(1) << bits.TrailingZeros64(start)
			}
			remaining := end - start + 1
			for blockSize > remaining {
				blockSize >>= 1
			}
			entry := uidLPMKey{PrefixLength: uint32(32 - bits.TrailingZeros64(blockSize))}
			binary.BigEndian.PutUint32(entry.UID[:], uint32(start))
			entries[entry] = struct{}{}
			start += blockSize
		}
	}
	compiled := make([]uidLPMKey, 0, len(entries))
	for entry := range entries {
		compiled = append(compiled, entry)
	}
	sort.Slice(compiled, func(i, j int) bool {
		if compiled[i].PrefixLength != compiled[j].PrefixLength {
			return compiled[i].PrefixLength < compiled[j].PrefixLength
		}
		return binary.BigEndian.Uint32(compiled[i].UID[:]) < binary.BigEndian.Uint32(compiled[j].UID[:])
	})
	return compiled
}
