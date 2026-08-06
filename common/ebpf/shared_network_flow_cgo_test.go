//go:build with_ebpf && (linux || android) && cgo

package ebpf

import "testing"

func TestPendingTCPFlowExpired(t *testing.T) {
	const now = uint64(1_000)
	const maxAge = uint64(100)
	for _, test := range []struct {
		createdAt uint64
		expired   bool
	}{
		{0, false},
		{now + 1, false},
		{now - maxAge + 1, false},
		{now - maxAge, true},
		{1, true},
	} {
		if expired := pendingTCPFlowExpired(test.createdAt, now, maxAge); expired != test.expired {
			t.Fatalf("unexpected expiration for created_at=%d: %v", test.createdAt, expired)
		}
	}
}

func TestSharedNetworkFlowReferences(t *testing.T) {
	backend := new(SharedNetworkBackend)
	flow := SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{InterfaceIndex: 7, Protocol: ProtocolTCP},
		listenerKey: sharedNetworkListenerKey{Protocol: ProtocolTCP, ListenerPort: 1234},
	}
	backend.retainFlowLocked(flow)
	backend.retainFlowLocked(flow)
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("first release removed a multiply referenced flow")
	}
	if references := backend.flowReferences[flow]; references != 1 {
		t.Fatalf("unexpected remaining flow references: %d", references)
	}
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last release did not select the flow for cleanup")
	}
	if _, loaded := backend.flowReferences[flow]; loaded {
		t.Fatal("released flow reference was retained")
	}
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("duplicate release selected an already released flow for cleanup")
	}
}
