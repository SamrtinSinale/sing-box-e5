package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestRedirectABI(t *testing.T) {
	if size := unsafe.Sizeof(redirectKey{}); size != 40 {
		t.Fatalf("unexpected redirect key size: %d", size)
	}
	if size := unsafe.Sizeof(originalDestination{}); size != 24 {
		t.Fatalf("unexpected original destination size: %d", size)
	}

	key, err := makeRedirectKey(
		ProtocolUDP,
		netip.MustParseAddrPort("[::ffff:127.2.3.4]:65532"),
		netip.MustParseAddrPort("[::ffff:127.0.0.1]:12345"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.RedirectPort != 65532 || key.ClientPort != 12345 {
		t.Fatalf("unexpected redirect key header: %+v", key)
	}
	if [4]byte(key.RedirectAddr[:4]) != [4]byte{127, 2, 3, 4} {
		t.Fatalf("unexpected redirect address: %v", key.RedirectAddr)
	}
	if [4]byte(key.ClientAddr[:4]) != [4]byte{127, 0, 0, 1} {
		t.Fatalf("unexpected client address: %v", key.ClientAddr)
	}
}
