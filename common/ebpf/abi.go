package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17

	addressFamilyIPv4 = 2
	addressFamilyIPv6 = 10
)

type OriginalDestination struct {
	Destination  netip.AddrPort
	ConnectedUDP bool
}

type redirectKey struct {
	Family       uint8
	Protocol     uint8
	RedirectPort uint16
	RedirectAddr [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type originalDestination struct {
	Family   uint8
	Protocol uint8
	Port     uint16
	Addr     [16]byte
	Flags    uint8
	Reserved [3]byte
}

func makeRedirectKey(protocol uint8, redirect netip.AddrPort, client netip.AddrPort) (redirectKey, error) {
	var key redirectKey
	key.Protocol = protocol
	key.RedirectPort = redirect.Port()
	key.ClientPort = client.Port()
	if err := putAddress(&key.Family, &key.RedirectAddr, redirect.Addr()); err != nil {
		return redirectKey{}, E.Cause(err, "invalid redirect address")
	}
	if client.IsValid() {
		clientAddress := client.Addr().Unmap()
		if clientAddress.Is4() {
			address := clientAddress.As4()
			copy(key.ClientAddr[:4], address[:])
		} else if clientAddress.Is6() {
			address := clientAddress.As16()
			copy(key.ClientAddr[:], address[:])
		}
	}
	return key, nil
}

func putAddress(family *uint8, destination *[16]byte, source netip.Addr) error {
	source = source.Unmap()
	if source.Is4() {
		*family = addressFamilyIPv4
		address := source.As4()
		copy(destination[:4], address[:])
		return nil
	}
	if source.Is6() {
		*family = addressFamilyIPv6
		address := source.As16()
		copy(destination[:], address[:])
		return nil
	}
	return E.New("invalid IP address")
}
