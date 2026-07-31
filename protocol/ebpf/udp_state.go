//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

type udpClientTable struct {
	access             sync.RWMutex
	clients            map[netip.AddrPort]*udpClientState
	redirectAccess     sync.Mutex
	redirectReferences map[udpRedirectReference]uint32
}

type udpClientState struct {
	access    sync.RWMutex
	connected bool
	uid       uint32
	bindings  map[netip.AddrPort]udpRedirectBinding
}

type udpRedirectBinding struct {
	address    netip.Addr
	connected  bool
	reference  udpRedirectReference
	sharedFlow *ECommon.SharedNetworkFlow
}

type udpRedirectReference struct {
	client  netip.AddrPort
	address netip.Addr
}

type udpRedirectRelease struct {
	reference  udpRedirectReference
	sharedFlow *ECommon.SharedNetworkFlow
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	t.access.RUnlock()
	return clientState, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	t.access.Lock()
	defer t.access.Unlock()
	return t.loadOrCreateLocked(client)
}

func (t *udpClientTable) loadOrCreateLocked(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.clients[client]; loaded {
		return clientState
	}
	if t.clients == nil {
		t.clients = make(map[netip.AddrPort]*udpClientState)
	}
	clientState := &udpClientState{bindings: make(map[netip.AddrPort]udpRedirectBinding)}
	t.clients[client] = clientState
	return clientState
}

func (t *udpClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
	uid uint32,
) []netip.Addr {
	releases := t.setBinding0(
		client,
		destination,
		redirectAddress,
		connected,
		uid,
		udpRedirectReference{address: redirectAddress},
		nil,
	)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *udpClientTable) setSharedBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	flow *ECommon.SharedNetworkFlow,
) []udpRedirectRelease {
	return t.setBinding0(
		client,
		destination,
		redirectAddress,
		false,
		0,
		udpRedirectReference{client: client, address: redirectAddress},
		flow,
	)
}

func (t *udpClientTable) setBinding0(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
	uid uint32,
	reference udpRedirectReference,
	sharedFlow *ECommon.SharedNetworkFlow,
) []udpRedirectRelease {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	if loaded {
		released := t.setClientBinding(
			clientState, destination, redirectAddress, connected, uid, reference, sharedFlow,
		)
		t.access.RUnlock()
		return released
	}
	t.access.RUnlock()

	t.access.Lock()
	clientState = t.loadOrCreateLocked(client)
	released := t.setClientBinding(
		clientState, destination, redirectAddress, connected, uid, reference, sharedFlow,
	)
	t.access.Unlock()
	return released
}

func (t *udpClientTable) setClientBinding(
	clientState *udpClientState,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
	uid uint32,
	reference udpRedirectReference,
	sharedFlow *ECommon.SharedNetworkFlow,
) []udpRedirectRelease {
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	uidMatches := clientState.uid == uid
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected && uidMatches {
		return nil
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	clientState.uid = uid
	if loaded && current.address == redirectAddress && current.connected == connected {
		return nil
	}
	clientState.bindings[destination] = udpRedirectBinding{
		address:    redirectAddress,
		connected:  connected,
		reference:  reference,
		sharedFlow: sharedFlow,
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if !connected {
		t.retainRedirectLocked(reference)
	}
	if loaded && !current.connected && t.releaseRedirectLocked(current.reference) {
		return []udpRedirectRelease{{
			reference:  current.reference,
			sharedFlow: current.sharedFlow,
		}}
	}
	return nil
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	releases := t.delete0(client, expected)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *udpClientTable) deleteShared(client netip.AddrPort, expected *udpClientState) []udpRedirectRelease {
	return t.delete0(client, expected)
}

func (t *udpClientTable) delete0(client netip.AddrPort, expected *udpClientState) []udpRedirectRelease {
	t.access.Lock()
	defer t.access.Unlock()
	if t.clients[client] != expected {
		return nil
	}
	delete(t.clients, client)

	expected.access.Lock()
	defer expected.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []udpRedirectRelease
	for _, binding := range expected.bindings {
		if !binding.connected && t.releaseRedirectLocked(binding.reference) {
			released = append(released, udpRedirectRelease{
				reference:  binding.reference,
				sharedFlow: binding.sharedFlow,
			})
		}
	}
	clear(expected.bindings)
	return released
}

func (t *udpClientTable) retainRedirectLocked(reference udpRedirectReference) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[udpRedirectReference]uint32)
	}
	t.redirectReferences[reference]++
}

func (t *udpClientTable) releaseRedirectLocked(reference udpRedirectReference) bool {
	references := t.redirectReferences[reference]
	if references > 1 {
		t.redirectReferences[reference] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, reference)
		return true
	}
	return false
}

func (s *udpClientState) redirectAddress(destination netip.AddrPort) (netip.Addr, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding.address, loaded
}

func (s *udpClientState) setConnected(connected bool) {
	s.access.Lock()
	s.connected = connected
	s.access.Unlock()
}

func (s *udpClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}

func (s *udpClientState) sourceUID() uint32 {
	s.access.RLock()
	uid := s.uid
	s.access.RUnlock()
	return uid
}
