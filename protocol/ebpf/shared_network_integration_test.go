//go:build with_ebpf && linux && cgo

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/net/ipv4"
)

func TestSharedNetworkDataPathIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_SHARED_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_SHARED_INTEGRATION=1 to run the root TC integration test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-network integration test requires root")
	}

	const (
		namespace = "sb-ebpf-test"
		hostLink  = "sbe-host"
		peerLink  = "sbe-peer"
	)
	runIP := func(arguments ...string) {
		t.Helper()
		command := exec.Command("ip", arguments...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
	}
	_ = exec.Command("ip", "netns", "del", namespace).Run()
	_ = exec.Command("ip", "link", "del", hostLink).Run()
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
		_ = exec.Command("ip", "link", "del", hostLink).Run()
	})
	runIP("netns", "add", namespace)
	runIP("link", "add", hostLink, "type", "veth", "peer", "name", peerLink)
	runIP("link", "set", peerLink, "netns", namespace)
	runIP("address", "add", "192.0.2.1/24", "dev", hostLink)
	runIP("link", "set", hostLink, "up")
	runIP("netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	runIP("netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/24", "dev", peerLink)
	runIP("netns", "exec", namespace, "ip", "link", "set", peerLink, "up")
	runIP("netns", "exec", namespace, "ip", "route", "add", "default", "via", "192.0.2.1")
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	bridgePort := uint16(tcpListener.Addr().(*net.TCPAddr).Port)
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(bridgePort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpListener.Close() })
	if err = ipv4.NewPacketConn(udpListener).SetControlMessage(ipv4.FlagDst, true); err != nil {
		t.Fatal(err)
	}

	redirectPrefix := netip.MustParsePrefix("127.128.0.0/9")
	parent, err := ECommon.Prepare("", bridgePort, true, true, redirectPrefix, netip.Prefix{}, ECommon.Policy{HijackDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	backend, err := ECommon.PrepareSharedNetwork(parent, bridgePort, true, true, redirectPrefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.UpdateHostAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	manager := &sharedTCManager{
		backend:     backend,
		logger:      discardInterfaceLogger{},
		interfaces:  []string{"sbe-not-found", hostLink},
		enableIPv4:  true,
		attachments: make(map[string]*sharedTCAttachment),
	}
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 1 {
		t.Fatalf("unexpected initial TC state: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	t.Cleanup(func() { _ = manager.closeAttachments() })

	tcpResult := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			tcpResult <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		redirect := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, lookupErr := backend.LookupOriginal(ECommon.ProtocolTCP, client, redirect)
		if lookupErr != nil {
			tcpResult <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("8.8.8.8:18080") {
			tcpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		_, writeErr := conn.Write([]byte("tcp-ok"))
		tcpResult <- writeErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-w", "3", "8.8.8.8", "18080")
	tcpOutput, err := tcpCommand.Output()
	if err != nil {
		t.Fatalf("TCP client: %v", err)
	}
	if string(tcpOutput) != "tcp-ok" {
		t.Fatalf("unexpected TCP response: %q", tcpOutput)
	}
	if err = <-tcpResult; err != nil {
		t.Fatal(err)
	}

	udpResult := make(chan error, 1)
	go func() {
		_ = udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		oob := make([]byte, 256)
		n, oobN, _, client, readErr := udpListener.ReadMsgUDPAddrPort(payload, oob)
		if readErr != nil {
			udpResult <- readErr
			return
		}
		redirectAddress, parseErr := redirectAddressFromOOB(oob[:oobN])
		if parseErr != nil {
			udpResult <- parseErr
			return
		}
		redirect := netip.AddrPortFrom(redirectAddress, bridgePort)
		original, lookupErr := backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
		if lookupErr != nil {
			udpResult <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("192.0.2.1:53") {
			udpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		controlMessage := (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
		_, _, writeErr := udpListener.WriteMsgUDPAddrPort(append([]byte("udp-ok:"), payload[:n]...), controlMessage, client)
		udpResult <- writeErr
	}()
	udpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-u", "-w", "3", "192.0.2.1", "53")
	udpCommand.Stdin = strings.NewReader("dns")
	udpOutput, err := udpCommand.Output()
	if err != nil {
		t.Fatalf("UDP client: %v", err)
	}
	if string(udpOutput) != "udp-ok:dns" {
		t.Fatalf("unexpected UDP response: %q", udpOutput)
	}
	if err = <-udpResult; err != nil {
		t.Fatal(err)
	}

	dhcpListener, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("192.0.2.1"),
		Port: 67,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dhcpListener.Close()
	dhcpResult := make(chan error, 1)
	go func() {
		_ = dhcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		n, client, readErr := dhcpListener.ReadFromUDPAddrPort(payload)
		if readErr != nil {
			dhcpResult <- readErr
			return
		}
		_, writeErr := dhcpListener.WriteToUDPAddrPort(append([]byte("dhcp-ok:"), payload[:n]...), client)
		dhcpResult <- writeErr
	}()
	dhcpContext, dhcpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dhcpCancel()
	dhcpCommand := exec.CommandContext(
		dhcpContext,
		"ip", "netns", "exec", namespace,
		"nc", "-u", "-p", "68", "-w", "2", "192.0.2.1", "67",
	)
	dhcpCommand.Stdin = strings.NewReader("discover")
	dhcpOutput, err := dhcpCommand.Output()
	if err != nil {
		t.Fatalf("DHCP client: %v", err)
	}
	if string(dhcpOutput) != "dhcp-ok:discover" {
		t.Fatalf("unexpected DHCP response: %q", dhcpOutput)
	}
	if err = <-dhcpResult; err != nil {
		t.Fatal(err)
	}

	runIP("link", "del", hostLink)
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if manager.enabled || len(manager.attachments) != 0 {
		t.Fatalf("TC state was retained after interface removal: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	runIP("link", "add", hostLink, "type", "dummy")
	runIP("link", "set", hostLink, "up")
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 1 {
		t.Fatalf("TC state was not restored after interface recreation: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
}

type discardInterfaceLogger struct{}

func (discardInterfaceLogger) Info(...any) {}
func (discardInterfaceLogger) Warn(...any) {}

type unexpectedDestinationError struct {
	destination netip.AddrPort
}

func (e *unexpectedDestinationError) Error() string {
	return "unexpected original destination: " + e.destination.String()
}
