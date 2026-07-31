//go:build with_ebpf && (linux || android) && cgo && (386 || amd64 || arm || arm64)

package ebpf

import (
	"net/netip"
	"os"
	"testing"
)

const integrationTestEnv = "SING_BOX_EBPF_INTEGRATION"

func TestBackendProgramLoadIntegration(t *testing.T) {
	if os.Getenv(integrationTestEnv) != "1" {
		t.Skip("set " + integrationTestEnv + "=1 to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}

	backend, err := Prepare(
		os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		65532,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		Policy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})

	programs := backend.AttachedPrograms()
	if !containsProgram(programs, "sb_ebpf_rel (cgroup/sock_release)") {
		t.Fatalf("socket-release program was not built: %v", programs)
	}
	stats, err := backend.RuntimeStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats != (RuntimeStats{}) {
		t.Fatalf("new eBPF backend has non-zero runtime stats: %+v", stats)
	}

	if os.Getenv("SING_BOX_EBPF_INTEGRATION_ATTACH") == "1" {
		if err = backend.Attach(); err != nil {
			t.Fatal(err)
		}
	}
}

func containsProgram(programs []string, expected string) bool {
	for _, program := range programs {
		if program == expected {
			return true
		}
	}
	return false
}
