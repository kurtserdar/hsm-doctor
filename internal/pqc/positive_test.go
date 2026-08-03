//go:build integration

package pqc_test

import (
	"os"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
)

// TestPositivePathAgainstPQCModule exercises the happy path against a
// PKCS#11 3.2 module with real PQC support (e.g. Kryoptic in CI). It is
// skipped unless HSMDOCTOR_PQC_MODULE points at such a module with an
// initialized token.
func TestPositivePathAgainstPQCModule(t *testing.T) {
	module := os.Getenv("HSMDOCTOR_PQC_MODULE")
	if module == "" {
		t.Skip("HSMDOCTOR_PQC_MODULE not set; skipping positive PQC path")
	}
	pin := os.Getenv("HSMDOCTOR_PQC_PIN")
	if pin == "" {
		pin = "123456"
	}

	client, err := p11.Open(module)
	if err != nil {
		t.Fatalf("opening PQC module: %v", err)
	}
	defer client.Close()

	slots, err := client.Slots()
	if err != nil {
		t.Fatalf("listing slots: %v", err)
	}
	var slot *uint
	for _, s := range slots {
		if s.TokenPresent && s.Token != nil && s.Token.Initialized {
			id := s.ID
			slot = &id
			break
		}
	}
	if slot == nil {
		t.Fatal("no initialized token found in the PQC module")
	}

	mechs, err := client.Mechanisms(*slot)
	if err != nil {
		t.Fatalf("listing mechanisms: %v", err)
	}
	det := pqc.Detect(mechs)
	if det.Verdict == pqc.VerdictNotReady {
		t.Fatalf("module was declared PQC-capable but advertises no PQC mechanisms: %+v", det.Families)
	}

	results, err := pqc.RunTests(client, *slot, pin, det)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no functional probes ran despite advertised families")
	}

	passes := 0
	mlkemPass := 0
	for _, r := range results {
		t.Logf("%s %s: %s %s", r.Family, r.Set, r.Status, r.Detail)
		if r.Status == pqc.TestFail {
			t.Errorf("%s %s failed functionally: %s", r.Family, r.Set, r.Detail)
		}
		if r.Status == pqc.TestPass {
			passes++
			if r.Family == "ML-KEM" {
				mlkemPass++
			}
		}
	}
	if passes == 0 {
		t.Errorf("expected at least one parameter set to pass functionally: %+v", results)
	}
	// The module has real PQC support, so ML-KEM must complete the full
	// encapsulate/decapsulate round trip, not just key generation.
	if mlkemPass == 0 {
		t.Errorf("expected ML-KEM encapsulate/decapsulate to pass on a 3.2 module: %+v", results)
	}
}
