//go:build integration

package pqc_test

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/pqc"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

// SoftHSM 2.6 predates PKCS#11 3.2: the correct result is a clean
// NOT READY with no functional probes, not an error.
func TestDetectAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	mechs, err := client.Mechanisms(slot)
	if err != nil {
		t.Fatalf("Mechanisms: %v", err)
	}
	det := pqc.Detect(mechs)
	if det.Verdict != pqc.VerdictNotReady {
		t.Errorf("SoftHSM verdict: want NOT READY, got %s", det.Verdict)
	}
	for _, f := range det.Families {
		if f.Advertised || f.Incomplete {
			t.Errorf("family %s should be fully unadvertised on SoftHSM: %+v", f.Family, f)
		}
	}

	results, err := pqc.RunTests(client, slot, testutil.UserPIN, det)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("no families advertised, so no probes should run: %+v", results)
	}
}
