//go:build integration

package doctor_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/doctor"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/kurtserdar/hsm-doctor/rules"
)

func TestDoctorAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	// A weak, extractable key guarantees a critical posture finding.
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{Label: "weak", ID: []byte{0x01}, Bits: 1024, Extractable: true})
	sess.Close()

	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cfg, err := policy.Load(rules.Default)
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	rep := report.New("test", inv, policy.Evaluate(inv, cfg, time.Now()))

	diag := doctor.Build("test", doctor.Input{Report: rep})
	if diag.Verdict != doctor.VerdictCritical {
		t.Errorf("extractable weak key should yield a critical verdict, got %s", diag.Verdict)
	}
	if len(diag.Issues) == 0 {
		t.Error("expected at least one issue")
	}

	var txt bytes.Buffer
	if err := diag.Text(&txt); err != nil {
		t.Fatalf("Text: %v", err)
	}
}
