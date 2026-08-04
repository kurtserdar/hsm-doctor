//go:build integration

package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

// A CBOM built from a real SoftHSM inventory must be well-formed CycloneDX and
// describe the token that owns the assets.
func TestCBOMAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{Label: "cbom-rsa", ID: []byte{0x01}, Bits: 2048})
	testutil.GenerateECKeyPair(t, sess, "cbom-ec", []byte{0x02})
	sess.Close()

	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	rep := report.New("test", inv, &policy.Result{})

	var buf bytes.Buffer
	if err := rep.CBOM(&buf); err != nil {
		t.Fatalf("CBOM: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	if m["specVersion"] != "1.6" {
		t.Errorf("wrong specVersion: %v", m["specVersion"])
	}
	if comp, _ := m["metadata"].(map[string]any)["component"].(map[string]any); comp == nil || comp["type"] != "device" {
		t.Error("CBOM must carry the token as a device component")
	}
	// The two generated keys and their algorithms must surface.
	if len(m["components"].([]any)) < 3 {
		t.Errorf("expected keys + algorithm components, got %d", len(m["components"].([]any)))
	}
}
