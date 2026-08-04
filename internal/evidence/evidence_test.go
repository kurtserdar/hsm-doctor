package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

func boolp(v bool) *bool { return &v }

func sampleInventory() *inventory.Inventory {
	return &inventory.Inventory{
		Slot: p11.SlotInfo{Token: &p11.TokenInfo{Label: "PROD", SerialNumber: "S-1", Model: "vHSM"}},
		Objects: []inventory.Object{
			{Class: inventory.ClassPrivateKey, Label: "leaky", KeyType: "RSA", KeyBits: 2048,
				Extractable: boolp(true)},
		},
	}
}

func samplePack() LoadedPack {
	return LoadedPack{
		Name:        "test-pack",
		Description: "unit test controls",
		Config: &policy.Config{Rules: []policy.Rule{
			// Fails: the private key is extractable.
			{ID: "T-001", Title: "No extractable private keys", Severity: policy.SevCritical,
				Remediation: "Regenerate non-extractable.",
				Match:       policy.Condition{Class: inventory.ClassPrivateKey, Extractable: boolp(true)}},
			// Passes: applicable (a private key exists) but the condition
			// (DSA key type) does not match the RSA key.
			{ID: "T-002", Title: "No DSA private keys", Severity: policy.SevMedium,
				Match: policy.Condition{Class: inventory.ClassPrivateKey, KeyType: "DSA"}},
			// Not applicable: no certificate objects on the token.
			{ID: "T-003", Title: "Certificates not expired", Severity: policy.SevHigh,
				Match: policy.Condition{Class: inventory.ClassCertificate, CertExpired: boolp(true)}},
		}},
	}
}

func TestBuildStatuses(t *testing.T) {
	rep := Build("test", sampleInventory(), []LoadedPack{samplePack()},
		time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))

	if len(rep.Packs) != 1 {
		t.Fatalf("want 1 pack, got %d", len(rep.Packs))
	}
	p := rep.Packs[0]
	if p.Passed != 1 || p.Failed != 1 || p.NotApplicable != 1 {
		t.Errorf("summary wrong: pass=%d fail=%d na=%d", p.Passed, p.Failed, p.NotApplicable)
	}

	status := map[string]Status{}
	for _, c := range p.Controls {
		status[c.RuleID] = c.Status
	}
	if status["T-001"] != StatusFail {
		t.Errorf("T-001 should fail: %v", status["T-001"])
	}
	if status["T-002"] != StatusPass {
		t.Errorf("T-002 should pass: %v", status["T-002"])
	}
	if status["T-003"] != StatusNotApplicable {
		t.Errorf("T-003 should be N/A (no certificates): %v", status["T-003"])
	}

	// The failing control must carry the offending object and its remediation.
	for _, c := range p.Controls {
		if c.RuleID == "T-001" {
			if len(c.Violations) != 1 || c.Remediation == "" {
				t.Errorf("failing control missing violations/remediation: %+v", c)
			}
		}
	}
}

func TestBuildTokenIdentity(t *testing.T) {
	rep := Build("v9", sampleInventory(), []LoadedPack{samplePack()}, time.Now())
	if rep.Token.Label != "PROD" || rep.Token.SerialNumber != "S-1" || rep.Version != "v9" {
		t.Errorf("token/version metadata wrong: %+v tool=%s", rep.Token, rep.Version)
	}
	if rep.GeneratedAt == "" {
		t.Error("generated_at should be set")
	}
}

func TestTokenScopedRuleAlwaysApplicable(t *testing.T) {
	// A mechanism rule targets the token, not objects, so on an empty token it
	// is applicable (and passes when the mechanism is absent), never N/A.
	inv := &inventory.Inventory{Slot: p11.SlotInfo{Token: &p11.TokenInfo{Label: "empty"}}}
	pack := LoadedPack{Name: "m", Config: &policy.Config{Rules: []policy.Rule{
		{ID: "M-1", Title: "risky mechanism absent", Severity: policy.SevLow,
			Match: policy.Condition{MechanismAnyOf: []string{"CKM_DES_ECB"}}},
	}}}
	rep := Build("t", inv, []LoadedPack{pack}, time.Now())
	if s := rep.Packs[0].Controls[0].Status; s != StatusPass {
		t.Errorf("absent risky mechanism should PASS, got %v", s)
	}
}

func TestRenderers(t *testing.T) {
	rep := Build("test", sampleInventory(), []LoadedPack{samplePack()}, time.Now())

	var j bytes.Buffer
	if err := rep.JSON(&j); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(j.Bytes(), &back); err != nil {
		t.Fatalf("JSON round-trip: %v", err)
	}

	var h bytes.Buffer
	if err := rep.HTML(&h); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := h.String()
	for _, want := range []string{"compliance evidence", "test-pack", "T-001", "FAIL", "N/A",
		"not a compliance or certification statement"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}
