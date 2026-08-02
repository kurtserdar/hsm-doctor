package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/rules"
)

func b(v bool) *bool { return &v }

// testInventory builds a synthetic inventory that triggers every default rule.
func testInventory(now time.Time) *inventory.Inventory {
	valid := now.Add(365 * 24 * time.Hour)
	return &inventory.Inventory{
		Mechanisms: []p11.Mechanism{
			{Name: "CKM_RSA_PKCS"},
			{Name: "CKM_SHA1_RSA_PKCS"},
			{Name: "CKM_DES_CBC"},
		},
		Objects: []inventory.Object{
			// Fires HSM-001/002/003/007/009: weak, extractable, non-sensitive,
			// orphaned RSA key that both signs and decrypts.
			{Class: inventory.ClassPrivateKey, Label: "bad-key", ID: "01",
				KeyType: "RSA", KeyBits: 1024,
				Extractable: b(true), Sensitive: b(false), Sign: b(true), Decrypt: b(true)},

			// Healthy pair: no findings.
			{Class: inventory.ClassPrivateKey, Label: "good-key", ID: "02",
				KeyType: "RSA", KeyBits: 3072,
				Extractable: b(false), Sensitive: b(true), Sign: b(true), Decrypt: b(false)},
			{Class: inventory.ClassPublicKey, Label: "good-key", ID: "02", KeyType: "RSA", KeyBits: 3072},
			{Class: inventory.ClassCertificate, Label: "good-cert", ID: "02",
				Certificate: &inventory.CertInfo{NotAfter: valid}},

			// Fires HSM-004 and HSM-008: expired and orphaned certificate.
			{Class: inventory.ClassCertificate, Label: "expired-cert", ID: "03",
				Certificate: &inventory.CertInfo{NotAfter: now.Add(-24 * time.Hour)}},

			// Fires HSM-005 only: certificate expiring in 10 days, key present.
			{Class: inventory.ClassPrivateKey, Label: "soon-key", ID: "04",
				KeyType: "EC", KeyBits: 256,
				Extractable: b(false), Sensitive: b(true), Sign: b(true)},
			{Class: inventory.ClassCertificate, Label: "soon-cert", ID: "04",
				Certificate: &inventory.CertInfo{NotAfter: now.Add(10 * 24 * time.Hour)}},

			// Fires HSM-006 twice: duplicate labels within one class.
			{Class: inventory.ClassSecretKey, Label: "dup", ID: "05", KeyType: "AES", KeyBits: 256,
				Sensitive: b(true), Extractable: b(false)},
			{Class: inventory.ClassSecretKey, Label: "dup", ID: "06", KeyType: "AES", KeyBits: 256,
				Sensitive: b(true), Extractable: b(false)},

			// Fires HSM-012 and HSM-013: a secret key that is neither sensitive
			// nor non-extractable.
			{Class: inventory.ClassSecretKey, Label: "leaky-secret", ID: "07", KeyType: "AES", KeyBits: 256,
				Sensitive: b(false), Extractable: b(true)},

			// Fires HSM-011 only: SHA-1 signed certificate. Shares ID 02 with a
			// key (not orphaned) and expires far in the future.
			{Class: inventory.ClassCertificate, Label: "weak-cert", ID: "02",
				Certificate: &inventory.CertInfo{NotAfter: valid, SignatureAlgorithm: "SHA1-RSA"}},

			// Fires HSM-014: self-signed non-CA certificate.
			{Class: inventory.ClassCertificate, Label: "selfsigned-cert", ID: "02",
				Certificate: &inventory.CertInfo{NotAfter: valid, SelfSigned: true, IsCA: false}},

			// Fires HSM-015: certificate not yet valid (notBefore in the future).
			{Class: inventory.ClassCertificate, Label: "future-cert", ID: "02",
				Certificate: &inventory.CertInfo{NotBefore: now.Add(48 * time.Hour), NotAfter: valid}},

			// Fires HSM-016: certificate carrying a weak RSA public key.
			{Class: inventory.ClassCertificate, Label: "weakkey-cert", ID: "02",
				Certificate: &inventory.CertInfo{NotAfter: valid, PublicKeyAlgorithm: "RSA", PublicKeyBits: 1024}},

			// Fires HSM-017: CA certificate without keyCertSign usage.
			{Class: inventory.ClassCertificate, Label: "ca-nokcs", ID: "02",
				Certificate: &inventory.CertInfo{NotAfter: valid, IsCA: true, KeyUsage: []string{"digitalSignature"}}},

			// Fires HSM-018: certificate whose public key does not match the key
			// sharing its CKA_ID. The key itself is otherwise healthy.
			{Class: inventory.ClassPrivateKey, Label: "mk", ID: "08",
				KeyType: "RSA", KeyBits: 3072, Extractable: b(false), Sensitive: b(true), Sign: b(true),
				PublicKeyFingerprint: "aaaa"},
			{Class: inventory.ClassCertificate, Label: "mismatch-cert", ID: "08",
				Certificate: &inventory.CertInfo{NotAfter: valid, PublicKeyFingerprint: "bbbb"}},

			// A matching cert/key pair (same fingerprint) must NOT fire HSM-018.
			{Class: inventory.ClassPrivateKey, Label: "gk", ID: "09",
				KeyType: "RSA", KeyBits: 3072, Extractable: b(false), Sensitive: b(true), Sign: b(true),
				PublicKeyFingerprint: "cccc"},
			{Class: inventory.ClassCertificate, Label: "match-cert", ID: "09",
				Certificate: &inventory.CertInfo{NotAfter: valid, PublicKeyFingerprint: "cccc"}},

			// Fires HSM-019: certificate whose chain did not validate (shares
			// ID 09 with a key, so not orphaned).
			{Class: inventory.ClassCertificate, Label: "broken-chain", ID: "09",
				Certificate: &inventory.CertInfo{NotAfter: valid,
					ChainStatus: "unverified: x509: certificate signed by unknown authority"}},
		},
	}
}

func findingsByRule(res *Result) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range res.Findings {
		out[f.RuleID] = append(out[f.RuleID], f)
	}
	return out
}

func TestEvaluateDefaultRules(t *testing.T) {
	cfg, err := Load(rules.Default)
	if err != nil {
		t.Fatalf("loading default rules: %v", err)
	}
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	res := Evaluate(testInventory(now), cfg, now)

	byRule := findingsByRule(res)
	wantCounts := map[string]int{
		"HSM-001": 1, "HSM-002": 1, "HSM-003": 1, "HSM-004": 1, "HSM-005": 1,
		"HSM-006": 2, "HSM-007": 1, "HSM-008": 1, "HSM-009": 1, "HSM-010": 1,
		"HSM-011": 1, "HSM-012": 1, "HSM-013": 1, "HSM-014": 1, "HSM-015": 1,
		"HSM-016": 1, "HSM-017": 1, "HSM-018": 1, "HSM-019": 1,
	}
	for id, want := range wantCounts {
		if got := len(byRule[id]); got != want {
			t.Errorf("rule %s: want %d finding(s), got %d: %+v", id, want, got, byRule[id])
		}
	}
	if len(res.Findings) != 20 {
		t.Errorf("total findings: want 20, got %d", len(res.Findings))
	}

	// Findings must be sorted most-severe first.
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Severity.Rank() > res.Findings[i].Severity.Rank() {
			t.Errorf("findings not sorted by severity at index %d", i)
		}
	}

	// 2*critical(25) + 2*high(10) + 6*medium(5) + 1*low(2) = 102 > 100 → floor 0.
	if res.Score != 0 {
		t.Errorf("score: want 0 (floored), got %d", res.Score)
	}

	// The healthy pair must not appear in any finding.
	for _, f := range res.Findings {
		if f.Object != "" && (strings.Contains(f.Object, "good-key") || strings.Contains(f.Object, "good-cert")) {
			t.Errorf("healthy object flagged: %+v", f)
		}
	}
}

func TestScoreArithmetic(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{{
			ID: "T-1", Title: "expiring cert", Severity: SevMedium,
			Match: Condition{Class: inventory.ClassCertificate, CertExpiresWithinDays: 30},
		}},
	}
	now := time.Now()
	inv := &inventory.Inventory{Objects: []inventory.Object{
		{Class: inventory.ClassCertificate, Label: "c1", ID: "01",
			Certificate: &inventory.CertInfo{NotAfter: now.Add(5 * 24 * time.Hour)}},
	}}
	res := Evaluate(inv, cfg, now)
	if len(res.Findings) != 1 || res.Score != 95 {
		t.Errorf("want 1 finding and score 95, got %d findings, score %d", len(res.Findings), res.Score)
	}
}

func TestConditionRequiresExposedAttribute(t *testing.T) {
	cfg := &Config{Rules: []Rule{{
		ID: "T-1", Title: "extractable", Severity: SevCritical,
		Match: Condition{Class: inventory.ClassPrivateKey, Extractable: b(true)},
	}}}
	// Attribute not exposed (nil): the rule must NOT fire on absence.
	inv := &inventory.Inventory{Objects: []inventory.Object{
		{Class: inventory.ClassPrivateKey, Label: "k", ID: "01"},
	}}
	res := Evaluate(inv, cfg, time.Now())
	if len(res.Findings) != 0 {
		t.Errorf("rule fired on absent attribute: %+v", res.Findings)
	}
}
