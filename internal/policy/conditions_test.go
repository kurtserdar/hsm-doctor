package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

// evalOne runs a single rule against a single-object inventory.
func evalOne(t *testing.T, rule Rule, obj inventory.Object, mechs ...string) *Result {
	t.Helper()
	inv := &inventory.Inventory{Objects: []inventory.Object{obj}}
	for _, m := range mechs {
		inv.Mechanisms = append(inv.Mechanisms, p11.Mechanism{Name: m})
	}
	cfg := &Config{Rules: []Rule{rule}}
	return Evaluate(inv, cfg, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
}

func TestKeyTypeInCondition(t *testing.T) {
	rule := Rule{ID: "T", Title: "legacy cipher", Severity: SevMedium,
		Match: Condition{KeyTypeIn: []string{"DES", "DES3", "RC4"}}}

	if res := evalOne(t, rule, inventory.Object{Class: inventory.ClassSecretKey, KeyType: "DES3"}); len(res.Findings) != 1 {
		t.Errorf("DES3 should match key_type_in: %+v", res.Findings)
	}
	if res := evalOne(t, rule, inventory.Object{Class: inventory.ClassSecretKey, KeyType: "AES"}); len(res.Findings) != 0 {
		t.Errorf("AES should not match: %+v", res.Findings)
	}
}

func TestCurveConditions(t *testing.T) {
	notIn := Rule{ID: "T1", Title: "curve outside allow-list", Severity: SevMedium,
		Match: Condition{Class: inventory.ClassPrivateKey, CurveNotIn: []string{"P-256", "P-384", "P-521"}}}

	if res := evalOne(t, notIn, inventory.Object{Class: inventory.ClassPrivateKey, KeyType: "EC", Curve: "secp256k1"}); len(res.Findings) != 1 {
		t.Errorf("secp256k1 should violate the allow-list: %+v", res.Findings)
	}
	if res := evalOne(t, notIn, inventory.Object{Class: inventory.ClassPrivateKey, KeyType: "EC", Curve: "P-256"}); len(res.Findings) != 0 {
		t.Errorf("P-256 is allowed: %+v", res.Findings)
	}
	// Non-EC keys expose no curve and must never match curve conditions.
	if res := evalOne(t, notIn, inventory.Object{Class: inventory.ClassPrivateKey, KeyType: "RSA"}); len(res.Findings) != 0 {
		t.Errorf("RSA key must not match curve_not_in: %+v", res.Findings)
	}

	in := Rule{ID: "T2", Title: "koblitz curve", Severity: SevLow,
		Match: Condition{CurveIn: []string{"secp256k1"}}}
	if res := evalOne(t, in, inventory.Object{Class: inventory.ClassPrivateKey, KeyType: "EC", Curve: "secp256k1"}); len(res.Findings) != 1 {
		t.Errorf("curve_in should match: %+v", res.Findings)
	}
}

func TestCertConditions(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	longValidity := Rule{ID: "T1", Title: "certificate valid too long", Severity: SevMedium,
		Match: Condition{Class: inventory.ClassCertificate, CertValidityDaysGT: 398, CertIsCA: b(false)}}
	leaf := inventory.Object{Class: inventory.ClassCertificate, Certificate: &inventory.CertInfo{
		NotBefore: now.Add(-500 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour), IsCA: false}}
	if res := evalOne(t, longValidity, leaf); len(res.Findings) != 1 {
		t.Errorf("600-day leaf certificate should match: %+v", res.Findings)
	}
	ca := leaf
	ca.Certificate = &inventory.CertInfo{NotBefore: leaf.Certificate.NotBefore, NotAfter: leaf.Certificate.NotAfter, IsCA: true}
	if res := evalOne(t, longValidity, ca); len(res.Findings) != 0 {
		t.Errorf("CA certificate is excluded via cert_is_ca=false: %+v", res.Findings)
	}

	sigAlg := Rule{ID: "T2", Title: "weak signature", Severity: SevHigh,
		Match: Condition{Class: inventory.ClassCertificate, CertSigAlgIn: []string{"SHA1-RSA", "MD5-RSA"}}}
	weak := inventory.Object{Class: inventory.ClassCertificate, Certificate: &inventory.CertInfo{
		SignatureAlgorithm: "SHA1-RSA", NotAfter: now.Add(24 * time.Hour)}}
	if res := evalOne(t, sigAlg, weak); len(res.Findings) != 1 {
		t.Errorf("SHA1-RSA cert should match: %+v", res.Findings)
	}
}

func TestTriStateAttributeConditions(t *testing.T) {
	rule := Rule{ID: "T", Title: "key was extractable at some point", Severity: SevMedium,
		Match: Condition{Class: inventory.ClassPrivateKey, NeverExtractable: b(false)}}

	hit := inventory.Object{Class: inventory.ClassPrivateKey, NeverExtractable: b(false)}
	if res := evalOne(t, rule, hit); len(res.Findings) != 1 {
		t.Errorf("never_extractable=false should match: %+v", res.Findings)
	}
	// Attribute not exposed: must not match.
	miss := inventory.Object{Class: inventory.ClassPrivateKey}
	if res := evalOne(t, rule, miss); len(res.Findings) != 0 {
		t.Errorf("absent attribute must not match: %+v", res.Findings)
	}
}

func TestMechanismMissingCondition(t *testing.T) {
	rule := Rule{ID: "T", Title: "no PQC signature mechanism", Severity: SevInfo,
		Match: Condition{MechanismMissing: []string{"CKM_ML_DSA", "CKM_ML_DSA_KEY_PAIR_GEN"}}}

	res := evalOne(t, rule, inventory.Object{}, "CKM_RSA_PKCS", "CKM_AES_GCM")
	if len(res.Findings) != 1 {
		t.Fatalf("missing mechanisms should fire: %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Detail, "none of") {
		t.Errorf("detail should explain the gap: %q", res.Findings[0].Detail)
	}
	// Score-neutral: info findings never subtract.
	if res.Score != 100 {
		t.Errorf("info finding must not affect the score: %d", res.Score)
	}

	// Advertising just one of the listed mechanisms closes the gap.
	res = evalOne(t, rule, inventory.Object{}, "CKM_ML_DSA")
	if len(res.Findings) != 0 {
		t.Errorf("present mechanism should suppress the finding: %+v", res.Findings)
	}
}

func TestMergeRejectsDuplicateIDs(t *testing.T) {
	a := &Config{Pack: &PackMeta{Name: "a"}, Rules: []Rule{{ID: "X-1", Title: "t", Severity: SevLow,
		Match: Condition{Class: inventory.ClassPrivateKey}}}}
	c := &Config{Pack: &PackMeta{Name: "c"}, Rules: []Rule{{ID: "X-1", Title: "t2", Severity: SevLow,
		Match: Condition{Class: inventory.ClassPublicKey}}}}

	if _, err := Merge(a, c); err == nil || !strings.Contains(err.Error(), "X-1") {
		t.Errorf("duplicate rule IDs must be rejected: %v", err)
	}

	m, err := Merge(a, &Config{Pack: &PackMeta{Name: "b"}, Rules: []Rule{{ID: "Y-1", Title: "t", Severity: SevLow,
		Match: Condition{Class: inventory.ClassPrivateKey}}}})
	if err != nil || len(m.Rules) != 2 {
		t.Errorf("merge failed: %v, %+v", err, m)
	}
}

func TestInfoSeverityIsValidAndSortsLast(t *testing.T) {
	if !SevInfo.Valid() {
		t.Error("info must be a valid severity")
	}
	cfg := &Config{Rules: []Rule{
		{ID: "A", Title: "advisory", Severity: SevInfo, Match: Condition{Class: inventory.ClassPrivateKey}},
		{ID: "B", Title: "serious", Severity: SevHigh, Match: Condition{Class: inventory.ClassPrivateKey}},
	}}
	inv := &inventory.Inventory{Objects: []inventory.Object{{Class: inventory.ClassPrivateKey, Label: "k"}}}
	res := Evaluate(inv, cfg, time.Now())
	if len(res.Findings) != 2 || res.Findings[0].Severity != SevHigh || res.Findings[1].Severity != SevInfo {
		t.Errorf("info must sort after high: %+v", res.Findings)
	}
	if res.Score != 90 {
		t.Errorf("only the high finding should cost points: %d", res.Score)
	}
}

func TestCertLifecycleConditions(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	shortLived := Rule{ID: "SL", Title: "short-lived certificate", Severity: SevInfo,
		Match: Condition{Class: inventory.ClassCertificate, CertValidityDaysLT: 48}}

	// 41-day validity matches; a 100-day certificate does not.
	c41 := inventory.Object{Class: inventory.ClassCertificate,
		Certificate: &inventory.CertInfo{NotBefore: now.Add(-1 * day), NotAfter: now.Add(40 * day)}}
	if res := Evaluate(single(c41), &Config{Rules: []Rule{shortLived}}, now); len(res.Findings) != 1 {
		t.Errorf("41-day cert should be short-lived: %+v", res.Findings)
	}
	c100 := inventory.Object{Class: inventory.ClassCertificate,
		Certificate: &inventory.CertInfo{NotBefore: now.Add(-1 * day), NotAfter: now.Add(99 * day)}}
	if res := Evaluate(single(c100), &Config{Rules: []Rule{shortLived}}, now); len(res.Findings) != 0 {
		t.Errorf("100-day cert is not short-lived: %+v", res.Findings)
	}

	pastPct := Rule{ID: "PP", Title: "past renewal threshold", Severity: SevMedium,
		Match: Condition{Class: inventory.ClassCertificate, CertLifetimeRemainingPctLT: 20}}

	// 100-day lifetime with 10 days left = 10% remaining -> matches < 20%.
	c10pct := inventory.Object{Class: inventory.ClassCertificate,
		Certificate: &inventory.CertInfo{NotBefore: now.Add(-90 * day), NotAfter: now.Add(10 * day)}}
	if res := Evaluate(single(c10pct), &Config{Rules: []Rule{pastPct}}, now); len(res.Findings) != 1 {
		t.Errorf("10%% remaining should match past-threshold: %+v", res.Findings)
	}
	// 50% remaining does not match.
	c50pct := inventory.Object{Class: inventory.ClassCertificate,
		Certificate: &inventory.CertInfo{NotBefore: now.Add(-50 * day), NotAfter: now.Add(50 * day)}}
	if res := Evaluate(single(c50pct), &Config{Rules: []Rule{pastPct}}, now); len(res.Findings) != 0 {
		t.Errorf("50%% remaining should not match: %+v", res.Findings)
	}
	// Already-expired certificates are left to cert_expired rules.
	cExpired := inventory.Object{Class: inventory.ClassCertificate,
		Certificate: &inventory.CertInfo{NotBefore: now.Add(-100 * day), NotAfter: now.Add(-1 * day)}}
	if res := Evaluate(single(cExpired), &Config{Rules: []Rule{pastPct}}, now); len(res.Findings) != 0 {
		t.Errorf("expired cert must not match lifetime-percentage rule: %+v", res.Findings)
	}
}

func single(obj inventory.Object) *inventory.Inventory {
	return &inventory.Inventory{Objects: []inventory.Object{obj}}
}
