package pqc

import (
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

func b(v bool) *bool { return &v }

func mechs(codes ...uint) []p11.Mechanism {
	out := make([]p11.Mechanism, len(codes))
	for i, c := range codes {
		out[i] = p11.Mechanism{Code: c}
	}
	return out
}

func TestDetectNotReady(t *testing.T) {
	// A classical-only token (RSA + AES mechanisms).
	d := Detect(mechs(0x0000, 0x0001, 0x1085))
	if d.Verdict != VerdictNotReady {
		t.Errorf("verdict: want NOT READY, got %s", d.Verdict)
	}
	for _, f := range d.Families {
		if f.Advertised || f.Incomplete {
			t.Errorf("family %s should not be advertised: %+v", f.Family, f)
		}
	}
}

func TestDetectReady(t *testing.T) {
	d := Detect(mechs(
		CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
		CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKM_HASH_ML_DSA,
	))
	if d.Verdict != VerdictReady {
		t.Errorf("verdict: want READY, got %s", d.Verdict)
	}
	byName := map[string]FamilyStatus{}
	for _, f := range d.Families {
		byName[f.Family] = f
	}
	if !byName["ML-KEM"].Advertised || !byName["ML-DSA"].Advertised {
		t.Errorf("ML-KEM and ML-DSA should be advertised: %+v", d.Families)
	}
	if byName["SLH-DSA"].Advertised {
		t.Error("SLH-DSA should not be advertised")
	}
	if len(byName["ML-DSA"].Mechanisms) != 3 {
		t.Errorf("ML-DSA should list 3 mechanisms: %+v", byName["ML-DSA"].Mechanisms)
	}
}

func TestDetectPartialAndIncomplete(t *testing.T) {
	// Only SLH-DSA fully advertised; ML-DSA keygen without the sign
	// mechanism is incomplete.
	d := Detect(mechs(CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKM_ML_DSA_KEY_PAIR_GEN))
	if d.Verdict != VerdictPartial {
		t.Errorf("verdict: want PARTIAL, got %s", d.Verdict)
	}
	for _, f := range d.Families {
		if f.Family == "ML-DSA" && !f.Incomplete {
			t.Errorf("ML-DSA with keygen only should be incomplete: %+v", f)
		}
	}
}

func TestDetectVendorDefined(t *testing.T) {
	d := Detect(mechs(0x0000, 0x80000A01, 0x80000A02))
	if len(d.VendorDefined) != 2 || d.VendorDefined[0] != "0x80000A01" {
		t.Errorf("vendor-defined codes not reported: %+v", d.VendorDefined)
	}
}

func TestAssessExposure(t *testing.T) {
	inv := &inventory.Inventory{Objects: []inventory.Object{
		{Class: inventory.ClassPrivateKey, KeyType: "RSA", Sign: b(true), Decrypt: b(true)},
		{Class: inventory.ClassPrivateKey, KeyType: "RSA", Unwrap: b(true)},
		{Class: inventory.ClassPrivateKey, KeyType: "EC", Sign: b(true)},
		{Class: inventory.ClassPrivateKey, KeyType: "ML-DSA", Sign: b(true)},
		{Class: inventory.ClassCertificate, Certificate: &inventory.CertInfo{PublicKeyAlgorithm: "RSA"}},
		{Class: inventory.ClassSecretKey, KeyType: "AES"},
	}}
	det := Detect(nil)

	e := Assess(inv, det)
	if e.TotalPrivateKeys != 4 || e.ClassicalPrivateKeys != 3 || e.PQCPrivateKeys != 1 {
		t.Errorf("key counts wrong: %+v", e)
	}
	if e.HarvestNowDecryptLater != 2 {
		t.Errorf("HNDL count: want 2 (decrypt + unwrap), got %d", e.HarvestNowDecryptLater)
	}
	if e.ClassicalCertificates != 1 {
		t.Errorf("classical certs: want 1, got %d", e.ClassicalCertificates)
	}
	if !strings.Contains(e.Summary, "75%") {
		t.Errorf("summary should mention the classical share: %q", e.Summary)
	}
	if !strings.Contains(e.Summary, "no migration path") {
		t.Errorf("summary should reflect NOT READY verdict: %q", e.Summary)
	}
}

func TestAssessEmptyInventory(t *testing.T) {
	det := Detect(mechs(CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA))
	e := Assess(&inventory.Inventory{}, det)
	if e.TotalPrivateKeys != 0 {
		t.Errorf("expected empty inventory: %+v", e)
	}
	if !strings.Contains(e.Summary, "post-quantum from day one") {
		t.Errorf("summary should be positive for a READY empty token: %q", e.Summary)
	}
}
