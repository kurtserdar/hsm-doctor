package sharedkeys

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

func priv(label, fp, keyType string) inventory.Object {
	return inventory.Object{Class: inventory.ClassPrivateKey, Label: label,
		PublicKeyFingerprint: fp, KeyType: keyType}
}

func src(id int64, label string, objs ...inventory.Object) Source {
	return Source{HSMID: id, HSMLabel: label, Serial: label + "-serial",
		Inventory: &inventory.Inventory{Objects: objs}}
}

func TestDetectFlagsCrossHSMPrivateKey(t *testing.T) {
	sources := []Source{
		src(1, "hsm-a", priv("signing", "aa", "RSA"), priv("local-only", "bb", "RSA")),
		src(2, "hsm-b", priv("signing-copy", "aa", "RSA")),
	}
	shared := Detect(sources)
	if len(shared) != 1 {
		t.Fatalf("expected 1 shared key, got %d: %+v", len(shared), shared)
	}
	if shared[0].Fingerprint != "aa" || shared[0].HSMCount != 2 {
		t.Errorf("wrong shared key: %+v", shared[0])
	}
	if len(shared[0].Locations) != 2 {
		t.Errorf("expected 2 locations, got %d", len(shared[0].Locations))
	}
}

func TestDetectIgnoresSameHSMAndNonPrivate(t *testing.T) {
	// Fingerprint "aa" appears only on HSM 1 (twice) — one HSM, not shared.
	// A public key with the same fingerprint on HSM 2 must not count, since
	// only private keys are correlated.
	sources := []Source{
		src(1, "hsm-a", priv("k1", "aa", "RSA"), priv("k1-dup", "aa", "RSA")),
		{HSMID: 2, HSMLabel: "hsm-b", Inventory: &inventory.Inventory{Objects: []inventory.Object{
			{Class: inventory.ClassPublicKey, Label: "pub", PublicKeyFingerprint: "aa"},
			{Class: inventory.ClassSecretKey, Label: "aes"}, // no fingerprint
		}}},
	}
	if shared := Detect(sources); len(shared) != 0 {
		t.Errorf("nothing should be flagged, got %+v", shared)
	}
}

func TestDetectSortsMostSharedFirst(t *testing.T) {
	sources := []Source{
		src(1, "a", priv("k", "wide", "RSA"), priv("k2", "narrow", "EC")),
		src(2, "b", priv("k", "wide", "RSA"), priv("k2", "narrow", "EC")),
		src(3, "c", priv("k", "wide", "RSA")),
	}
	shared := Detect(sources)
	if len(shared) != 2 {
		t.Fatalf("expected 2 shared keys, got %d", len(shared))
	}
	if shared[0].Fingerprint != "wide" || shared[0].HSMCount != 3 {
		t.Errorf("widest-shared key should sort first: %+v", shared)
	}
	if shared[1].Fingerprint != "narrow" || shared[1].KeyType != "EC" {
		t.Errorf("second key wrong: %+v", shared[1])
	}
}

func TestDetectEmptyAndNil(t *testing.T) {
	if got := Detect(nil); len(got) != 0 {
		t.Errorf("nil sources: %+v", got)
	}
	if got := Detect([]Source{{HSMID: 1}}); len(got) != 0 {
		t.Errorf("nil inventory must be skipped: %+v", got)
	}
}
