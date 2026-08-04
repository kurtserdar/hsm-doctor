package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

func keyReport(serial, label string, keys ...inventory.Object) *report.Report {
	return &report.Report{
		Tool: "hsmdoctor", Version: "test",
		Inventory: &inventory.Inventory{
			ScannedAt: time.Now().UTC(),
			Slot: p11.SlotInfo{TokenPresent: true, Token: &p11.TokenInfo{
				SerialNumber: serial, Label: label,
			}},
			Objects: keys,
		},
	}
}

func privKey(label, fp string) inventory.Object {
	return inventory.Object{Class: inventory.ClassPrivateKey, Label: label,
		PublicKeyFingerprint: fp, KeyType: "RSA"}
}

func TestServerSharedKeys(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	s := NewCentral("test", st, "")

	// Two distinct HSMs holding a private key with the same fingerprint, plus
	// a key unique to the first.
	s.persistScan(keyReport("HSM-A", "alpha", privKey("signing", "shared-fp"), privKey("local", "unique-fp")), "local")
	s.persistScan(keyReport("HSM-B", "beta", privKey("signing-copy", "shared-fp")), "agent-1")

	shared, err := s.SharedKeys()
	if err != nil {
		t.Fatalf("SharedKeys: %v", err)
	}
	if len(shared) != 1 {
		t.Fatalf("expected 1 shared key, got %d: %+v", len(shared), shared)
	}
	if shared[0].Fingerprint != "shared-fp" || shared[0].HSMCount != 2 {
		t.Errorf("wrong shared key: %+v", shared[0])
	}
	if len(shared[0].Locations) != 2 {
		t.Errorf("expected 2 locations, got %d", len(shared[0].Locations))
	}
}
