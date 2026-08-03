package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/report"
)

func writeReport(t *testing.T, objs []inventory.Object) string {
	t.Helper()
	rep := report.Report{Inventory: &inventory.Inventory{Objects: objs}}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inv.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInventoryKeyRefsFiltersToKeys(t *testing.T) {
	path := writeReport(t, []inventory.Object{
		{Class: inventory.ClassPrivateKey, Label: "sign", ID: "01"},
		{Class: inventory.ClassSecretKey, Label: "aes", ID: "02"},
		{Class: inventory.ClassPublicKey, Label: "pub", ID: "01"},
		{Class: inventory.ClassCertificate, Label: "cert", ID: "01"},
	})
	refs, err := inventoryKeyRefs(path)
	if err != nil {
		t.Fatalf("inventoryKeyRefs: %v", err)
	}
	// Only the private and secret keys are idle-analysis candidates.
	if len(refs) != 2 {
		t.Fatalf("want 2 key refs (private + secret), got %d: %+v", len(refs), refs)
	}
	classes := map[string]bool{}
	for _, r := range refs {
		classes[r.Class] = true
	}
	if !classes[inventory.ClassPrivateKey] || !classes[inventory.ClassSecretKey] {
		t.Errorf("expected private and secret keys, got %+v", refs)
	}
	if classes[inventory.ClassPublicKey] || classes[inventory.ClassCertificate] {
		t.Error("public keys and certificates must not be idle candidates")
	}
}

func TestInventoryKeyRefsMissingFile(t *testing.T) {
	if _, err := inventoryKeyRefs(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("a missing inventory file should be an error")
	}
}

func TestInventoryKeyRefsNoInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"score":100}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inventoryKeyRefs(path); err == nil {
		t.Error("a report with no inventory should be an error")
	}
}
