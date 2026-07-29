package snapshot

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

func b(v bool) *bool { return &v }

func baseInventory() *inventory.Inventory {
	return &inventory.Inventory{
		ScannedAt: time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
		Slot: p11.SlotInfo{ID: 1, TokenPresent: true, Token: &p11.TokenInfo{
			Label: "PROD", FirmwareVersion: "7.8.1", SerialNumber: "S1",
		}},
		Mechanisms: []p11.Mechanism{
			{Name: "CKM_RSA_PKCS"},
			{Name: "CKM_SHA256_RSA_PKCS_PSS"},
		},
		Objects: []inventory.Object{
			{Class: inventory.ClassPrivateKey, Label: "app-key", ID: "01",
				KeyType: "RSA", KeyBits: 2048, Extractable: b(false), Sensitive: b(true)},
			{Class: inventory.ClassCertificate, Label: "old-cert", ID: "02",
				Certificate: &inventory.CertInfo{Subject: "CN=old", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		},
	}
}

func TestCompareNoDrift(t *testing.T) {
	d := Compare(baseInventory(), baseInventory())
	if !d.Empty() || d.Count() != 0 {
		t.Errorf("identical inventories must produce an empty diff: %+v", d)
	}
	var buf bytes.Buffer
	d.Text(&buf)
	if !strings.Contains(buf.String(), "No drift detected") {
		t.Errorf("text output should state no drift:\n%s", buf.String())
	}
}

func TestCompareDetectsDrift(t *testing.T) {
	oldInv := baseInventory()
	newInv := baseInventory()
	newInv.ScannedAt = time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)

	// Firmware upgrade.
	newInv.Slot.Token.FirmwareVersion = "7.8.2"
	// PSS mechanism disappears, GCM appears.
	newInv.Mechanisms = []p11.Mechanism{{Name: "CKM_RSA_PKCS"}, {Name: "CKM_AES_GCM"}}
	// app-key becomes extractable (the critical drift case).
	newInv.Objects[0].Extractable = b(true)
	// old-cert removed, new key added.
	newInv.Objects = append(newInv.Objects[:1],
		inventory.Object{Class: inventory.ClassPrivateKey, Label: "new-key", ID: "03",
			KeyType: "EC", KeyBits: 256, Extractable: b(false), Sensitive: b(true)})

	d := Compare(oldInv, newInv)

	if len(d.TokenChanges) != 1 || d.TokenChanges[0].Field != "firmware version" {
		t.Errorf("firmware change not detected: %+v", d.TokenChanges)
	}
	if len(d.MechanismsAdded) != 1 || d.MechanismsAdded[0] != "CKM_AES_GCM" {
		t.Errorf("mechanism addition not detected: %+v", d.MechanismsAdded)
	}
	if len(d.MechanismsRemoved) != 1 || d.MechanismsRemoved[0] != "CKM_SHA256_RSA_PKCS_PSS" {
		t.Errorf("mechanism removal not detected: %+v", d.MechanismsRemoved)
	}
	if len(d.ObjectsAdded) != 1 || !strings.Contains(d.ObjectsAdded[0], "new-key") {
		t.Errorf("added object not detected: %+v", d.ObjectsAdded)
	}
	if len(d.ObjectsRemoved) != 1 || !strings.Contains(d.ObjectsRemoved[0], "old-cert") {
		t.Errorf("removed object not detected: %+v", d.ObjectsRemoved)
	}
	found := false
	for _, c := range d.ObjectChanges {
		if c.Field == "CKA_EXTRACTABLE" && c.Old == "false" && c.New == "true" {
			found = true
		}
	}
	if !found {
		t.Errorf("CKA_EXTRACTABLE flip not detected: %+v", d.ObjectChanges)
	}

	var buf bytes.Buffer
	d.Text(&buf)
	out := buf.String()
	for _, want := range []string{
		"! firmware version changed 7.8.1 -> 7.8.2",
		"- mechanism CKM_SHA256_RSA_PKCS_PSS no longer available",
		"+ private-key new-key (id 03) added",
		"- certificate old-cert (id 02) removed",
		"CKA_EXTRACTABLE changed false -> true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff text missing %q\n---\n%s", want, out)
		}
	}
}

func TestCompareAttributeVisibilityChange(t *testing.T) {
	oldInv := baseInventory()
	newInv := baseInventory()
	// Attribute no longer exposed: must be reported, not treated as false.
	newInv.Objects[0].Sensitive = nil

	d := Compare(oldInv, newInv)
	found := false
	for _, c := range d.ObjectChanges {
		if c.Field == "CKA_SENSITIVE" && c.New == "(not exposed)" {
			found = true
		}
	}
	if !found {
		t.Errorf("visibility change not detected: %+v", d.ObjectChanges)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	snap := New("0.1.0-test", baseInventory())
	var buf bytes.Buffer
	if err := snap.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := t.TempDir() + "/snap.json"
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	back, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if back.Version != "0.1.0-test" || len(back.Inventory.Objects) != 2 {
		t.Errorf("round trip lost data: %+v", back)
	}
	if d := Compare(snap.Inventory, back.Inventory); !d.Empty() {
		t.Errorf("round-tripped inventory differs: %+v", d)
	}
}

func TestLoadFileRejectsNonSnapshot(t *testing.T) {
	path := t.TempDir() + "/bad.json"
	if err := os.WriteFile(path, []byte(`{"tool":"hsmdoctor"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Error("snapshot without inventory must be rejected")
	}
}
