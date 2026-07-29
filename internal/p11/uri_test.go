package p11

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	u, err := ParseURI("pkcs11:token=PROD%20PARTITION;serial=abc123;manufacturer=SoftHSM%20project?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if u.Token != "PROD PARTITION" || u.Serial != "abc123" || u.Manufacturer != "SoftHSM project" {
		t.Errorf("attributes wrong: %+v", u)
	}
	if u.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" || u.PINValue != "1234" {
		t.Errorf("query attributes wrong: %+v", u)
	}

	pin, err := u.PIN()
	if err != nil || pin != "1234" {
		t.Errorf("PIN: %q, %v", pin, err)
	}
}

func TestParseURISlotID(t *testing.T) {
	u, err := ParseURI("pkcs11:slot-id=42")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if u.SlotID == nil || *u.SlotID != 42 {
		t.Errorf("slot-id wrong: %+v", u.SlotID)
	}
	slot, err := u.MatchSlot(nil)
	if err != nil || slot != 42 {
		t.Errorf("MatchSlot with slot-id: %d, %v", slot, err)
	}
}

func TestParseURIErrors(t *testing.T) {
	for _, raw := range []string{
		"pkcs12:token=x",
		"pkcs11:token",
		"pkcs11:slot-id=notanumber",
	} {
		if _, err := ParseURI(raw); err == nil {
			t.Errorf("ParseURI(%q) should fail", raw)
		}
	}
}

func TestURIIgnoresUnknownAttributes(t *testing.T) {
	u, err := ParseURI("pkcs11:token=T;object=mykey;type=private;vendor-thing=1")
	if err != nil {
		t.Fatalf("unknown attributes must be ignored: %v", err)
	}
	if u.Token != "T" {
		t.Errorf("token lost: %+v", u)
	}
}

func TestPINSource(t *testing.T) {
	pinFile := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := ParseURI("pkcs11:token=T?pin-source=" + pinFile)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := u.PIN()
	if err != nil || pin != "s3cret" {
		t.Errorf("pin-source: %q, %v", pin, err)
	}
}

func TestMatchSlot(t *testing.T) {
	slots := []SlotInfo{
		{ID: 1, TokenPresent: true, Token: &TokenInfo{Label: "PROD", SerialNumber: "S1"}},
		{ID: 2, TokenPresent: true, Token: &TokenInfo{Label: "PROD", SerialNumber: "S2"}},
		{ID: 3, TokenPresent: true, Token: &TokenInfo{Label: "DEV", SerialNumber: "S3"}},
		{ID: 4, TokenPresent: false},
	}

	u, _ := ParseURI("pkcs11:token=DEV")
	if slot, err := u.MatchSlot(slots); err != nil || slot != 3 {
		t.Errorf("unique match: %d, %v", slot, err)
	}

	u, _ = ParseURI("pkcs11:token=PROD")
	if _, err := u.MatchSlot(slots); err == nil || !strings.Contains(err.Error(), "2 tokens") {
		t.Errorf("ambiguous match should fail with guidance, got %v", err)
	}

	u, _ = ParseURI("pkcs11:token=PROD;serial=S2")
	if slot, err := u.MatchSlot(slots); err != nil || slot != 2 {
		t.Errorf("serial disambiguation: %d, %v", slot, err)
	}

	u, _ = ParseURI("pkcs11:token=MISSING")
	if _, err := u.MatchSlot(slots); err == nil {
		t.Error("no match should fail")
	}
}
