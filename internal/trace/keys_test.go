package trace

import "testing"

func u(v uint64) *uint64 { return &v }

// evseq builds a small trace in one session.
func findInit(label, id string) Event {
	return Event{Function: "C_FindObjectsInit", Session: u(1), Label: label, KeyID: id}
}
func found(handle uint64) Event {
	return Event{Function: "C_FindObjects", Session: u(1), Object: u(handle)}
}
func op(fn string, handle uint64, mech string) Event {
	return Event{Function: fn, Session: u(1), Object: u(handle), Mechanism: mech}
}

func findKey(r *KeyUsageReport, label string) *KeyUsage {
	for i := range r.Keys {
		if r.Keys[i].Label == label {
			return &r.Keys[i]
		}
	}
	return nil
}

func TestKeyUsageResolvesByLabel(t *testing.T) {
	events := []Event{
		findInit("tls-signing", ""),
		found(5),
		op("C_SignInit", 5, "CKM_ECDSA"),
		op("C_SignInit", 5, "CKM_ECDSA"),
	}
	r := KeyUsageOf(events)
	if len(r.Keys) != 1 || r.Unresolved != 0 {
		t.Fatalf("want 1 resolved key, got %+v", r)
	}
	k := r.Keys[0]
	if !k.Resolved || k.Label != "tls-signing" {
		t.Errorf("key not resolved by label: %+v", k)
	}
	if k.Operations["C_SignInit"] != 2 || k.Total != 2 {
		t.Errorf("sign count wrong: %+v", k.Operations)
	}
	if len(k.Mechanisms) != 1 || k.Mechanisms[0] != "CKM_ECDSA" {
		t.Errorf("mechanisms wrong: %v", k.Mechanisms)
	}
}

func TestKeyUsageUnresolvedHandle(t *testing.T) {
	// A key used without a preceding find-by-label/id stays unresolved.
	events := []Event{op("C_DecryptInit", 9, "CKM_RSA_PKCS")}
	r := KeyUsageOf(events)
	if len(r.Keys) != 1 || r.Unresolved != 1 {
		t.Fatalf("want 1 unresolved key, got %+v", r)
	}
	if r.Keys[0].Resolved || r.Keys[0].Handle != 9 {
		t.Errorf("should be an unresolved handle 9: %+v", r.Keys[0])
	}
}

func TestKeyUsageMixedAndAggregated(t *testing.T) {
	events := []Event{
		findInit("signer", "01"),
		found(3),
		op("C_SignInit", 3, "CKM_ECDSA"),
		findInit("decryptor", "02"),
		found(4),
		op("C_DecryptInit", 4, "CKM_RSA_PKCS"),
		op("C_DecryptInit", 4, "CKM_RSA_PKCS"),
		op("C_EncryptInit", 7, "CKM_AES_GCM"), // never found by id/label
	}
	r := KeyUsageOf(events)
	if r.Unresolved != 1 {
		t.Errorf("want 1 unresolved, got %d", r.Unresolved)
	}
	signer := findKey(r, "signer")
	if signer == nil || signer.KeyID != "01" || signer.Operations["C_SignInit"] != 1 {
		t.Errorf("signer usage wrong: %+v", signer)
	}
	dec := findKey(r, "decryptor")
	if dec == nil || dec.Operations["C_DecryptInit"] != 2 {
		t.Errorf("decryptor usage wrong: %+v", dec)
	}
	// Resolved keys must sort before the unresolved one.
	if !r.Keys[0].Resolved || r.Keys[len(r.Keys)-1].Resolved {
		t.Errorf("ordering: resolved keys should come first: %+v", r.Keys)
	}
}

func TestKeyUsageEmptyTemplateFindIgnored(t *testing.T) {
	// A find with no label/id in its template can't name the handle, so a later
	// operation on that handle is unresolved.
	events := []Event{
		findInit("", ""),
		found(5),
		op("C_SignInit", 5, "CKM_ECDSA"),
	}
	r := KeyUsageOf(events)
	if r.Unresolved != 1 || r.Keys[0].Resolved {
		t.Errorf("empty-template find must not resolve the handle: %+v", r)
	}
}
