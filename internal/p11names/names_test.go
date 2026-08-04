package p11names

import "testing"

func TestMechanismCode(t *testing.T) {
	// A name from the generated table round-trips through both directions.
	code, ok := MechanismCode("CKM_RSA_PKCS_KEY_PAIR_GEN")
	if !ok {
		t.Fatal("CKM_RSA_PKCS_KEY_PAIR_GEN should resolve")
	}
	if Mechanism(code) != "CKM_RSA_PKCS_KEY_PAIR_GEN" {
		t.Errorf("round trip mismatch: %s", Mechanism(code))
	}

	// Case-insensitive and whitespace-tolerant.
	if _, ok := MechanismCode("  ckm_rsa_pkcs_key_pair_gen "); !ok {
		t.Error("lookup should be case-insensitive and trimmed")
	}

	// A supplemental (post-2.40) name resolves.
	if c, ok := MechanismCode("CKM_ML_DSA"); !ok || c != 0x1d {
		t.Errorf("CKM_ML_DSA should resolve to 0x1d, got 0x%x ok=%v", c, ok)
	}

	// Raw hex is accepted.
	if c, ok := MechanismCode("0x00000001"); !ok || c != 1 {
		t.Errorf("hex code should resolve, got 0x%x ok=%v", c, ok)
	}

	// Unknown names are rejected.
	if _, ok := MechanismCode("CKM_NOT_A_REAL_MECHANISM"); ok {
		t.Error("unknown mechanism must not resolve")
	}
}
