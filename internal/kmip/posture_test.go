package kmip

import "testing"

func has(rep *Report, ruleID string) bool {
	for _, f := range rep.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestEvaluateWeakAndState(t *testing.T) {
	inv := &Inventory{Objects: []Object{
		{ID: "1", Type: "PublicKey", Algorithm: "RSA", Length: 1024, State: "Active", Names: []string{"weak-rsa"}},
		{ID: "2", Type: "SymmetricKey", Algorithm: "AES", Length: 256, State: "Compromised", Names: []string{"bad"}},
		{ID: "3", Type: "SymmetricKey", Algorithm: "AES", Length: 256, State: "Deactivated", Names: []string{"old"}},
		{ID: "4", Type: "SymmetricKey", Algorithm: "AES", Length: 256, State: "Active", Names: []string{"good"}},
	}}
	rep := Evaluate(inv)
	if !has(rep, "KMIP-001") {
		t.Error("weak RSA-1024 should raise KMIP-001")
	}
	if !has(rep, "KMIP-002") {
		t.Error("compromised object should raise KMIP-002")
	}
	if !has(rep, "KMIP-003") {
		t.Error("deactivated object should raise KMIP-003")
	}
	// The healthy active AES-256 key with a name raises nothing.
	for _, f := range rep.Findings {
		if f.Object == "SymmetricKey good (4)" {
			t.Errorf("healthy key should have no finding: %+v", f)
		}
	}
	if rep.Score >= 100 {
		t.Errorf("score should be penalized, got %d", rep.Score)
	}
}

func TestEvaluateUsageAndUnnamed(t *testing.T) {
	inv := &Inventory{Objects: []Object{
		{ID: "5", Type: "PrivateKey", Algorithm: "RSA", Length: 3072, State: "Active",
			UsageMask: []string{"Sign", "Decrypt"}, Names: []string{"mixed"}},
		{ID: "6", Type: "SymmetricKey", Algorithm: "AES", Length: 256, State: "Active"}, // no name
	}}
	rep := Evaluate(inv)
	if !has(rep, "KMIP-004") {
		t.Error("sign+decrypt usage should raise KMIP-004")
	}
	if !has(rep, "KMIP-005") {
		t.Error("unnamed object should raise KMIP-005")
	}
	if has(rep, "KMIP-001") {
		t.Error("RSA-3072 must not be flagged weak")
	}
}

func TestWeakKey(t *testing.T) {
	cases := []struct {
		alg  string
		bits int
		weak bool
	}{
		{"RSA", 2048, false},
		{"RSA", 1024, true},
		{"DSA", 1024, true},
		{"AES", 256, false},
		{"AES", 64, true},
		{"ECDSA", 256, false},
		{"ECDSA", 160, true},
		{"DES", 56, true},
		{"Triple DES", 168, true},
	}
	for _, c := range cases {
		weak, _ := weakKey(Object{Algorithm: c.alg, Length: c.bits})
		if weak != c.weak {
			t.Errorf("%s/%d: weak=%v, want %v", c.alg, c.bits, weak, c.weak)
		}
	}
}

func TestUsageMaskNames(t *testing.T) {
	// Sign (0x01) | Decrypt (0x08) = 0x09
	got := usageMaskNames(0x09)
	if len(got) != 2 || got[0] != "Sign" || got[1] != "Decrypt" {
		t.Errorf("usageMaskNames(0x09) = %v", got)
	}
}
