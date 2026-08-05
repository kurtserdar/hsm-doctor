package kmip

import (
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

func TestLoadRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"missing id":    "rules:\n  - title: x\n    severity: high\n    match: {unnamed: true}\n",
		"bad severity":  "rules:\n  - id: A\n    title: x\n    severity: nope\n    match: {unnamed: true}\n",
		"empty match":   "rules:\n  - id: A\n    title: x\n    severity: high\n    match: {}\n",
		"duplicate id":  "rules:\n  - id: A\n    title: x\n    severity: high\n    match: {unnamed: true}\n  - id: A\n    title: y\n    severity: low\n    match: {unnamed: true}\n",
		"unknown field": "rules:\n  - id: A\n    title: x\n    severity: high\n    bogus: 1\n    match: {unnamed: true}\n",
		"unknown cond":  "rules:\n  - id: A\n    title: x\n    severity: high\n    match: {no_such_condition: true}\n",
	}
	for name, y := range cases {
		if _, err := Load([]byte(y)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDefaultRuleSetReproducesBuiltins(t *testing.T) {
	rs, err := DefaultRuleSet()
	if err != nil {
		t.Fatalf("DefaultRuleSet: %v", err)
	}
	if len(rs.Rules) != 5 {
		t.Fatalf("expected 5 built-in rules, got %d", len(rs.Rules))
	}
}

func evalOne(t *testing.T, rs *RuleSet, o Object) *Report {
	t.Helper()
	return Evaluate(&Inventory{Objects: []Object{o}}, rs)
}

func ruleset(m Match, sev policy.Severity) *RuleSet {
	return &RuleSet{Rules: []Rule{{ID: "R-1", Title: "t", Severity: sev, Match: m}}}
}

func TestMatchAlgorithmAndLength(t *testing.T) {
	rs := ruleset(Match{AlgorithmIn: []string{"rsa"}, LengthLT: 2048}, policy.SevHigh)

	if rep := evalOne(t, rs, Object{Algorithm: "RSA", Length: 1024}); !has(rep, "R-1") {
		t.Error("RSA-1024 should match algorithm_in+length_lt")
	}
	if rep := evalOne(t, rs, Object{Algorithm: "RSA", Length: 3072}); has(rep, "R-1") {
		t.Error("RSA-3072 must not match length_lt 2048")
	}
	if rep := evalOne(t, rs, Object{Algorithm: "AES", Length: 128}); has(rep, "R-1") {
		t.Error("AES must not match algorithm_in [rsa]")
	}
}

func TestMatchUsageAllAnyAndState(t *testing.T) {
	allOf := ruleset(Match{UsageAllOf: []string{"Sign", "Decrypt"}}, policy.SevMedium)
	if rep := evalOne(t, allOf, Object{UsageMask: []string{"Sign", "Verify"}}); has(rep, "R-1") {
		t.Error("usage_all_of requires ALL listed usages")
	}
	if rep := evalOne(t, allOf, Object{UsageMask: []string{"Sign", "Decrypt", "Verify"}}); !has(rep, "R-1") {
		t.Error("usage_all_of should match when all present")
	}

	anyOf := ruleset(Match{UsageAnyOf: []string{"WrapKey", "UnwrapKey"}}, policy.SevLow)
	if rep := evalOne(t, anyOf, Object{UsageMask: []string{"UnwrapKey"}}); !has(rep, "R-1") {
		t.Error("usage_any_of should match on any listed usage")
	}

	st := ruleset(Match{StateIn: []string{"Compromised"}}, policy.SevCritical)
	if rep := evalOne(t, st, Object{State: "compromised"}); !has(rep, "R-1") {
		t.Error("state_in should be case-insensitive")
	}
}

func TestMatchWeakKeyCompositeAndDetail(t *testing.T) {
	rs := ruleset(Match{WeakKey: b(true)}, policy.SevHigh)
	rep := evalOne(t, rs, Object{Algorithm: "RSA", Length: 1024})
	if !has(rep, "R-1") {
		t.Fatal("weak_key should flag RSA-1024")
	}
	if !strings.Contains(rep.Findings[0].Detail, "1024") {
		t.Errorf("detail should describe the weakness: %q", rep.Findings[0].Detail)
	}
	if rep := evalOne(t, rs, Object{Algorithm: "RSA", Length: 4096}); has(rep, "R-1") {
		t.Error("weak_key must not flag RSA-4096")
	}
}

func b(v bool) *bool { return &v }
