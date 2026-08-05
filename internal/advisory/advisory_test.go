package advisory

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

func TestDefaultFeedLoads(t *testing.T) {
	f, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if f.DataVersion == "" || len(f.Advisories) == 0 {
		t.Errorf("built-in feed looks empty: %+v", f)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"missing id":       "advisories:\n  - title: x\n    severity: high\n    match: {component: library, fixed_in: \"1.0\"}\n",
		"bad severity":     "advisories:\n  - id: A\n    title: x\n    severity: nope\n    match: {component: library, fixed_in: \"1.0\"}\n",
		"bad component":    "advisories:\n  - id: A\n    title: x\n    severity: high\n    match: {component: cpu, fixed_in: \"1.0\"}\n",
		"missing fixed_in": "advisories:\n  - id: A\n    title: x\n    severity: high\n    match: {component: library}\n",
		"duplicate id":     "advisories:\n  - id: A\n    title: x\n    severity: high\n    match: {component: library, fixed_in: \"1.0\"}\n  - id: A\n    title: y\n    severity: low\n    match: {component: library, fixed_in: \"2.0\"}\n",
		"unknown field":    "advisories:\n  - id: A\n    title: x\n    severity: high\n    bogus: 1\n    match: {component: library, fixed_in: \"1.0\"}\n",
	}
	for name, yaml := range cases {
		if _, err := Load([]byte(yaml)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestVersionCompareNumeric(t *testing.T) {
	// "2.6" must be LESS than "2.10" (numeric, not lexical).
	if c, ok := compareVersions("2.6", "2.10"); !ok || c != -1 {
		t.Errorf("2.6 < 2.10 expected, got c=%d ok=%v", c, ok)
	}
	if c, ok := compareVersions("7.8.0", "7.8"); !ok || c != 0 {
		t.Errorf("7.8.0 == 7.8 expected, got c=%d ok=%v", c, ok)
	}
	if c, ok := compareVersions("FW 6.24.7-3", "6.24.8"); !ok || c != -1 {
		t.Errorf("prefixed/suffixed parse failed, got c=%d ok=%v", c, ok)
	}
	if _, ok := compareVersions("unknown", "1.0"); ok {
		t.Error("unparseable version must report ok=false")
	}
}

func lib(mfr, ver string) p11.ModuleInfo {
	return p11.ModuleInfo{Manufacturer: mfr, LibraryVersion: ver, Description: "desc"}
}

func fw(mfr, model, ver string) *p11.TokenInfo {
	return &p11.TokenInfo{Manufacturer: mfr, Model: model, FirmwareVersion: ver}
}

func feed(m Match, sev policy.Severity) *Feed {
	return &Feed{Advisories: []Advisory{{ID: "A-1", Title: "t", Severity: sev, Match: m}}}
}

func TestEvaluateLibraryMatch(t *testing.T) {
	f := feed(Match{Component: "library", Manufacturer: "SoftHSM", FixedIn: "2.7.0"}, policy.SevHigh)

	// Below fixed_in and manufacturer matches -> fires.
	if got := f.Evaluate(lib("SoftHSM project", "2.6.0"), nil); len(got) != 1 || got[0].RuleID != "A-1" {
		t.Errorf("expected a finding, got %+v", got)
	}
	// At/above fixed_in -> no finding.
	if got := f.Evaluate(lib("SoftHSM project", "2.7.0"), nil); len(got) != 0 {
		t.Errorf("version at fixed_in must not fire: %+v", got)
	}
	// Manufacturer mismatch -> no finding.
	if got := f.Evaluate(lib("OtherVendor", "1.0.0"), nil); len(got) != 0 {
		t.Errorf("manufacturer mismatch must not fire: %+v", got)
	}
}

func TestEvaluateFirmwareRangeAndModel(t *testing.T) {
	f := feed(Match{Component: "firmware", Manufacturer: "Acme", Model: "vHSM",
		IntroducedIn: "1.0.0", FixedIn: "2.0.0"}, policy.SevCritical)

	if got := f.Evaluate(p11.ModuleInfo{}, fw("Acme", "vHSM-1", "1.5.0")); len(got) != 1 {
		t.Errorf("in-range firmware must fire: %+v", got)
	}
	// Below introduced_in -> not affected.
	if got := f.Evaluate(p11.ModuleInfo{}, fw("Acme", "vHSM-1", "0.9.0")); len(got) != 0 {
		t.Errorf("below introduced_in must not fire: %+v", got)
	}
	// Model mismatch.
	if got := f.Evaluate(p11.ModuleInfo{}, fw("Acme", "OtherModel", "1.5.0")); len(got) != 0 {
		t.Errorf("model mismatch must not fire: %+v", got)
	}
	// A firmware advisory with a nil token must be skipped safely.
	if got := f.Evaluate(p11.ModuleInfo{}, nil); len(got) != 0 {
		t.Errorf("nil token must not fire: %+v", got)
	}
}

func TestEvaluateUnparseableVersionSkips(t *testing.T) {
	f := feed(Match{Component: "firmware", Manufacturer: "Acme", FixedIn: "2.0.0"}, policy.SevHigh)
	if got := f.Evaluate(p11.ModuleInfo{}, fw("Acme", "m", "unknown")); len(got) != 0 {
		t.Errorf("unparseable version must be skipped, got %+v", got)
	}
}
