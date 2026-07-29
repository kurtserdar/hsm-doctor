package rules_test

import (
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/rules"
)

// Every embedded pack must parse, validate and carry proper metadata.
func TestEmbeddedPacksLoad(t *testing.T) {
	packs := rules.Packs()
	if len(packs) != 4 {
		t.Fatalf("expected 4 embedded packs, got %d", len(packs))
	}

	expectedPrefix := map[string]string{
		"nist": "NIST-", "cabf": "CABF-", "strict": "STRICT-", "pqc-migration": "PQCM-",
	}
	var configs []*policy.Config
	for _, p := range packs {
		cfg, err := policy.Load(p.Data)
		if err != nil {
			t.Errorf("pack %s does not load: %v", p.Name, err)
			continue
		}
		if cfg.Pack == nil || cfg.Pack.Name != p.Name {
			t.Errorf("pack %s: metadata name mismatch: %+v", p.Name, cfg.Pack)
		}
		if cfg.Pack != nil && cfg.Pack.Description == "" {
			t.Errorf("pack %s: missing description", p.Name)
		}
		prefix := expectedPrefix[p.Name]
		if prefix == "" {
			t.Errorf("unexpected pack %s", p.Name)
			continue
		}
		for _, r := range cfg.Rules {
			if !strings.HasPrefix(r.ID, prefix) {
				t.Errorf("pack %s: rule %s does not use prefix %s", p.Name, r.ID, prefix)
			}
		}
		configs = append(configs, cfg)
	}

	// Compliance-inspired packs must state they are guidance, not
	// certification.
	for _, name := range []string{"nist", "cabf"} {
		data, ok := rules.PackData(name)
		if !ok {
			t.Fatalf("PackData(%s) missing", name)
		}
		if !strings.Contains(strings.ToLower(string(data)), "not a compliance or certification statement") {
			t.Errorf("pack %s must carry the guidance disclaimer", name)
		}
	}

	// All packs plus the default must merge without ID collisions.
	def, err := policy.Load(rules.Default)
	if err != nil {
		t.Fatalf("default rules: %v", err)
	}
	configs = append(configs, def)
	merged, err := policy.Merge(configs...)
	if err != nil {
		t.Fatalf("packs must merge cleanly with default: %v", err)
	}
	if len(merged.Rules) < 30 {
		t.Errorf("merged rule count suspiciously low: %d", len(merged.Rules))
	}
}

func TestPackDataDefaultAlias(t *testing.T) {
	data, ok := rules.PackData("default")
	if !ok || len(data) == 0 {
		t.Fatal("PackData(default) should return the default rule set")
	}
	if _, ok := rules.PackData("no-such-pack"); ok {
		t.Error("unknown pack name should not resolve")
	}
}
