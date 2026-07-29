package policy

import (
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/rules"
)

func TestLoadDefaultRules(t *testing.T) {
	cfg, err := Load(rules.Default)
	if err != nil {
		t.Fatalf("default rules must load: %v", err)
	}
	if len(cfg.Rules) != 10 {
		t.Errorf("expected 10 default rules, got %d", len(cfg.Rules))
	}
	if cfg.Scoring == nil || cfg.Scoring.Critical != 25 {
		t.Errorf("default scoring not parsed: %+v", cfg.Scoring)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"empty file", "rules: []", "no rules"},
		{"missing id", "rules:\n  - title: x\n    severity: low\n    match: {class: private-key}", "no id"},
		{"duplicate id", `rules:
  - {id: A, title: x, severity: low, match: {class: private-key}}
  - {id: A, title: y, severity: low, match: {class: private-key}}`, "duplicate rule id"},
		{"bad severity", "rules:\n  - {id: A, title: x, severity: urgent, match: {class: private-key}}", "invalid severity"},
		{"empty match", "rules:\n  - {id: A, title: x, severity: low, match: {}}", "empty match"},
		{"unknown field", "rules:\n  - {id: A, title: x, severity: low, match: {extractible: true}}", "field extractible not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}
