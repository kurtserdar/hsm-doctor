package kmip

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"gopkg.in/yaml.v3"
)

//go:embed rules/default.yaml
var defaultRules []byte

// Match expresses what a KMIP rule matches on a managed object. All specified
// fields must hold (logical AND).
type Match struct {
	// ObjectTypeIn matches the KMIP object type (case-insensitive).
	ObjectTypeIn []string `yaml:"object_type_in,omitempty" json:"object_type_in,omitempty"`
	// AlgorithmIn matches the cryptographic algorithm (case-insensitive).
	AlgorithmIn []string `yaml:"algorithm_in,omitempty" json:"algorithm_in,omitempty"`
	// LengthLT matches keys whose known length is below N bits.
	LengthLT int `yaml:"length_lt,omitempty" json:"length_lt,omitempty"`
	// StateIn matches the lifecycle state (case-insensitive).
	StateIn []string `yaml:"state_in,omitempty" json:"state_in,omitempty"`
	// UsageAllOf matches when the usage mask grants every listed usage.
	UsageAllOf []string `yaml:"usage_all_of,omitempty" json:"usage_all_of,omitempty"`
	// UsageAnyOf matches when the usage mask grants any listed usage.
	UsageAnyOf []string `yaml:"usage_any_of,omitempty" json:"usage_any_of,omitempty"`
	// Unnamed matches on the presence/absence of a Name attribute.
	Unnamed *bool `yaml:"unnamed,omitempty" json:"unnamed,omitempty"`
	// WeakKey applies the built-in below-minimum-strength heuristic
	// (RSA/DSA/DH < 2048, EC < 224, AES < 128, DES/3DES broken).
	WeakKey *bool `yaml:"weak_key,omitempty" json:"weak_key,omitempty"`
}

func (m *Match) empty() bool {
	return len(m.ObjectTypeIn) == 0 && len(m.AlgorithmIn) == 0 && m.LengthLT == 0 &&
		len(m.StateIn) == 0 && len(m.UsageAllOf) == 0 && len(m.UsageAnyOf) == 0 &&
		m.Unnamed == nil && m.WeakKey == nil
}

// Rule is one KMIP posture check.
type Rule struct {
	ID          string          `yaml:"id" json:"id"`
	Title       string          `yaml:"title" json:"title"`
	Severity    policy.Severity `yaml:"severity" json:"severity"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Remediation string          `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Reference   string          `yaml:"reference,omitempty" json:"reference,omitempty"`
	Match       Match           `yaml:"match" json:"match"`
}

// PackMeta names and describes a rule pack.
type PackMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// RuleSet is a parsed KMIP rules file (kept distinct from the connection
// Config in client.go).
type RuleSet struct {
	Pack  *PackMeta `yaml:"pack,omitempty" json:"pack,omitempty"`
	Rules []Rule    `yaml:"rules" json:"rules"`
}

// Load parses and validates a KMIP rules file.
func Load(data []byte) (*RuleSet, error) {
	var cfg RuleSet
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing KMIP rules: %w", err)
	}
	seen := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		switch {
		case r.ID == "":
			return nil, fmt.Errorf("rule #%d: missing id", i+1)
		case seen[r.ID]:
			return nil, fmt.Errorf("rule %s: duplicate id", r.ID)
		case r.Title == "":
			return nil, fmt.Errorf("rule %s: missing title", r.ID)
		case !r.Severity.Valid():
			return nil, fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
		case r.Match.empty():
			return nil, fmt.Errorf("rule %s: match has no conditions", r.ID)
		}
		seen[r.ID] = true
	}
	return &cfg, nil
}

// DefaultRuleSet returns the built-in KMIP rule set.
func DefaultRuleSet() (*RuleSet, error) {
	return Load(defaultRules)
}

// DefaultRules is the raw built-in rule YAML, exposed for a --rules starting
// point.
var DefaultRules = defaultRules
