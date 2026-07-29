// Package policy evaluates a token inventory against a set of YAML-defined
// security posture rules and computes a weighted health score.
package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Severity levels, ordered from most to least severe.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

// severityOrder is used for sorting findings; lower is more severe.
var severityOrder = map[Severity]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	_, ok := severityOrder[s]
	return ok
}

// Rank returns the sort rank of the severity (0 = most severe).
func (s Severity) Rank() int {
	return severityOrder[s]
}

// Condition expresses what a rule matches. All specified fields must hold
// (logical AND). Boolean fields are tri-state: nil means "don't care", and a
// non-nil condition only matches objects that expose the attribute.
type Condition struct {
	Class   string `yaml:"class,omitempty" json:"class,omitempty"`
	KeyType string `yaml:"key_type,omitempty" json:"key_type,omitempty"`

	Extractable *bool `yaml:"extractable,omitempty" json:"extractable,omitempty"`
	Sensitive   *bool `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	Sign        *bool `yaml:"sign,omitempty" json:"sign,omitempty"`
	Decrypt     *bool `yaml:"decrypt,omitempty" json:"decrypt,omitempty"`
	Wrap        *bool `yaml:"wrap,omitempty" json:"wrap,omitempty"`
	Unwrap      *bool `yaml:"unwrap,omitempty" json:"unwrap,omitempty"`

	KeySizeLT uint `yaml:"key_size_lt,omitempty" json:"key_size_lt,omitempty"`

	CertExpired           *bool `yaml:"cert_expired,omitempty" json:"cert_expired,omitempty"`
	CertExpiresWithinDays int   `yaml:"cert_expires_within_days,omitempty" json:"cert_expires_within_days,omitempty"`

	DuplicateLabel *bool `yaml:"duplicate_label,omitempty" json:"duplicate_label,omitempty"`
	Orphan         *bool `yaml:"orphan,omitempty" json:"orphan,omitempty"`

	// MechanismAnyOf makes the rule token-scoped: it fires when the token
	// advertises any of the listed CKM_* mechanism names.
	MechanismAnyOf []string `yaml:"mechanism_any_of,omitempty" json:"mechanism_any_of,omitempty"`
}

// empty reports whether no condition field is set.
func (c *Condition) empty() bool {
	return c.Class == "" && c.KeyType == "" &&
		c.Extractable == nil && c.Sensitive == nil && c.Sign == nil &&
		c.Decrypt == nil && c.Wrap == nil && c.Unwrap == nil &&
		c.KeySizeLT == 0 && c.CertExpired == nil && c.CertExpiresWithinDays == 0 &&
		c.DuplicateLabel == nil && c.Orphan == nil && len(c.MechanismAnyOf) == 0
}

// Rule is a single security posture check.
type Rule struct {
	ID          string    `yaml:"id" json:"id"`
	Title       string    `yaml:"title" json:"title"`
	Severity    Severity  `yaml:"severity" json:"severity"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Match       Condition `yaml:"match" json:"match"`
}

// Scoring holds the per-finding penalty for each severity. The health score
// starts at 100 and each finding subtracts its severity penalty (floor 0).
type Scoring struct {
	Critical int `yaml:"critical" json:"critical"`
	High     int `yaml:"high" json:"high"`
	Medium   int `yaml:"medium" json:"medium"`
	Low      int `yaml:"low" json:"low"`
}

// DefaultScoring is used when the rules file has no scoring section.
var DefaultScoring = Scoring{Critical: 25, High: 10, Medium: 5, Low: 2}

func (s Scoring) penalty(sev Severity) int {
	switch sev {
	case SevCritical:
		return s.Critical
	case SevHigh:
		return s.High
	case SevMedium:
		return s.Medium
	case SevLow:
		return s.Low
	}
	return 0
}

// Config is a full parsed rules file.
type Config struct {
	Rules   []Rule   `yaml:"rules" json:"rules"`
	Scoring *Scoring `yaml:"scoring,omitempty" json:"scoring,omitempty"`
}

// scoring returns the configured scoring or the defaults.
func (c *Config) scoring() Scoring {
	if c.Scoring != nil {
		return *c.Scoring
	}
	return DefaultScoring
}

// Load parses and validates a YAML rules document. Unknown fields are
// rejected so typos in rule files fail loudly instead of silently never
// matching.
func Load(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing rules: %w", err)
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("rules file contains no rules")
	}
	seen := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("rule #%d has no id", i+1)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" {
			return nil, fmt.Errorf("rule %s has no title", r.ID)
		}
		if !r.Severity.Valid() {
			return nil, fmt.Errorf("rule %s has invalid severity %q", r.ID, r.Severity)
		}
		if r.Match.empty() {
			return nil, fmt.Errorf("rule %s has an empty match condition", r.ID)
		}
	}
	return &cfg, nil
}
