// Package policy evaluates a token inventory against a set of YAML-defined
// security posture rules and computes a weighted health score.
package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Severity levels, ordered from most to least severe. Info findings are
// advisory: they never affect the health score.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// severityOrder is used for sorting findings; lower is more severe.
var severityOrder = map[Severity]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4}

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
	Class     string   `yaml:"class,omitempty" json:"class,omitempty"`
	KeyType   string   `yaml:"key_type,omitempty" json:"key_type,omitempty"`
	KeyTypeIn []string `yaml:"key_type_in,omitempty" json:"key_type_in,omitempty"`

	Extractable      *bool `yaml:"extractable,omitempty" json:"extractable,omitempty"`
	Sensitive        *bool `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	AlwaysSensitive  *bool `yaml:"always_sensitive,omitempty" json:"always_sensitive,omitempty"`
	NeverExtractable *bool `yaml:"never_extractable,omitempty" json:"never_extractable,omitempty"`
	Modifiable       *bool `yaml:"modifiable,omitempty" json:"modifiable,omitempty"`
	Sign             *bool `yaml:"sign,omitempty" json:"sign,omitempty"`
	Verify           *bool `yaml:"verify,omitempty" json:"verify,omitempty"`
	Encrypt          *bool `yaml:"encrypt,omitempty" json:"encrypt,omitempty"`
	Decrypt          *bool `yaml:"decrypt,omitempty" json:"decrypt,omitempty"`
	Derive           *bool `yaml:"derive,omitempty" json:"derive,omitempty"`
	Wrap             *bool `yaml:"wrap,omitempty" json:"wrap,omitempty"`
	Unwrap           *bool `yaml:"unwrap,omitempty" json:"unwrap,omitempty"`

	KeySizeLT uint `yaml:"key_size_lt,omitempty" json:"key_size_lt,omitempty"`

	CurveIn    []string `yaml:"curve_in,omitempty" json:"curve_in,omitempty"`
	CurveNotIn []string `yaml:"curve_not_in,omitempty" json:"curve_not_in,omitempty"`

	CertExpired           *bool    `yaml:"cert_expired,omitempty" json:"cert_expired,omitempty"`
	CertExpiresWithinDays int      `yaml:"cert_expires_within_days,omitempty" json:"cert_expires_within_days,omitempty"`
	CertValidityDaysGT    int      `yaml:"cert_validity_days_gt,omitempty" json:"cert_validity_days_gt,omitempty"`
	CertSigAlgIn          []string `yaml:"cert_sig_alg_in,omitempty" json:"cert_sig_alg_in,omitempty"`
	CertIsCA              *bool    `yaml:"cert_is_ca,omitempty" json:"cert_is_ca,omitempty"`

	CertSelfSigned           *bool    `yaml:"cert_self_signed,omitempty" json:"cert_self_signed,omitempty"`
	CertNotYetValid          *bool    `yaml:"cert_not_yet_valid,omitempty" json:"cert_not_yet_valid,omitempty"`
	CertKeySizeLT            uint     `yaml:"cert_key_size_lt,omitempty" json:"cert_key_size_lt,omitempty"`
	CertPubKeyAlgIn          []string `yaml:"cert_pubkey_alg_in,omitempty" json:"cert_pubkey_alg_in,omitempty"`
	CertCAWithoutKeyCertSign *bool    `yaml:"cert_ca_without_keycertsign,omitempty" json:"cert_ca_without_keycertsign,omitempty"`
	CertKeyMismatch          *bool    `yaml:"cert_key_mismatch,omitempty" json:"cert_key_mismatch,omitempty"`

	DuplicateLabel *bool `yaml:"duplicate_label,omitempty" json:"duplicate_label,omitempty"`
	Orphan         *bool `yaml:"orphan,omitempty" json:"orphan,omitempty"`

	// MechanismAnyOf makes the rule token-scoped: it fires when the token
	// advertises any of the listed CKM_* mechanism names.
	MechanismAnyOf []string `yaml:"mechanism_any_of,omitempty" json:"mechanism_any_of,omitempty"`
	// MechanismMissing makes the rule token-scoped: it fires when the token
	// advertises none of the listed CKM_* mechanism names (capability gap).
	MechanismMissing []string `yaml:"mechanism_missing,omitempty" json:"mechanism_missing,omitempty"`
}

// tokenScoped reports whether the condition targets the token rather than
// individual objects.
func (c *Condition) tokenScoped() bool {
	return len(c.MechanismAnyOf) > 0 || len(c.MechanismMissing) > 0
}

// empty reports whether no condition field is set.
func (c *Condition) empty() bool {
	return c.Class == "" && c.KeyType == "" && len(c.KeyTypeIn) == 0 &&
		c.Extractable == nil && c.Sensitive == nil && c.AlwaysSensitive == nil &&
		c.NeverExtractable == nil && c.Modifiable == nil && c.Sign == nil &&
		c.Verify == nil && c.Encrypt == nil &&
		c.Decrypt == nil && c.Derive == nil && c.Wrap == nil && c.Unwrap == nil &&
		c.KeySizeLT == 0 && len(c.CurveIn) == 0 && len(c.CurveNotIn) == 0 &&
		c.CertExpired == nil && c.CertExpiresWithinDays == 0 &&
		c.CertValidityDaysGT == 0 && len(c.CertSigAlgIn) == 0 && c.CertIsCA == nil &&
		c.CertSelfSigned == nil && c.CertNotYetValid == nil && c.CertKeySizeLT == 0 &&
		len(c.CertPubKeyAlgIn) == 0 && c.CertCAWithoutKeyCertSign == nil &&
		c.CertKeyMismatch == nil &&
		c.DuplicateLabel == nil && c.Orphan == nil &&
		len(c.MechanismAnyOf) == 0 && len(c.MechanismMissing) == 0
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

// PackMeta names and describes a rule pack.
type PackMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Config is a full parsed rules file.
type Config struct {
	Pack    *PackMeta `yaml:"pack,omitempty" json:"pack,omitempty"`
	Rules   []Rule    `yaml:"rules" json:"rules"`
	Scoring *Scoring  `yaml:"scoring,omitempty" json:"scoring,omitempty"`

	// SourcePacks records which pack names produced this configuration
	// (filled by the loader, not part of the YAML format).
	SourcePacks []string `yaml:"-" json:"-"`
}

// Merge combines several packs into one configuration. Rule IDs must be
// globally unique; the first non-nil scoring section wins.
func Merge(configs ...*Config) (*Config, error) {
	merged := &Config{}
	seen := map[string]string{} // rule ID -> pack name
	for _, cfg := range configs {
		packName := "(unnamed)"
		if cfg.Pack != nil {
			packName = cfg.Pack.Name
		}
		for _, r := range cfg.Rules {
			if owner, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("rule id %q appears in both %s and %s", r.ID, owner, packName)
			}
			seen[r.ID] = packName
			merged.Rules = append(merged.Rules, r)
		}
		if merged.Scoring == nil && cfg.Scoring != nil {
			merged.Scoring = cfg.Scoring
		}
	}
	if len(merged.Rules) == 0 {
		return nil, fmt.Errorf("merged configuration contains no rules")
	}
	return merged, nil
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
