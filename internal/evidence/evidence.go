// Package evidence turns a policy pack plus a token inventory into an
// auditor-facing compliance evidence report: one entry per control (rule) with
// a pass / fail / not-applicable verdict and the objects behind any failure.
//
// It reuses the ordinary policy engine — a control fails when the scan produces
// a finding for its rule — so the evidence is exactly consistent with `scan`.
// It is guidance, not a certification statement.
package evidence

import (
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// Status is a control's verdict.
type Status string

const (
	// StatusPass means the control was applicable and found no violation.
	StatusPass Status = "pass"
	// StatusFail means at least one object violates the control.
	StatusFail Status = "fail"
	// StatusNotApplicable means the token holds no object of the kind the
	// control applies to, so there was nothing to check.
	StatusNotApplicable Status = "not-applicable"
)

// Control is one rule's evidence.
type Control struct {
	RuleID      string           `json:"rule_id"`
	Title       string           `json:"title"`
	Severity    policy.Severity  `json:"severity"`
	Description string           `json:"description,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
	Reference   string           `json:"reference,omitempty"`
	Status      Status           `json:"status"`
	Violations  []policy.Finding `json:"violations,omitempty"`
}

// Pack is the evidence for one policy pack.
type Pack struct {
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Passed        int       `json:"passed"`
	Failed        int       `json:"failed"`
	NotApplicable int       `json:"not_applicable"`
	Controls      []Control `json:"controls"`
}

// Token identifies the assessed token.
type Token struct {
	Label        string `json:"label,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
}

// Report is a full compliance evidence report.
type Report struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at,omitempty"`
	Token       Token  `json:"token"`
	Packs       []Pack `json:"packs"`
}

// LoadedPack is a pack's identity and parsed rules.
type LoadedPack struct {
	Name        string
	Description string
	Config      *policy.Config
}

// Build assembles the evidence report by evaluating each pack against the same
// inventory.
func Build(version string, inv *inventory.Inventory, packs []LoadedPack, now time.Time) *Report {
	rep := &Report{
		Tool:        "hsmdoctor",
		Version:     version,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Token:       tokenOf(inv),
	}
	for _, p := range packs {
		res := policy.Evaluate(inv, p.Config, now)
		byRule := map[string][]policy.Finding{}
		for _, f := range res.Findings {
			byRule[f.RuleID] = append(byRule[f.RuleID], f)
		}

		pack := Pack{Name: p.Name, Description: p.Description}
		for i := range p.Config.Rules {
			rule := &p.Config.Rules[i]
			ctl := Control{
				RuleID:      rule.ID,
				Title:       rule.Title,
				Severity:    rule.Severity,
				Description: rule.Description,
				Remediation: rule.Remediation,
				Reference:   rule.Reference,
			}
			switch {
			case len(byRule[rule.ID]) > 0:
				ctl.Status = StatusFail
				ctl.Violations = byRule[rule.ID]
				pack.Failed++
			case applicable(inv, rule):
				ctl.Status = StatusPass
				pack.Passed++
			default:
				ctl.Status = StatusNotApplicable
				pack.NotApplicable++
			}
			pack.Controls = append(pack.Controls, ctl)
		}
		rep.Packs = append(rep.Packs, pack)
	}
	return rep
}

// applicable reports whether a rule had anything to check: token-scoped
// (mechanism) rules always apply, object rules apply when the token holds at
// least one object of the matched class. Consulted only for non-failing rules,
// so a rule that produced a finding is never marked not-applicable.
func applicable(inv *inventory.Inventory, rule *policy.Rule) bool {
	m := rule.Match
	if len(m.MechanismAnyOf) > 0 || len(m.MechanismMissing) > 0 {
		return true
	}
	if m.Class == "" {
		return len(inv.Objects) > 0
	}
	for _, o := range inv.Objects {
		if o.Class == m.Class {
			return true
		}
	}
	return false
}

func tokenOf(inv *inventory.Inventory) Token {
	if inv == nil || inv.Slot.Token == nil {
		return Token{}
	}
	t := inv.Slot.Token
	return Token{
		Label:        t.Label,
		SerialNumber: t.SerialNumber,
		Model:        t.Model,
		Manufacturer: t.Manufacturer,
		Firmware:     t.FirmwareVersion,
	}
}
