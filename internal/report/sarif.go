package report

import (
	"encoding/json"
	"io"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// SARIF renders the report's findings as a SARIF 2.1.0 log, so that scan
// results can be uploaded to code-scanning dashboards (for example GitHub
// Advanced Security). Both posture and vendor findings are included.
//
// HSM findings are not tied to source files, so each result carries a
// logical location (the offending object, qualified by the token serial)
// rather than a physical one.
func (r *Report) SARIF(w io.Writer) error {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "hsmdoctor",
				Version:        r.Version,
				InformationURI: "https://github.com/kurtserdar/hsm-doctor",
				Rules:          []sarifRule{},
			}},
			Results: []sarifResult{},
		}},
	}
	run := &log.Runs[0]

	serial := ""
	if r.Inventory != nil && r.Inventory.Slot.Token != nil {
		serial = r.Inventory.Slot.Token.SerialNumber
	}

	findings := append([]policy.Finding{}, r.Findings...)
	if r.Vendor != nil {
		findings = append(findings, r.Vendor.Findings...)
	}

	ruleIndex := map[string]int{}
	for _, f := range findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(run.Tool.Driver.Rules)
			ruleIndex[f.RuleID] = idx
			rule := sarifRule{
				ID:                   f.RuleID,
				ShortDescription:     sarifText{Text: f.Title},
				DefaultConfiguration: &sarifConfig{Level: sarifLevel(f.Severity)},
				Properties: &sarifRuleProps{
					SecuritySeverity: securitySeverity(f.Severity),
					Tags:             []string{"hsm", "security", string(f.Severity)},
				},
			}
			if f.Remediation != "" {
				rule.FullDescription = &sarifText{Text: f.Remediation}
				rule.Help = &sarifText{Text: f.Remediation}
			}
			if f.Reference != "" {
				rule.HelpURI = f.Reference
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}

		msg := f.Detail
		if msg == "" {
			msg = f.Title
		}
		result := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: msg},
			// A stable key for cross-run de-duplication in the dashboard.
			PartialFingerprints: map[string]string{
				"hsmDoctorRuleObject/v1": f.RuleID + ":" + f.Object,
			},
		}
		if f.Object != "" {
			fq := f.Object
			if serial != "" {
				fq = serial + "/" + f.Object
			}
			result.Locations = []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					Name:               f.Object,
					FullyQualifiedName: fq,
					Kind:               "object",
				}},
			}}
		}
		run.Results = append(run.Results, result)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifLevel maps a severity to a SARIF result level. SARIF has only
// error/warning/note/none, so critical and high both map to error.
func sarifLevel(sev policy.Severity) string {
	switch sev {
	case policy.SevCritical, policy.SevHigh:
		return "error"
	case policy.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps a severity to the 0.0-10.0 numeric string that
// code-scanning dashboards use to sort and threshold results.
func securitySeverity(sev policy.Severity) string {
	switch sev {
	case policy.SevCritical:
		return "9.0"
	case policy.SevHigh:
		return "7.0"
	case policy.SevMedium:
		return "5.0"
	case policy.SevLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// SARIF 2.1.0 document types (only the subset we emit).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      *sarifText      `json:"fullDescription,omitempty"`
	Help                 *sarifText      `json:"help,omitempty"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifConfig    `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProps `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
