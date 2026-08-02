package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	vendor "github.com/kurtserdar/hsm-doctor/internal/vendors"
)

func sarifOf(t *testing.T, rep *Report) sarifLog {
	t.Helper()
	var buf bytes.Buffer
	if err := rep.SARIF(&buf); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	return log
}

func findRule(rules []sarifRule, id string) *sarifRule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

func TestSARIFStructure(t *testing.T) {
	rep := sampleReport()
	rep.Findings = []policy.Finding{
		{RuleID: "HSM-001", Title: "Extractable private key", Severity: policy.SevCritical,
			Object: "private-key tls-key (id 01)", Detail: "CKA_EXTRACTABLE=true",
			Remediation: "Regenerate the key with CKA_EXTRACTABLE=false."},
		{RuleID: "HSM-003", Title: "Weak RSA key", Severity: policy.SevHigh,
			Object: "private-key tls-key (id 01)", Detail: "key size 1024 < 2048 bits",
			Remediation: "Use RSA-3072+.", Reference: "https://example.com/keys"},
		// Same rule fires twice: only one rule entry, two results.
		{RuleID: "HSM-003", Title: "Weak RSA key", Severity: policy.SevHigh,
			Object: "private-key old-key (id 02)", Detail: "key size 1024 < 2048 bits",
			Remediation: "Use RSA-3072+."},
	}
	// A vendor finding must also reach the SARIF output.
	rep.Vendor = &vendor.Info{Provider: "softhsm", Findings: []policy.Finding{
		{RuleID: "SOFTHSM-002", Title: "World-accessible token store", Severity: policy.SevMedium,
			Detail: "tokendir is world-readable"},
	}}

	log := sarifOf(t, rep)
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Fatalf("bad envelope: version=%q schema=%q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "hsmdoctor" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}

	// Three distinct rule IDs across four findings.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("want 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 4 {
		t.Errorf("want 4 results, got %d", len(run.Results))
	}

	// Severity → level and security-severity mapping.
	crit := findRule(run.Tool.Driver.Rules, "HSM-001")
	if crit == nil || crit.DefaultConfiguration.Level != "error" || crit.Properties.SecuritySeverity != "9.0" {
		t.Errorf("critical rule mapping wrong: %+v", crit)
	}
	if crit.Help == nil || crit.Help.Text == "" {
		t.Error("remediation should populate help")
	}
	high := findRule(run.Tool.Driver.Rules, "HSM-003")
	if high == nil || high.HelpURI != "https://example.com/keys" {
		t.Errorf("reference should populate helpUri: %+v", high)
	}
	vend := findRule(run.Tool.Driver.Rules, "SOFTHSM-002")
	if vend == nil || vend.DefaultConfiguration.Level != "warning" {
		t.Errorf("vendor finding missing or mis-levelled: %+v", vend)
	}

	// A result's ruleIndex must point at the matching rule.
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range", res.RuleIndex)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex mismatch: result %s -> rule %s", res.RuleID, run.Tool.Driver.Rules[res.RuleIndex].ID)
		}
		if res.PartialFingerprints["hsmDoctorRuleObject/v1"] == "" {
			t.Errorf("result %s missing partial fingerprint", res.RuleID)
		}
	}

	// An object-scoped result carries a logical location qualified by the
	// token serial; a token-scoped one carries none.
	var objRes, tokRes *sarifResult
	for i := range run.Results {
		switch run.Results[i].RuleID {
		case "HSM-001":
			objRes = &run.Results[i]
		case "SOFTHSM-002":
			tokRes = &run.Results[i]
		}
	}
	if objRes == nil || len(objRes.Locations) != 1 {
		t.Fatalf("object result should have a location: %+v", objRes)
	}
	if fq := objRes.Locations[0].LogicalLocations[0].FullyQualifiedName; fq != "abc123/private-key tls-key (id 01)" {
		t.Errorf("fully qualified name = %q", fq)
	}
	if tokRes == nil || len(tokRes.Locations) != 0 {
		t.Errorf("token-scoped result should have no location: %+v", tokRes)
	}
}

func TestSARIFEmpty(t *testing.T) {
	rep := sampleReport()
	rep.Findings = nil
	rep.Vendor = nil
	log := sarifOf(t, rep)
	// Empty runs must still serialize rules/results as arrays, not null.
	if log.Runs[0].Tool.Driver.Rules == nil {
		t.Error("rules should be an empty array, not null")
	}
	if log.Runs[0].Results == nil {
		t.Error("results should be an empty array, not null")
	}
}
