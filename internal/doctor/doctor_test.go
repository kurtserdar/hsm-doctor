package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
	"github.com/kurtserdar/hsm-doctor/internal/report"
)

func mkReport(score int, hndl int, findings ...policy.Finding) *report.Report {
	return &report.Report{
		Tool: "hsmdoctor", Version: "t", Score: score, Findings: findings,
		PQC:       &report.PQCSummary{Exposure: &pqc.Exposure{HarvestNowDecryptLater: hndl}},
		Inventory: &inventory.Inventory{Slot: p11.SlotInfo{Token: &p11.TokenInfo{Label: "PROD", Model: "vHSM"}}},
	}
}

func find(sev policy.Severity, title string) policy.Finding {
	return policy.Finding{RuleID: "R", Title: title, Severity: sev, Object: "private-key k (id 01)"}
}

func TestVerdictCriticalOnCriticalFinding(t *testing.T) {
	d := Build("t", Input{Report: mkReport(40, 0, find(policy.SevCritical, "extractable key"))})
	if d.Verdict != VerdictCritical {
		t.Errorf("want critical, got %s", d.Verdict)
	}
}

func TestVerdictAttentionOnLesserIssue(t *testing.T) {
	d := Build("t", Input{Report: mkReport(85, 0, find(policy.SevHigh, "weak rsa"))})
	if d.Verdict != VerdictAttention {
		t.Errorf("a high (non-critical) finding should be attention, got %s", d.Verdict)
	}
}

func TestVerdictAttentionOnLowScoreOnly(t *testing.T) {
	// No findings, but the score is below the healthy threshold.
	d := Build("t", Input{Report: mkReport(80, 0)})
	if d.Verdict != VerdictAttention {
		t.Errorf("score<90 with no findings should be attention, got %s", d.Verdict)
	}
}

func TestVerdictHealthy(t *testing.T) {
	d := Build("t", Input{Report: mkReport(100, 0)})
	if d.Verdict != VerdictHealthy || len(d.Issues) != 0 {
		t.Errorf("clean token should be healthy with no issues: %s / %d", d.Verdict, len(d.Issues))
	}
}

func TestFunctionalFailureIsCritical(t *testing.T) {
	tests := &funtest.Result{Steps: []funtest.StepResult{
		{Name: "sign", Status: funtest.StatusPass},
		{Name: "verify", Status: funtest.StatusFail},
	}}
	d := Build("t", Input{Report: mkReport(100, 0), Tests: tests, TestsRan: true})
	if d.Verdict != VerdictCritical {
		t.Errorf("a failed functional step should make the verdict critical, got %s", d.Verdict)
	}
	if !checkRan(d, "functional") {
		t.Error("functional check should be marked as run")
	}
}

func TestPQCExposureSurfacesAsInfo(t *testing.T) {
	d := Build("t", Input{Report: mkReport(100, 3)})
	if d.Verdict != VerdictAttention {
		t.Errorf("pqc exposure should raise attention, got %s", d.Verdict)
	}
	var found bool
	for _, i := range d.Issues {
		if i.Source == "pqc" && i.Severity == policy.SevInfo {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a pqc info issue: %+v", d.Issues)
	}
}

func TestPrioritizationMostSevereFirst(t *testing.T) {
	d := Build("t", Input{Report: mkReport(50, 0,
		find(policy.SevLow, "low"), find(policy.SevCritical, "crit"), find(policy.SevMedium, "med"))})
	if d.Issues[0].Severity != policy.SevCritical || d.Issues[len(d.Issues)-1].Severity != policy.SevLow {
		t.Errorf("issues not sorted most-severe-first: %+v", d.Issues)
	}
}

func TestChecksSkippedFlags(t *testing.T) {
	d := Build("t", Input{Report: mkReport(100, 0)})
	if checkRan(d, "functional") || checkRan(d, "vendor") {
		t.Error("functional and vendor should be skipped when not requested")
	}
	if !checkRan(d, "posture") {
		t.Error("posture should always run")
	}
}

func TestRenderers(t *testing.T) {
	d := Build("t", Input{Report: mkReport(40, 2, find(policy.SevCritical, "extractable key"))})

	var j bytes.Buffer
	if err := d.JSON(&j); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(j.Bytes(), &back); err != nil {
		t.Fatalf("JSON round-trip: %v", err)
	}

	var txt bytes.Buffer
	if err := d.Text(&txt); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := txt.String()
	for _, want := range []string{"Diagnosis: CRITICAL", "Health 40/100", "PROD", "extractable key", "Checks:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
}

func checkRan(d *Report, name string) bool {
	for _, c := range d.Checks {
		if c.Name == name {
			return c.Ran
		}
	}
	return false
}
