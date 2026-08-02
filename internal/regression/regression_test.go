package regression

import "testing"

import "github.com/kurtserdar/hsm-doctor/internal/policy"

func f(id string, sev policy.Severity) policy.Finding {
	return policy.Finding{RuleID: id, Title: id + " title", Severity: sev}
}

func TestNoRegression(t *testing.T) {
	// Same score, same findings.
	old := []policy.Finding{f("HSM-001", policy.SevCritical)}
	got := Detect(90, 90, old, old, 10)
	if got != nil {
		t.Errorf("expected no regression, got %+v", got)
	}
}

func TestScoreImproved(t *testing.T) {
	if got := Detect(70, 95, nil, nil, 10); got != nil {
		t.Errorf("an improving score is not a regression: %+v", got)
	}
}

func TestSmallDropIgnored(t *testing.T) {
	// A 5-point drop with no new severe finding is below the threshold.
	if got := Detect(90, 85, nil, nil, 10); got != nil {
		t.Errorf("sub-threshold drop should not fire: %+v", got)
	}
}

func TestScoreDrop(t *testing.T) {
	got := Detect(90, 75, nil, nil, 10)
	if got == nil || !got.ScoreDropped {
		t.Fatalf("15-point drop should be a regression: %+v", got)
	}
	if got.ScoreDelta != -15 {
		t.Errorf("ScoreDelta = %d, want -15", got.ScoreDelta)
	}
	if len(got.Reasons) == 0 {
		t.Error("expected a reason line")
	}
}

func TestNewSevereFinding(t *testing.T) {
	// Score unchanged, but a new high finding appeared.
	old := []policy.Finding{f("HSM-005", policy.SevMedium)}
	nw := []policy.Finding{f("HSM-005", policy.SevMedium), f("HSM-003", policy.SevHigh)}
	got := Detect(80, 80, old, nw, 10)
	if got == nil {
		t.Fatal("a new high finding should be a regression even at equal score")
	}
	if got.ScoreDropped {
		t.Error("score did not drop")
	}
	if len(got.NewSevere) != 1 || got.NewSevere[0].RuleID != "HSM-003" {
		t.Fatalf("NewSevere wrong: %+v", got.NewSevere)
	}
}

func TestPreexistingSevereNotNew(t *testing.T) {
	// The same critical finding in both scans is not "new".
	old := []policy.Finding{f("HSM-001", policy.SevCritical)}
	nw := []policy.Finding{f("HSM-001", policy.SevCritical)}
	if got := Detect(80, 80, old, nw, 10); got != nil {
		t.Errorf("a pre-existing critical is not a new regression: %+v", got)
	}
}

func TestNewSevereDedupedAndSorted(t *testing.T) {
	nw := []policy.Finding{
		f("HSM-003", policy.SevHigh), f("HSM-001", policy.SevCritical),
		f("HSM-003", policy.SevHigh), // duplicate rule (per-object) collapses
	}
	got := Detect(80, 80, nil, nw, 10)
	if got == nil || len(got.NewSevere) != 2 {
		t.Fatalf("want 2 deduped severe findings: %+v", got)
	}
	if got.NewSevere[0].RuleID != "HSM-001" || got.NewSevere[1].RuleID != "HSM-003" {
		t.Errorf("not sorted by rule ID: %+v", got.NewSevere)
	}
}

func TestMediumFindingIgnored(t *testing.T) {
	// A new medium finding, no score drop → not a regression.
	nw := []policy.Finding{f("HSM-005", policy.SevMedium)}
	if got := Detect(80, 80, nil, nw, 10); got != nil {
		t.Errorf("a new medium finding alone should not fire: %+v", got)
	}
}

func TestDefaultThreshold(t *testing.T) {
	// dropThreshold <= 0 falls back to the default (10).
	if got := Detect(90, 82, nil, nil, 0); got != nil {
		t.Errorf("8-point drop is below the default threshold of 10: %+v", got)
	}
	if got := Detect(90, 78, nil, nil, 0); got == nil || !got.ScoreDropped {
		t.Errorf("12-point drop should fire under the default threshold: %+v", got)
	}
}
