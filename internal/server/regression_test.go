package server

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

func regReport(score int, findings []policy.Finding) *report.Report {
	return &report.Report{
		Tool:     "hsmdoctor",
		Version:  "test",
		Score:    score,
		Findings: findings,
		Inventory: &inventory.Inventory{
			ScannedAt: time.Now().UTC(),
			Slot: p11.SlotInfo{TokenPresent: true, Token: &p11.TokenInfo{
				SerialNumber: "REG-1", Label: "regtok",
			}},
		},
	}
}

func TestPersistScanRegression(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	s := NewCentral("test", st, "")

	// Baseline: healthy, no findings. First scan has no predecessor, so it
	// can never be a regression.
	s.persistScan(regReport(95, nil), "local")

	hsms, err := st.ListHSMs()
	if err != nil || len(hsms) != 1 {
		t.Fatalf("want 1 HSM, got %d (err %v)", len(hsms), err)
	}
	hsmID := hsms[0].ID

	if evs, _ := st.ListRegressionEvents(hsmID, 10); len(evs) != 0 {
		t.Fatalf("baseline scan must not record a regression: %+v", evs)
	}

	// Worse: score drops 25 points and a new critical finding appears.
	s.persistScan(regReport(70, []policy.Finding{
		{RuleID: "HSM-001", Title: "Extractable private key", Severity: policy.SevCritical},
	}), "local")

	evs, err := st.ListRegressionEvents(hsmID, 10)
	if err != nil {
		t.Fatalf("ListRegressionEvents: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 regression event, got %d", len(evs))
	}
	if evs[0].ScoreDelta != -25 {
		t.Errorf("ScoreDelta = %d, want -25", evs[0].ScoreDelta)
	}
	var detail struct {
		ScoreDropped bool `json:"score_dropped"`
		NewSevere    []struct {
			RuleID string `json:"rule_id"`
		} `json:"new_severe"`
	}
	if err := json.Unmarshal(evs[0].Detail, &detail); err != nil {
		t.Fatalf("detail not valid JSON: %v", err)
	}
	if !detail.ScoreDropped {
		t.Error("detail should record the score drop")
	}
	if len(detail.NewSevere) != 1 || detail.NewSevere[0].RuleID != "HSM-001" {
		t.Errorf("detail should list the new critical finding: %+v", detail.NewSevere)
	}

	// Recovery: score climbs back and the critical clears — not a regression.
	s.persistScan(regReport(95, nil), "local")
	if evs, _ := st.ListRegressionEvents(hsmID, 10); len(evs) != 1 {
		t.Errorf("recovery must not add a regression event, have %d", len(evs))
	}
}
