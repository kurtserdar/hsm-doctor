// Package regression detects a worsening of a token's security posture
// between two consecutive scans: a drop in the health score or the
// appearance of a new critical/high finding. It complements drift detection,
// which tracks inventory changes rather than posture.
package regression

import (
	"fmt"
	"sort"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// DefaultScoreDropThreshold is the health-score drop (in points) that counts
// as a regression on its own.
const DefaultScoreDropThreshold = 10

// SevereFinding is a newly-appeared critical or high finding.
type SevereFinding struct {
	RuleID   string          `json:"rule_id"`
	Title    string          `json:"title"`
	Severity policy.Severity `json:"severity"`
}

// Regression describes how a scan's posture worsened relative to the
// previous scan. A nil *Regression means no regression.
type Regression struct {
	// ScoreDelta is newScore - oldScore; it is negative for a worse score.
	ScoreDelta int `json:"score_delta"`
	// ScoreDropped is true when the drop met the threshold.
	ScoreDropped bool `json:"score_dropped"`
	// NewSevere lists critical/high findings (by rule) not present, at
	// critical/high, in the previous scan.
	NewSevere []SevereFinding `json:"new_severe,omitempty"`
	// Reasons is a short human-readable summary for alerts.
	Reasons []string `json:"reasons"`
}

// Detect compares the previous scan to the new one and returns a Regression
// when the score dropped by at least dropThreshold OR a new critical/high
// finding appeared. It returns nil otherwise. A dropThreshold <= 0 falls back
// to DefaultScoreDropThreshold.
func Detect(oldScore, newScore int, oldFindings, newFindings []policy.Finding, dropThreshold int) *Regression {
	if dropThreshold <= 0 {
		dropThreshold = DefaultScoreDropThreshold
	}

	r := &Regression{ScoreDelta: newScore - oldScore}
	if oldScore-newScore >= dropThreshold {
		r.ScoreDropped = true
		r.Reasons = append(r.Reasons,
			fmt.Sprintf("health score dropped %d points (%d → %d)", oldScore-newScore, oldScore, newScore))
	}

	// Rule IDs that were already critical/high before are not "new".
	oldSevere := map[string]bool{}
	for _, f := range oldFindings {
		if isSevere(f.Severity) {
			oldSevere[f.RuleID] = true
		}
	}
	seen := map[string]bool{}
	for _, f := range newFindings {
		if !isSevere(f.Severity) || oldSevere[f.RuleID] || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		r.NewSevere = append(r.NewSevere, SevereFinding{
			RuleID: f.RuleID, Title: f.Title, Severity: f.Severity,
		})
	}
	sort.Slice(r.NewSevere, func(i, j int) bool { return r.NewSevere[i].RuleID < r.NewSevere[j].RuleID })
	for _, f := range r.NewSevere {
		r.Reasons = append(r.Reasons, fmt.Sprintf("new %s finding %s: %s", f.Severity, f.RuleID, f.Title))
	}

	if !r.ScoreDropped && len(r.NewSevere) == 0 {
		return nil
	}
	return r
}

func isSevere(s policy.Severity) bool {
	return s == policy.SevCritical || s == policy.SevHigh
}
