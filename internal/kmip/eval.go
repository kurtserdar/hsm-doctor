package kmip

import (
	"sort"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// Evaluate applies a KMIP rule set to an inventory and scores it. The score
// starts at 100 and each finding subtracts its severity penalty (floor 0),
// matching the PKCS#11 scan scoring.
func Evaluate(inv *Inventory, cfg *RuleSet) *Report {
	var findings []policy.Finding
	for _, o := range inv.Objects {
		ref := objectRef(o)
		for i := range cfg.Rules {
			r := &cfg.Rules[i]
			if ok, detail := matchRule(o, r.Match); ok {
				findings = append(findings, policy.Finding{
					RuleID:      r.ID,
					Title:       r.Title,
					Severity:    r.Severity,
					Object:      ref,
					Detail:      detail,
					Remediation: r.Remediation,
					Reference:   r.Reference,
				})
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity.Rank() < findings[j].Severity.Rank()
	})

	score := 100
	for _, f := range findings {
		score -= severityPenalty(f.Severity)
	}
	if score < 0 {
		score = 0
	}
	return &Report{Inventory: inv, Score: score, Findings: findings}
}

// matchRule reports whether every condition in the match holds for the object,
// along with a human-readable detail assembled from the matched conditions.
func matchRule(o Object, m Match) (bool, string) {
	var details []string

	if len(m.ObjectTypeIn) > 0 {
		if !containsFold(m.ObjectTypeIn, o.Type) {
			return false, ""
		}
		details = append(details, "type "+o.Type)
	}
	if len(m.AlgorithmIn) > 0 {
		if !containsFold(m.AlgorithmIn, o.Algorithm) {
			return false, ""
		}
		details = append(details, "algorithm "+o.Algorithm)
	}
	if m.LengthLT > 0 {
		if o.Length == 0 || o.Length >= m.LengthLT {
			return false, ""
		}
		details = append(details, "length "+itoa(o.Length)+" < "+itoa(m.LengthLT))
	}
	if len(m.StateIn) > 0 {
		if !containsFold(m.StateIn, o.State) {
			return false, ""
		}
		details = append(details, "state "+o.State)
	}
	if len(m.UsageAllOf) > 0 {
		for _, u := range m.UsageAllOf {
			if !hasUsage(o, u) {
				return false, ""
			}
		}
		details = append(details, "usage "+strings.Join(m.UsageAllOf, "+"))
	}
	if len(m.UsageAnyOf) > 0 {
		found := false
		for _, u := range m.UsageAnyOf {
			if hasUsage(o, u) {
				found = true
				break
			}
		}
		if !found {
			return false, ""
		}
		details = append(details, "usage any of "+strings.Join(m.UsageAnyOf, "/"))
	}
	if m.Unnamed != nil {
		unnamed := len(o.Names) == 0
		if unnamed != *m.Unnamed {
			return false, ""
		}
		if unnamed {
			details = append(details, "no Name attribute")
		}
	}
	if m.WeakKey != nil {
		weak, d := weakKey(o)
		if weak != *m.WeakKey {
			return false, ""
		}
		if weak {
			details = append(details, d)
		}
	}
	return true, strings.Join(details, "; ")
}

// containsFold reports whether want equals any of list, case-insensitively.
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
