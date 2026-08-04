// Package doctor aggregates the individual checks — posture, certificate
// expiry, post-quantum exposure, optional functional tests and vendor health —
// into a single prioritized diagnosis with one top-line verdict. It is the
// namesake "is my HSM healthy?" answer, built entirely from the other packages'
// results; it collects nothing itself.
package doctor

import (
	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
)

// Verdict is the overall health assessment.
type Verdict string

const (
	VerdictHealthy   Verdict = "healthy"
	VerdictAttention Verdict = "attention"
	VerdictCritical  Verdict = "critical"
)

// Rank orders verdicts from best to worst (0 = healthy).
func (v Verdict) Rank() int {
	switch v {
	case VerdictAttention:
		return 1
	case VerdictCritical:
		return 2
	default:
		return 0
	}
}

// Issue is one prioritized problem found across the checks.
type Issue struct {
	Severity policy.Severity `json:"severity"`
	Source   string          `json:"source"` // posture | pqc | functional
	Title    string          `json:"title"`
	Detail   string          `json:"detail,omitempty"`
	Action   string          `json:"action,omitempty"`
}

// Check records whether one check ran.
type Check struct {
	Name string `json:"name"`
	Ran  bool   `json:"ran"`
}

// Token identifies the assessed token.
type Token struct {
	Label        string `json:"label,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

// Report is the aggregated diagnosis.
type Report struct {
	Tool    string  `json:"tool"`
	Version string  `json:"version"`
	Token   Token   `json:"token"`
	Verdict Verdict `json:"verdict"`
	Score   int     `json:"score"`
	Summary string  `json:"summary"`
	Issues  []Issue `json:"issues"`
	Checks  []Check `json:"checks"`
}

// Input carries the collected results the diagnosis is built from. Certificate
// expiry is covered by the posture findings (the default and standard packs
// carry expiry rules), so it is not collected separately here.
type Input struct {
	Report    *report.Report
	Tests     *funtest.Result // nil unless functional tests ran
	TestsRan  bool
	VendorRan bool
}

// Build turns the collected results into a single diagnosis.
func Build(version string, in Input) *Report {
	rep := &Report{Tool: "hsmdoctor", Version: version}
	if in.Report != nil {
		rep.Score = in.Report.Score
		rep.Token = tokenOf(in.Report)
	}

	var issues []Issue

	// Posture (and merged vendor) findings.
	if in.Report != nil {
		for _, f := range in.Report.Findings {
			issues = append(issues, Issue{
				Severity: f.Severity,
				Source:   "posture",
				Title:    f.Title,
				Detail:   findingDetail(f),
				Action:   f.Remediation,
			})
		}
	}

	// Post-quantum harvest-now-decrypt-later exposure (informational).
	if in.Report != nil && in.Report.PQC != nil && in.Report.PQC.Exposure != nil {
		if n := in.Report.PQC.Exposure.HarvestNowDecryptLater; n > 0 {
			issues = append(issues, Issue{
				Severity: policy.SevInfo, Source: "pqc",
				Title:  plural(n, "quantum-vulnerable key can decrypt/unwrap", "quantum-vulnerable keys can decrypt/unwrap"),
				Detail: "harvest-now-decrypt-later exposure: traffic recorded today is decryptable once a quantum computer exists",
				Action: "Plan migration to ML-KEM and rotate these keys.",
			})
		}
	}

	// Functional test failures: the HSM cannot perform basic crypto.
	if in.TestsRan && in.Tests != nil {
		if _, fail, _ := in.Tests.Counts(); fail > 0 {
			issues = append(issues, Issue{
				Severity: policy.SevCritical, Source: "functional",
				Title:  plural(fail, "functional test step failed", "functional test steps failed"),
				Detail: "a supported cryptographic operation did not succeed",
				Action: "Investigate the failing mechanism; the token may be misconfigured or degraded.",
			})
		}
	}

	sortIssues(issues)
	rep.Issues = issues
	rep.Verdict = verdictOf(issues, rep.Score)
	rep.Summary = summarize(rep.Verdict, issues)
	rep.Checks = []Check{
		{Name: "inventory", Ran: in.Report != nil},
		{Name: "posture", Ran: in.Report != nil},
		{Name: "certificates", Ran: in.Report != nil},
		{Name: "pqc", Ran: in.Report != nil && in.Report.PQC != nil},
		{Name: "functional", Ran: in.TestsRan},
		{Name: "vendor", Ran: in.VendorRan},
	}
	return rep
}

// verdictOf derives the top-line verdict: any critical issue is CRITICAL; any
// other issue, or a health score below 90, is ATTENTION; otherwise HEALTHY.
func verdictOf(issues []Issue, score int) Verdict {
	for _, i := range issues {
		if i.Severity == policy.SevCritical {
			return VerdictCritical
		}
	}
	if len(issues) > 0 || score < 90 {
		return VerdictAttention
	}
	return VerdictHealthy
}

func summarize(v Verdict, issues []Issue) string {
	switch v {
	case VerdictCritical:
		return "critical issues need immediate attention"
	case VerdictAttention:
		if len(issues) == 0 {
			return "posture is below the healthy threshold; review the score"
		}
		return plural(len(issues), "issue to review", "issues to review")
	default:
		return "no issues found; the token's posture is healthy"
	}
}

func sortIssues(issues []Issue) {
	// Insertion by severity rank keeps a stable, most-severe-first order
	// without pulling in sort for such small slices.
	for i := 1; i < len(issues); i++ {
		for j := i; j > 0 && issues[j].Severity.Rank() < issues[j-1].Severity.Rank(); j-- {
			issues[j], issues[j-1] = issues[j-1], issues[j]
		}
	}
}

func tokenOf(rep *report.Report) Token {
	if rep.Inventory == nil || rep.Inventory.Slot.Token == nil {
		return Token{}
	}
	t := rep.Inventory.Slot.Token
	return Token{Label: t.Label, SerialNumber: t.SerialNumber, Model: t.Model, Manufacturer: t.Manufacturer}
}

func findingDetail(f policy.Finding) string {
	switch {
	case f.Object != "" && f.Detail != "":
		return f.Object + " — " + f.Detail
	case f.Object != "":
		return f.Object
	default:
		return f.Detail
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

// itoa avoids importing strconv for a single small conversion.
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
