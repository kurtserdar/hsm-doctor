package kmip

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// Report is a KMIP inventory with its posture findings and health score.
type Report struct {
	Inventory *Inventory       `json:"inventory"`
	Score     int              `json:"score"`
	Findings  []policy.Finding `json:"findings"`
}

// Evaluate applies the KMIP posture rules to an inventory and scores it. The
// score starts at 100 and each finding subtracts its severity penalty (floor 0),
// matching the PKCS#11 scan scoring.
func Evaluate(inv *Inventory) *Report {
	var findings []policy.Finding
	for _, o := range inv.Objects {
		findings = append(findings, objectFindings(o)...)
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

func severityPenalty(s policy.Severity) int {
	switch s {
	case policy.SevCritical:
		return policy.DefaultScoring.Critical
	case policy.SevHigh:
		return policy.DefaultScoring.High
	case policy.SevMedium:
		return policy.DefaultScoring.Medium
	case policy.SevLow:
		return policy.DefaultScoring.Low
	}
	return 0
}

func objectFindings(o Object) []policy.Finding {
	var out []policy.Finding
	ref := objectRef(o)

	if weak, detail := weakKey(o); weak {
		out = append(out, policy.Finding{
			RuleID: "KMIP-001", Title: "Weak cryptographic key", Severity: policy.SevHigh,
			Object: ref, Detail: detail,
			Remediation: "Replace the key with an approved strength (RSA-2048+/ECC P-224+/AES-128+) and re-key its consumers.",
		})
	}

	switch o.State {
	case "Compromised", "Destroyed Compromised":
		out = append(out, policy.Finding{
			RuleID: "KMIP-002", Title: "Compromised key still present", Severity: policy.SevCritical,
			Object: ref, Detail: "object state is " + o.State,
			Remediation: "Destroy the compromised object and rotate anything it protected.",
		})
	case "Deactivated":
		out = append(out, policy.Finding{
			RuleID: "KMIP-003", Title: "Deactivated key not destroyed", Severity: policy.SevMedium,
			Object: ref, Detail: "object is Deactivated but still stored",
			Remediation: "Destroy deactivated keys once their retention period ends.",
		})
	}

	if hasUsage(o, "Sign") && hasUsage(o, "Decrypt") {
		out = append(out, policy.Finding{
			RuleID: "KMIP-004", Title: "Key mixes signing and decryption", Severity: policy.SevMedium,
			Object: ref, Detail: "usage mask grants both Sign and Decrypt",
			Remediation: "Split signing and decryption into separate single-purpose keys.",
		})
	}

	if len(o.Names) == 0 {
		out = append(out, policy.Finding{
			RuleID: "KMIP-005", Title: "Unnamed managed object", Severity: policy.SevLow,
			Object: ref, Detail: "object has no Name attribute",
			Remediation: "Give every managed object a Name so operators can identify it.",
		})
	}
	return out
}

func objectRef(o Object) string {
	label := o.Type
	if label == "" {
		label = "object"
	}
	if len(o.Names) > 0 {
		label += " " + o.Names[0]
	}
	return fmt.Sprintf("%s (%s)", label, o.ID)
}

func hasUsage(o Object, name string) bool {
	for _, u := range o.UsageMask {
		if u == name {
			return true
		}
	}
	return false
}

// weakKey reports whether the object's algorithm/length is below the accepted
// minimum strength.
func weakKey(o Object) (bool, string) {
	if o.Length == 0 {
		return false, ""
	}
	alg := strings.ToUpper(o.Algorithm)
	switch {
	case alg == "DES" || strings.Contains(alg, "TRIPLE DES") || alg == "DES3":
		return true, o.Algorithm + " is a broken cipher"
	case alg == "RSA" || alg == "DSA" || alg == "DH":
		if o.Length < 2048 {
			return true, fmt.Sprintf("%s key is %d bits (< 2048)", o.Algorithm, o.Length)
		}
	case strings.HasPrefix(alg, "EC"):
		if o.Length < 224 {
			return true, fmt.Sprintf("%s key is %d bits (< 224)", o.Algorithm, o.Length)
		}
	case alg == "AES":
		if o.Length < 128 {
			return true, fmt.Sprintf("AES key is %d bits (< 128)", o.Length)
		}
	}
	return false, ""
}
