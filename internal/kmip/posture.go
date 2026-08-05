package kmip

import (
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// Report is a KMIP inventory with its posture findings and health score.
type Report struct {
	Inventory *Inventory       `json:"inventory"`
	RulePacks []string         `json:"rule_packs,omitempty"`
	Score     int              `json:"score"`
	Findings  []policy.Finding `json:"findings"`
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
