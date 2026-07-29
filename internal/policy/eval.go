package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// Finding is one triggered rule instance.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Object identifies the offending object ("private-key label (id 01)"),
	// empty for token-scoped findings such as weak mechanisms.
	Object string `json:"object,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Result is the outcome of evaluating an inventory against a rule set.
type Result struct {
	Findings []Finding `json:"findings"`
	Score    int       `json:"score"`
}

// CountBySeverity tallies findings per severity.
func (r *Result) CountBySeverity() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// facts holds derived per-inventory information shared by all rules.
type facts struct {
	now time.Time
	// duplicateLabels: class -> label -> count (non-empty labels only)
	duplicateLabels map[string]map[string]int
	// idOwners: hex CKA_ID -> set of classes carrying that ID
	idOwners map[string]map[string]bool
}

func buildFacts(inv *inventory.Inventory, now time.Time) *facts {
	f := &facts{
		now:             now,
		duplicateLabels: map[string]map[string]int{},
		idOwners:        map[string]map[string]bool{},
	}
	for _, o := range inv.Objects {
		if o.Label != "" {
			if f.duplicateLabels[o.Class] == nil {
				f.duplicateLabels[o.Class] = map[string]int{}
			}
			f.duplicateLabels[o.Class][o.Label]++
		}
		if o.ID != "" {
			if f.idOwners[o.ID] == nil {
				f.idOwners[o.ID] = map[string]bool{}
			}
			f.idOwners[o.ID][o.Class] = true
		}
	}
	return f
}

// isDuplicateLabel reports whether another object of the same class shares
// this object's label. Keys and their certificates legitimately share labels
// across classes, so duplicates are only counted within a class.
func (f *facts) isDuplicateLabel(o *inventory.Object) bool {
	return o.Label != "" && f.duplicateLabels[o.Class][o.Label] > 1
}

// isOrphan reports whether the object lacks its expected counterparts:
// a private key with no certificate or public key sharing its CKA_ID, or a
// certificate with no private key sharing its CKA_ID. Objects without a
// CKA_ID cannot be correlated at all and count as orphans.
func (f *facts) isOrphan(o *inventory.Object) bool {
	switch o.Class {
	case inventory.ClassPrivateKey:
		if o.ID == "" {
			return true
		}
		owners := f.idOwners[o.ID]
		return !owners[inventory.ClassCertificate] && !owners[inventory.ClassPublicKey]
	case inventory.ClassCertificate:
		if o.ID == "" {
			return true
		}
		return !f.idOwners[o.ID][inventory.ClassPrivateKey]
	}
	return false
}

// Evaluate runs all rules against the inventory. The now parameter anchors
// certificate expiry checks so results are reproducible in tests.
func Evaluate(inv *inventory.Inventory, cfg *Config, now time.Time) *Result {
	f := buildFacts(inv, now)
	res := &Result{}

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if len(rule.Match.MechanismAnyOf) > 0 {
			evalMechanismRule(inv, rule, res)
			continue
		}
		for j := range inv.Objects {
			obj := &inv.Objects[j]
			if matched, detail := matchObject(rule, obj, f); matched {
				res.Findings = append(res.Findings, Finding{
					RuleID:   rule.ID,
					Title:    rule.Title,
					Severity: rule.Severity,
					Object:   objectRef(obj),
					Detail:   detail,
				})
			}
		}
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity.Rank() < res.Findings[j].Severity.Rank()
	})

	scoring := cfg.scoring()
	res.Score = 100
	for _, fd := range res.Findings {
		res.Score -= scoring.penalty(fd.Severity)
	}
	if res.Score < 0 {
		res.Score = 0
	}
	return res
}

func evalMechanismRule(inv *inventory.Inventory, rule *Rule, res *Result) {
	available := map[string]bool{}
	for _, m := range inv.Mechanisms {
		available[m.Name] = true
	}
	var hits []string
	for _, name := range rule.Match.MechanismAnyOf {
		if available[name] {
			hits = append(hits, name)
		}
	}
	if len(hits) > 0 {
		res.Findings = append(res.Findings, Finding{
			RuleID:   rule.ID,
			Title:    rule.Title,
			Severity: rule.Severity,
			Detail:   "token advertises: " + strings.Join(hits, ", "),
		})
	}
}

// matchObject checks every set condition field against one object. The
// returned detail explains why the rule fired.
func matchObject(rule *Rule, o *inventory.Object, f *facts) (bool, string) {
	c := &rule.Match
	var details []string

	if c.Class != "" && o.Class != c.Class {
		return false, ""
	}
	if c.KeyType != "" && o.KeyType != c.KeyType {
		return false, ""
	}
	for _, b := range []struct {
		cond *bool
		attr *bool
		name string
	}{
		{c.Extractable, o.Extractable, "CKA_EXTRACTABLE"},
		{c.Sensitive, o.Sensitive, "CKA_SENSITIVE"},
		{c.Sign, o.Sign, "CKA_SIGN"},
		{c.Decrypt, o.Decrypt, "CKA_DECRYPT"},
		{c.Wrap, o.Wrap, "CKA_WRAP"},
		{c.Unwrap, o.Unwrap, "CKA_UNWRAP"},
	} {
		if b.cond == nil {
			continue
		}
		if b.attr == nil || *b.attr != *b.cond {
			return false, ""
		}
		details = append(details, fmt.Sprintf("%s=%v", b.name, *b.attr))
	}
	if c.KeySizeLT > 0 {
		if o.KeyBits == 0 || o.KeyBits >= c.KeySizeLT {
			return false, ""
		}
		details = append(details, fmt.Sprintf("key size %d < %d bits", o.KeyBits, c.KeySizeLT))
	}
	if c.CertExpired != nil {
		if o.Certificate == nil {
			return false, ""
		}
		expired := o.Certificate.NotAfter.Before(f.now)
		if expired != *c.CertExpired {
			return false, ""
		}
		details = append(details, fmt.Sprintf("expired %s", o.Certificate.NotAfter.Format("2006-01-02")))
	}
	if c.CertExpiresWithinDays > 0 {
		if o.Certificate == nil {
			return false, ""
		}
		left := o.Certificate.NotAfter.Sub(f.now)
		// Already-expired certificates are covered by cert_expired rules.
		if left <= 0 || left > time.Duration(c.CertExpiresWithinDays)*24*time.Hour {
			return false, ""
		}
		details = append(details, fmt.Sprintf("expires %s (%d days left)",
			o.Certificate.NotAfter.Format("2006-01-02"), int(left.Hours()/24)))
	}
	if c.DuplicateLabel != nil {
		if f.isDuplicateLabel(o) != *c.DuplicateLabel {
			return false, ""
		}
		details = append(details, fmt.Sprintf("label %q used by multiple %s objects", o.Label, o.Class))
	}
	if c.Orphan != nil {
		if f.isOrphan(o) != *c.Orphan {
			return false, ""
		}
		if o.ID == "" {
			details = append(details, "object has no CKA_ID to correlate")
		} else {
			details = append(details, "no counterpart object shares CKA_ID "+o.ID)
		}
	}
	return true, strings.Join(details, "; ")
}

// objectRef renders a short human-readable object reference.
func objectRef(o *inventory.Object) string {
	ref := o.Class
	if o.Label != "" {
		ref += " " + o.Label
	}
	if o.ID != "" {
		ref += " (id " + o.ID + ")"
	}
	return ref
}
