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
	scoring  Scoring
}

// AddFindings merges extra findings (e.g. from a vendor provider) into the
// result, re-sorts by severity and recomputes the score with the same
// penalties used for the rule set.
func (r *Result) AddFindings(extra ...Finding) {
	if len(extra) == 0 {
		return
	}
	r.Findings = append(r.Findings, extra...)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity.Rank() < r.Findings[j].Severity.Rank()
	})
	r.Score = 100
	for _, f := range r.Findings {
		r.Score -= r.scoring.penalty(f.Severity)
	}
	if r.Score < 0 {
		r.Score = 0
	}
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
		if rule.Match.tokenScoped() {
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

	res.scoring = cfg.scoring()
	res.Score = 100
	for _, fd := range res.Findings {
		res.Score -= res.scoring.penalty(fd.Severity)
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

	if len(rule.Match.MechanismAnyOf) > 0 {
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
		return
	}

	// mechanism_missing: a capability gap. Fires only when the token
	// advertises none of the listed mechanisms.
	for _, name := range rule.Match.MechanismMissing {
		if available[name] {
			return
		}
	}
	res.Findings = append(res.Findings, Finding{
		RuleID:   rule.ID,
		Title:    rule.Title,
		Severity: rule.Severity,
		Detail:   "token advertises none of: " + strings.Join(rule.Match.MechanismMissing, ", "),
	})
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
	if len(c.KeyTypeIn) > 0 {
		if o.KeyType == "" || !contains(c.KeyTypeIn, o.KeyType) {
			return false, ""
		}
		details = append(details, "key type "+o.KeyType)
	}
	if len(c.CurveIn) > 0 {
		if o.Curve == "" || !contains(c.CurveIn, o.Curve) {
			return false, ""
		}
		details = append(details, "curve "+o.Curve)
	}
	if len(c.CurveNotIn) > 0 {
		if o.Curve == "" || contains(c.CurveNotIn, o.Curve) {
			return false, ""
		}
		details = append(details, fmt.Sprintf("curve %s outside the allowed set", o.Curve))
	}
	for _, b := range []struct {
		cond *bool
		attr *bool
		name string
	}{
		{c.Extractable, o.Extractable, "CKA_EXTRACTABLE"},
		{c.Sensitive, o.Sensitive, "CKA_SENSITIVE"},
		{c.AlwaysSensitive, o.AlwaysSensitive, "CKA_ALWAYS_SENSITIVE"},
		{c.NeverExtractable, o.NeverExtractable, "CKA_NEVER_EXTRACTABLE"},
		{c.Modifiable, o.Modifiable, "CKA_MODIFIABLE"},
		{c.Sign, o.Sign, "CKA_SIGN"},
		{c.Verify, o.Verify, "CKA_VERIFY"},
		{c.Encrypt, o.Encrypt, "CKA_ENCRYPT"},
		{c.Decrypt, o.Decrypt, "CKA_DECRYPT"},
		{c.Derive, o.Derive, "CKA_DERIVE"},
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
	if c.CertValidityDaysGT > 0 {
		if o.Certificate == nil {
			return false, ""
		}
		validity := o.Certificate.NotAfter.Sub(o.Certificate.NotBefore)
		if validity <= time.Duration(c.CertValidityDaysGT)*24*time.Hour {
			return false, ""
		}
		details = append(details, fmt.Sprintf("validity %d days > %d",
			int(validity.Hours()/24), c.CertValidityDaysGT))
	}
	if len(c.CertSigAlgIn) > 0 {
		if o.Certificate == nil || !contains(c.CertSigAlgIn, o.Certificate.SignatureAlgorithm) {
			return false, ""
		}
		details = append(details, "signature algorithm "+o.Certificate.SignatureAlgorithm)
	}
	if c.CertIsCA != nil {
		if o.Certificate == nil || o.Certificate.IsCA != *c.CertIsCA {
			return false, ""
		}
		if *c.CertIsCA {
			details = append(details, "CA certificate")
		}
	}
	if c.CertSelfSigned != nil {
		if o.Certificate == nil || o.Certificate.SelfSigned != *c.CertSelfSigned {
			return false, ""
		}
		if *c.CertSelfSigned {
			details = append(details, "self-signed (issuer equals subject)")
		}
	}
	if c.CertNotYetValid != nil {
		notYet := o.Certificate != nil && o.Certificate.NotBefore.After(f.now)
		if o.Certificate == nil || notYet != *c.CertNotYetValid {
			return false, ""
		}
		if *c.CertNotYetValid {
			details = append(details, "not valid until "+o.Certificate.NotBefore.Format("2006-01-02"))
		}
	}
	if c.CertKeySizeLT > 0 {
		if o.Certificate == nil || o.Certificate.PublicKeyBits == 0 ||
			uint(o.Certificate.PublicKeyBits) >= c.CertKeySizeLT {
			return false, ""
		}
		details = append(details, fmt.Sprintf("certificate key %d bits < %d",
			o.Certificate.PublicKeyBits, c.CertKeySizeLT))
	}
	if len(c.CertPubKeyAlgIn) > 0 {
		if o.Certificate == nil || !contains(c.CertPubKeyAlgIn, o.Certificate.PublicKeyAlgorithm) {
			return false, ""
		}
		details = append(details, "certificate key algorithm "+o.Certificate.PublicKeyAlgorithm)
	}
	if c.CertCAWithoutKeyCertSign != nil {
		bad := o.Certificate != nil && o.Certificate.IsCA && !o.Certificate.HasKeyUsage("keyCertSign")
		if o.Certificate == nil || bad != *c.CertCAWithoutKeyCertSign {
			return false, ""
		}
		if *c.CertCAWithoutKeyCertSign {
			details = append(details, "CA certificate lacks keyCertSign usage")
		}
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

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
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
