// Package advisory matches an HSM's firmware version and its PKCS#11 library
// version against a curated feed of known-vulnerability advisories, producing
// posture findings. It complements the configuration-based policy rules with
// version-based, known-issue detection.
//
// The advisory data is curated and dated, not exhaustive: it ships a small
// illustrative seed, and operators supply authoritative vendor/CVE data with
// `--advisories`. Matching is version-based and read-only.
package advisory

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"gopkg.in/yaml.v3"
)

// Match selects which version to check and the affected range.
type Match struct {
	// Component is "firmware" (the token's firmware version) or "library"
	// (the PKCS#11 module's version).
	Component string `yaml:"component" json:"component"`
	// Manufacturer is a case-insensitive substring the component's
	// manufacturer must contain (empty matches any).
	Manufacturer string `yaml:"manufacturer,omitempty" json:"manufacturer,omitempty"`
	// Model is an optional case-insensitive substring the token model (for
	// firmware) or module description (for library) must contain.
	Model string `yaml:"model,omitempty" json:"model,omitempty"`
	// IntroducedIn is the first affected version (inclusive); empty means "any
	// version before FixedIn".
	IntroducedIn string `yaml:"introduced_in,omitempty" json:"introduced_in,omitempty"`
	// FixedIn is the first unaffected version: the component is affected when
	// its version is below this. Required.
	FixedIn string `yaml:"fixed_in" json:"fixed_in"`
}

// Advisory is one known-vulnerability entry.
type Advisory struct {
	ID          string          `yaml:"id" json:"id"`
	Title       string          `yaml:"title" json:"title"`
	Severity    policy.Severity `yaml:"severity" json:"severity"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Remediation string          `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Reference   string          `yaml:"reference,omitempty" json:"reference,omitempty"`
	Match       Match           `yaml:"match" json:"match"`
}

// Feed is a dated set of advisories.
type Feed struct {
	// DataVersion is a human date/label recording how current the feed is.
	DataVersion string     `yaml:"data_version" json:"data_version"`
	Advisories  []Advisory `yaml:"advisories" json:"advisories"`
}

// Load parses and validates a feed from YAML.
func Load(data []byte) (*Feed, error) {
	var f Feed
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing advisory feed: %w", err)
	}
	seen := map[string]bool{}
	for i, a := range f.Advisories {
		switch {
		case a.ID == "":
			return nil, fmt.Errorf("advisory #%d: missing id", i+1)
		case seen[a.ID]:
			return nil, fmt.Errorf("advisory %s: duplicate id", a.ID)
		case a.Title == "":
			return nil, fmt.Errorf("advisory %s: missing title", a.ID)
		case !a.Severity.Valid():
			return nil, fmt.Errorf("advisory %s: invalid severity %q", a.ID, a.Severity)
		case a.Match.Component != "firmware" && a.Match.Component != "library":
			return nil, fmt.Errorf("advisory %s: component must be \"firmware\" or \"library\"", a.ID)
		case a.Match.FixedIn == "":
			return nil, fmt.Errorf("advisory %s: missing match.fixed_in", a.ID)
		}
		seen[a.ID] = true
	}
	return &f, nil
}

// Evaluate returns a finding for every advisory whose affected version range
// covers the module's or token's version.
func (f *Feed) Evaluate(mod p11.ModuleInfo, tok *p11.TokenInfo) []policy.Finding {
	var out []policy.Finding
	for _, a := range f.Advisories {
		var version, manufacturer, model string
		switch a.Match.Component {
		case "firmware":
			if tok == nil {
				continue
			}
			version, manufacturer, model = tok.FirmwareVersion, tok.Manufacturer, tok.Model
		case "library":
			version, manufacturer, model = mod.LibraryVersion, mod.Manufacturer, mod.Description
		default:
			continue
		}
		if a.Match.Manufacturer != "" && !containsFold(manufacturer, a.Match.Manufacturer) {
			continue
		}
		if a.Match.Model != "" && !containsFold(model, a.Match.Model) {
			continue
		}
		// Affected iff version < FixedIn (and >= IntroducedIn when set).
		if cmp, ok := compareVersions(version, a.Match.FixedIn); !ok || cmp >= 0 {
			continue
		}
		if a.Match.IntroducedIn != "" {
			if cmp, ok := compareVersions(version, a.Match.IntroducedIn); !ok || cmp < 0 {
				continue
			}
		}
		out = append(out, policy.Finding{
			RuleID:      a.ID,
			Title:       a.Title,
			Severity:    a.Severity,
			Object:      strings.TrimSpace(a.Match.Component+" "+manufacturer+" "+model) + " " + version,
			Detail:      fmt.Sprintf("version %s is affected; fixed in %s", version, a.Match.FixedIn),
			Remediation: a.Remediation,
			Reference:   a.Reference,
		})
	}
	return out
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// parseVersion extracts the leading dotted-numeric components of a version
// string ("FW 6.24.7-3" -> [6 24 7]), tolerating vendor prefixes and suffixes.
func parseVersion(s string) []int {
	start := strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' })
	if start < 0 {
		return nil
	}
	end := start
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	var out []int
	for _, p := range strings.Split(strings.Trim(s[start:end], "."), ".") {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// compareVersions reports a<b (-1), a==b (0) or a>b (1). ok is false when
// either version has no parseable numeric component (then callers skip the
// advisory rather than risk a false positive).
func compareVersions(a, b string) (int, bool) {
	va, vb := parseVersion(a), parseVersion(b)
	if len(va) == 0 || len(vb) == 0 {
		return 0, false
	}
	for i := 0; i < len(va) || i < len(vb); i++ {
		var x, y int
		if i < len(va) {
			x = va[i]
		}
		if i < len(vb) {
			y = vb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}
