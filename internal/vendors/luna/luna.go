// Package luna is an EXPERIMENTAL provider for Thales Luna network HSMs.
//
// It shells out to lunash over SSH and parses the human-readable output of
// commands such as "hsm show" and "partition list". The parsers are written
// against the output formats in public Thales documentation and have NOT
// been validated against real hardware. Treat findings accordingly and,
// ideally, contribute corrections from a real appliance.
package luna

import (
	"context"
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type provider struct {
	// runner is overridable in tests; nil means build an SSH runner from
	// the config at collect time.
	runner vendor.Runner
}

func init() {
	vendor.Register(&provider{})
}

func (p *provider) Name() string { return "luna" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "luna") || strings.Contains(hay, "safenet") ||
		strings.Contains(hay, "gemalto") || strings.Contains(hay, "thales")
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	runner := p.runner
	if runner == nil {
		if cfg["host"] == "" {
			return nil, vendor.ErrNotConfigured
		}
		r, err := newSSHRunner(cfg)
		if err != nil {
			return nil, err
		}
		runner = r
	}

	info := &vendor.Info{Provider: p.Name(), Experimental: true, Extra: map[string]string{}}

	if out, err := runner.Run(ctx, "hsm", "show"); err == nil {
		parseHSMShow(out, info)
	} else {
		return nil, fmt.Errorf("lunash 'hsm show': %w", err)
	}
	if out, err := runner.Run(ctx, "partition", "list"); err == nil {
		parsePartitionList(out, info)
	}
	return info, nil
}

// parseHSMShow extracts firmware, serial and tamper state from "hsm show".
// Tamper is decided across all matching lines so a single tripped sensor wins,
// and only an affirmative tamper value raises the critical finding — a bare
// "No" must never be misread as a tamper condition.
func parseHSMShow(out string, info *vendor.Info) {
	var tamperSeen, tampered bool
	var tamperDetail string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch {
		case strings.Contains(key, "firmware"):
			info.Extra["firmware"] = value
		case strings.Contains(key, "serial"):
			info.Extra["serial"] = value
		case strings.Contains(key, "tamper"):
			tamperSeen = true
			if tamperTripped(value) {
				tampered = true
				tamperDetail = value
			} else if tamperDetail == "" {
				tamperDetail = value
			}
		}
	}
	if tamperSeen {
		info.Tamper = &vendor.TamperStatus{Tampered: tampered, Detail: tamperDetail}
		if tampered {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "LUNA-001",
				Title:    "HSM reports a tamper condition",
				Severity: policy.SevCritical,
				Detail:   tamperDetail,
			})
		}
	}
}

// tamperTripped reports whether a tamper-state value affirmatively indicates a
// tamper event. Known-clear values ("No", "None", "No tamper(s)"…) and
// ambiguous values are treated as not tripped to avoid false criticals.
func tamperTripped(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "", "no", "none", "clear", "ok", "false", "0", "normal", "not tampered":
		return false
	}
	if strings.Contains(v, "no tamper") || strings.Contains(v, "none") {
		return false
	}
	for _, s := range []string{"yes", "true", "detected", "active", "intrusion", "tampered", "tamper detected"} {
		if strings.Contains(v, s) {
			return true
		}
	}
	// Unknown wording: do not raise a critical finding on uncertainty.
	return false
}

// parsePartitionList extracts partition object counts from "partition list".
// The heuristic reads "<label> ... <objects>" data rows and skips header and
// separator lines.
func parsePartitionList(out string, info *vendor.Info) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if isSeparator(fields[0]) || isSeparator(fields[len(fields)-1]) {
			continue
		}
		used, err := atoiSafe(fields[len(fields)-1])
		if err != nil || used < 0 {
			continue
		}
		info.Partitions = append(info.Partitions, vendor.PartitionInfo{
			Label:       fields[0],
			UsedObjects: &used,
		})
	}
}

// isSeparator reports whether a token is a table rule made only of separator
// characters (=, -, _), used to skip header underlines.
func isSeparator(s string) bool {
	if s == "" {
		return true
	}
	return strings.Trim(s, "=-_") == ""
}
