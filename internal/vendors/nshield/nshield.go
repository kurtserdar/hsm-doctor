// Package nshield is an EXPERIMENTAL provider for Entrust nShield HSMs.
//
// It runs the local nShield tools ("enquiry", "nfkminfo") and parses their
// output. The parsers follow the formats documented publicly by Entrust and
// have NOT been validated against real hardware.
package nshield

import (
	"context"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type provider struct {
	runner vendor.Runner
}

func init() {
	vendor.Register(&provider{runner: vendor.ExecRunner{}})
}

func (p *provider) Name() string { return "nshield" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "nshield") || strings.Contains(hay, "entrust") ||
		strings.Contains(hay, "ncipher")
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	info := &vendor.Info{Provider: p.Name(), Experimental: true, Extra: map[string]string{}}

	out, err := p.runner.Run(ctx, "enquiry")
	if err != nil {
		// enquiry is the fundamental tool; without it there is nothing to
		// report, but this is a soft failure (tools may be absent).
		return nil, err
	}
	parseEnquiry(out, info)

	if out, err := p.runner.Run(ctx, "nfkminfo"); err == nil {
		parseNfkminfo(out, info)
	}
	return info, nil
}

// parseEnquiry reads module mode and version from "enquiry" output. Lines
// look like "<key>   <value...>" with leading indentation.
func parseEnquiry(out string, info *vendor.Info) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		switch {
		case strings.HasPrefix(key, "mode"):
			info.Extra["mode"] = value
			// "maintenance" or "initialization" mode means the unit is not
			// serving operations normally.
			if lv := strings.ToLower(value); lv != "" && !strings.Contains(lv, "operational") {
				info.Findings = append(info.Findings, policy.Finding{
					RuleID:   "NSHIELD-001",
					Title:    "Module not in operational mode",
					Severity: policy.SevHigh,
					Detail:   "enquiry reports mode: " + value,
				})
			}
		case strings.HasPrefix(key, "version"):
			info.Extra["version"] = value
		}
	}
}

// parseNfkminfo reads the security-world state from "nfkminfo" output.
func parseNfkminfo(out string, info *vendor.Info) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "state ") || strings.HasPrefix(line, "State ") {
			_, value, ok := strings.Cut(line, " ")
			if ok {
				info.Extra["security_world_state"] = strings.TrimSpace(value)
			}
		}
	}
}
