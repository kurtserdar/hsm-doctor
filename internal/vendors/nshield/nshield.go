// Package nshield is an EXPERIMENTAL provider for Entrust nShield HSMs.
//
// It runs the local nShield tools ("enquiry", "nfkminfo") and parses their
// output. The parsers follow the formats documented publicly by Entrust and
// have NOT been validated against real hardware.
package nshield

import (
	"context"
	"fmt"
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
		// report. This is a soft failure (the tools may simply be absent) that
		// the caller skips gracefully.
		return nil, fmt.Errorf("nshield: running enquiry: %w", err)
	}
	parseEnquiry(out, info)

	// nfkminfo is best-effort: a missing tool or security world must not sink
	// the module data already gathered from enquiry.
	if out, err := p.runner.Run(ctx, "nfkminfo"); err == nil {
		parseNfkminfo(out, info)
	}
	return info, nil
}

// parseEnquiry reads module mode and version from "enquiry" output. Lines look
// like "<key>   <value...>" with leading indentation, grouped under "Server:"
// and "Module #N:" headers. Tolerant of extra whitespace and CRLF endings
// (strings.Fields treats \r as whitespace).
func parseEnquiry(out string, info *vendor.Info) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		switch key {
		case "mode":
			info.Extra["mode"] = value
			// Anything other than "operational" (maintenance, initialization,
			// pre-maintenance, …) means the unit is not serving normally.
			if lv := strings.ToLower(value); lv != "" && !strings.Contains(lv, "operational") {
				info.Findings = append(info.Findings, policy.Finding{
					RuleID:   "NSHIELD-001",
					Title:    "Module not in operational mode",
					Severity: policy.SevHigh,
					Detail:   "enquiry reports mode: " + value,
				})
			}
		case "version":
			info.Extra["version"] = value
		}
	}
}

// parseNfkminfo reads the security-world state from "nfkminfo" output. The
// relevant line looks like:
//
//	state    0x37270009 Initialised Usable Recovery ...
//
// where flag tokens without a leading "!" are set.
func parseNfkminfo(out string, info *vendor.Info) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, " ")
		if !ok || !strings.EqualFold(key, "state") {
			continue
		}
		state := strings.TrimSpace(value)
		if state == "" {
			continue
		}
		info.Extra["security_world_state"] = state
		checkWorldState(state, info)
	}
}

// checkWorldState flags a security world that is initialised but not usable —
// a real operational problem (e.g. missing card set / recovery data).
func checkWorldState(state string, info *vendor.Info) {
	var initialised, usable bool
	for _, tok := range strings.Fields(state) {
		switch {
		case strings.EqualFold(tok, "Initialised"), strings.EqualFold(tok, "Initialized"):
			initialised = true
		case strings.EqualFold(tok, "Usable"):
			usable = true
		}
	}
	if initialised && !usable {
		info.Findings = append(info.Findings, policy.Finding{
			RuleID:   "NSHIELD-002",
			Title:    "Security world not usable",
			Severity: policy.SevHigh,
			Detail:   "nfkminfo security-world state: " + state,
		})
	}
}
