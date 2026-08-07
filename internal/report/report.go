// Package report renders scan results as console text, JSON or a
// self-contained HTML file.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

// PQCSummary is the score-neutral post-quantum block embedded in reports.
type PQCSummary struct {
	Verdict            pqc.Verdict   `json:"verdict"`
	AdvertisedFamilies []string      `json:"advertised_families,omitempty"`
	Exposure           *pqc.Exposure `json:"exposure"`
}

// Report bundles everything a single scan produced.
type Report struct {
	Tool      string               `json:"tool"`
	Version   string               `json:"version"`
	RulePacks []string             `json:"rule_packs,omitempty"`
	Score     int                  `json:"score"`
	Counts    inventory.Counts     `json:"counts"`
	Findings  []policy.Finding     `json:"findings"`
	PQC       *PQCSummary          `json:"pqc,omitempty"`
	Vendor    *vendor.Info         `json:"vendor,omitempty"`
	Inventory *inventory.Inventory `json:"inventory"`
}

// New assembles a report from scan results, including the PQC readiness
// summary derived from the inventory's mechanism list.
func New(version string, inv *inventory.Inventory, res *policy.Result) *Report {
	det := pqc.Detect(inv.Mechanisms)
	summary := &PQCSummary{
		Verdict:  det.Verdict,
		Exposure: pqc.Assess(inv, det),
	}
	for _, f := range det.Families {
		if f.Advertised {
			summary.AdvertisedFamilies = append(summary.AdvertisedFamilies, f.Family)
		}
	}
	return &Report{
		Tool:      "hsmdoctor",
		Version:   version,
		Score:     res.Score,
		Counts:    inv.Count(),
		Findings:  res.Findings,
		PQC:       summary,
		Inventory: inv,
	}
}

// JSON writes the full report as indented JSON.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// severities in display order; info findings are advisory and score-neutral.
var severities = []policy.Severity{policy.SevCritical, policy.SevHigh, policy.SevMedium, policy.SevLow, policy.SevInfo}

// Text writes the human-readable console report.
func (r *Report) Text(w io.Writer) error {
	inv := r.Inventory
	fmt.Fprintf(w, "HSM Doctor %s — scan report\n", r.Version)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", 40))

	fmt.Fprintf(w, "Module:   %s\n", inv.Module.Path)
	fmt.Fprintf(w, "          %s %s (Cryptoki %s)\n", inv.Module.Manufacturer, inv.Module.LibraryVersion, inv.Module.CryptokiVersion)
	fmt.Fprintf(w, "Slot:     %d (0x%x)\n", inv.Slot.ID, inv.Slot.ID)
	if t := inv.Slot.Token; t != nil {
		fmt.Fprintf(w, "Token:    %s\n", t.Label)
		fmt.Fprintf(w, "          %s %s, serial %s, firmware %s\n", t.Manufacturer, t.Model, t.SerialNumber, t.FirmwareVersion)
	}
	login := "no (private objects were not visible)"
	if inv.LoggedIn {
		login = "yes"
	}
	fmt.Fprintf(w, "Scanned:  %s (logged in: %s)\n", inv.ScannedAt.Format("2006-01-02 15:04:05 MST"), login)
	if len(r.RulePacks) > 0 {
		fmt.Fprintf(w, "Rules:    %s\n", strings.Join(r.RulePacks, ", "))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Health Score: %d/100\n\n", r.Score)

	bySev := map[policy.Severity][]policy.Finding{}
	for _, f := range r.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No findings. All %d objects passed the rule set.\n\n", len(inv.Objects))
	}
	for _, sev := range severities {
		fs := bySev[sev]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s (%d)\n", strings.ToUpper(string(sev)), len(fs))
		for _, f := range fs {
			fmt.Fprintf(w, "  [%s] %s\n", f.RuleID, f.Title)
			if f.Object != "" {
				fmt.Fprintf(w, "          %s\n", f.Object)
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "          %s\n", f.Detail)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "          fix: %s\n", f.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	c := r.Counts
	fmt.Fprintln(w, "SUMMARY")
	fmt.Fprintf(w, "  Private keys:   %d\n", c.PrivateKeys)
	fmt.Fprintf(w, "  Public keys:    %d\n", c.PublicKeys)
	fmt.Fprintf(w, "  Secret keys:    %d\n", c.SecretKeys)
	fmt.Fprintf(w, "  Certificates:   %d\n", c.Certificates)
	fmt.Fprintf(w, "  Mechanisms:     %d\n", len(inv.Mechanisms))

	if v := r.Vendor; v != nil {
		fmt.Fprintf(w, "\nVENDOR: %s", v.Provider)
		if v.Experimental {
			fmt.Fprint(w, " (experimental — not validated on real hardware)")
		}
		fmt.Fprintln(w)
		if v.Device != nil && v.Device.DiskPercent != nil {
			fmt.Fprintf(w, "  Disk usage:     %.0f%%\n", *v.Device.DiskPercent)
		}
		if v.HA != nil {
			up := 0
			for _, m := range v.HA.Members {
				if m.Up {
					up++
				}
			}
			fmt.Fprintf(w, "  HA members up:  %d/%d\n", up, len(v.HA.Members))
		}
		if v.Tamper != nil {
			state := "clear"
			if v.Tamper.Tampered {
				state = "TAMPERED"
			}
			fmt.Fprintf(w, "  Tamper:         %s\n", state)
		}
		if len(v.Partitions) > 0 {
			fmt.Fprintf(w, "  Partitions:     %d\n", len(v.Partitions))
		}
		// Vendor findings count toward the score, so they must be shown here —
		// they are not part of the main findings list above.
		if len(v.Findings) > 0 {
			fmt.Fprintln(w, "  Findings:")
			for _, f := range v.Findings {
				fmt.Fprintf(w, "    [%s] %s (%s)\n", f.RuleID, f.Title, f.Severity)
				if f.Detail != "" {
					fmt.Fprintf(w, "        %s\n", f.Detail)
				}
				if f.Remediation != "" {
					fmt.Fprintf(w, "        fix: %s\n", f.Remediation)
				}
			}
		}
	}

	if p := r.PQC; p != nil {
		fmt.Fprintf(w, "\nPQC READINESS: %s", p.Verdict)
		if len(p.AdvertisedFamilies) > 0 {
			fmt.Fprintf(w, " (%s)", strings.Join(p.AdvertisedFamilies, ", "))
		}
		fmt.Fprintln(w)
		if p.Exposure != nil {
			fmt.Fprintf(w, "  %s\n", p.Exposure.Summary)
		}
		fmt.Fprintln(w, "  (informational; does not affect the health score — see 'hsmdoctor pqc')")
	}
	return nil
}
