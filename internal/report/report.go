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
)

// Report bundles everything a single scan produced.
type Report struct {
	Tool      string               `json:"tool"`
	Version   string               `json:"version"`
	Score     int                  `json:"score"`
	Counts    inventory.Counts     `json:"counts"`
	Findings  []policy.Finding     `json:"findings"`
	Inventory *inventory.Inventory `json:"inventory"`
}

// New assembles a report from scan results.
func New(version string, inv *inventory.Inventory, res *policy.Result) *Report {
	return &Report{
		Tool:      "hsmdoctor",
		Version:   version,
		Score:     res.Score,
		Counts:    inv.Count(),
		Findings:  res.Findings,
		Inventory: inv,
	}
}

// JSON writes the full report as indented JSON.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// severities in display order.
var severities = []policy.Severity{policy.SevCritical, policy.SevHigh, policy.SevMedium, policy.SevLow}

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
	fmt.Fprintf(w, "Scanned:  %s (logged in: %s)\n\n", inv.ScannedAt.Format("2006-01-02 15:04:05 MST"), login)

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
		}
		fmt.Fprintln(w)
	}

	c := r.Counts
	fmt.Fprintln(w, "INFO")
	fmt.Fprintf(w, "  Private keys:   %d\n", c.PrivateKeys)
	fmt.Fprintf(w, "  Public keys:    %d\n", c.PublicKeys)
	fmt.Fprintf(w, "  Secret keys:    %d\n", c.SecretKeys)
	fmt.Fprintf(w, "  Certificates:   %d\n", c.Certificates)
	fmt.Fprintf(w, "  Mechanisms:     %d\n", len(inv.Mechanisms))
	return nil
}
