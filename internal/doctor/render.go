package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

// JSON writes the diagnosis as indented JSON.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var severityMark = map[policy.Severity]string{
	policy.SevCritical: "✗",
	policy.SevHigh:     "✗",
	policy.SevMedium:   "!",
	policy.SevLow:      "·",
	policy.SevInfo:     "·",
}

// Text writes a human-readable diagnosis.
func (r *Report) Text(w io.Writer) error {
	fmt.Fprintf(w, "Diagnosis: %s    Health %d/100    Token: %s\n",
		strings.ToUpper(string(r.Verdict)), r.Score, tokenLine(r.Token))
	fmt.Fprintf(w, "%s\n", r.Summary)

	if len(r.Issues) > 0 {
		fmt.Fprintf(w, "\nTop issues (most severe first):\n")
		for _, i := range r.Issues {
			mark := severityMark[i.Severity]
			if mark == "" {
				mark = "·"
			}
			fmt.Fprintf(w, "  %s %-8s %s\n", mark, strings.ToUpper(string(i.Severity)), i.Title)
			if i.Detail != "" {
				fmt.Fprintf(w, "  %s\n", indent(i.Detail))
			}
			if i.Action != "" {
				fmt.Fprintf(w, "  %s→ %s\n", pad, i.Action)
			}
		}
	}

	fmt.Fprintf(w, "\nChecks: ")
	parts := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		if c.Ran {
			parts = append(parts, c.Name+" ✓")
		} else {
			parts = append(parts, c.Name+" (skipped)")
		}
	}
	fmt.Fprintln(w, strings.Join(parts, "  "))
	return nil
}

// pad aligns continuation lines under an issue's title (mark + severity column).
const pad = "           "

func indent(s string) string {
	return pad + s
}

func tokenLine(t Token) string {
	name := t.Label
	if name == "" {
		name = t.SerialNumber
	}
	if name == "" {
		return "(no token)"
	}
	model := strings.TrimSpace(t.Manufacturer + " " + t.Model)
	if model != "" {
		return name + " (" + model + ")"
	}
	return name
}
