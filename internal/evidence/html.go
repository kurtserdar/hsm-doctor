package evidence

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
)

//go:embed evidence.html
var htmlTemplate string

// HTML writes a self-contained, auditor-facing single-file HTML report.
func (r *Report) HTML(w io.Writer) error {
	tmpl, err := template.New("evidence").Funcs(template.FuncMap{
		"statusClass": func(s Status) string {
			switch s {
			case StatusPass:
				return "pass"
			case StatusFail:
				return "fail"
			default:
				return "na"
			}
		},
		"statusLabel": func(s Status) string {
			switch s {
			case StatusPass:
				return "PASS"
			case StatusFail:
				return "FAIL"
			default:
				return "N/A"
			}
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r)
}

// JSON writes the structured evidence bundle.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
