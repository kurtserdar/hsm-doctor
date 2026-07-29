package report

import (
	_ "embed"
	"html/template"
	"io"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

//go:embed template.html
var htmlTemplate string

// htmlData is the template input: the report plus small presentation helpers.
type htmlData struct {
	*Report
	GeneratedAt time.Time
	SevGroups   []sevGroup
	ScoreClass  string
}

type sevGroup struct {
	Severity policy.Severity
	Findings []policy.Finding
}

// HTML writes a self-contained single-file HTML report.
func (r *Report) HTML(w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"date":     func(t time.Time) string { return t.Format("2006-01-02") },
		"datetime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05 MST") },
		"deref":    func(b *bool) bool { return b != nil && *b },
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	data := htmlData{Report: r, GeneratedAt: time.Now()}
	bySev := map[policy.Severity][]policy.Finding{}
	for _, f := range r.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	for _, sev := range severities {
		if len(bySev[sev]) > 0 {
			data.SevGroups = append(data.SevGroups, sevGroup{Severity: sev, Findings: bySev[sev]})
		}
	}
	switch {
	case r.Score >= 90:
		data.ScoreClass = "good"
	case r.Score >= 70:
		data.ScoreClass = "warn"
	default:
		data.ScoreClass = "bad"
	}
	return tmpl.Execute(w, data)
}
