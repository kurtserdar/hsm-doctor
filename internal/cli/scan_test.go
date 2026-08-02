package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/spf13/cobra"
)

// writeBaseline saves a report as a baseline JSON file, as `scan --format json
// --out` would.
func writeBaseline(t *testing.T, rep *report.Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	return cmd, &errBuf
}

func crit(id string) policy.Finding {
	return policy.Finding{RuleID: id, Title: id, Severity: policy.SevCritical}
}

func TestCheckBaselineDisabled(t *testing.T) {
	cmd, _ := newCmd()
	if err := checkBaseline(cmd, "", 10, &report.Report{Score: 50}); err != nil {
		t.Errorf("no baseline path should be a no-op, got %v", err)
	}
}

func TestCheckBaselineNoRegression(t *testing.T) {
	base := writeBaseline(t, &report.Report{Score: 90})
	cmd, errBuf := newCmd()
	// Score improved, no new findings.
	if err := checkBaseline(cmd, base, 10, &report.Report{Score: 95}); err != nil {
		t.Errorf("an improving scan must not fail: %v", err)
	}
	if errBuf.Len() != 0 {
		t.Errorf("no summary expected, got %q", errBuf.String())
	}
}

func TestCheckBaselineScoreDrop(t *testing.T) {
	base := writeBaseline(t, &report.Report{Score: 90})
	cmd, errBuf := newCmd()
	err := checkBaseline(cmd, base, 10, &report.Report{Score: 70})
	if err == nil {
		t.Fatal("a 20-point drop must fail the run")
	}
	if !strings.Contains(errBuf.String(), "Posture regression") {
		t.Errorf("summary should go to stderr, got %q", errBuf.String())
	}
}

func TestCheckBaselineNewCritical(t *testing.T) {
	base := writeBaseline(t, &report.Report{Score: 80})
	cmd, _ := newCmd()
	// Same score, but a new critical finding appeared.
	err := checkBaseline(cmd, base, 10, &report.Report{
		Score: 80, Findings: []policy.Finding{crit("HSM-001")},
	})
	if err == nil {
		t.Fatal("a new critical finding must fail even at equal score")
	}
}

func TestCheckBaselineRespectsThreshold(t *testing.T) {
	base := writeBaseline(t, &report.Report{Score: 90})
	cmd, _ := newCmd()
	// An 8-point drop is below a threshold of 10.
	if err := checkBaseline(cmd, base, 10, &report.Report{Score: 82}); err != nil {
		t.Errorf("sub-threshold drop must not fail: %v", err)
	}
	// ...but does fail when the caller tightens the threshold to 5.
	if err := checkBaseline(cmd, base, 5, &report.Report{Score: 82}); err == nil {
		t.Error("an 8-point drop should fail at threshold 5")
	}
}

func TestCheckBaselineMissingFile(t *testing.T) {
	cmd, _ := newCmd()
	if err := checkBaseline(cmd, filepath.Join(t.TempDir(), "nope.json"), 10, &report.Report{Score: 50}); err == nil {
		t.Error("a missing baseline file should be an error")
	}
}

func TestCheckBaselineMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, _ := newCmd()
	if err := checkBaseline(cmd, path, 10, &report.Report{Score: 50}); err == nil {
		t.Error("a malformed baseline should be an error")
	}
}
