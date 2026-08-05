package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/kmip"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

func writeKMIPBaseline(t *testing.T, rep *kmip.Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kmip-baseline.json")
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckKMIPBaselineDisabled(t *testing.T) {
	cmd, _ := newCmd()
	if err := checkKMIPBaseline(cmd, "", 10, &kmip.Report{Score: 50}); err != nil {
		t.Errorf("no baseline path should be a no-op, got %v", err)
	}
}

func TestCheckKMIPBaselineNoRegression(t *testing.T) {
	base := writeKMIPBaseline(t, &kmip.Report{Score: 90})
	cmd, errBuf := newCmd()
	if err := checkKMIPBaseline(cmd, base, 10, &kmip.Report{Score: 95}); err != nil {
		t.Errorf("an improving scan must not fail: %v", err)
	}
	if errBuf.Len() != 0 {
		t.Errorf("no summary expected, got %q", errBuf.String())
	}
}

func TestCheckKMIPBaselineScoreDrop(t *testing.T) {
	base := writeKMIPBaseline(t, &kmip.Report{Score: 90})
	cmd, errBuf := newCmd()
	if err := checkKMIPBaseline(cmd, base, 10, &kmip.Report{Score: 70}); err == nil {
		t.Fatal("a 20-point drop must fail the run")
	}
	if !strings.Contains(errBuf.String(), "regressed against baseline") {
		t.Errorf("summary should go to stderr, got %q", errBuf.String())
	}
}

func TestCheckKMIPBaselineNewCritical(t *testing.T) {
	base := writeKMIPBaseline(t, &kmip.Report{Score: 80})
	cmd, _ := newCmd()
	err := checkKMIPBaseline(cmd, base, 10, &kmip.Report{
		Score: 80, Findings: []policy.Finding{crit("KMIP-002")},
	})
	if err == nil {
		t.Fatal("a new critical finding must fail even at equal score")
	}
}

func TestCheckKMIPBaselineMissingFile(t *testing.T) {
	cmd, _ := newCmd()
	if err := checkKMIPBaseline(cmd, filepath.Join(t.TempDir(), "nope.json"), 10, &kmip.Report{Score: 50}); err == nil {
		t.Error("a missing baseline file should be an error")
	}
}

func TestCheckKMIPBaselineMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, _ := newCmd()
	if err := checkKMIPBaseline(cmd, path, 10, &kmip.Report{Score: 50}); err == nil {
		t.Error("a malformed baseline should be an error")
	}
}
