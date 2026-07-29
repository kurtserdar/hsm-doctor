package softhsm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendor"
)

// fakeRunner returns canned command output.
type fakeRunner struct{ out string }

func (f fakeRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return f.out, nil
}

func TestTokenDirParsing(t *testing.T) {
	conf := `# SoftHSM configuration
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
log.level = ERROR
`
	if got := tokenDir(conf); got != "/var/lib/softhsm/tokens/" {
		t.Errorf("tokenDir = %q", got)
	}
	if got := tokenDir("# only comments\n"); got != "" {
		t.Errorf("missing tokendir should yield empty, got %q", got)
	}
}

func TestDetect(t *testing.T) {
	p := &provider{runner: fakeRunner{}}
	if !p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("should detect via module manufacturer")
	}
	if !p.Detect(p11.ModuleInfo{}, &p11.TokenInfo{Manufacturer: "SoftHSM project"}) {
		t.Error("should detect via token manufacturer")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "Thales"}, nil) {
		t.Error("must not detect a non-SoftHSM module")
	}
}

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	tokenStore := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(filepath.Join(tokenStore, "abc-123"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenStore, "abc-123", "token.object"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+tokenStore+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &provider{runner: fakeRunner{out: "2.6.1"}}
	info, err := p.Collect(context.Background(), vendor.Config{"conf": conf})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if info.Provider != "softhsm" {
		t.Errorf("provider name: %q", info.Provider)
	}
	if info.Extra["version"] != "2.6.1" || info.Extra["tokendir"] != tokenStore {
		t.Errorf("extra fields wrong: %+v", info.Extra)
	}
	if len(info.Partitions) != 1 || info.Partitions[0].Label != "abc-123" {
		t.Errorf("expected one partition for the token dir: %+v", info.Partitions)
	}
	if info.Partitions[0].UsedStorageBytes == nil || *info.Partitions[0].UsedStorageBytes != 4 {
		t.Errorf("partition storage size wrong: %+v", info.Partitions[0])
	}
}

func TestCollectFlagsWorldAccessibleStore(t *testing.T) {
	dir := t.TempDir()
	tokenStore := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenStore, 0o777); err != nil {
		t.Fatal(err)
	}
	// t.TempDir may apply a umask; force the permissive mode.
	if err := os.Chmod(tokenStore, 0o777); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+tokenStore+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &provider{runner: fakeRunner{}}
	info, err := p.Collect(context.Background(), vendor.Config{"conf": conf})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasFinding(info.Findings, "SOFTHSM-002") {
		t.Errorf("world-accessible store should raise SOFTHSM-002: %+v", info.Findings)
	}
}

func TestCollectMissingConf(t *testing.T) {
	p := &provider{runner: fakeRunner{}}
	if _, err := p.Collect(context.Background(), vendor.Config{"conf": "/nonexistent/softhsm2.conf"}); err == nil {
		t.Error("missing config file should error")
	}
}

func hasFinding(findings []policy.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
