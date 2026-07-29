//go:build integration

// Package testutil provides SoftHSM-backed helpers for integration tests.
// Everything here is test-only and guarded by the "integration" build tag.
package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

const (
	// TokenLabel is the label of the throwaway test token.
	TokenLabel = "HSMDOCTOR-IT"
	// UserPIN is the user PIN of the throwaway test token.
	UserPIN = "123456"
	soPIN   = "12345678"
)

// modulePaths lists common install locations of the SoftHSM2 library.
var modulePaths = []string{
	"/usr/lib/softhsm/libsofthsm2.so",
	"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	"/usr/local/lib/softhsm/libsofthsm2.so",
}

// ModulePath locates the SoftHSM2 PKCS#11 library, honoring the
// HSMDOCTOR_TEST_MODULE environment variable, and skips the test when the
// library is not installed.
func ModulePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HSMDOCTOR_TEST_MODULE"); p != "" {
		return p
	}
	for _, p := range modulePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("SoftHSM2 library not found; install softhsm2 or set HSMDOCTOR_TEST_MODULE")
	return ""
}

// NewSoftHSM initializes a fresh SoftHSM token in a temporary directory and
// returns an open client plus the slot ID of the new token. The client is
// closed and the token directory removed automatically when the test ends.
func NewSoftHSM(t *testing.T) (*p11.Client, uint) {
	t.Helper()
	module := ModulePath(t)

	tokenDir := t.TempDir()
	conf := filepath.Join(tokenDir, "softhsm2.conf")
	content := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokenDir)
	if err := os.WriteFile(conf, []byte(content), 0o600); err != nil {
		t.Fatalf("writing softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", TokenLabel, "--so-pin", soPIN, "--pin", UserPIN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token failed: %v\n%s", err, out)
	}

	client, err := p11.Open(module)
	if err != nil {
		t.Fatalf("opening SoftHSM module: %v", err)
	}
	t.Cleanup(client.Close)

	slots, err := client.Slots()
	if err != nil {
		t.Fatalf("listing slots: %v", err)
	}
	for _, s := range slots {
		if s.TokenPresent && s.Token != nil && s.Token.Label == TokenLabel {
			return client, s.ID
		}
	}
	t.Fatalf("test token %q not found after init", TokenLabel)
	return nil, 0
}
