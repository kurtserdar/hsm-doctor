// Package softhsm is the reference vendor provider. SoftHSM has no
// appliance, but its token store lives on a filesystem whose health and
// permissions matter — and the provider doubles as a fully CI-testable
// template for real vendor integrations.
package softhsm

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendor"
)

type provider struct {
	runner vendor.Runner
}

func init() {
	vendor.Register(&provider{runner: vendor.ExecRunner{}})
}

func (p *provider) Name() string { return "softhsm" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	if strings.Contains(module.Manufacturer, "SoftHSM") {
		return true
	}
	return token != nil && strings.Contains(token.Manufacturer, "SoftHSM")
}

// confPath resolves the active softhsm2.conf the same way SoftHSM does.
func confPath(cfg vendor.Config) string {
	if p := cfg["conf"]; p != "" {
		return p
	}
	if p := os.Getenv("SOFTHSM2_CONF"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		user := filepath.Join(home, ".config", "softhsm2", "softhsm2.conf")
		if _, err := os.Stat(user); err == nil {
			return user
		}
	}
	return "/etc/softhsm/softhsm2.conf"
}

// tokenDir extracts directories.tokendir from a softhsm2.conf document.
func tokenDir(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "directories.tokendir" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	info := &vendor.Info{Provider: p.Name(), Extra: map[string]string{}}

	path := confPath(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	dir := tokenDir(string(data))
	if dir == "" {
		return nil, fmt.Errorf("no directories.tokendir in %s", path)
	}
	info.Extra["config"] = path
	info.Extra["tokendir"] = dir

	if out, err := p.runner.Run(ctx, "softhsm2-util", "--version"); err == nil {
		info.Extra["version"] = strings.TrimSpace(out)
	}

	// Filesystem health of the token store: SoftHSM's "appliance" is the
	// disk its tokens live on.
	if used, ok := diskUsedPercent(dir); ok {
		info.Device = &vendor.DeviceHealth{DiskPercent: &used}
		if used > 90 {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "SOFTHSM-001",
				Title:    "Token store filesystem nearly full",
				Severity: policy.SevHigh,
				Detail:   fmt.Sprintf("%s is %.0f%% full; token writes will start failing", dir, used),
			})
		}
	}

	// One partition entry per initialized token directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading token directory: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		size := dirSize(filepath.Join(dir, e.Name()))
		info.Partitions = append(info.Partitions, vendor.PartitionInfo{
			Label:            e.Name(),
			UsedStorageBytes: &size,
		})
	}

	// The token store must not be readable by other users: serialized
	// objects contain (encrypted) key material and PIN-derived secrets.
	if fi, err := os.Stat(dir); err == nil {
		if fi.Mode().Perm()&0o007 != 0 {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "SOFTHSM-002",
				Title:    "Token store is world-accessible",
				Severity: policy.SevMedium,
				Detail:   fmt.Sprintf("%s has mode %s; restrict it to the owning user", dir, fi.Mode().Perm()),
			})
		}
	}
	return info, nil
}

// dirSize sums the file sizes under a directory (best effort).
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
