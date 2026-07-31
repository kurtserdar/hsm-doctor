// Package bouncyhsm is an EXPERIMENTAL provider for BouncyHsm, a software HSM
// and PKCS#11 simulator with a REST management API
// (https://github.com/harrison314/BouncyHsm).
//
// Unlike the exec-based providers, it talks to BouncyHsm's HTTP API (base URL
// from the vendor configuration) to read data PKCS#11 cannot expose — the
// server version and object statistics. BouncyHsm is a development/testing
// simulator that deliberately does not protect keys in storage or on the wire,
// so this provider always warns against production use.
package bouncyhsm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type provider struct {
	client *http.Client // nil → a default client is built at collect time
}

func init() {
	vendor.Register(&provider{})
}

func (p *provider) Name() string { return "bouncyhsm" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "bouncyhsm") || strings.Contains(hay, "bouncy hsm") ||
		strings.Contains(hay, "bouncy castle")
}

// versionResp mirrors GET /HsmInfo/Versions.
type versionResp struct {
	Version             string   `json:"version"`
	BouncyCastleVersion string   `json:"bouncyCastleVersion"`
	P11Versions         []string `json:"p11Versions"`
	Commit              string   `json:"commit"`
}

// statsResp mirrors the subset of GET /Stats we surface.
type statsResp struct {
	ConnectedApplications int `json:"connectedApplications"`
	SlotCount             int `json:"slotCount"`
	TotalObjectCount      int `json:"totalObjectCount"`
	PrivateKeys           int `json:"privateKeys"`
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	base := strings.TrimRight(cfg["url"], "/")
	if base == "" {
		return nil, vendor.ErrNotConfigured
	}
	client := p.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	info := &vendor.Info{Provider: p.Name(), Experimental: true, Extra: map[string]string{}}

	// Versions is the fundamental call; if the management API is unreachable
	// there is nothing to report.
	var ver versionResp
	if err := getJSON(ctx, client, base+"/HsmInfo/Versions", &ver); err != nil {
		return nil, fmt.Errorf("bouncyhsm: GET /HsmInfo/Versions: %w", err)
	}
	info.Extra["version"] = ver.Version
	info.Extra["bouncycastle_version"] = ver.BouncyCastleVersion
	info.Extra["commit"] = ver.Commit
	if len(ver.P11Versions) > 0 {
		info.Extra["pkcs11_versions"] = strings.Join(ver.P11Versions, ", ")
	}

	// BouncyHsm is a non-production simulator with no key protection — always
	// warn so a real deployment never silently trusts it with production keys.
	info.Findings = append(info.Findings, policy.Finding{
		RuleID:   "BOUNCYHSM-001",
		Title:    "Non-production HSM simulator",
		Severity: policy.SevHigh,
		Detail:   "BouncyHsm does not protect keys in storage or on the network; never use it for production keys",
	})

	// Stats is best-effort: a failure must not sink the version data.
	var st statsResp
	if err := getJSON(ctx, client, base+"/Stats", &st); err == nil {
		info.Extra["slots"] = fmt.Sprintf("%d", st.SlotCount)
		info.Extra["objects"] = fmt.Sprintf("%d", st.TotalObjectCount)
		info.Extra["private_keys"] = fmt.Sprintf("%d", st.PrivateKeys)
		info.Extra["connected_applications"] = fmt.Sprintf("%d", st.ConnectedApplications)
	}
	return info, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
