// Package gcp is an EXPERIMENTAL provider for Google Cloud HSM (Cloud KMS
// keys with an HSM protection level, exposed to PKCS#11 through libkmsp11).
//
// It shells out to the gcloud CLI ("gcloud kms keys list") and maps key and
// key-version state into vendor findings: keys that are software-protected
// rather than HSM-backed, disabled or destruction-scheduled versions, and
// symmetric keys without automatic rotation. It has NOT been validated
// against a live Google Cloud project; the JSON shape follows the public
// Cloud KMS API docs.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type provider struct {
	runner vendor.Runner
}

func init() {
	vendor.Register(&provider{runner: vendor.ExecRunner{}})
}

func (p *provider) Name() string { return "gcp" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "kmsp11") ||
		strings.Contains(hay, "cloud kms") ||
		strings.Contains(hay, "google")
}

// cryptoKey is the subset of a Cloud KMS CryptoKey we consume. For symmetric
// (ENCRYPT_DECRYPT) keys the "primary" version carries the live state; for
// asymmetric keys there is no primary and protection level comes from the
// version template.
type cryptoKey struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Primary struct {
		State           string `json:"state"`
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	} `json:"primary"`
	VersionTemplate struct {
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	} `json:"versionTemplate"`
	RotationPeriod   string `json:"rotationPeriod"`
	NextRotationTime string `json:"nextRotationTime"`
}

// protectionLevel returns the key's effective protection level, preferring the
// primary version and falling back to the version template.
func (k cryptoKey) protectionLevel() string {
	if k.Primary.ProtectionLevel != "" {
		return k.Primary.ProtectionLevel
	}
	return k.VersionTemplate.ProtectionLevel
}

// shortName returns the trailing segment of a fully qualified key name.
func shortName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 && i < len(name)-1 {
		return name[i+1:]
	}
	return name
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	keyring := cfg["keyring"]
	location := cfg["location"]
	if keyring == "" || location == "" {
		return nil, vendor.ErrNotConfigured
	}

	args := []string{"kms", "keys", "list",
		"--keyring", keyring, "--location", location, "--format", "json"}
	if project := cfg["project"]; project != "" {
		args = append(args, "--project", project)
	}
	out, err := p.runner.Run(ctx, "gcloud", args...)
	if err != nil {
		return nil, fmt.Errorf("gcloud kms keys list: %w", err)
	}
	return parseKeys(out, keyring)
}

func parseKeys(out, keyring string) (*vendor.Info, error) {
	var keys []cryptoKey
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		return nil, fmt.Errorf("parsing kms keys list JSON: %w", err)
	}
	info := &vendor.Info{Provider: "gcp", Experimental: true, Extra: map[string]string{}}
	info.Extra["keyring"] = keyring

	var hsmKeys, softwareKeys int
	for _, k := range keys {
		name := shortName(k.Name)
		pl := k.protectionLevel()
		switch pl {
		case "HSM":
			hsmKeys++
		case "SOFTWARE":
			softwareKeys++
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "GCP-001",
				Title:    "Software-protected key in the key ring",
				Severity: policy.SevMedium,
				Detail:   fmt.Sprintf("key %q is SOFTWARE-protected, not HSM-backed", name),
			})
		}

		switch k.Primary.State {
		case "DESTROY_SCHEDULED":
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "GCP-003",
				Title:    "Key version scheduled for destruction",
				Severity: policy.SevHigh,
				Detail:   fmt.Sprintf("primary version of key %q is DESTROY_SCHEDULED", name),
			})
		case "DISABLED":
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "GCP-002",
				Title:    "Key primary version disabled",
				Severity: policy.SevMedium,
				Detail:   fmt.Sprintf("primary version of key %q is DISABLED", name),
			})
		}

		// Only symmetric keys support automatic rotation; asymmetric keys are
		// rotated by adding versions and cannot carry a rotation schedule.
		if k.Purpose == "ENCRYPT_DECRYPT" && k.NextRotationTime == "" && k.RotationPeriod == "" {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "GCP-004",
				Title:    "Key has no automatic rotation",
				Severity: policy.SevLow,
				Detail:   fmt.Sprintf("symmetric key %q has no rotation schedule", name),
			})
		}
	}

	info.Extra["key_count"] = fmt.Sprintf("%d", len(keys))
	info.Extra["hsm_keys"] = fmt.Sprintf("%d", hsmKeys)
	info.Extra["software_keys"] = fmt.Sprintf("%d", softwareKeys)
	return info, nil
}
