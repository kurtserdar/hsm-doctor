// Package azurehsm is an EXPERIMENTAL provider for Azure Key Vault Managed
// HSM.
//
// It shells out to the Azure CLI ("az keyvault show --hsm-name") and maps the
// pool's control-plane state into vendor findings: security-domain activation
// (loss of the security domain is an irrecoverable loss of all keys),
// provisioning state, purge protection and public network exposure. It has
// NOT been validated against a live Azure subscription; the JSON shape follows
// the public Managed HSM ARM API docs.
package azurehsm

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

func (p *provider) Name() string { return "azure-hsm" }

func (p *provider) Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool {
	hay := strings.ToLower(module.Manufacturer + " " + module.Description)
	if token != nil {
		hay += " " + strings.ToLower(token.Manufacturer+" "+token.Model)
	}
	return strings.Contains(hay, "managed hsm") ||
		strings.Contains(hay, "azure") ||
		strings.Contains(hay, "microsoft")
}

// managedHsm is the subset of the ManagedHsm ARM resource we consume.
type managedHsm struct {
	Location string `json:"location"`
	SKU      struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		ProvisioningState     string `json:"provisioningState"`
		EnablePurgeProtection *bool  `json:"enablePurgeProtection"`
		PublicNetworkAccess   string `json:"publicNetworkAccess"`
		Regions               []struct {
			Name string `json:"name"`
		} `json:"regions"`
		SecurityDomainProperties struct {
			ActivationStatus string `json:"activationStatus"`
		} `json:"securityDomainProperties"`
	} `json:"properties"`
}

func (p *provider) Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error) {
	name := cfg["hsm_name"]
	if name == "" {
		return nil, vendor.ErrNotConfigured
	}

	args := []string{"keyvault", "show", "--hsm-name", name, "-o", "json"}
	if sub := cfg["subscription"]; sub != "" {
		args = append(args, "--subscription", sub)
	}
	out, err := p.runner.Run(ctx, "az", args...)
	if err != nil {
		return nil, fmt.Errorf("az keyvault show: %w", err)
	}
	return parseHsm(out, name)
}

func parseHsm(out, name string) (*vendor.Info, error) {
	var hsm managedHsm
	if err := json.Unmarshal([]byte(out), &hsm); err != nil {
		return nil, fmt.Errorf("parsing keyvault show JSON: %w", err)
	}
	info := &vendor.Info{Provider: "azure-hsm", Experimental: true, Extra: map[string]string{}}
	info.Extra["hsm_name"] = name
	info.Extra["location"] = hsm.Location
	info.Extra["sku"] = hsm.SKU.Name
	info.Extra["provisioning_state"] = hsm.Properties.ProvisioningState
	info.Extra["regions"] = fmt.Sprintf("%d", len(hsm.Properties.Regions))

	// Security domain: an un-activated or failed domain means the pool cannot
	// serve keys. Loss of the security domain is an irrecoverable loss of all
	// keys, so this is the most serious signal. Skip when the field is absent
	// (older API versions do not always return it).
	if st := hsm.Properties.SecurityDomainProperties.ActivationStatus; st != "" {
		info.Extra["activation_status"] = st
		if st != "Active" {
			info.Findings = append(info.Findings, policy.Finding{
				RuleID:   "AZUREHSM-001",
				Title:    "Security domain not active",
				Severity: policy.SevCritical,
				Detail:   "security-domain activation status: " + st,
			})
		}
	}

	// Provisioning state: "Succeeded" and "Activated" are healthy; anything
	// else is a problem or a transient restore/provisioning operation.
	if ps := hsm.Properties.ProvisioningState; ps != "" && ps != "Succeeded" && ps != "Activated" {
		info.Findings = append(info.Findings, policy.Finding{
			RuleID:   "AZUREHSM-002",
			Title:    "Managed HSM not fully provisioned",
			Severity: policy.SevHigh,
			Detail:   "provisioning state: " + ps,
		})
	}

	// Purge protection guards against irreversible deletion of the pool and
	// its keys. It is recommended for production pools.
	if hsm.Properties.EnablePurgeProtection != nil && !*hsm.Properties.EnablePurgeProtection {
		info.Findings = append(info.Findings, policy.Finding{
			RuleID:   "AZUREHSM-003",
			Title:    "Purge protection disabled",
			Severity: policy.SevMedium,
			Detail:   "the pool and its keys can be permanently deleted before the retention period ends",
		})
	}

	// Public network access exposes the data plane to the internet.
	if hsm.Properties.PublicNetworkAccess == "Enabled" {
		info.Findings = append(info.Findings, policy.Finding{
			RuleID:   "AZUREHSM-004",
			Title:    "Public network access enabled",
			Severity: policy.SevMedium,
			Detail:   "the Managed HSM is reachable from public networks; restrict with private endpoints or network rules",
		})
	}

	return info, nil
}
