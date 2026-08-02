package azurehsm

import (
	"context"
	"errors"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
	"github.com/kurtserdar/hsm-doctor/internal/vendors/vendortest"
)

func TestDetect(t *testing.T) {
	p := &provider{}
	if !p.Detect(p11.ModuleInfo{Description: "Azure Managed HSM"}, nil) {
		t.Error("should detect Azure Managed HSM")
	}
	if !p.Detect(p11.ModuleInfo{Manufacturer: "Microsoft"}, nil) {
		t.Error("should detect Microsoft")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Response shapes modeled on "az keyvault show --hsm-name -o json".
const healthyHsm = `{
  "location": "westus",
  "sku": {"family": "B", "name": "Standard_B1"},
  "properties": {
    "provisioningState": "Succeeded",
    "enablePurgeProtection": true,
    "publicNetworkAccess": "Disabled",
    "regions": [{"name": "westus"}],
    "securityDomainProperties": {"activationStatus": "Active"}
  }
}`

const problemHsm = `{
  "location": "westus",
  "sku": {"family": "B", "name": "Standard_B1"},
  "properties": {
    "provisioningState": "Failed",
    "enablePurgeProtection": false,
    "publicNetworkAccess": "Enabled",
    "regions": [{"name": "westus"}],
    "securityDomainProperties": {"activationStatus": "NotActivated"}
  }
}`

// A pool whose control plane omits securityDomainProperties: the SD finding
// must be skipped rather than false-flagged.
const noSDHsm = `{
  "location": "westus",
  "sku": {"name": "Standard_B1"},
  "properties": {
    "provisioningState": "Succeeded",
    "enablePurgeProtection": true,
    "publicNetworkAccess": "Disabled"
  }
}`

func collect(t *testing.T, out string) *vendor.Info {
	t.Helper()
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"az": out}}}
	info, err := p.Collect(context.Background(), vendor.Config{"hsm_name": "hsm1"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return info
}

func hasFinding(info *vendor.Info, id string) bool {
	for _, f := range info.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestHealthyHsm(t *testing.T) {
	info := collect(t, healthyHsm)
	if !info.Experimental {
		t.Error("azure-hsm provider must be marked experimental")
	}
	if info.Extra["activation_status"] != "Active" || info.Extra["sku"] != "Standard_B1" {
		t.Errorf("extras not recorded: %+v", info.Extra)
	}
	if len(info.Findings) != 0 {
		t.Errorf("healthy pool should have no findings: %+v", info.Findings)
	}
}

func TestProblemHsm(t *testing.T) {
	info := collect(t, problemHsm)
	if !hasFinding(info, "AZUREHSM-001") {
		t.Error("inactive security domain should raise AZUREHSM-001")
	}
	if !hasFinding(info, "AZUREHSM-002") {
		t.Error("failed provisioning should raise AZUREHSM-002")
	}
	if !hasFinding(info, "AZUREHSM-003") {
		t.Error("purge protection disabled should raise AZUREHSM-003")
	}
	if !hasFinding(info, "AZUREHSM-004") {
		t.Error("public network access should raise AZUREHSM-004")
	}
}

func TestNoSecurityDomainField(t *testing.T) {
	info := collect(t, noSDHsm)
	if hasFinding(info, "AZUREHSM-001") {
		t.Error("absent securityDomainProperties must not raise AZUREHSM-001")
	}
	if _, ok := info.Extra["activation_status"]; ok {
		t.Error("activation_status should be omitted when the field is absent")
	}
}

func TestNotConfigured(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{}}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing hsm_name should return ErrNotConfigured, got %v", err)
	}
}

func TestAzCommandError(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Errs: map[string]error{"az": errors.New("please run az login")}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"hsm_name": "hsm1"}); err == nil {
		t.Fatal("expected an error when the az CLI fails")
	}
}

func TestMalformedJSON(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"az": "not json"}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"hsm_name": "hsm1"}); err == nil {
		t.Fatal("expected an error on malformed JSON")
	}
}
