package gcp

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
	if !p.Detect(p11.ModuleInfo{Description: "Google Cloud KMS PKCS#11 Library"}, nil) {
		t.Error("should detect the Cloud KMS PKCS#11 library")
	}
	if !p.Detect(p11.ModuleInfo{Path: "/usr/lib/libkmsp11.so", Description: "kmsp11"}, nil) {
		t.Error("should detect kmsp11")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Response shapes modeled on "gcloud kms keys list --format json".
const healthyKeys = `[
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/signing",
    "purpose": "ASYMMETRIC_SIGN",
    "versionTemplate": {"protectionLevel": "HSM", "algorithm": "EC_SIGN_P256_SHA256"}
  },
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/data",
    "purpose": "ENCRYPT_DECRYPT",
    "primary": {"state": "ENABLED", "protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
    "rotationPeriod": "7776000s",
    "nextRotationTime": "2026-09-01T00:00:00Z"
  }
]`

const problemKeys = `[
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/soft",
    "purpose": "ENCRYPT_DECRYPT",
    "primary": {"state": "ENABLED", "protectionLevel": "SOFTWARE", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
    "rotationPeriod": "7776000s",
    "nextRotationTime": "2026-09-01T00:00:00Z"
  },
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/disabled",
    "purpose": "ENCRYPT_DECRYPT",
    "primary": {"state": "DISABLED", "protectionLevel": "HSM"},
    "rotationPeriod": "7776000s",
    "nextRotationTime": "2026-09-01T00:00:00Z"
  },
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/doomed",
    "purpose": "ENCRYPT_DECRYPT",
    "primary": {"state": "DESTROY_SCHEDULED", "protectionLevel": "HSM"},
    "rotationPeriod": "7776000s",
    "nextRotationTime": "2026-09-01T00:00:00Z"
  },
  {
    "name": "projects/p/locations/us/keyRings/kr/cryptoKeys/norotate",
    "purpose": "ENCRYPT_DECRYPT",
    "primary": {"state": "ENABLED", "protectionLevel": "HSM"}
  }
]`

func collect(t *testing.T, out string) *vendor.Info {
	t.Helper()
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"gcloud": out}}}
	info, err := p.Collect(context.Background(), vendor.Config{"keyring": "kr", "location": "us"})
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

func TestHealthyKeys(t *testing.T) {
	info := collect(t, healthyKeys)
	if !info.Experimental {
		t.Error("gcp provider must be marked experimental")
	}
	if info.Extra["hsm_keys"] != "2" || info.Extra["key_count"] != "2" {
		t.Errorf("counts not recorded: %+v", info.Extra)
	}
	if len(info.Findings) != 0 {
		t.Errorf("healthy HSM keys should have no findings: %+v", info.Findings)
	}
}

func TestProblemKeys(t *testing.T) {
	info := collect(t, problemKeys)
	if !hasFinding(info, "GCP-001") {
		t.Error("software-protected key should raise GCP-001")
	}
	if !hasFinding(info, "GCP-002") {
		t.Error("disabled primary version should raise GCP-002")
	}
	if !hasFinding(info, "GCP-003") {
		t.Error("destroy-scheduled version should raise GCP-003")
	}
	if !hasFinding(info, "GCP-004") {
		t.Error("symmetric key without rotation should raise GCP-004")
	}
	if info.Extra["software_keys"] != "1" {
		t.Errorf("software_keys = %q, want 1", info.Extra["software_keys"])
	}
}

func TestNotConfigured(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{}}
	if _, err := p.Collect(context.Background(), vendor.Config{"location": "us"}); err != vendor.ErrNotConfigured {
		t.Errorf("missing keyring should return ErrNotConfigured, got %v", err)
	}
}

func TestGcloudCommandError(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Errs: map[string]error{"gcloud": errors.New("credentials not found")}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"keyring": "kr", "location": "us"}); err == nil {
		t.Fatal("expected an error when the gcloud CLI fails")
	}
}

func TestMalformedJSON(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"gcloud": "not json"}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"keyring": "kr", "location": "us"}); err == nil {
		t.Fatal("expected an error on malformed JSON")
	}
}
