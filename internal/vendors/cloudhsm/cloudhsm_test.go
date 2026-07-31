package cloudhsm

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
	if !p.Detect(p11.ModuleInfo{Manufacturer: "Cavium"}, nil) {
		t.Error("should detect Cavium (CloudHSM)")
	}
	if !p.Detect(p11.ModuleInfo{Description: "AWS CloudHSM"}, nil) {
		t.Error("should detect CloudHSM")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Response shapes modeled on the public cloudhsmv2 describe-clusters API.
const healthyCluster = `{
  "Clusters": [
    {
      "ClusterId": "cluster-abc",
      "State": "ACTIVE",
      "Hsms": [
        {"HsmId": "hsm-1", "State": "ACTIVE", "AvailabilityZone": "us-east-1a"},
        {"HsmId": "hsm-2", "State": "ACTIVE", "AvailabilityZone": "us-east-1b"}
      ]
    }
  ]
}`

const degradedCluster = `{
  "Clusters": [
    {
      "ClusterId": "cluster-abc",
      "State": "DEGRADED",
      "Hsms": [
        {"HsmId": "hsm-1", "State": "ACTIVE", "AvailabilityZone": "us-east-1a"},
        {"HsmId": "hsm-2", "State": "DEGRADED", "AvailabilityZone": "us-east-1b"}
      ]
    }
  ]
}`

const singleHSMCluster = `{
  "Clusters": [
    {"ClusterId": "cluster-abc", "State": "ACTIVE",
     "Hsms": [{"HsmId": "hsm-1", "State": "ACTIVE", "AvailabilityZone": "us-east-1a"}]}
  ]
}`

const singleAZCluster = `{
  "Clusters": [
    {"ClusterId": "cluster-abc", "State": "ACTIVE",
     "Hsms": [
       {"HsmId": "hsm-1", "State": "ACTIVE", "AvailabilityZone": "us-east-1a"},
       {"HsmId": "hsm-2", "State": "ACTIVE", "AvailabilityZone": "us-east-1a"}
     ]}
  ]
}`

func collect(t *testing.T, out string) *vendor.Info {
	t.Helper()
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"aws": out}}}
	info, err := p.Collect(context.Background(), vendor.Config{"cluster_id": "cluster-abc"})
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

func TestHealthyCluster(t *testing.T) {
	info := collect(t, healthyCluster)
	if !info.Experimental {
		t.Error("cloudhsm provider must be marked experimental")
	}
	if info.HA == nil || len(info.HA.Members) != 2 {
		t.Fatalf("HA members not parsed: %+v", info.HA)
	}
	if info.Extra["availability_zones"] != "2" || info.Extra["hsm_count"] != "2" {
		t.Errorf("counts not recorded: %+v", info.Extra)
	}
	if len(info.Findings) != 0 {
		t.Errorf("healthy 2-AZ cluster should have no findings: %+v", info.Findings)
	}
}

func TestDegradedCluster(t *testing.T) {
	info := collect(t, degradedCluster)
	if !hasFinding(info, "CLOUDHSM-001") {
		t.Error("non-ACTIVE cluster should raise CLOUDHSM-001")
	}
	if !hasFinding(info, "CLOUDHSM-003") {
		t.Error("degraded HSM should raise CLOUDHSM-003")
	}
}

func TestSingleHSMCluster(t *testing.T) {
	info := collect(t, singleHSMCluster)
	if !hasFinding(info, "CLOUDHSM-002") {
		t.Error("single-HSM cluster should raise CLOUDHSM-002 (no HA redundancy)")
	}
	if hasFinding(info, "CLOUDHSM-004") {
		t.Error("single-HSM cluster should not also raise the AZ-spread finding")
	}
}

func TestSingleAZCluster(t *testing.T) {
	info := collect(t, singleAZCluster)
	if !hasFinding(info, "CLOUDHSM-004") {
		t.Error("2 HSMs in one AZ should raise CLOUDHSM-004 (no cross-AZ redundancy)")
	}
	if hasFinding(info, "CLOUDHSM-002") {
		t.Error("a 2-HSM cluster should not raise the redundancy-count finding")
	}
	if info.Extra["availability_zones"] != "1" {
		t.Errorf("availability_zones = %q, want 1", info.Extra["availability_zones"])
	}
}

func TestNotConfigured(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{}}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing cluster_id should return ErrNotConfigured, got %v", err)
	}
}

func TestAWSCommandError(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Errs: map[string]error{"aws": errors.New("Unable to locate credentials")}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"cluster_id": "cluster-abc"}); err == nil {
		t.Fatal("expected an error when the AWS CLI fails")
	}
}

func TestMalformedJSON(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"aws": "not json at all"}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"cluster_id": "cluster-abc"}); err == nil {
		t.Fatal("expected an error on malformed JSON")
	}
}

func TestClusterNotFound(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Outputs: map[string]string{"aws": healthyCluster}}}
	if _, err := p.Collect(context.Background(), vendor.Config{"cluster_id": "cluster-missing"}); err == nil {
		t.Fatal("expected an error when the requested cluster is absent")
	}
}
