package cloudhsm

import (
	"context"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type fakeRunner struct{ out string }

func (f fakeRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return f.out, nil
}

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

// Response shape modeled on the public cloudhsmv2 describe-clusters API.
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

func collect(t *testing.T, out string) *vendor.Info {
	t.Helper()
	p := &provider{runner: fakeRunner{out: out}}
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
	if len(info.Findings) != 0 {
		t.Errorf("healthy 2-HSM cluster should have no findings: %+v", info.Findings)
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
}

func TestNotConfigured(t *testing.T) {
	p := &provider{runner: fakeRunner{}}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing cluster_id should return ErrNotConfigured, got %v", err)
	}
}
