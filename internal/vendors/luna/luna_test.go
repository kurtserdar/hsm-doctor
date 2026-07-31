package luna

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
	cases := map[string]bool{
		"SafeNet":      true,
		"Thales Group": true,
		"Gemalto":      true,
		"SoftHSM":      false,
		"Entrust":      false,
	}
	for mfr, want := range cases {
		if got := p.Detect(p11.ModuleInfo{Manufacturer: mfr}, nil); got != want {
			t.Errorf("Detect(%q) = %v, want %v", mfr, got, want)
		}
	}
}

// Output shapes modeled on public Thales lunash documentation.
const hsmShowOutput = `
   Appliance Details:
   ==================
   Software Version:            7.7.0

   HSM Details:
   ===========
   Serial Number:               1234567
   Firmware Version:            7.7.1
   Tamper State:                No tamper(s)
`

const hsmShowTampered = `
   HSM Details:
   ===========
   Tamper State:                Chassis intrusion detected
`

// hsmShowTamperNo is the regression fixture: a bare "No" must not be read as a
// tamper condition.
const hsmShowTamperNo = `
   HSM Details:
   ===========
   Serial Number:               1234567
   Firmware Version:            7.7.1
   Tamper State:                No
`

const partitionListOutput = `
   Partition Name           Objects
   ============             =======
   PROD-PARTITION           142
   TEST-PARTITION           7
`

func collect(t *testing.T, r *vendortest.Runner) *vendor.Info {
	t.Helper()
	p := &provider{runner: r}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !info.Experimental {
		t.Error("luna provider must be marked experimental")
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

func TestCollectHealthy(t *testing.T) {
	info := collect(t, &vendortest.Runner{Outputs: map[string]string{
		"hsm":       hsmShowOutput,
		"partition": partitionListOutput,
	}})
	if info.Extra["firmware"] != "7.7.1" || info.Extra["serial"] != "1234567" {
		t.Errorf("hsm show not parsed: %+v", info.Extra)
	}
	if info.Tamper == nil || info.Tamper.Tampered {
		t.Errorf("healthy HSM should report no tamper: %+v", info.Tamper)
	}
	if len(info.Findings) != 0 {
		t.Errorf("healthy HSM should have no findings: %+v", info.Findings)
	}
	if len(info.Partitions) != 2 || *info.Partitions[0].UsedObjects != 142 {
		t.Errorf("partition list not parsed: %+v", info.Partitions)
	}
}

// Regression: "Tamper State: No" must not raise a critical finding.
func TestTamperNoIsNotTripped(t *testing.T) {
	info := collect(t, &vendortest.Runner{Outputs: map[string]string{"hsm": hsmShowTamperNo}})
	if info.Tamper == nil || info.Tamper.Tampered {
		t.Errorf("a bare \"No\" must not be read as tampered: %+v", info.Tamper)
	}
	if hasFinding(info, "LUNA-001") {
		t.Error("\"No\" tamper state must not raise LUNA-001")
	}
}

func TestTamperDetectedRaisesCriticalFinding(t *testing.T) {
	info := collect(t, &vendortest.Runner{Outputs: map[string]string{"hsm": hsmShowTampered}})
	if info.Tamper == nil || !info.Tamper.Tampered {
		t.Fatalf("tamper state not detected: %+v", info.Tamper)
	}
	if len(info.Findings) != 1 || info.Findings[0].RuleID != "LUNA-001" {
		t.Errorf("tamper should raise exactly one LUNA-001: %+v", info.Findings)
	}
}

// hsm show is the fundamental command; if it fails, Collect reports an error.
func TestHSMShowError(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Errs: map[string]error{"hsm": errors.New("ssh: connection refused")}}}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err == nil {
		t.Fatal("expected an error when 'hsm show' fails")
	}
}

// A failing 'partition list' must not sink the HSM data already gathered.
func TestPartitionListErrorIsPartial(t *testing.T) {
	info := collect(t, &vendortest.Runner{
		Outputs: map[string]string{"hsm": hsmShowOutput},
		Errs:    map[string]error{"partition": errors.New("timeout")},
	})
	if info.Extra["firmware"] != "7.7.1" {
		t.Errorf("hsm data should survive partition-list failure: %+v", info.Extra)
	}
	if len(info.Partitions) != 0 {
		t.Errorf("no partitions expected when 'partition list' fails: %+v", info.Partitions)
	}
}

func TestCollectRequiresConfigWithoutRunner(t *testing.T) {
	p := &provider{}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing host should return ErrNotConfigured, got %v", err)
	}
}
