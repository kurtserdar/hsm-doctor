package luna

import (
	"context"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type fakeRunner struct{ outputs map[string]string }

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	return f.outputs[key], nil
}

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

const partitionListOutput = `
   Partition Name           Objects
   ============             =======
   PROD-PARTITION           142
   TEST-PARTITION           7
`

func TestCollectHealthy(t *testing.T) {
	p := &provider{runner: fakeRunner{outputs: map[string]string{
		"hsm show":       hsmShowOutput,
		"partition list": partitionListOutput,
	}}}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !info.Experimental {
		t.Error("luna provider must be marked experimental")
	}
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

func TestCollectTamperRaisesCriticalFinding(t *testing.T) {
	p := &provider{runner: fakeRunner{outputs: map[string]string{"hsm show": hsmShowTampered}}}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if info.Tamper == nil || !info.Tamper.Tampered {
		t.Fatalf("tamper state not detected: %+v", info.Tamper)
	}
	if len(info.Findings) != 1 || info.Findings[0].RuleID != "LUNA-001" {
		t.Errorf("tamper should raise LUNA-001: %+v", info.Findings)
	}
}

func TestCollectRequiresConfigWithoutRunner(t *testing.T) {
	p := &provider{}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing host should return ErrNotConfigured, got %v", err)
	}
}
