package nshield

import (
	"context"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

type fakeRunner struct{ outputs map[string]string }

func (f fakeRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	return f.outputs[name], nil
}

func TestDetect(t *testing.T) {
	p := &provider{}
	if !p.Detect(p11.ModuleInfo{Manufacturer: "nCipher Corp. Ltd"}, nil) {
		t.Error("should detect nCipher")
	}
	if !p.Detect(p11.ModuleInfo{Description: "Entrust nShield"}, nil) {
		t.Error("should detect Entrust nShield")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Output shapes modeled on public Entrust nShield documentation.
const enquiryOperational = `Server:
 enquiry reply flags  none
 mode                 operational
 version              12.80.4
`

const enquiryMaintenance = `Module #1:
 mode                 maintenance
 version              12.80.4
`

func TestParseEnquiryOperational(t *testing.T) {
	p := &provider{runner: fakeRunner{outputs: map[string]string{"enquiry": enquiryOperational}}}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !info.Experimental {
		t.Error("nshield provider must be marked experimental")
	}
	if info.Extra["mode"] != "operational" || info.Extra["version"] != "12.80.4" {
		t.Errorf("enquiry not parsed: %+v", info.Extra)
	}
	if len(info.Findings) != 0 {
		t.Errorf("operational module should have no findings: %+v", info.Findings)
	}
}

func TestParseEnquiryMaintenanceRaisesFinding(t *testing.T) {
	p := &provider{runner: fakeRunner{outputs: map[string]string{"enquiry": enquiryMaintenance}}}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(info.Findings) != 1 || info.Findings[0].RuleID != "NSHIELD-001" {
		t.Errorf("maintenance mode should raise NSHIELD-001: %+v", info.Findings)
	}
}
