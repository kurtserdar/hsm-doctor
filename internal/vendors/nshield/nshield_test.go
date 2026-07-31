package nshield

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
	"github.com/kurtserdar/hsm-doctor/internal/vendors/vendortest"
)

func TestDetect(t *testing.T) {
	p := &provider{}
	if !p.Detect(p11.ModuleInfo{Manufacturer: "nCipher Corp. Ltd"}, nil) {
		t.Error("should detect nCipher")
	}
	if !p.Detect(p11.ModuleInfo{Description: "Entrust nShield"}, nil) {
		t.Error("should detect Entrust nShield")
	}
	if !p.Detect(p11.ModuleInfo{}, &p11.TokenInfo{Model: "nShield Solo XC"}) {
		t.Error("should detect via token model")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Output shapes modeled on public Entrust nShield documentation.
const enquiryOperational = `Server:
 enquiry reply flags  none
 enquiry reply level  Six
 serial number        1234-5678-9ABC
 mode                 operational
 version              12.80.4
Module #1:
 mode                 operational
 version              12.80.4
`

// enquiryOperationalCRLF is the same data with Windows line endings.
var enquiryOperationalCRLF = strings.ReplaceAll(enquiryOperational, "\n", "\r\n")

const enquiryMaintenance = `Module #1:
 mode                 maintenance
 version              12.80.4
`

const enquiryInitialization = `Module #1:
 mode                 initialization
 version              12.80.4
`

const nfkminfoUsable = `World
 generation  2
 state       0x37270009 Initialised Usable Recovery PINRecovery
`

const nfkminfoNotUsable = `World
 generation  2
 state       0x37000001 Initialised !Usable Recovery
`

func collect(t *testing.T, r *vendortest.Runner) *vendor.Info {
	t.Helper()
	p := &provider{runner: r}
	info, err := p.Collect(context.Background(), vendor.Config{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !info.Experimental {
		t.Error("nshield provider must be marked experimental")
	}
	return info
}

func hasFinding(info *vendor.Info, ruleID string) bool {
	for _, f := range info.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestParseEnquiry(t *testing.T) {
	cases := []struct {
		name      string
		enquiry   string
		wantMode  string
		wantVer   string
		wantNS001 bool
		wantFinds int
	}{
		{"operational", enquiryOperational, "operational", "12.80.4", false, 0},
		{"operational CRLF", enquiryOperationalCRLF, "operational", "12.80.4", false, 0},
		{"maintenance", enquiryMaintenance, "maintenance", "12.80.4", true, 1},
		{"initialization", enquiryInitialization, "initialization", "12.80.4", true, 1},
		{"empty", "", "", "", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := collect(t, &vendortest.Runner{Outputs: map[string]string{"enquiry": tc.enquiry}})
			if info.Extra["mode"] != tc.wantMode {
				t.Errorf("mode = %q, want %q", info.Extra["mode"], tc.wantMode)
			}
			if info.Extra["version"] != tc.wantVer {
				t.Errorf("version = %q, want %q", info.Extra["version"], tc.wantVer)
			}
			if got := hasFinding(info, "NSHIELD-001"); got != tc.wantNS001 {
				t.Errorf("NSHIELD-001 present = %v, want %v", got, tc.wantNS001)
			}
			if len(info.Findings) != tc.wantFinds {
				t.Errorf("findings = %d, want %d: %+v", len(info.Findings), tc.wantFinds, info.Findings)
			}
		})
	}
}

func TestSecurityWorldState(t *testing.T) {
	cases := []struct {
		name      string
		nfkminfo  string
		wantState string
		wantNS002 bool
	}{
		{"usable", nfkminfoUsable, "0x37270009 Initialised Usable Recovery PINRecovery", false},
		{"not usable", nfkminfoNotUsable, "0x37000001 Initialised !Usable Recovery", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := collect(t, &vendortest.Runner{Outputs: map[string]string{
				"enquiry":  enquiryOperational,
				"nfkminfo": tc.nfkminfo,
			}})
			if info.Extra["security_world_state"] != tc.wantState {
				t.Errorf("state = %q, want %q", info.Extra["security_world_state"], tc.wantState)
			}
			if got := hasFinding(info, "NSHIELD-002"); got != tc.wantNS002 {
				t.Errorf("NSHIELD-002 present = %v, want %v", got, tc.wantNS002)
			}
		})
	}
}

// enquiry is the fundamental tool; if it is missing, Collect reports an error
// so the caller can skip the provider gracefully.
func TestEnquiryMissingReturnsError(t *testing.T) {
	p := &provider{runner: &vendortest.Runner{Errs: map[string]error{"enquiry": errors.New("enquiry: command not found")}}}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err == nil {
		t.Fatal("expected an error when enquiry is unavailable")
	}
}

// A failing nfkminfo must not sink the module data already gathered.
func TestNfkminfoMissingIsPartial(t *testing.T) {
	info := collect(t, &vendortest.Runner{
		Outputs: map[string]string{"enquiry": enquiryOperational},
		Errs:    map[string]error{"nfkminfo": errors.New("nfkminfo: permission denied")},
	})
	if info.Extra["mode"] != "operational" {
		t.Errorf("enquiry data should survive nfkminfo failure: %+v", info.Extra)
	}
	if _, ok := info.Extra["security_world_state"]; ok {
		t.Error("no security-world state expected when nfkminfo fails")
	}
}
