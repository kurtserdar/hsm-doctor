package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
)

func b(v bool) *bool { return &v }

func sampleReport() *Report {
	inv := &inventory.Inventory{
		ScannedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Module: p11.ModuleInfo{
			Path: "/usr/lib/softhsm/libsofthsm2.so", Manufacturer: "SoftHSM",
			Description: "Implementation of PKCS11", CryptokiVersion: "2.40", LibraryVersion: "2.6",
		},
		Slot: p11.SlotInfo{ID: 42, TokenPresent: true, Token: &p11.TokenInfo{
			Label: "PROD-PARTITION", Manufacturer: "SoftHSM project", Model: "SoftHSM v2",
			SerialNumber: "abc123", FirmwareVersion: "2.6",
		}},
		Mechanisms: []p11.Mechanism{{Name: "CKM_RSA_PKCS", Flags: []string{"SIGN", "VERIFY"}}},
		LoggedIn:   true,
		Objects: []inventory.Object{
			{Class: inventory.ClassPrivateKey, Label: "tls-key", ID: "01",
				KeyType: "RSA", KeyBits: 1024, Extractable: b(true), Sign: b(true)},
			{Class: inventory.ClassCertificate, Label: "tls-cert", ID: "01",
				Certificate: &inventory.CertInfo{
					Subject: "CN=api.example.com", Issuer: "CN=Test CA",
					NotAfter: time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
				}},
		},
	}
	res := &policy.Result{
		Score: 65,
		Findings: []policy.Finding{
			{RuleID: "HSM-001", Title: "Extractable private key", Severity: policy.SevCritical,
				Object: "private-key tls-key (id 01)", Detail: "CKA_EXTRACTABLE=true",
				Remediation: "Regenerate the key with CKA_EXTRACTABLE=false."},
			{RuleID: "HSM-003", Title: "Weak RSA key", Severity: policy.SevHigh,
				Object: "private-key tls-key (id 01)", Detail: "key size 1024 < 2048 bits"},
		},
	}
	return New("0.1.0-test", inv, res)
}

func TestTextReport(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleReport().Text(&buf); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Health Score: 65/100",
		"CRITICAL (1)",
		"[HSM-001] Extractable private key",
		"fix: Regenerate the key with CKA_EXTRACTABLE=false.",
		"HIGH (1)",
		"PROD-PARTITION",
		"Private keys:   1",
		"Certificates:   1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q\n---\n%s", want, out)
		}
	}
}

func TestJSONReportRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleReport().JSON(&buf); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Score != 65 || len(back.Findings) != 2 || back.Inventory == nil {
		t.Errorf("round trip lost data: score=%d findings=%d", back.Score, len(back.Findings))
	}
	if back.Inventory.Objects[0].Extractable == nil || !*back.Inventory.Objects[0].Extractable {
		t.Error("round trip lost tri-state attribute")
	}
}

func TestHTMLReport(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleReport().HTML(&buf); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"PROD-PARTITION",
		"HSM-001",
		"Extractable private key",
		"CN=api.example.com",
		"CKM_RSA_PKCS",
		"fix: Regenerate the key with CKA_EXTRACTABLE=false.",
		">65<",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	// The report warns when the scan ran without login.
	rep := sampleReport()
	rep.Inventory.LoggedIn = false
	buf.Reset()
	if err := rep.HTML(&buf); err != nil {
		t.Fatalf("HTML (no login): %v", err)
	}
	if !strings.Contains(buf.String(), "no login") {
		t.Error("HTML report should warn about missing login")
	}
}
