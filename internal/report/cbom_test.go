package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

func cbomSampleReport() *Report {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	inv := &inventory.Inventory{
		Slot: p11.SlotInfo{Token: &p11.TokenInfo{Label: "PROD", SerialNumber: "ABC123", Manufacturer: "ACME"}},
		Objects: []inventory.Object{
			{Class: inventory.ClassPrivateKey, Label: "rsa-key", ID: "01", KeyType: "RSA", KeyBits: 2048,
				Extractable: b(false), PublicKeyFingerprint: "ffee"},
			{Class: inventory.ClassSecretKey, Label: "aes-key", ID: "02", KeyType: "AES", KeyBits: 256},
			{Class: inventory.ClassPrivateKey, Label: "pqc-key", ID: "03", KeyType: "ML-DSA"},
			{Class: inventory.ClassCertificate, Label: "leaf", ID: "01",
				Certificate: &inventory.CertInfo{
					Subject: "CN=api.example.com,O=ACME", Issuer: "CN=ACME CA",
					SerialNumber: "0A0B", NotBefore: notBefore, NotAfter: notAfter,
					SignatureAlgorithm: "SHA256-RSA", PublicKeyAlgorithm: "RSA", PublicKeyBits: 2048,
					PublicKeyFingerprint: "ffee"}},
		},
	}
	return &Report{Tool: "hsmdoctor", Version: "test", Inventory: inv}
}

func decodeCBOM(t *testing.T, r *Report) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := r.CBOM(&buf); err != nil {
		t.Fatalf("CBOM: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return m
}

func TestCBOMStructureAndQuantumAnnotation(t *testing.T) {
	m := decodeCBOM(t, cbomSampleReport())

	if m["bomFormat"] != "CycloneDX" || m["specVersion"] != "1.6" {
		t.Errorf("wrong BOM header: %v / %v", m["bomFormat"], m["specVersion"])
	}

	comps := m["components"].([]any)
	algos := map[string]map[string]any{} // name -> cryptoProperties
	quantumVuln := map[string]string{}
	var keyTypes, certs int
	for _, ci := range comps {
		c := ci.(map[string]any)
		cp := c["cryptoProperties"].(map[string]any)
		switch cp["assetType"] {
		case "algorithm":
			algos[c["name"].(string)] = cp["algorithmProperties"].(map[string]any)
			for _, pi := range c["properties"].([]any) {
				p := pi.(map[string]any)
				if p["name"] == "hsmdoctor:quantumVulnerable" {
					quantumVuln[c["name"].(string)] = p["value"].(string)
				}
			}
		case "related-crypto-material":
			keyTypes++
		case "certificate":
			certs++
		}
	}

	// Classical algorithms are quantum-vulnerable; AES and ML-DSA are not.
	if quantumVuln["RSA-2048"] != "true" {
		t.Errorf("RSA-2048 must be quantum-vulnerable: %v", quantumVuln)
	}
	if quantumVuln["AES-256"] != "false" || quantumVuln["ML-DSA"] != "false" {
		t.Errorf("AES/ML-DSA must not be quantum-vulnerable: %v", quantumVuln)
	}
	// AES-256 carries a NIST quantum security level of 5.
	if lvl, _ := algos["AES-256"]["nistQuantumSecurityLevel"].(float64); lvl != 5 {
		t.Errorf("AES-256 nistQuantumSecurityLevel want 5, got %v", algos["AES-256"]["nistQuantumSecurityLevel"])
	}
	if keyTypes != 3 || certs != 1 {
		t.Errorf("want 3 keys + 1 cert, got %d keys %d certs", keyTypes, certs)
	}
}

func TestCBOMCertificateLinksToKeyByFingerprint(t *testing.T) {
	m := decodeCBOM(t, cbomSampleReport())

	var certProps map[string]any
	for _, ci := range m["components"].([]any) {
		c := ci.(map[string]any)
		cp := c["cryptoProperties"].(map[string]any)
		if cp["assetType"] == "certificate" {
			certProps = cp["certificateProperties"].(map[string]any)
		}
	}
	if certProps == nil {
		t.Fatal("no certificate component emitted")
	}
	// The certificate and the RSA key share fingerprint "ffee", so the cert
	// must point at the key object, not a bare algorithm.
	if got := certProps["subjectPublicKeyRef"]; got != "key:private-key:01" {
		t.Errorf("cert should reference the key by fingerprint, got %v", got)
	}
	if got := certProps["signatureAlgorithmRef"]; got != "algorithm:SHA256-RSA" {
		t.Errorf("cert signature algorithm ref wrong: %v", got)
	}
}

func TestCBOMIsDeterministic(t *testing.T) {
	var a, c bytes.Buffer
	if err := cbomSampleReport().CBOM(&a); err != nil {
		t.Fatal(err)
	}
	if err := cbomSampleReport().CBOM(&c); err != nil {
		t.Fatal(err)
	}
	if a.String() != c.String() {
		t.Error("CBOM output must be deterministic across runs")
	}
}

func TestAlgoIdentity(t *testing.T) {
	cases := []struct {
		keyType, curve string
		bits           uint
		wantName       string
		wantVuln       bool
	}{
		{"RSA", "", 2048, "RSA-2048", true},
		{"EC", "P-256", 0, "EC-P-256", true},
		{"AES", "", 256, "AES-256", false},
		{"ML-DSA", "", 0, "ML-DSA", false},
		{"ML-KEM", "", 0, "ML-KEM", false},
	}
	for _, tc := range cases {
		name, _, _, _, vuln := algoIdentity(tc.keyType, tc.curve, tc.bits)
		if name != tc.wantName || vuln != tc.wantVuln {
			t.Errorf("algoIdentity(%q,%q,%d) = (%q,%v), want (%q,%v)",
				tc.keyType, tc.curve, tc.bits, name, vuln, tc.wantName, tc.wantVuln)
		}
	}
}
