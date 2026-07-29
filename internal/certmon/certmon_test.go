package certmon

import (
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	inv := &inventory.Inventory{Objects: []inventory.Object{
		{Class: inventory.ClassCertificate, Label: "healthy", ID: "01",
			Certificate: &inventory.CertInfo{Subject: "CN=h", NotAfter: now.Add(365 * 24 * time.Hour)}},
		{Class: inventory.ClassCertificate, Label: "soon", ID: "02",
			Certificate: &inventory.CertInfo{Subject: "CN=s", NotAfter: now.Add(9*24*time.Hour + time.Hour)}},
		{Class: inventory.ClassCertificate, Label: "gone", ID: "03",
			Certificate: &inventory.CertInfo{Subject: "CN=g", NotAfter: now.Add(-10 * 24 * time.Hour)}},
		// Non-certificate and unparsed-certificate objects are ignored.
		{Class: inventory.ClassPrivateKey, Label: "key"},
		{Class: inventory.ClassCertificate, Label: "opaque"},
	}}

	entries := Classify(inv, now, 30)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	// Sorted most-urgent first: expired, expiring, ok.
	if entries[0].Label != "gone" || entries[0].Status != StatusExpired || entries[0].DaysLeft != -10 {
		t.Errorf("expired entry wrong: %+v", entries[0])
	}
	if entries[1].Label != "soon" || entries[1].Status != StatusExpiring || entries[1].DaysLeft != 9 {
		t.Errorf("expiring entry wrong: %+v", entries[1])
	}
	if entries[2].Label != "healthy" || entries[2].Status != StatusOK {
		t.Errorf("healthy entry wrong: %+v", entries[2])
	}

	ok, expiring, expired := Counts(entries)
	if ok != 1 || expiring != 1 || expired != 1 {
		t.Errorf("counts wrong: ok=%d expiring=%d expired=%d", ok, expiring, expired)
	}
}

func TestClassifyWarnDaysBoundary(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	inv := &inventory.Inventory{Objects: []inventory.Object{
		{Class: inventory.ClassCertificate, Label: "exact",
			Certificate: &inventory.CertInfo{NotAfter: now.Add(30 * 24 * time.Hour)}},
		{Class: inventory.ClassCertificate, Label: "outside",
			Certificate: &inventory.CertInfo{NotAfter: now.Add(30*24*time.Hour + time.Minute)}},
	}}
	entries := Classify(inv, now, 30)
	if entries[0].Status != StatusExpiring {
		t.Errorf("certificate expiring exactly at warn boundary should be expiring: %+v", entries[0])
	}
	if entries[1].Status != StatusOK {
		t.Errorf("certificate just outside warn window should be ok: %+v", entries[1])
	}
}
