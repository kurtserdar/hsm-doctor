package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeMailer captures sent messages.
type fakeMailer struct {
	sent []struct{ subject, body string }
}

func (f *fakeMailer) Send(subject, body string, _ []string) error {
	f.sent = append(f.sent, struct{ subject, body string }{subject, body})
	return nil
}

// fakeLedger records tuples and reports each as new only once.
type fakeLedger struct{ seen map[string]bool }

func newFakeLedger() *fakeLedger { return &fakeLedger{seen: map[string]bool{}} }

func (l *fakeLedger) MarkNotified(hsmID int64, kind, ref string, threshold int) (bool, error) {
	key := fmt.Sprintf("%d|%s|%s|%d", hsmID, kind, ref, threshold)
	if l.seen[key] {
		return false, nil
	}
	l.seen[key] = true
	return true, nil
}

func testConfig() *Config {
	return &Config{SMTP: SMTPConfig{Host: "h", Port: 25, From: "a@b", To: []string{"ops@example.com"}}}
}

func TestNotifyDrift(t *testing.T) {
	m := &fakeMailer{}
	n := newWithMailer(testConfig(), nil, m)
	n.NotifyDrift(DriftInfo{
		HSMID: 1, Serial: "S1", Label: "PROD", Source: "edge-01", Changes: 2,
		Summary: []string{"firmware version changed 7.8.1 -> 7.8.2", "private-key k1 (id 01): CKA_EXTRACTABLE changed false -> true"},
	})
	if len(m.sent) != 1 {
		t.Fatalf("expected 1 e-mail, got %d", len(m.sent))
	}
	if !strings.Contains(m.sent[0].subject, "Drift on PROD") || !strings.Contains(m.sent[0].subject, "2 changes") {
		t.Errorf("drift subject wrong: %q", m.sent[0].subject)
	}
	if !strings.Contains(m.sent[0].body, "CKA_EXTRACTABLE changed false -> true") {
		t.Errorf("drift body missing change detail: %q", m.sent[0].body)
	}
}

func TestDriftDisabled(t *testing.T) {
	m := &fakeMailer{}
	off := false
	cfg := testConfig()
	cfg.Drift = &off
	n := newWithMailer(cfg, nil, m)
	n.NotifyDrift(DriftInfo{HSMID: 1, Changes: 1})
	if len(m.sent) != 0 {
		t.Error("drift disabled should send nothing")
	}
}

func TestCertExpiryThresholdsAndDedup(t *testing.T) {
	m := &fakeMailer{}
	ledger := newFakeLedger()
	n := newWithMailer(testConfig(), ledger, m) // default thresholds 30/14/1

	certs := []CertInfo{
		{Label: "api-cert", Subject: "CN=api", DaysLeft: 13, NotAfter: time.Now().Add(13 * 24 * time.Hour)},
		{Label: "ca-cert", Subject: "CN=ca", DaysLeft: 40, NotAfter: time.Now().Add(40 * 24 * time.Hour)}, // outside 30 → no mail
		{Label: "old-cert", Subject: "CN=old", DaysLeft: -2, NotAfter: time.Now().Add(-2 * 24 * time.Hour)},
	}
	n.NotifyCertExpiry(7, "PROD", certs)

	// api-cert (13 → bucket 14) and old-cert (expired → bucket 1) mail; ca-cert does not.
	if len(m.sent) != 2 {
		t.Fatalf("expected 2 e-mails, got %d: %+v", len(m.sent), m.sent)
	}

	// Re-running the same scan must not resend (dedup by ledger).
	n.NotifyCertExpiry(7, "PROD", certs)
	if len(m.sent) != 2 {
		t.Errorf("dedup failed: resent, total now %d", len(m.sent))
	}

	// api-cert moving into a tighter bucket (13 → 1-day) is a new reminder.
	tighter := []CertInfo{{Label: "api-cert", Subject: "CN=api", DaysLeft: 1, NotAfter: time.Now().Add(24 * time.Hour)}}
	n.NotifyCertExpiry(7, "PROD", tighter)
	if len(m.sent) != 3 {
		t.Errorf("crossing into a tighter threshold should send again, total %d", len(m.sent))
	}
}

func TestCrossedThreshold(t *testing.T) {
	th := []int{30, 14, 1}
	cases := []struct {
		days   int
		bucket int
		ok     bool
	}{
		{40, 0, false},
		{30, 30, true},
		{20, 14, true}, // <=30 and <=14? 20<=30 yes, 20<=14 no → bucket 30
		{14, 14, true},
		{1, 1, true},
		{-5, 1, true}, // expired → smallest bucket
	}
	for _, c := range cases {
		got, ok := crossedThreshold(c.days, th)
		if c.days == 20 {
			// 20 falls in the 30 bucket (smallest threshold >= days that it is <=).
			if !ok || got != 30 {
				t.Errorf("days=20: got bucket %d ok %v", got, ok)
			}
			continue
		}
		if ok != c.ok || (ok && got != c.bucket) {
			t.Errorf("days=%d: got (%d,%v), want (%d,%v)", c.days, got, ok, c.bucket, c.ok)
		}
	}
}

func TestLoadConfigValidation(t *testing.T) {
	// Missing required fields.
	if _, err := parseConfig([]byte(`smtp: {host: h, port: 25}`)); err == nil {
		t.Error("missing from/to should fail")
	}
	// Valid.
	c, err := parseConfig([]byte(`
smtp:
  host: smtp.example.com
  port: 587
  from: hsmdoctor@example.com
  to: [ops@example.com]
`))
	if err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if c.SMTP.TLS != TLSStartTLS {
		t.Errorf("tls should default to starttls, got %q", c.SMTP.TLS)
	}
	if !c.DriftEnabled() || !c.CertExpiryEnabled() {
		t.Error("triggers should default to enabled")
	}
}
