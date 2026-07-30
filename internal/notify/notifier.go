package notify

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Ledger records which (hsm, kind, ref, threshold) notifications were already
// sent, so recurring scans do not re-send. The store implements it.
type Ledger interface {
	MarkNotified(hsmID int64, kind, ref string, threshold int) (bool, error)
}

// DriftInfo is the minimal drift context an e-mail needs.
type DriftInfo struct {
	HSMID   int64
	Serial  string
	Label   string
	Source  string
	Changes int
	// Summary is a short human-readable list of changes.
	Summary []string
}

// CertInfo is one certificate's expiry status for notification.
type CertInfo struct {
	Label    string
	Subject  string
	DaysLeft int
	NotAfter time.Time
}

// Notifier sends alert e-mails, deduplicating certificate reminders via the
// ledger. A nil Notifier is a no-op, so callers need not check for it.
type Notifier struct {
	mailer Mailer
	cfg    *Config
	ledger Ledger
}

// New builds a Notifier. Returns nil when cfg is nil (notifications off).
func New(cfg *Config, ledger Ledger) *Notifier {
	if cfg == nil {
		return nil
	}
	return &Notifier{mailer: NewSMTPMailer(cfg.SMTP), cfg: cfg, ledger: ledger}
}

// newWithMailer is used by tests to inject a fake mailer.
func newWithMailer(cfg *Config, ledger Ledger, m Mailer) *Notifier {
	return &Notifier{mailer: m, cfg: cfg, ledger: ledger}
}

// MaxWarnDays is the widest certificate-expiry threshold, so callers know how
// far ahead to look. Returns 0 for a nil Notifier.
func (n *Notifier) MaxWarnDays() int {
	if n == nil {
		return 0
	}
	max := 0
	for _, d := range n.cfg.warnDays() {
		if d > max {
			max = d
		}
	}
	return max
}

// NotifyDrift e-mails a drift alert. Delivery failures are logged, never
// propagated, so they cannot disrupt scanning.
func (n *Notifier) NotifyDrift(d DriftInfo) {
	if n == nil || !n.cfg.DriftEnabled() {
		return
	}
	name := d.Label
	if name == "" {
		name = d.Serial
	}
	subject := fmt.Sprintf("[HSM Doctor] Drift on %s (%d change%s)", name, d.Changes, plural(d.Changes))
	var b strings.Builder
	fmt.Fprintf(&b, "Configuration drift was detected on HSM %q (serial %s, source %s).\n\n", d.Label, d.Serial, d.Source)
	fmt.Fprintf(&b, "%d change(s):\n", d.Changes)
	for _, c := range d.Summary {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	fmt.Fprintf(&b, "\nReview the full diff in the HSM Doctor dashboard.\n")
	n.send(subject, b.String())
}

// NotifyCertExpiry e-mails a reminder for each certificate that has newly
// crossed a warning threshold, once per certificate and threshold. certs
// should already be filtered to those expiring (or expired).
func (n *Notifier) NotifyCertExpiry(hsmID int64, hsmLabel string, certs []CertInfo) {
	if n == nil || !n.cfg.CertExpiryEnabled() {
		return
	}
	thresholds := n.cfg.warnDays()
	sort.Sort(sort.Reverse(sort.IntSlice(thresholds)))

	for _, c := range certs {
		bucket, ok := crossedThreshold(c.DaysLeft, thresholds)
		if !ok {
			continue
		}
		ref := c.Label
		if ref == "" {
			ref = c.Subject
		}
		fresh := true
		if n.ledger != nil {
			var err error
			if fresh, err = n.ledger.MarkNotified(hsmID, "cert-expiry", ref, bucket); err != nil {
				log.Printf("warning: notification ledger: %v", err)
				continue
			}
		}
		if !fresh {
			continue
		}
		subject := fmt.Sprintf("[HSM Doctor] Certificate expiring: %s (%d day%s)", ref, c.DaysLeft, plural(c.DaysLeft))
		if c.DaysLeft < 0 {
			subject = fmt.Sprintf("[HSM Doctor] Certificate EXPIRED: %s", ref)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "A certificate on HSM %q needs attention.\n\n", hsmLabel)
		fmt.Fprintf(&b, "  Label:    %s\n", c.Label)
		fmt.Fprintf(&b, "  Subject:  %s\n", c.Subject)
		fmt.Fprintf(&b, "  Expires:  %s\n", c.NotAfter.Format("2006-01-02"))
		if c.DaysLeft < 0 {
			fmt.Fprintf(&b, "  Status:   EXPIRED %d day(s) ago\n", -c.DaysLeft)
		} else {
			fmt.Fprintf(&b, "  Status:   %d day(s) left\n", c.DaysLeft)
		}
		n.send(subject, b.String())
	}
}

// crossedThreshold returns the smallest threshold >= daysLeft (the bucket the
// certificate now falls into), or false when it is outside every threshold.
// Expired certificates (daysLeft < 0) map to the smallest threshold.
func crossedThreshold(daysLeft int, thresholdsDesc []int) (int, bool) {
	if len(thresholdsDesc) == 0 {
		return 0, false
	}
	if daysLeft < 0 {
		return thresholdsDesc[len(thresholdsDesc)-1], true
	}
	bucket := 0
	found := false
	for _, th := range thresholdsDesc {
		if daysLeft <= th {
			bucket = th
			found = true
		}
	}
	return bucket, found
}

func (n *Notifier) send(subject, body string) {
	if err := n.mailer.Send(subject, body, n.cfg.SMTP.To); err != nil {
		log.Printf("warning: sending notification e-mail: %v", err)
	}
}

func plural(n int) string {
	if n == 1 || n == -1 {
		return ""
	}
	return "s"
}
