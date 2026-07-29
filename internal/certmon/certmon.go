// Package certmon classifies the certificates of an inventory by expiry
// status for monitoring and alerting.
package certmon

import (
	"sort"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// Status describes where a certificate stands in its lifecycle.
type Status string

const (
	StatusOK       Status = "ok"
	StatusExpiring Status = "expiring"
	StatusExpired  Status = "expired"
)

// Entry is one certificate with its computed expiry state.
type Entry struct {
	Label    string    `json:"label,omitempty"`
	ID       string    `json:"id,omitempty"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	IsCA     bool      `json:"is_ca"`
	Status   Status    `json:"status"`
	// DaysLeft is negative for expired certificates.
	DaysLeft int `json:"days_left"`
}

// Classify extracts all X.509 certificate objects from the inventory and
// computes their status. Certificates expiring within warnDays are marked
// StatusExpiring. Results are sorted most-urgent first.
func Classify(inv *inventory.Inventory, now time.Time, warnDays int) []Entry {
	var entries []Entry
	for _, o := range inv.Objects {
		if o.Class != inventory.ClassCertificate || o.Certificate == nil {
			continue
		}
		c := o.Certificate
		e := Entry{
			Label:    o.Label,
			ID:       o.ID,
			Subject:  c.Subject,
			Issuer:   c.Issuer,
			NotAfter: c.NotAfter,
			IsCA:     c.IsCA,
		}
		left := c.NotAfter.Sub(now)
		e.DaysLeft = int(left.Hours() / 24)
		switch {
		case left <= 0:
			e.Status = StatusExpired
		case left <= time.Duration(warnDays)*24*time.Hour:
			e.Status = StatusExpiring
		default:
			e.Status = StatusOK
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].NotAfter.Before(entries[j].NotAfter)
	})
	return entries
}

// Counts tallies entries per status.
func Counts(entries []Entry) (ok, expiring, expired int) {
	for _, e := range entries {
		switch e.Status {
		case StatusOK:
			ok++
		case StatusExpiring:
			expiring++
		case StatusExpired:
			expired++
		}
	}
	return
}
