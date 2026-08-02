// Package certmon classifies the certificates of an inventory by expiry
// status for monitoring and alerting.
package certmon

import (
	"fmt"
	"sort"
	"strings"
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
	// Warnings lists validation issues beyond expiry (self-signed, weak key,
	// key mismatch, unverified chain, ...).
	Warnings []string `json:"warnings,omitempty"`
}

// Classify extracts all X.509 certificate objects from the inventory and
// computes their status. Certificates expiring within warnDays are marked
// StatusExpiring. Results are sorted most-urgent first.
func Classify(inv *inventory.Inventory, now time.Time, warnDays int) []Entry {
	// Key public-key fingerprints per CKA_ID, for certificate/key matching.
	keyFPs := map[string][]string{}
	for _, o := range inv.Objects {
		if (o.Class == inventory.ClassPrivateKey || o.Class == inventory.ClassPublicKey) &&
			o.ID != "" && o.PublicKeyFingerprint != "" {
			keyFPs[o.ID] = append(keyFPs[o.ID], o.PublicKeyFingerprint)
		}
	}

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
			Warnings: certWarnings(o, c, now, keyFPs),
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

// certWarnings collects validation issues (beyond expiry) for one certificate.
func certWarnings(o inventory.Object, c *inventory.CertInfo, now time.Time, keyFPs map[string][]string) []string {
	var w []string
	if c.SelfSigned && !c.IsCA {
		w = append(w, "self-signed")
	}
	if c.NotBefore.After(now) {
		w = append(w, "not yet valid")
	}
	if c.PublicKeyAlgorithm == "RSA" && c.PublicKeyBits > 0 && c.PublicKeyBits < 2048 {
		w = append(w, fmt.Sprintf("weak RSA key (%d-bit)", c.PublicKeyBits))
	}
	if c.IsCA && !c.HasKeyUsage("keyCertSign") {
		w = append(w, "CA without keyCertSign")
	}
	if o.ID != "" && c.PublicKeyFingerprint != "" {
		fps := keyFPs[o.ID]
		if len(fps) > 0 && !containsFP(fps, c.PublicKeyFingerprint) {
			w = append(w, "key mismatch")
		}
	}
	if strings.HasPrefix(c.ChainStatus, "unverified") {
		w = append(w, "chain unverified")
	}
	return w
}

func containsFP(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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
