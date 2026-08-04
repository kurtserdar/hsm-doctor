// Package sharedkeys correlates the key inventories of many HSMs to find a
// private key whose public fingerprint appears on more than one HSM — a strong
// signal that the key material left its hardware boundary and was copied.
//
// Only asymmetric private keys are considered: a symmetric secret key exposes
// no public fingerprint (its material is never read), so it cannot be
// correlated this way. Detection uses the public-key fingerprint (SHA-256 of
// the RSA modulus or EC point) that the inventory already records; no private
// key material is ever read.
package sharedkeys

import (
	"sort"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// Location is one place a shared key was observed.
type Location struct {
	HSMID    int64  `json:"hsm_id"`
	HSMLabel string `json:"hsm_label,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Source   string `json:"source,omitempty"`
	Object   string `json:"object"`
	KeyType  string `json:"key_type,omitempty"`
}

// SharedKey is a private-key fingerprint present on more than one HSM.
type SharedKey struct {
	Fingerprint string     `json:"fingerprint"`
	KeyType     string     `json:"key_type,omitempty"`
	HSMCount    int        `json:"hsm_count"`
	Locations   []Location `json:"locations"`
}

// Source is one HSM's identity and its collected inventory.
type Source struct {
	HSMID     int64
	HSMLabel  string
	Serial    string
	Source    string
	Inventory *inventory.Inventory
}

// Detect returns the private-key fingerprints found on two or more distinct
// HSMs, most widely shared first.
func Detect(sources []Source) []SharedKey {
	type agg struct {
		keyType   string
		locations []Location
		hsms      map[int64]bool
	}
	groups := map[string]*agg{}

	for _, s := range sources {
		if s.Inventory == nil {
			continue
		}
		for _, o := range s.Inventory.Objects {
			if o.Class != inventory.ClassPrivateKey || o.PublicKeyFingerprint == "" {
				continue
			}
			g := groups[o.PublicKeyFingerprint]
			if g == nil {
				g = &agg{hsms: map[int64]bool{}}
				groups[o.PublicKeyFingerprint] = g
			}
			g.hsms[s.HSMID] = true
			if g.keyType == "" {
				g.keyType = o.KeyType
			}
			g.locations = append(g.locations, Location{
				HSMID:    s.HSMID,
				HSMLabel: s.HSMLabel,
				Serial:   s.Serial,
				Source:   s.Source,
				Object:   objectName(o),
				KeyType:  o.KeyType,
			})
		}
	}

	out := make([]SharedKey, 0)
	for fp, g := range groups {
		if len(g.hsms) < 2 {
			continue
		}
		locs := g.locations
		sort.Slice(locs, func(i, j int) bool {
			if locs[i].HSMID != locs[j].HSMID {
				return locs[i].HSMID < locs[j].HSMID
			}
			return locs[i].Object < locs[j].Object
		})
		out = append(out, SharedKey{
			Fingerprint: fp,
			KeyType:     g.keyType,
			HSMCount:    len(g.hsms),
			Locations:   locs,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HSMCount != out[j].HSMCount {
			return out[i].HSMCount > out[j].HSMCount
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// objectName is a short human label for a key object.
func objectName(o inventory.Object) string {
	switch {
	case o.Label != "":
		return o.Label
	case o.ID != "":
		return "id " + o.ID
	default:
		return "(unnamed)"
	}
}
