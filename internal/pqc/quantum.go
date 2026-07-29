package pqc

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// classicalKeyTypes are the public-key algorithms a cryptographically
// relevant quantum computer breaks via Shor's algorithm.
var classicalKeyTypes = map[string]bool{
	"RSA": true, "EC": true, "DSA": true, "DH": true,
}

// pqcKeyTypes are the key type names produced by the inventory collector
// for PKCS#11 3.2 PQC keys.
var pqcKeyTypes = map[string]bool{
	"ML-KEM": true, "ML-DSA": true, "SLH-DSA": true,
}

// Exposure quantifies how much of the current inventory a quantum
// adversary would compromise.
type Exposure struct {
	TotalPrivateKeys     int `json:"total_private_keys"`
	ClassicalPrivateKeys int `json:"classical_private_keys"`
	PQCPrivateKeys       int `json:"pqc_private_keys"`
	// HarvestNowDecryptLater counts classical private keys that can
	// decrypt or unwrap: traffic recorded today is decryptable once a
	// quantum computer exists, making these the most urgent keys.
	HarvestNowDecryptLater int `json:"harvest_now_decrypt_later"`
	ClassicalCertificates  int `json:"classical_certificates"`
	// Summary is a manager-level sentence describing the situation.
	Summary string `json:"summary"`
}

// Assess computes the quantum exposure of an inventory, in combination
// with the token's detection result.
func Assess(inv *inventory.Inventory, det *Detection) *Exposure {
	e := &Exposure{}
	for _, o := range inv.Objects {
		switch o.Class {
		case inventory.ClassPrivateKey:
			e.TotalPrivateKeys++
			switch {
			case classicalKeyTypes[o.KeyType]:
				e.ClassicalPrivateKeys++
				if (o.Decrypt != nil && *o.Decrypt) || (o.Unwrap != nil && *o.Unwrap) {
					e.HarvestNowDecryptLater++
				}
			case pqcKeyTypes[o.KeyType]:
				e.PQCPrivateKeys++
			}
		case inventory.ClassCertificate:
			if o.Certificate != nil {
				alg := o.Certificate.PublicKeyAlgorithm
				// Go's x509 names: RSA, ECDSA, Ed25519, DSA — all classical.
				if alg != "" && alg != "0" {
					e.ClassicalCertificates++
				}
			}
		}
	}
	e.Summary = summarize(e, det)
	return e
}

func summarize(e *Exposure, det *Detection) string {
	if e.TotalPrivateKeys == 0 {
		if det.Verdict == VerdictNotReady {
			return "No private keys stored; the token advertises no PQC mechanisms, so post-quantum keys cannot be created on this device yet."
		}
		return "No private keys stored; the token already advertises PQC mechanisms, so new keys can be created post-quantum from day one."
	}

	classicalShare := 100 * e.ClassicalPrivateKeys / e.TotalPrivateKeys
	base := fmt.Sprintf("%d of %d private keys (%d%%) use quantum-vulnerable algorithms",
		e.ClassicalPrivateKeys, e.TotalPrivateKeys, classicalShare)
	if e.HarvestNowDecryptLater > 0 {
		base += fmt.Sprintf("; %d of them can decrypt or unwrap and are exposed to harvest-now-decrypt-later attacks", e.HarvestNowDecryptLater)
	}
	switch det.Verdict {
	case VerdictNotReady:
		base += ". The token advertises no PQC mechanisms: there is no migration path on this device yet."
	case VerdictPartial:
		base += ". The token advertises some PQC mechanisms: partial migration is possible."
	case VerdictReady:
		base += ". The token advertises ML-KEM and ML-DSA: migration can begin."
	}
	return base
}
