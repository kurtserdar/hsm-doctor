// Package inventory collects metadata about the objects stored on a PKCS#11
// token: keys and certificates, their attributes and X.509 details.
//
// Only metadata is ever read. Private or secret key material (CKA_VALUE,
// CKA_PRIVATE_EXPONENT, ...) is never requested from the token.
package inventory

import (
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

// Object classes as reported in Object.Class.
const (
	ClassPrivateKey  = "private-key"
	ClassPublicKey   = "public-key"
	ClassSecretKey   = "secret-key"
	ClassCertificate = "certificate"
)

// Inventory is the full metadata snapshot of one token.
type Inventory struct {
	ScannedAt  time.Time       `json:"scanned_at"`
	Module     p11.ModuleInfo  `json:"module"`
	Slot       p11.SlotInfo    `json:"slot"`
	Mechanisms []p11.Mechanism `json:"mechanisms"`
	// LoggedIn records whether the scan ran with a user session. Without
	// login most tokens hide private objects, so an anonymous inventory
	// is incomplete by design.
	LoggedIn bool     `json:"logged_in"`
	Objects  []Object `json:"objects"`
}

// Object describes a single token object. Boolean attributes use pointers:
// nil means the token did not expose that attribute for this object.
type Object struct {
	Class   string `json:"class"`
	Label   string `json:"label,omitempty"`
	ID      string `json:"id,omitempty"` // hex-encoded CKA_ID
	KeyType string `json:"key_type,omitempty"`
	KeyBits uint   `json:"key_bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	// PublicKeyFingerprint is a hex SHA-256 of the public key material (RSA
	// modulus or EC point) — used to correlate certificates with their keys.
	PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`

	Token            *bool `json:"token,omitempty"`
	Private          *bool `json:"private,omitempty"`
	Modifiable       *bool `json:"modifiable,omitempty"`
	Local            *bool `json:"local,omitempty"`
	Sensitive        *bool `json:"sensitive,omitempty"`
	Extractable      *bool `json:"extractable,omitempty"`
	AlwaysSensitive  *bool `json:"always_sensitive,omitempty"`
	NeverExtractable *bool `json:"never_extractable,omitempty"`
	Sign             *bool `json:"sign,omitempty"`
	Verify           *bool `json:"verify,omitempty"`
	Encrypt          *bool `json:"encrypt,omitempty"`
	Decrypt          *bool `json:"decrypt,omitempty"`
	Wrap             *bool `json:"wrap,omitempty"`
	Unwrap           *bool `json:"unwrap,omitempty"`
	Derive           *bool `json:"derive,omitempty"`

	Certificate *CertInfo `json:"certificate,omitempty"`
}

// CertInfo holds parsed X.509 details of a certificate object.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits,omitempty"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed,omitempty"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	// PublicKeyFingerprint is a hex SHA-256 of the certificate's public key
	// material (RSA modulus or EC point), comparable with an Object's.
	PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`
	// ChainStatus is set by ValidateChains: "verified", or "unverified: ..."
	// with the reason. Empty when chain validation was not run.
	ChainStatus string `json:"chain_status,omitempty"`
	// Raw is the certificate DER, retained in-memory for chain building. It is
	// not serialized (certificates are public, but this keeps reports compact).
	Raw []byte `json:"-"`
}

// HasKeyUsage reports whether the certificate asserts the named X.509 key
// usage (e.g. "keyCertSign", "digitalSignature").
func (c *CertInfo) HasKeyUsage(name string) bool {
	for _, u := range c.KeyUsage {
		if u == name {
			return true
		}
	}
	return false
}

// Counts summarizes the inventory by object class.
type Counts struct {
	PrivateKeys  int `json:"private_keys"`
	PublicKeys   int `json:"public_keys"`
	SecretKeys   int `json:"secret_keys"`
	Certificates int `json:"certificates"`
}

// Count tallies objects by class.
func (inv *Inventory) Count() Counts {
	var c Counts
	for _, o := range inv.Objects {
		switch o.Class {
		case ClassPrivateKey:
			c.PrivateKeys++
		case ClassPublicKey:
			c.PublicKeys++
		case ClassSecretKey:
			c.SecretKeys++
		case ClassCertificate:
			c.Certificates++
		}
	}
	return c
}
