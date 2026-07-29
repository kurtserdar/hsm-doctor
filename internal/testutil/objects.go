//go:build integration

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

// oidP256 is the DER-encoded OID for the NIST P-256 curve (CKA_EC_PARAMS).
var oidP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// KeyPairOpts controls test key pair generation.
type KeyPairOpts struct {
	Label       string
	ID          []byte
	Bits        int  // RSA modulus bits
	Extractable bool // CKA_EXTRACTABLE on the private key
	Sensitive   bool // CKA_SENSITIVE on the private key
}

// GenerateRSAKeyPair creates a persistent RSA key pair on the test token.
func GenerateRSAKeyPair(t *testing.T, sess *p11.Session, o KeyPairOpts) {
	t.Helper()
	ctx, h := sess.Raw()
	pub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, o.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, o.ID),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, o.Bits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	}
	priv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, o.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, o.ID),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, o.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, o.Extractable),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	if _, _, err := ctx.GenerateKeyPair(h, mech, pub, priv); err != nil {
		t.Fatalf("generating RSA-%d key pair %q: %v", o.Bits, o.Label, err)
	}
}

// GenerateECKeyPair creates a persistent P-256 key pair on the test token.
func GenerateECKeyPair(t *testing.T, sess *p11.Session, label string, id []byte) {
	t.Helper()
	ctx, h := sess.Raw()
	pub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidP256),
	}
	priv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	if _, _, err := ctx.GenerateKeyPair(h, mech, pub, priv); err != nil {
		t.Fatalf("generating EC key pair %q: %v", label, err)
	}
}

// GenerateAESKey creates a persistent AES key on the test token.
func GenerateAESKey(t *testing.T, sess *p11.Session, label string, id []byte, bytes int) {
	t.Helper()
	ctx, h := sess.Raw()
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, bytes),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	if _, err := ctx.GenerateKey(h, mech, tmpl); err != nil {
		t.Fatalf("generating AES key %q: %v", label, err)
	}
}

// ImportSelfSignedCert creates a self-signed X.509 certificate (signed in
// software, outside the token) and stores it as a certificate object.
// The validity window is controlled by notBefore/notAfter so tests can
// create both valid and expired certificates.
func ImportSelfSignedCert(t *testing.T, sess *p11.Session, label string, id []byte, cn string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating cert key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"HSM Doctor Tests"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("re-parsing certificate: %v", err)
	}

	ctx, h := sess.Raw()
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, der),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
	}
	if _, err := ctx.CreateObject(h, attrs); err != nil {
		t.Fatalf("importing certificate %q: %v", label, err)
	}
}
