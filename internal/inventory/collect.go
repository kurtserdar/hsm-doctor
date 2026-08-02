package inventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

// keyTypeNames maps CKK_* codes to short display names.
var keyTypeNames = map[uint]string{
	pkcs11.CKK_RSA:            "RSA",
	pkcs11.CKK_DSA:            "DSA",
	pkcs11.CKK_DH:             "DH",
	pkcs11.CKK_EC:             "EC",
	pkcs11.CKK_GENERIC_SECRET: "GENERIC-SECRET",
	pkcs11.CKK_DES:            "DES",
	pkcs11.CKK_DES2:           "DES2",
	pkcs11.CKK_DES3:           "DES3",
	pkcs11.CKK_AES:            "AES",
	pkcs11.CKK_SHA_1_HMAC:     "SHA1-HMAC",
	pkcs11.CKK_SHA256_HMAC:    "SHA256-HMAC",
	pkcs11.CKK_SHA384_HMAC:    "SHA384-HMAC",
	pkcs11.CKK_SHA512_HMAC:    "SHA512-HMAC",
	// PKCS#11 3.2 post-quantum key types (values from the OASIS 3.02
	// header; not present in the miekg v2.40 constant set).
	0x49: "ML-KEM",
	0x4a: "ML-DSA",
	0x4b: "SLH-DSA",
}

func keyTypeName(code uint) string {
	if name, ok := keyTypeNames[code]; ok {
		return name
	}
	return fmt.Sprintf("CKK_0x%08X", code)
}

// scannedClasses lists the object classes the collector enumerates.
var scannedClasses = []struct {
	class uint
	name  string
}{
	{pkcs11.CKO_PRIVATE_KEY, ClassPrivateKey},
	{pkcs11.CKO_PUBLIC_KEY, ClassPublicKey},
	{pkcs11.CKO_SECRET_KEY, ClassSecretKey},
	{pkcs11.CKO_CERTIFICATE, ClassCertificate},
}

// Collect gathers the full metadata inventory of the token in the given
// slot. When pin is empty the scan runs without login and will usually only
// see public objects.
func Collect(client *p11.Client, slotID uint, pin string) (*Inventory, error) {
	inv := &Inventory{ScannedAt: time.Now().UTC(), LoggedIn: pin != ""}

	var err error
	if inv.Module, err = client.Info(); err != nil {
		return nil, err
	}
	slots, err := client.Slots()
	if err != nil {
		return nil, err
	}
	found := false
	for _, s := range slots {
		if s.ID == slotID {
			inv.Slot = s
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("slot %d not found in module %s", slotID, inv.Module.Path)
	}
	if !inv.Slot.TokenPresent {
		return nil, fmt.Errorf("slot %d has no token present", slotID)
	}
	if inv.Mechanisms, err = client.Mechanisms(slotID); err != nil {
		return nil, err
	}

	sess, err := client.OpenSession(slotID, pin, false)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	for _, sc := range scannedClasses {
		handles, err := sess.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, sc.class),
		})
		if err != nil {
			return nil, fmt.Errorf("enumerating %s objects: %w", sc.name, err)
		}
		for _, h := range handles {
			inv.Objects = append(inv.Objects, collectObject(sess, h, sc.name))
		}
	}
	return inv, nil
}

// collectObject reads the metadata attributes relevant for the object class.
// Missing attributes are left as nil/zero: tokens differ in what they expose
// and absence is a data point, not an error.
func collectObject(sess *p11.Session, h pkcs11.ObjectHandle, class string) Object {
	obj := Object{Class: class}

	if v, ok := sess.AttrBytes(h, pkcs11.CKA_LABEL); ok {
		obj.Label = string(v)
	}
	if v, ok := sess.AttrBytes(h, pkcs11.CKA_ID); ok && len(v) > 0 {
		obj.ID = hex.EncodeToString(v)
	}
	obj.Token = attrBoolPtr(sess, h, pkcs11.CKA_TOKEN)
	obj.Private = attrBoolPtr(sess, h, pkcs11.CKA_PRIVATE)
	obj.Modifiable = attrBoolPtr(sess, h, pkcs11.CKA_MODIFIABLE)

	switch class {
	case ClassPrivateKey, ClassPublicKey, ClassSecretKey:
		collectKeyAttrs(sess, h, &obj)
	case ClassCertificate:
		collectCertAttrs(sess, h, &obj)
	}
	return obj
}

func collectKeyAttrs(sess *p11.Session, h pkcs11.ObjectHandle, obj *Object) {
	if kt, ok := sess.AttrUint(h, pkcs11.CKA_KEY_TYPE); ok {
		obj.KeyType = keyTypeName(kt)
	}
	obj.Local = attrBoolPtr(sess, h, pkcs11.CKA_LOCAL)

	// Key size, without ever touching key material: RSA public modulus
	// length, EC curve parameters, or CKA_VALUE_LEN for secret keys.
	switch obj.KeyType {
	case "RSA":
		if v, ok := sess.AttrBytes(h, pkcs11.CKA_MODULUS); ok {
			obj.KeyBits = rsaBitsFromModulus(v)
			obj.PublicKeyFingerprint = fingerprint(normalizeBig(v))
		}
	case "EC":
		if v, ok := sess.AttrBytes(h, pkcs11.CKA_EC_PARAMS); ok {
			obj.Curve, obj.KeyBits = curveFromECParams(v)
		}
		if v, ok := sess.AttrBytes(h, pkcs11.CKA_EC_POINT); ok {
			obj.PublicKeyFingerprint = fingerprint(ecPointBytes(v))
		}
	default:
		if v, ok := sess.AttrUint(h, pkcs11.CKA_VALUE_LEN); ok {
			obj.KeyBits = v * 8
		}
	}

	switch obj.Class {
	case ClassPrivateKey:
		obj.Sensitive = attrBoolPtr(sess, h, pkcs11.CKA_SENSITIVE)
		obj.Extractable = attrBoolPtr(sess, h, pkcs11.CKA_EXTRACTABLE)
		obj.AlwaysSensitive = attrBoolPtr(sess, h, pkcs11.CKA_ALWAYS_SENSITIVE)
		obj.NeverExtractable = attrBoolPtr(sess, h, pkcs11.CKA_NEVER_EXTRACTABLE)
		obj.Sign = attrBoolPtr(sess, h, pkcs11.CKA_SIGN)
		obj.Decrypt = attrBoolPtr(sess, h, pkcs11.CKA_DECRYPT)
		obj.Unwrap = attrBoolPtr(sess, h, pkcs11.CKA_UNWRAP)
		obj.Derive = attrBoolPtr(sess, h, pkcs11.CKA_DERIVE)
	case ClassPublicKey:
		obj.Verify = attrBoolPtr(sess, h, pkcs11.CKA_VERIFY)
		obj.Encrypt = attrBoolPtr(sess, h, pkcs11.CKA_ENCRYPT)
		obj.Wrap = attrBoolPtr(sess, h, pkcs11.CKA_WRAP)
		obj.Derive = attrBoolPtr(sess, h, pkcs11.CKA_DERIVE)
	case ClassSecretKey:
		obj.Sensitive = attrBoolPtr(sess, h, pkcs11.CKA_SENSITIVE)
		obj.Extractable = attrBoolPtr(sess, h, pkcs11.CKA_EXTRACTABLE)
		obj.AlwaysSensitive = attrBoolPtr(sess, h, pkcs11.CKA_ALWAYS_SENSITIVE)
		obj.NeverExtractable = attrBoolPtr(sess, h, pkcs11.CKA_NEVER_EXTRACTABLE)
		obj.Sign = attrBoolPtr(sess, h, pkcs11.CKA_SIGN)
		obj.Verify = attrBoolPtr(sess, h, pkcs11.CKA_VERIFY)
		obj.Encrypt = attrBoolPtr(sess, h, pkcs11.CKA_ENCRYPT)
		obj.Decrypt = attrBoolPtr(sess, h, pkcs11.CKA_DECRYPT)
		obj.Wrap = attrBoolPtr(sess, h, pkcs11.CKA_WRAP)
		obj.Unwrap = attrBoolPtr(sess, h, pkcs11.CKA_UNWRAP)
	}
}

func collectCertAttrs(sess *p11.Session, h pkcs11.ObjectHandle, obj *Object) {
	der, ok := sess.AttrBytes(h, pkcs11.CKA_VALUE)
	if !ok || len(der) == 0 {
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Not fatal: some tokens store non-X.509 certificate objects.
		return
	}
	obj.Certificate = ParseCert(cert)
}

// ParseCert converts an x509 certificate into the report-friendly CertInfo.
func ParseCert(cert *x509.Certificate) *CertInfo {
	return &CertInfo{
		Subject:              cert.Subject.String(),
		Issuer:               cert.Issuer.String(),
		SerialNumber:         cert.SerialNumber.Text(16),
		NotBefore:            cert.NotBefore.UTC(),
		NotAfter:             cert.NotAfter.UTC(),
		SignatureAlgorithm:   cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:   cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:        certPublicKeyBits(cert.PublicKey),
		IsCA:                 cert.IsCA,
		SelfSigned:           cert.Subject.String() == cert.Issuer.String(),
		KeyUsage:             keyUsageNames(cert.KeyUsage),
		PublicKeyFingerprint: publicKeyFingerprint(cert.PublicKey),
		Raw:                  cert.Raw,
	}
}

// fingerprint is a hex SHA-256 of the given bytes ("" for empty input).
func fingerprint(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// normalizeBig strips leading zero bytes so the same integer hashes equally
// regardless of a leading-zero prefix.
func normalizeBig(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// ecPointBytes unwraps a CKA_EC_POINT (a DER OCTET STRING around the ANSI
// X9.62 point); it falls back to the raw bytes when not DER-wrapped.
func ecPointBytes(v []byte) []byte {
	var raw []byte
	if _, err := asn1.Unmarshal(v, &raw); err == nil && len(raw) > 0 {
		return raw
	}
	return v
}

// publicKeyFingerprint fingerprints a certificate's public key using the same
// material (RSA modulus / EC point) that the token key attributes expose.
func publicKeyFingerprint(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fingerprint(normalizeBig(k.N.Bytes()))
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		k.X.FillBytes(point[1 : 1+size])
		k.Y.FillBytes(point[1+size:])
		return fingerprint(point)
	}
	return ""
}

// certPublicKeyBits returns the security size of a certificate's public key:
// RSA modulus length, EC curve bit size, or 256 for Ed25519.
func certPublicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// keyUsageNames decodes an X.509 key-usage bitmask into its named flags.
func keyUsageNames(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var out []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func attrBoolPtr(sess *p11.Session, h pkcs11.ObjectHandle, typ uint) *bool {
	if v, ok := sess.AttrBool(h, typ); ok {
		return &v
	}
	return nil
}
