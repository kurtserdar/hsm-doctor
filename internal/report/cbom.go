package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// cbomSpecVersion is the CycloneDX version whose cryptographic-asset model we
// emit.
const cbomSpecVersion = "1.6"

// CBOM renders the token's cryptographic assets — keys, certificates and the
// algorithms behind them — as a CycloneDX 1.6 Cryptographic Bill of Materials.
// Each algorithm is annotated with its post-quantum standing, which is the
// main reason to keep a CBOM: planning the migration off quantum-vulnerable
// algorithms.
//
// Only assets that actually exist on the token are included (not the token's
// full mechanism capability list). Output is deterministic: no timestamp or
// serial number is emitted, so successive runs diff cleanly.
func (r *Report) CBOM(w io.Writer) error {
	b := &cbomBuilder{algoRefs: map[string]string{}}

	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cbomSpecVersion,
		Version:     1,
		Metadata: &cdxMetadata{
			Tools: &cdxTools{Components: []cdxComponent{{
				Type: "application", Name: "hsmdoctor", Version: r.Version,
			}}},
			Component: tokenComponent(r.Inventory),
		},
	}

	if r.Inventory != nil {
		// Keys first, so certificates can reference them by fingerprint.
		byFingerprint := map[string]string{}
		for _, o := range r.Inventory.Objects {
			ref := b.addKey(o)
			if ref != "" && o.PublicKeyFingerprint != "" {
				byFingerprint[o.PublicKeyFingerprint] = ref
			}
		}
		for _, o := range r.Inventory.Objects {
			if o.Certificate != nil {
				b.addCertificate(o, byFingerprint)
			}
		}
	}

	bom.Components = b.components
	bom.Dependencies = b.deps

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// cbomBuilder accumulates components and de-duplicates algorithm entries so a
// shared algorithm (e.g. RSA-2048) appears once and is referenced by every key
// and certificate that uses it.
type cbomBuilder struct {
	components []cdxComponent
	algoRefs   map[string]string // algorithm identity -> bom-ref
	deps       []cdxDependency
}

// addKey emits a related-crypto-material component for a key object and returns
// its bom-ref. Non-key objects (certificates) return "".
func (b *cbomBuilder) addKey(o inventory.Object) string {
	kind := keyMaterialType(o.Class)
	if kind == "" {
		return ""
	}
	ref := "key:" + o.Class + ":" + firstNonEmpty(o.ID, o.Label, strconv.Itoa(len(b.components)))
	algoRef := b.algorithm(o.KeyType, o.Curve, o.KeyBits)

	rcm := &cdxRelatedCryptoMaterialProps{
		Type:         kind,
		ID:           o.ID,
		AlgorithmRef: algoRef,
	}
	if o.KeyBits > 0 {
		rcm.Size = int(o.KeyBits)
	}
	// A non-extractable, hardware-resident key is secured by the HSM itself.
	if o.Extractable != nil && !*o.Extractable {
		rcm.SecuredBy = &cdxSecuredBy{Mechanism: "HSM"}
	}

	b.components = append(b.components, cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   firstNonEmpty(o.Label, o.ID, kind),
		CryptoProperties: &cdxCryptoProperties{
			AssetType:                       "related-crypto-material",
			RelatedCryptoMaterialProperties: rcm,
		},
	})
	if algoRef != "" {
		b.deps = append(b.deps, cdxDependency{Ref: ref, DependsOn: []string{algoRef}})
	}
	return ref
}

// addCertificate emits a certificate component and links it to its public key
// (by fingerprint, else a freshly registered algorithm) and its signature
// algorithm.
func (b *cbomBuilder) addCertificate(o inventory.Object, keysByFingerprint map[string]string) {
	c := o.Certificate
	ref := "certificate:" + firstNonEmpty(c.SerialNumber, o.ID, o.Label, strconv.Itoa(len(b.components)))

	cp := &cdxCertificateProperties{
		SubjectName:       c.Subject,
		IssuerName:        c.Issuer,
		CertificateFormat: "X.509",
	}
	if !c.NotBefore.IsZero() {
		cp.NotValidBefore = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		cp.NotValidAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}

	var dependsOn []string
	// Subject public key: prefer an existing key object on the token.
	if kref, ok := keysByFingerprint[c.PublicKeyFingerprint]; ok && c.PublicKeyFingerprint != "" {
		cp.SubjectPublicKeyRef = kref
		dependsOn = append(dependsOn, kref)
	} else if c.PublicKeyAlgorithm != "" {
		aref := b.algorithm(c.PublicKeyAlgorithm, "", uint(c.PublicKeyBits))
		cp.SubjectPublicKeyRef = aref
		dependsOn = append(dependsOn, aref)
	}
	// Signature algorithm.
	if c.SignatureAlgorithm != "" {
		sref := b.signatureAlgorithm(c.SignatureAlgorithm)
		cp.SignatureAlgorithmRef = sref
		dependsOn = append(dependsOn, sref)
	}

	b.components = append(b.components, cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   firstNonEmpty(certCommonName(c.Subject), c.Subject, "certificate"),
		CryptoProperties: &cdxCryptoProperties{
			AssetType:             "certificate",
			CertificateProperties: cp,
		},
	})
	if len(dependsOn) > 0 {
		b.deps = append(b.deps, cdxDependency{Ref: ref, DependsOn: dependsOn})
	}
}

// algorithm registers (once) an algorithm component for a key type and returns
// its bom-ref.
func (b *cbomBuilder) algorithm(keyType, curve string, bits uint) string {
	name, primitive, paramSet, qLevel, vulnerable := algoIdentity(keyType, curve, bits)
	if name == "" {
		return ""
	}
	if ref, ok := b.algoRefs[name]; ok {
		return ref
	}
	ref := "algorithm:" + name
	b.algoRefs[name] = ref

	props := &cdxAlgorithmProperties{
		Primitive:              primitive,
		ParameterSetIdentifier: paramSet,
		Curve:                  curve,
	}
	if qLevel > 0 {
		props.NISTQuantumSecurityLevel = qLevel
	}
	b.components = append(b.components, cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   name,
		CryptoProperties: &cdxCryptoProperties{
			AssetType:           "algorithm",
			AlgorithmProperties: props,
		},
		Properties: []cdxProperty{{
			Name:  "hsmdoctor:quantumVulnerable",
			Value: strconv.FormatBool(vulnerable),
		}},
	})
	return ref
}

// signatureAlgorithm registers (once) an algorithm component for an X.509
// signature algorithm string (e.g. "SHA256-RSA").
func (b *cbomBuilder) signatureAlgorithm(sigAlg string) string {
	if ref, ok := b.algoRefs[sigAlg]; ok {
		return ref
	}
	ref := "algorithm:" + sigAlg
	b.algoRefs[sigAlg] = ref
	b.components = append(b.components, cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   sigAlg,
		CryptoProperties: &cdxCryptoProperties{
			AssetType:           "algorithm",
			AlgorithmProperties: &cdxAlgorithmProperties{Primitive: "signature"},
		},
		Properties: []cdxProperty{{
			Name:  "hsmdoctor:quantumVulnerable",
			Value: strconv.FormatBool(sigAlgVulnerable(sigAlg)),
		}},
	})
	return ref
}

// tokenComponent describes the HSM/token that owns the assets.
func tokenComponent(inv *inventory.Inventory) *cdxComponent {
	if inv == nil || inv.Slot.Token == nil {
		return &cdxComponent{Type: "device", Name: "token"}
	}
	t := inv.Slot.Token
	comp := &cdxComponent{Type: "device", Name: firstNonEmpty(t.Label, "token")}
	if t.Model != "" {
		comp.Version = t.FirmwareVersion
	}
	var props []cdxProperty
	if t.SerialNumber != "" {
		props = append(props, cdxProperty{Name: "hsmdoctor:tokenSerial", Value: t.SerialNumber})
	}
	if t.Manufacturer != "" {
		props = append(props, cdxProperty{Name: "hsmdoctor:manufacturer", Value: t.Manufacturer})
	}
	if t.Model != "" {
		props = append(props, cdxProperty{Name: "hsmdoctor:model", Value: t.Model})
	}
	comp.Properties = props
	comp.BOMRef = "token:" + firstNonEmpty(t.SerialNumber, t.Label, "token")
	return comp
}

// keyMaterialType maps an inventory object class to the CycloneDX
// related-crypto-material type, or "" for non-key classes.
func keyMaterialType(class string) string {
	switch class {
	case inventory.ClassPrivateKey:
		return "private-key"
	case inventory.ClassPublicKey:
		return "public-key"
	case inventory.ClassSecretKey:
		return "secret-key"
	default:
		return ""
	}
}

// algoIdentity classifies a key type into a CycloneDX algorithm identity and
// its post-quantum standing. vulnerable is true for algorithms broken by a
// cryptographically relevant quantum computer (Shor); qLevel is the NIST
// quantum security level where meaningful (0 = not asserted).
func algoIdentity(keyType, curve string, bits uint) (name, primitive, paramSet string, qLevel int, vulnerable bool) {
	kt := strings.ToUpper(strings.TrimSpace(keyType))
	switch {
	case kt == "":
		return "", "", "", 0, false
	case kt == "RSA":
		name = "RSA"
		if bits > 0 {
			name = fmt.Sprintf("RSA-%d", bits)
			paramSet = strconv.Itoa(int(bits))
		}
		return name, "pke", paramSet, 0, true
	case kt == "EC" || kt == "ECDSA":
		name = "EC"
		if curve != "" {
			name = "EC-" + curve
		}
		return name, "signature", curve, 0, true
	case kt == "DSA":
		return "DSA", "signature", paramSetBits(bits), 0, true
	case kt == "DH":
		return "DH", "keyagree", paramSetBits(bits), 0, true
	case strings.HasPrefix(kt, "AES"):
		name = "AES"
		if bits > 0 {
			name = fmt.Sprintf("AES-%d", bits)
			paramSet = strconv.Itoa(int(bits))
		}
		return name, "blockcipher", paramSet, aesQuantumLevel(bits), false
	case strings.Contains(kt, "ML-DSA") || strings.Contains(kt, "ML_DSA"):
		return "ML-DSA", "signature", "", 0, false
	case strings.Contains(kt, "ML-KEM") || strings.Contains(kt, "ML_KEM"):
		return "ML-KEM", "kem", "", 0, false
	case strings.Contains(kt, "SLH-DSA") || strings.Contains(kt, "SLH_DSA"):
		return "SLH-DSA", "signature", "", 0, false
	case kt == "DES" || kt == "DES2" || kt == "DES3":
		return kt, "blockcipher", "", 0, false
	default:
		return kt, "unknown", "", 0, false
	}
}

// aesQuantumLevel maps an AES key size to its NIST quantum security level.
func aesQuantumLevel(bits uint) int {
	switch bits {
	case 128:
		return 1
	case 192:
		return 3
	case 256:
		return 5
	default:
		return 0
	}
}

// sigAlgVulnerable reports whether an X.509 signature algorithm relies on a
// quantum-vulnerable primitive.
func sigAlgVulnerable(sigAlg string) bool {
	s := strings.ToUpper(sigAlg)
	if strings.Contains(s, "ML-DSA") || strings.Contains(s, "SLH-DSA") {
		return false
	}
	// RSA, ECDSA, DSA and Ed25519 are all broken by Shor's algorithm.
	return strings.Contains(s, "RSA") || strings.Contains(s, "ECDSA") ||
		strings.Contains(s, "DSA") || strings.Contains(s, "ED25519") ||
		strings.Contains(s, "ED448")
}

func paramSetBits(bits uint) string {
	if bits == 0 {
		return ""
	}
	return strconv.Itoa(int(bits))
}

// certCommonName extracts the CN from an RFC 2253 subject string, if present.
func certCommonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:]
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
