package inventory

import "encoding/hex"

// namedCurve describes an elliptic curve identified by its DER-encoded OID
// as found in CKA_EC_PARAMS.
type namedCurve struct {
	Name string
	Bits uint
}

// knownCurves maps hex-encoded DER OIDs (the raw CKA_EC_PARAMS value) to
// curve names and sizes.
var knownCurves = map[string]namedCurve{
	"06052b81040021":         {"P-224", 224},
	"06082a8648ce3d030107":   {"P-256", 256},
	"06052b81040022":         {"P-384", 384},
	"06052b81040023":         {"P-521", 521},
	"06052b8104000a":         {"secp256k1", 256},
	"06032b6570":             {"Ed25519", 256},
	"06032b656e":             {"X25519", 256},
	"06092b2403030208010107": {"brainpoolP256r1", 256},
	"06092b240303020801010b": {"brainpoolP384r1", 384},
	"06092b240303020801010d": {"brainpoolP512r1", 512},
}

// curveFromECParams resolves CKA_EC_PARAMS bytes to a curve name and key
// size. Unknown parameter encodings are reported as a hex string so they
// remain visible in reports instead of silently disappearing.
func curveFromECParams(params []byte) (string, uint) {
	if len(params) == 0 {
		return "", 0
	}
	if c, ok := knownCurves[hex.EncodeToString(params)]; ok {
		return c.Name, c.Bits
	}
	return "unknown(" + hex.EncodeToString(params) + ")", 0
}

// rsaBitsFromModulus computes the RSA key size in bits from a CKA_MODULUS
// value, ignoring leading zero bytes some tokens include.
func rsaBitsFromModulus(modulus []byte) uint {
	i := 0
	for i < len(modulus) && modulus[i] == 0 {
		i++
	}
	return uint(len(modulus)-i) * 8
}
