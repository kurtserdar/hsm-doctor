// Package p11names resolves PKCS#11 numeric constants to their canonical
// CKM_*/CKR_* names. It holds only pure-Go lookup tables (no cgo), so it can
// be used from contexts that must not link the miekg/pkcs11 bindings — such
// as the c-shared trace shim.
package p11names

import (
	"fmt"
	"strconv"
	"strings"
)

// supplementalMechanismNames names mechanisms standardized after the
// PKCS#11 v2.40 constant set the generated table is built from (values from
// the OASIS 3.02 header). Consulted only when the generated table lacks an
// entry, so a future regeneration wins automatically.
var supplementalMechanismNames = map[uint]string{
	0x0000000f: "CKM_ML_KEM_KEY_PAIR_GEN",
	0x00000017: "CKM_ML_KEM",
	0x0000001c: "CKM_ML_DSA_KEY_PAIR_GEN",
	0x0000001d: "CKM_ML_DSA",
	0x0000001f: "CKM_HASH_ML_DSA",
	0x0000002d: "CKM_SLH_DSA_KEY_PAIR_GEN",
	0x0000002e: "CKM_SLH_DSA",
	0x00000034: "CKM_HASH_SLH_DSA",
}

// Mechanism returns the canonical CKM_* name for a mechanism code, or a
// formatted fallback for vendor-defined and unknown codes.
func Mechanism(code uint) string {
	if name, ok := mechanismNames[code]; ok {
		return name
	}
	if name, ok := supplementalMechanismNames[code]; ok {
		return name
	}
	if code >= 0x80000000 {
		return fmt.Sprintf("CKM_VENDOR_DEFINED_0x%08X", code)
	}
	return fmt.Sprintf("CKM_UNKNOWN_0x%08X", code)
}

// mechanismCodes is the reverse of the mechanism name tables, built lazily
// on first use so it costs nothing for the common code->name direction.
var mechanismCodes map[string]uint

// MechanismCode resolves a canonical CKM_* name (case-insensitive) to its
// numeric value. It also accepts a raw hexadecimal code ("0x00000001").
func MechanismCode(name string) (uint, bool) {
	if mechanismCodes == nil {
		mechanismCodes = make(map[string]uint, len(mechanismNames)+len(supplementalMechanismNames))
		for code, n := range mechanismNames {
			mechanismCodes[n] = code
		}
		for code, n := range supplementalMechanismNames {
			if _, ok := mechanismCodes[n]; !ok {
				mechanismCodes[n] = code
			}
		}
	}
	key := strings.ToUpper(strings.TrimSpace(name))
	if code, ok := mechanismCodes[key]; ok {
		return code, true
	}
	if strings.HasPrefix(key, "0X") {
		if v, err := strconv.ParseUint(key[2:], 16, 32); err == nil {
			return uint(v), true
		}
	}
	return 0, false
}

// ReturnCode returns the canonical CKR_* name for a return value, or a
// formatted fallback for vendor-defined and unknown codes.
func ReturnCode(code uint) string {
	if name, ok := returnCodeNames[code]; ok {
		return name
	}
	if code >= 0x80000000 {
		return fmt.Sprintf("CKR_VENDOR_DEFINED_0x%08X", code)
	}
	return fmt.Sprintf("CKR_UNKNOWN_0x%08X", code)
}
