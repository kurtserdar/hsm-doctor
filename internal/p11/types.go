// Package p11 is a thin, diagnostics-oriented wrapper around the miekg/pkcs11
// bindings. It exposes module, slot, token and mechanism information as plain
// data structures and provides safe session helpers for the higher layers.
//
// The wrapper never reads private key material: only public metadata
// attributes are ever requested from tokens.
package p11

import "fmt"

// ModuleInfo describes a loaded PKCS#11 library.
type ModuleInfo struct {
	Path            string `json:"path"`
	CryptokiVersion string `json:"cryptoki_version"`
	Manufacturer    string `json:"manufacturer"`
	Description     string `json:"description"`
	LibraryVersion  string `json:"library_version"`
}

// TokenInfo describes a token present in a slot.
type TokenInfo struct {
	Label           string `json:"label"`
	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	SerialNumber    string `json:"serial_number"`
	HardwareVersion string `json:"hardware_version"`
	FirmwareVersion string `json:"firmware_version"`
	Initialized     bool   `json:"initialized"`
	LoginRequired   bool   `json:"login_required"`
}

// SlotInfo describes a PKCS#11 slot and, when present, its token.
type SlotInfo struct {
	ID           uint       `json:"id"`
	Description  string     `json:"description"`
	Manufacturer string     `json:"manufacturer"`
	TokenPresent bool       `json:"token_present"`
	Token        *TokenInfo `json:"token,omitempty"`
}

// TokenLabel returns the token's label, or a placeholder when the slot has
// no token.
func (s SlotInfo) TokenLabel() string {
	if s.Token != nil {
		return s.Token.Label
	}
	return "(no token)"
}

// Mechanism describes a single mechanism supported by a token.
type Mechanism struct {
	Code       uint     `json:"code"`
	Name       string   `json:"name"`
	MinKeySize uint     `json:"min_key_size,omitempty"`
	MaxKeySize uint     `json:"max_key_size,omitempty"`
	Flags      []string `json:"flags,omitempty"`
	Hardware   bool     `json:"hardware"`
}

// supplementalMechanismNames names mechanisms standardized after the
// PKCS#11 v2.40 constant set the generated table is built from (values from
// the OASIS 3.02 header). Consulted only when the generated table has no
// entry, so a future regeneration from newer headers wins automatically.
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

// MechanismName returns the canonical CKM_* name for a mechanism code, or a
// formatted fallback for vendor-defined and unknown codes.
func MechanismName(code uint) string {
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

// ReturnCodeName returns the canonical CKR_* name for a PKCS#11 return value,
// or a formatted fallback for vendor-defined and unknown codes.
func ReturnCodeName(code uint) string {
	if name, ok := returnCodeNames[code]; ok {
		return name
	}
	if code >= 0x80000000 {
		return fmt.Sprintf("CKR_VENDOR_DEFINED_0x%08X", code)
	}
	return fmt.Sprintf("CKR_UNKNOWN_0x%08X", code)
}
