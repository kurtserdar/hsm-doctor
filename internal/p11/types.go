// Package p11 is a thin, diagnostics-oriented wrapper around the miekg/pkcs11
// bindings. It exposes module, slot, token and mechanism information as plain
// data structures and provides safe session helpers for the higher layers.
//
// The wrapper never reads private key material: only public metadata
// attributes are ever requested from tokens.
package p11

import "github.com/kurtserdar/hsm-doctor/internal/p11names"

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
	// MaxSessionCount and SessionCount come from CK_TOKEN_INFO. A max of 0
	// means "effectively unlimited" and a max of CK_UNAVAILABLE_INFORMATION
	// means the token does not report it; callers should treat both as
	// "no meaningful session cap".
	MaxSessionCount uint `json:"max_session_count,omitempty"`
	SessionCount    uint `json:"session_count,omitempty"`
}

// sessionInfoUnavailable is CK_UNAVAILABLE_INFORMATION: a token uses it when
// it cannot or will not report a count.
const sessionInfoUnavailable = ^uint(0)

// SessionCapacity returns the number of additional sessions the token can
// still open and whether that figure is meaningful. It is not meaningful when
// the token advertises no limit (max 0) or does not report the counts.
func (t *TokenInfo) SessionCapacity() (free uint, known bool) {
	if t.MaxSessionCount == 0 || t.MaxSessionCount == sessionInfoUnavailable ||
		t.SessionCount == sessionInfoUnavailable {
		return 0, false
	}
	if t.SessionCount >= t.MaxSessionCount {
		return 0, true
	}
	return t.MaxSessionCount - t.SessionCount, true
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

// MechanismName returns the canonical CKM_* name for a mechanism code.
func MechanismName(code uint) string { return p11names.Mechanism(code) }

// ReturnCodeName returns the canonical CKR_* name for a PKCS#11 return value.
func ReturnCodeName(code uint) string { return p11names.ReturnCode(code) }
