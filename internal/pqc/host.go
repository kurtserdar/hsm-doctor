package pqc

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// HostOpenSSL reports the PQC capabilities of the host's OpenSSL
// installation. HSM migration usually requires host tooling to follow.
type HostOpenSSL struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	MLKEM     bool   `json:"ml_kem"`
	MLDSA     bool   `json:"ml_dsa"`
	SLHDSA    bool   `json:"slh_dsa"`
}

// CheckHostOpenSSL probes the local openssl binary. Every invocation is
// bounded by a short timeout; a missing or broken openssl yields
// Available=false rather than an error.
func CheckHostOpenSSL(ctx context.Context) *HostOpenSSL {
	h := &HostOpenSSL{}

	version, err := runOpenSSL(ctx, "version")
	if err != nil {
		return h
	}
	h.Available = true
	h.Version = strings.TrimSpace(version)

	// OpenSSL 3.5+ ships native ML-KEM, ML-DSA and SLH-DSA; earlier
	// versions may provide them via providers (e.g. oqs-provider), which
	// the list commands also reflect.
	if out, err := runOpenSSL(ctx, "list", "-kem-algorithms"); err == nil {
		h.MLKEM = strings.Contains(out, "ML-KEM")
	}
	if out, err := runOpenSSL(ctx, "list", "-signature-algorithms"); err == nil {
		h.MLDSA = strings.Contains(out, "ML-DSA")
		h.SLHDSA = strings.Contains(out, "SLH-DSA")
	}
	return h
}

func runOpenSSL(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "openssl", args...).Output()
	return string(out), err
}
