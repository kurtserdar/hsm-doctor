//go:build integration

package preflight_test

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/preflight"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

// CKM_RSA_PKCS_KEY_PAIR_GEN — supported by SoftHSM, the mechanism a renewal
// would need to generate a fresh RSA key pair.
const ckmRSAKeyPairGen = 0x00000000

func TestPreflightReadyAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	res, err := preflight.Run(client, slot, testutil.UserPIN, preflight.Options{
		RequiredMechanisms: []uint{ckmRSAKeyPairGen},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Ready {
		t.Fatalf("expected ready, got postpone: %v", res.Reasons)
	}
}

func TestPreflightProbeAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	res, err := preflight.Run(client, slot, testutil.UserPIN, preflight.Options{Probe: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Ready {
		t.Fatalf("probe should pass on SoftHSM: %v", res.Reasons)
	}
	// A large session-capacity request must not fail when the token reports no
	// limit (SoftHSM); it degrades to a warning.
	res, _ = preflight.Run(client, slot, testutil.UserPIN, preflight.Options{MinFreeSessions: 1_000_000})
	if !res.Ready {
		t.Errorf("unknown session limit must warn, not postpone: %v", res.Reasons)
	}
}

func TestPreflightMissingMechanismPostpones(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	// A vendor-defined code SoftHSM does not advertise.
	res, err := preflight.Run(client, slot, testutil.UserPIN, preflight.Options{
		RequiredMechanisms: []uint{0x80001234},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Ready {
		t.Error("a missing required mechanism must postpone")
	}
}

func TestPreflightWrongPINPostpones(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	res, err := preflight.Run(client, slot, "0000", preflight.Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Ready {
		t.Error("a failed login must postpone")
	}
}
