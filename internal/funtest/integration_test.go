//go:build integration

package funtest_test

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

func TestSignVerifyProfileAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	res, err := funtest.Run(client, slot, testutil.UserPIN, "sign-verify")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Steps) == 0 {
		t.Fatal("profile produced no steps")
	}

	// SoftHSM supports every mechanism in the profile, so all steps must pass.
	for _, s := range res.Steps {
		if s.Status != funtest.StatusPass {
			t.Errorf("step %q: %s %s", s.Name, s.Status, s.Detail)
		}
	}

	// The ephemeral-objects promise: nothing may remain on the token.
	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect after test run: %v", err)
	}
	if len(inv.Objects) != 0 {
		t.Errorf("functional test left %d object(s) on the token: %+v", len(inv.Objects), inv.Objects)
	}
}

func TestUnknownProfile(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)
	if _, err := funtest.Run(client, slot, testutil.UserPIN, "no-such-profile"); err == nil {
		t.Error("unknown profile must return an error")
	}
}
