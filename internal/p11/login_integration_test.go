//go:build integration

package p11_test

import (
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/miekg/pkcs11"
)

// TestLoginSurvivesSiblingSessionClose reproduces the concurrency bug where
// closing one authenticated session logged the whole token out (PKCS#11
// login state is per token), breaking other still-open sessions.
func TestLoginSurvivesSiblingSessionClose(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sessA, err := client.OpenSession(slot, testutil.UserPIN, false)
	if err != nil {
		t.Fatalf("opening session A: %v", err)
	}
	sessB, err := client.OpenSession(slot, testutil.UserPIN, false)
	if err != nil {
		sessA.Close()
		t.Fatalf("opening session B: %v", err)
	}
	defer sessB.Close()

	// Closing A must NOT log the token out while B still holds a login
	// reference.
	sessA.Close()

	// Creating a private session object requires an active login.
	ctx, h := sessB.Raw()
	key, err := ctx.GenerateKey(h,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		})
	if err != nil {
		t.Fatalf("session B lost its login after sibling close: %v", err)
	}
	_ = ctx.DestroyObject(h, key)

	// After the last authenticated session closes, the token must actually
	// be logged out again: a fresh anonymous session cannot create private
	// objects.
	sessB.Close()
	anon, err := client.OpenSession(slot, "", false)
	if err != nil {
		t.Fatalf("opening anonymous session: %v", err)
	}
	defer anon.Close()
	ctx2, h2 := anon.Raw()
	if _, err := ctx2.GenerateKey(h2,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		}); err == nil {
		t.Error("token still logged in after the last authenticated session closed")
	}
}
