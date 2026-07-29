//go:build integration

package inventory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

func TestCollectAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{
		Label: "rsa-extractable", ID: []byte{0x01}, Bits: 2048,
		Extractable: true, Sensitive: false,
	})
	testutil.GenerateECKeyPair(t, sess, "ec-signing", []byte{0x02})
	testutil.GenerateAESKey(t, sess, "aes-storage", []byte{0x03}, 32)
	testutil.ImportSelfSignedCert(t, sess, "expired-cert", []byte{0x04}, "expired.test",
		time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	sess.Close()

	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	c := inv.Count()
	if c.PrivateKeys != 2 || c.PublicKeys != 2 || c.SecretKeys != 1 || c.Certificates != 1 {
		t.Fatalf("unexpected counts: %+v", c)
	}
	if !inv.LoggedIn {
		t.Error("inventory should record the logged-in state")
	}
	if len(inv.Mechanisms) == 0 {
		t.Error("expected a non-empty mechanism list")
	}

	byLabel := map[string]inventory.Object{}
	for _, o := range inv.Objects {
		if o.Class == inventory.ClassPrivateKey || o.Class == inventory.ClassSecretKey || o.Class == inventory.ClassCertificate {
			byLabel[o.Label+"/"+o.Class] = o
		}
	}

	rsa := byLabel["rsa-extractable/"+inventory.ClassPrivateKey]
	if rsa.KeyType != "RSA" || rsa.KeyBits != 2048 {
		t.Errorf("RSA private key: type=%s bits=%d", rsa.KeyType, rsa.KeyBits)
	}
	if rsa.Extractable == nil || !*rsa.Extractable {
		t.Error("RSA private key should be extractable")
	}
	if rsa.Sensitive == nil || *rsa.Sensitive {
		t.Error("RSA private key should be non-sensitive")
	}
	if rsa.ID != "01" {
		t.Errorf("RSA private key ID: %q", rsa.ID)
	}

	ec := byLabel["ec-signing/"+inventory.ClassPrivateKey]
	if ec.KeyType != "EC" || ec.Curve != "P-256" || ec.KeyBits != 256 {
		t.Errorf("EC private key: type=%s curve=%s bits=%d", ec.KeyType, ec.Curve, ec.KeyBits)
	}

	aes := byLabel["aes-storage/"+inventory.ClassSecretKey]
	if aes.KeyType != "AES" || aes.KeyBits != 256 {
		t.Errorf("AES key: type=%s bits=%d", aes.KeyType, aes.KeyBits)
	}

	cert := byLabel["expired-cert/"+inventory.ClassCertificate]
	if cert.Certificate == nil {
		t.Fatal("certificate object should carry parsed X.509 details")
	}
	if !strings.Contains(cert.Certificate.Subject, "expired.test") {
		t.Errorf("certificate subject: %q", cert.Certificate.Subject)
	}
	if !cert.Certificate.NotAfter.Before(time.Now()) {
		t.Error("certificate should be expired")
	}
}

func TestCollectWithoutLogin(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{
		Label: "rsa-hidden", ID: []byte{0x01}, Bits: 2048, Sensitive: true,
	})
	sess.Close()

	inv, err := inventory.Collect(client, slot, "")
	if err != nil {
		t.Fatalf("Collect without login: %v", err)
	}
	if inv.LoggedIn {
		t.Error("anonymous inventory must not be marked as logged in")
	}
	// Private objects must be invisible without a user session.
	if c := inv.Count(); c.PrivateKeys != 0 {
		t.Errorf("anonymous scan should not see private keys, got %d", c.PrivateKeys)
	}
}
