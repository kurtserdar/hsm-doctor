package inventory

import "testing"

func TestRSABitsFromModulus(t *testing.T) {
	// A realistic modulus starts with a non-zero byte; some tokens prepend
	// zero padding which must not change the reported size.
	mod2048 := make([]byte, 256)
	mod2048[0] = 0xC3
	cases := []struct {
		name string
		mod  []byte
		want uint
	}{
		{"exact 2048", mod2048, 2048},
		{"leading zero", append([]byte{0}, mod2048...), 2048},
		{"empty", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rsaBitsFromModulus(c.mod); got != c.want {
				t.Errorf("rsaBitsFromModulus() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestCurveFromECParams(t *testing.T) {
	p256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	name, bits := curveFromECParams(p256)
	if name != "P-256" || bits != 256 {
		t.Errorf("P-256 params: got (%s, %d)", name, bits)
	}

	name, bits = curveFromECParams([]byte{0x06, 0x01, 0x2a})
	if bits != 0 || name == "" {
		t.Errorf("unknown params should keep a hex name, got (%s, %d)", name, bits)
	}

	if name, bits := curveFromECParams(nil); name != "" || bits != 0 {
		t.Errorf("empty params: got (%s, %d)", name, bits)
	}
}

func TestKeyTypeName(t *testing.T) {
	if got := keyTypeName(0); got != "RSA" {
		t.Errorf("CKK_RSA: got %s", got)
	}
	if got := keyTypeName(0x99999999); got != "CKK_0x99999999" {
		t.Errorf("unknown key type: got %s", got)
	}
}

func TestCount(t *testing.T) {
	inv := &Inventory{Objects: []Object{
		{Class: ClassPrivateKey},
		{Class: ClassPrivateKey},
		{Class: ClassPublicKey},
		{Class: ClassSecretKey},
		{Class: ClassCertificate},
	}}
	c := inv.Count()
	if c.PrivateKeys != 2 || c.PublicKeys != 1 || c.SecretKeys != 1 || c.Certificates != 1 {
		t.Errorf("unexpected counts: %+v", c)
	}
}
