package funtest

import (
	"bytes"
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

// runtime carries the session and tracks created objects for cleanup.
type runtime struct {
	sess    *p11.Session
	created []pkcs11.ObjectHandle
}

func (rt *runtime) track(handles ...pkcs11.ObjectHandle) {
	rt.created = append(rt.created, handles...)
}

// destroyAll removes every object the step created. Session objects would
// disappear with the session anyway; destroying them eagerly keeps the
// "no traces" promise even for long multi-step runs.
func (rt *runtime) destroyAll() {
	ctx, h := rt.sess.Raw()
	for _, obj := range rt.created {
		_ = ctx.DestroyObject(h, obj)
	}
	rt.created = nil
}

// oidP256 is the DER-encoded OID of the NIST P-256 curve.
var oidP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// testPayload is the data signed and encrypted during tests.
var testPayload = []byte("hsmdoctor functional test payload")

// sessionKeyPair generates an ephemeral key pair (CKA_TOKEN=false).
func (rt *runtime) sessionKeyPair(mech uint, pubTmpl, privTmpl []*pkcs11.Attribute) (pub, priv pkcs11.ObjectHandle, err error) {
	ctx, h := rt.sess.Raw()
	common := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-funtest"),
	}
	pub, priv, err = ctx.GenerateKeyPair(h,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)},
		append(common, pubTmpl...), append(common, privTmpl...))
	if err == nil {
		rt.track(pub, priv)
	}
	return pub, priv, err
}

func (rt *runtime) signVerify(mech *pkcs11.Mechanism, priv, pub pkcs11.ObjectHandle, data []byte) error {
	ctx, h := rt.sess.Raw()
	if err := ctx.SignInit(h, []*pkcs11.Mechanism{mech}, priv); err != nil {
		return fmt.Errorf("C_SignInit: %w", err)
	}
	sig, err := ctx.Sign(h, data)
	if err != nil {
		return fmt.Errorf("C_Sign: %w", err)
	}
	if err := ctx.VerifyInit(h, []*pkcs11.Mechanism{mech}, pub); err != nil {
		return fmt.Errorf("C_VerifyInit: %w", err)
	}
	if err := ctx.Verify(h, data, sig); err != nil {
		return fmt.Errorf("C_Verify: %w", err)
	}
	return nil
}

var rsaKeyPairSteps = struct {
	pub  []*pkcs11.Attribute
	priv []*pkcs11.Attribute
}{
	pub: []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	},
	priv: []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	},
}

// rsaPair generates the RSA-2048 session key pair used by several steps.
// Each step regenerates its own pair to stay independent.
func (rt *runtime) rsaPair() (pub, priv pkcs11.ObjectHandle, err error) {
	return rt.sessionKeyPair(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, rsaKeyPairSteps.pub, rsaKeyPairSteps.priv)
}

var signVerifyProfile = &profile{
	name:        "sign-verify",
	description: "Key generation, signing and encryption smoke test with ephemeral session objects",
	steps: []step{
		{
			name:  "RSA-2048 generate",
			needs: []uint{pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN},
			run: func(rt *runtime) error {
				_, _, err := rt.rsaPair()
				return err
			},
		},
		{
			name:  "SHA256-RSA sign/verify",
			needs: []uint{pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11.CKM_SHA256_RSA_PKCS},
			run: func(rt *runtime) error {
				pub, priv, err := rt.rsaPair()
				if err != nil {
					return err
				}
				mech := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)
				return rt.signVerify(mech, priv, pub, testPayload)
			},
		},
		{
			name:  "RSA-PSS (SHA256) sign/verify",
			needs: []uint{pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11.CKM_SHA256_RSA_PKCS_PSS},
			run: func(rt *runtime) error {
				pub, priv, err := rt.rsaPair()
				if err != nil {
					return err
				}
				params := pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32)
				mech := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS_PSS, params)
				return rt.signVerify(mech, priv, pub, testPayload)
			},
		},
		{
			name:  "ECDSA P-256 sign/verify",
			needs: []uint{pkcs11.CKM_EC_KEY_PAIR_GEN, pkcs11.CKM_ECDSA},
			run: func(rt *runtime) error {
				pub, priv, err := rt.sessionKeyPair(pkcs11.CKM_EC_KEY_PAIR_GEN,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
						pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidP256),
					},
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
						pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
						pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
					})
				if err != nil {
					return err
				}
				// CKM_ECDSA signs a raw digest; use a 32-byte value.
				digest := bytes.Repeat([]byte{0x5a}, 32)
				return rt.signVerify(pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), priv, pub, digest)
			},
		},
		{
			name:  "AES-256 generate",
			needs: []uint{pkcs11.CKM_AES_KEY_GEN},
			run: func(rt *runtime) error {
				_, err := rt.aesKey()
				return err
			},
		},
		{
			name:  "AES-GCM encrypt/decrypt",
			needs: []uint{pkcs11.CKM_AES_KEY_GEN, pkcs11.CKM_AES_GCM},
			run: func(rt *runtime) error {
				key, err := rt.aesKey()
				if err != nil {
					return err
				}
				ctx, h := rt.sess.Raw()
				iv := bytes.Repeat([]byte{0x01}, 12)

				encParams := pkcs11.NewGCMParams(iv, nil, 128)
				defer encParams.Free()
				if err := ctx.EncryptInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, encParams)}, key); err != nil {
					return fmt.Errorf("C_EncryptInit: %w", err)
				}
				ciphertext, err := ctx.Encrypt(h, testPayload)
				if err != nil {
					return fmt.Errorf("C_Encrypt: %w", err)
				}

				// Some implementations generate their own IV and expose it
				// via the params after C_Encrypt.
				decIV := encParams.IV()
				if len(decIV) == 0 {
					decIV = iv
				}
				decParams := pkcs11.NewGCMParams(decIV, nil, 128)
				defer decParams.Free()
				if err := ctx.DecryptInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, decParams)}, key); err != nil {
					return fmt.Errorf("C_DecryptInit: %w", err)
				}
				plaintext, err := ctx.Decrypt(h, ciphertext)
				if err != nil {
					return fmt.Errorf("C_Decrypt: %w", err)
				}
				if !bytes.Equal(plaintext, testPayload) {
					return fmt.Errorf("decrypted payload does not match original")
				}
				return nil
			},
		},
	},
}

// aesKey generates an ephemeral AES-256 session key.
func (rt *runtime) aesKey() (pkcs11.ObjectHandle, error) {
	ctx, h := rt.sess.Raw()
	key, err := ctx.GenerateKey(h,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-funtest"),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})
	if err == nil {
		rt.track(key)
	}
	return key, err
}
