package funtest

import (
	"bytes"
	"fmt"

	"github.com/miekg/pkcs11"
)

// aesSessionKey generates an ephemeral AES-256 key; extractable controls
// whether it may be wrapped out.
func (rt *runtime) aesSessionKey(label string, extractable bool) (pkcs11.ObjectHandle, error) {
	ctx, h := rt.sess.Raw()
	key, err := ctx.GenerateKey(h,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		})
	if err == nil {
		rt.track(key)
	}
	return key, err
}

// unwrapTemplate is the template for keys re-imported via C_UnwrapKey.
var unwrapTemplate = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-funtest-unwrapped"),
	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
}

// roundTrip proves the unwrapped key equals the original without reading
// key material: encrypt with the original, decrypt with the unwrapped copy.
func (rt *runtime) roundTrip(original, unwrapped pkcs11.ObjectHandle) error {
	ctx, h := rt.sess.Raw()
	iv := bytes.Repeat([]byte{0x02}, 12)

	encParams := pkcs11.NewGCMParams(iv, nil, 128)
	defer encParams.Free()
	if err := ctx.EncryptInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, encParams)}, original); err != nil {
		return fmt.Errorf("C_EncryptInit(original): %w", err)
	}
	ciphertext, err := ctx.Encrypt(h, testPayload)
	if err != nil {
		return fmt.Errorf("C_Encrypt(original): %w", err)
	}

	decIV := encParams.IV()
	if len(decIV) == 0 {
		decIV = iv
	}
	decParams := pkcs11.NewGCMParams(decIV, nil, 128)
	defer decParams.Free()
	if err := ctx.DecryptInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, decParams)}, unwrapped); err != nil {
		return fmt.Errorf("C_DecryptInit(unwrapped): %w", err)
	}
	plaintext, err := ctx.Decrypt(h, ciphertext)
	if err != nil {
		return fmt.Errorf("C_Decrypt(unwrapped): %w", err)
	}
	if !bytes.Equal(plaintext, testPayload) {
		return fmt.Errorf("unwrapped key does not decrypt to the original payload")
	}
	return nil
}

var keyWrappingProfile = &profile{
	name:        "key-wrapping",
	description: "Wrap/unwrap round trips with AES and RSA-OAEP key-encryption keys",
	steps: []step{
		{
			name:  "AES KEK generate",
			needs: []uint{pkcs11.CKM_AES_KEY_GEN},
			run: func(rt *runtime) error {
				_, err := rt.aesSessionKey("hsmdoctor-funtest-kek", false)
				return err
			},
		},
		{
			name:  "AES key wrap/unwrap (CKM_AES_KEY_WRAP)",
			needs: []uint{pkcs11.CKM_AES_KEY_GEN, pkcs11.CKM_AES_KEY_WRAP, pkcs11.CKM_AES_GCM},
			run: func(rt *runtime) error {
				ctx, h := rt.sess.Raw()
				kek, err := rt.aesSessionKey("hsmdoctor-funtest-kek", false)
				if err != nil {
					return err
				}
				target, err := rt.aesSessionKey("hsmdoctor-funtest-target", true)
				if err != nil {
					return err
				}
				mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}
				wrapped, err := ctx.WrapKey(h, mech, kek, target)
				if err != nil {
					return fmt.Errorf("C_WrapKey: %w", err)
				}
				unwrapped, err := ctx.UnwrapKey(h, mech, kek, wrapped, unwrapTemplate)
				if err != nil {
					return fmt.Errorf("C_UnwrapKey: %w", err)
				}
				rt.track(unwrapped)
				return rt.roundTrip(target, unwrapped)
			},
		},
		{
			name: "RSA-OAEP key wrap/unwrap",
			needs: []uint{pkcs11.CKM_AES_KEY_GEN, pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
				pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKM_AES_GCM},
			run: func(rt *runtime) error {
				ctx, h := rt.sess.Raw()
				pub, priv, err := rt.sessionKeyPair(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
						pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
						pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
					},
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
						pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
						pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
					})
				if err != nil {
					return err
				}
				target, err := rt.aesSessionKey("hsmdoctor-funtest-target", true)
				if err != nil {
					return err
				}
				// SHA-1 OAEP is used for maximum vendor interoperability;
				// this exercises the wrap path, it is not a posture
				// statement about SHA-1.
				params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1,
					pkcs11.CKZ_DATA_SPECIFIED, nil)
				mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
				wrapped, err := ctx.WrapKey(h, mech, pub, target)
				if err != nil {
					return fmt.Errorf("C_WrapKey: %w", err)
				}
				unwrapped, err := ctx.UnwrapKey(h, mech, priv, wrapped, unwrapTemplate)
				if err != nil {
					return fmt.Errorf("C_UnwrapKey: %w", err)
				}
				rt.track(unwrapped)
				return rt.roundTrip(target, unwrapped)
			},
		},
	},
}

func init() {
	profiles[keyWrappingProfile.name] = keyWrappingProfile
}
