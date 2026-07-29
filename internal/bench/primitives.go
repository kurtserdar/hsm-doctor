package bench

import (
	"bytes"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

// primitive is one benchmarkable operation. setup creates the ephemeral
// session objects a worker needs and returns the operation closure plus a
// cleanup function.
type primitive struct {
	name  string
	needs []uint
	setup func(sess *p11.Session) (op func() error, cleanup func(), err error)
}

var (
	oidP256     = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	signPayload = bytes.Repeat([]byte{0xA5}, 32)
	gcmPayload  = bytes.Repeat([]byte{0x5A}, 1024)
	gcmIV       = bytes.Repeat([]byte{0x01}, 12)
)

var primitives = []primitive{
	{
		name:  "RSA-2048 sign (SHA256-RSA)",
		needs: []uint{pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11.CKM_SHA256_RSA_PKCS},
		setup: func(sess *p11.Session) (func() error, func(), error) {
			ctx, h := sess.Raw()
			pub, priv, err := ctx.GenerateKeyPair(h,
				[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-bench"),
					pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
					pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
					pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
				},
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-bench"),
					pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
					pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
					pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
				})
			if err != nil {
				return nil, func() {}, err
			}
			cleanup := func() {
				_ = ctx.DestroyObject(h, priv)
				_ = ctx.DestroyObject(h, pub)
			}
			op := func() error {
				if err := ctx.SignInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, priv); err != nil {
					return err
				}
				_, err := ctx.Sign(h, signPayload)
				return err
			}
			return op, cleanup, nil
		},
	},
	{
		name:  "ECDSA P-256 sign",
		needs: []uint{pkcs11.CKM_EC_KEY_PAIR_GEN, pkcs11.CKM_ECDSA},
		setup: func(sess *p11.Session) (func() error, func(), error) {
			ctx, h := sess.Raw()
			pub, priv, err := ctx.GenerateKeyPair(h,
				[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-bench"),
					pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
					pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidP256),
				},
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-bench"),
					pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
					pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
					pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
				})
			if err != nil {
				return nil, func() {}, err
			}
			cleanup := func() {
				_ = ctx.DestroyObject(h, priv)
				_ = ctx.DestroyObject(h, pub)
			}
			op := func() error {
				if err := ctx.SignInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, priv); err != nil {
					return err
				}
				_, err := ctx.Sign(h, signPayload)
				return err
			}
			return op, cleanup, nil
		},
	},
	{
		name:  "AES-256-GCM encrypt (1 KiB)",
		needs: []uint{pkcs11.CKM_AES_KEY_GEN, pkcs11.CKM_AES_GCM},
		setup: func(sess *p11.Session) (func() error, func(), error) {
			ctx, h := sess.Raw()
			key, err := ctx.GenerateKey(h,
				[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-bench"),
					pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
					pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
					pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
					pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
				})
			if err != nil {
				return nil, func() {}, err
			}
			cleanup := func() { _ = ctx.DestroyObject(h, key) }
			op := func() error {
				params := pkcs11.NewGCMParams(gcmIV, nil, 128)
				defer params.Free()
				if err := ctx.EncryptInit(h, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
					return err
				}
				_, err := ctx.Encrypt(h, gcmPayload)
				return err
			}
			return op, cleanup, nil
		},
	},
}
