package pqc

import (
	"bytes"
	"errors"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

// errKEMUnsupported means the module does not offer the PKCS#11 3.2
// C_EncapsulateKey/C_DecapsulateKey calls, so the KEM round trip cannot run.
var errKEMUnsupported = errors.New("KEM encapsulation not supported by the module")

// TestStatus is the outcome of one functional parameter-set test.
type TestStatus string

const (
	TestPass    TestStatus = "PASS"
	TestFail    TestStatus = "FAIL"
	TestSkipped TestStatus = "SKIPPED"
	// TestKeyGenOnly means key generation worked but the operation could
	// not be exercised (e.g. ML-KEM encapsulation needs the PKCS#11 3.2
	// C_EncapsulateKey call, which the underlying wrapper predates).
	TestKeyGenOnly TestStatus = "KEYGEN ONLY"
)

// SetResult is the functional test outcome for one parameter set.
type SetResult struct {
	Family string     `json:"family"`
	Set    string     `json:"set"`
	Status TestStatus `json:"status"`
	Detail string     `json:"detail,omitempty"`
}

var testMessage = []byte("hsmdoctor pqc functional probe")

// RunTests functionally probes every advertised family with ephemeral
// session objects: ML-DSA and SLH-DSA get a full keygen+sign+verify round
// trip per parameter set, and ML-KEM a full keygen+encapsulate+decapsulate
// round trip (via a cgo shim, since miekg predates C_EncapsulateKey). ML-KEM
// falls back to key generation only on modules without the PKCS#11 3.2 KEM
// interface, and on Windows / non-cgo builds.
func RunTests(client *p11.Client, slotID uint, pin string, det *Detection) ([]SetResult, error) {
	sess, err := client.OpenSession(slotID, pin, false)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	advertised := map[string]bool{}
	for _, f := range det.Families {
		advertised[f.Family] = f.Advertised
	}

	modulePath := client.Path()
	var results []SetResult
	for _, f := range Families {
		if !advertised[f.Name] {
			continue
		}
		for _, set := range f.Sets {
			results = append(results, testSet(sess, modulePath, f, set))
		}
	}
	return results, nil
}

func testSet(sess *p11.Session, modulePath string, f Family, set ParamSet) SetResult {
	res := SetResult{Family: f.Name, Set: set.Name}
	ctx, h := sess.Raw()

	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-pqc-probe"),
		pkcs11.NewAttribute(uint(CKA_PARAMETER_SET), set.Value),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "hsmdoctor-pqc-probe"),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	if f.Kind == "signature" {
		pubTmpl = append(pubTmpl, pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
		privTmpl = append(privTmpl, pkcs11.NewAttribute(pkcs11.CKA_SIGN, true))
	} else {
		// KEM keys encapsulate/decapsulate a shared secret (PKCS#11 3.2): the
		// public key must permit CKA_ENCAPSULATE, the private CKA_DECAPSULATE,
		// or C_EncapsulateKey/C_DecapsulateKey return CKR_KEY_FUNCTION_NOT_PERMITTED.
		pubTmpl = append(pubTmpl, pkcs11.NewAttribute(uint(CKA_ENCAPSULATE), true))
		privTmpl = append(privTmpl, pkcs11.NewAttribute(uint(CKA_DECAPSULATE), true))
	}

	pub, priv, err := ctx.GenerateKeyPair(h,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(uint(f.KeyGen), nil)},
		pubTmpl, privTmpl)
	if err != nil {
		res.Status = TestFail
		res.Detail = "key generation: " + err.Error()
		return res
	}
	defer func() {
		_ = ctx.DestroyObject(h, priv)
		_ = ctx.DestroyObject(h, pub)
	}()

	if f.Kind != "signature" {
		return testKEM(sess, modulePath, f, pub, priv, res)
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(uint(f.Op), nil)}
	if err := ctx.SignInit(h, mech, priv); err != nil {
		res.Status = TestFail
		res.Detail = "C_SignInit: " + err.Error()
		return res
	}
	sig, err := ctx.Sign(h, testMessage)
	if err != nil {
		res.Status = TestFail
		res.Detail = "C_Sign: " + err.Error()
		return res
	}
	if len(sig) == 0 || bytes.Equal(sig, testMessage) {
		res.Status = TestFail
		res.Detail = "implausible signature output"
		return res
	}
	if err := ctx.VerifyInit(h, mech, pub); err != nil {
		res.Status = TestFail
		res.Detail = "C_VerifyInit: " + err.Error()
		return res
	}
	if err := ctx.Verify(h, testMessage, sig); err != nil {
		res.Status = TestFail
		res.Detail = "C_Verify: " + err.Error()
		return res
	}
	res.Status = TestPass
	return res
}

// testKEM runs an ML-KEM encapsulate/decapsulate round trip on the freshly
// generated key pair and checks the two derived shared secrets match. The
// PKCS#11 3.2 C_EncapsulateKey/C_DecapsulateKey calls are reached through a
// small cgo shim (kemRoundTrip) that reuses this session; miekg predates them.
func testKEM(sess *p11.Session, modulePath string, f Family, pub, priv pkcs11.ObjectHandle, res SetResult) SetResult {
	ctx, h := sess.Raw()
	k1, k2, err := kemRoundTrip(modulePath, uint64(h), uint64(pub), uint64(priv), f.Op)
	if err != nil {
		if errors.Is(err, errKEMUnsupported) {
			res.Status = TestKeyGenOnly
			res.Detail = "key generation only: module offers no C_EncapsulateKey (PKCS#11 3.2)"
		} else {
			res.Status = TestFail
			res.Detail = "encapsulation: " + err.Error()
		}
		return res
	}
	o1, o2 := pkcs11.ObjectHandle(k1), pkcs11.ObjectHandle(k2)
	defer func() {
		_ = ctx.DestroyObject(h, o1)
		_ = ctx.DestroyObject(h, o2)
	}()

	v1, err := secretValue(ctx, h, o1)
	if err != nil {
		res.Status = TestFail
		res.Detail = "reading encapsulated secret: " + err.Error()
		return res
	}
	v2, err := secretValue(ctx, h, o2)
	if err != nil {
		res.Status = TestFail
		res.Detail = "reading decapsulated secret: " + err.Error()
		return res
	}
	if len(v1) == 0 || !bytes.Equal(v1, v2) {
		res.Status = TestFail
		res.Detail = "encapsulated and decapsulated shared secrets differ"
		return res
	}
	res.Status = TestPass
	res.Detail = "keygen + encapsulate/decapsulate; shared secrets match"
	return res
}

// secretValue reads a derived secret key's CKA_VALUE (the ephemeral test key is
// created non-sensitive and extractable so the probe can compare the secrets).
func secretValue(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle, key pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := ctx.GetAttributeValue(sess, key, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, errors.New("no CKA_VALUE returned")
	}
	return attrs[0].Value, nil
}
