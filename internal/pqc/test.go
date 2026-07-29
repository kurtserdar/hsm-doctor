package pqc

import (
	"bytes"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/miekg/pkcs11"
)

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
// trip per parameter set, ML-KEM gets key generation (encapsulation is not
// reachable through the current wrapper).
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

	var results []SetResult
	for _, f := range Families {
		if !advertised[f.Name] {
			continue
		}
		for _, set := range f.Sets {
			results = append(results, testSet(sess, f, set))
		}
	}
	return results, nil
}

func testSet(sess *p11.Session, f Family, set ParamSet) SetResult {
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
		// KEM keys derive shared secrets.
		privTmpl = append(privTmpl, pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true))
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
		res.Status = TestKeyGenOnly
		res.Detail = "encapsulation requires C_EncapsulateKey (PKCS#11 3.2), not available in the wrapper yet"
		return res
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
