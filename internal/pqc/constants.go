// Package pqc assesses post-quantum readiness: which NIST PQC algorithm
// families a token supports, how exposed the existing inventory is to a
// future quantum adversary, and whether the host tooling is ready.
package pqc

// PKCS#11 3.2 post-quantum constants, taken verbatim from the official
// OASIS header (oasis-tcs/pkcs11, published/3-02/pkcs11t.h). These are not
// in the miekg/pkcs11 v2.40 constant set, so they are curated here.
const (
	// Key types.
	CKK_ML_KEM  = 0x00000049
	CKK_ML_DSA  = 0x0000004a
	CKK_SLH_DSA = 0x0000004b

	// Mechanisms.
	CKM_ML_KEM_KEY_PAIR_GEN  = 0x0000000f
	CKM_ML_KEM               = 0x00000017
	CKM_ML_DSA_KEY_PAIR_GEN  = 0x0000001c
	CKM_ML_DSA               = 0x0000001d
	CKM_HASH_ML_DSA          = 0x0000001f
	CKM_SLH_DSA_KEY_PAIR_GEN = 0x0000002d
	CKM_SLH_DSA              = 0x0000002e
	CKM_HASH_SLH_DSA         = 0x00000034

	// Attributes.
	CKA_PARAMETER_SET = 0x0000061d

	// ML-DSA parameter set values (CKA_PARAMETER_SET).
	CKP_ML_DSA_44 = 0x00000001
	CKP_ML_DSA_65 = 0x00000002
	CKP_ML_DSA_87 = 0x00000003

	// ML-KEM parameter set values.
	CKP_ML_KEM_512  = 0x00000001
	CKP_ML_KEM_768  = 0x00000002
	CKP_ML_KEM_1024 = 0x00000003

	// SLH-DSA parameter set values.
	CKP_SLH_DSA_SHA2_128S  = 0x00000001
	CKP_SLH_DSA_SHAKE_128S = 0x00000002
	CKP_SLH_DSA_SHA2_128F  = 0x00000003
	CKP_SLH_DSA_SHAKE_128F = 0x00000004
	CKP_SLH_DSA_SHA2_192S  = 0x00000005
	CKP_SLH_DSA_SHAKE_192S = 0x00000006
	CKP_SLH_DSA_SHA2_192F  = 0x00000007
	CKP_SLH_DSA_SHAKE_192F = 0x00000008
	CKP_SLH_DSA_SHA2_256S  = 0x00000009
	CKP_SLH_DSA_SHAKE_256S = 0x0000000a
	CKP_SLH_DSA_SHA2_256F  = 0x0000000b
	CKP_SLH_DSA_SHAKE_256F = 0x0000000c
)

// ParamSet is one parameter set of a PQC family.
type ParamSet struct {
	Name  string `json:"name"`
	Value uint   `json:"value"`
}

// Family describes one NIST PQC algorithm family.
type Family struct {
	Name    string // "ML-KEM", "ML-DSA", "SLH-DSA"
	Kind    string // "kem" or "signature"
	FIPS    string // the FIPS standard defining it
	KeyGen  uint   // key pair generation mechanism
	Op      uint   // the base operation mechanism (sign or encapsulate)
	Extra   []uint // additional mechanisms worth reporting (Hash* variants)
	Sets    []ParamSet
	KeyType uint // CKK_* value for inventory matching
}

// Families lists the three standardized NIST PQC families.
var Families = []Family{
	{
		Name: "ML-KEM", Kind: "kem", FIPS: "FIPS 203",
		KeyGen: CKM_ML_KEM_KEY_PAIR_GEN, Op: CKM_ML_KEM,
		KeyType: CKK_ML_KEM,
		Sets: []ParamSet{
			{"ML-KEM-512", CKP_ML_KEM_512},
			{"ML-KEM-768", CKP_ML_KEM_768},
			{"ML-KEM-1024", CKP_ML_KEM_1024},
		},
	},
	{
		Name: "ML-DSA", Kind: "signature", FIPS: "FIPS 204",
		KeyGen: CKM_ML_DSA_KEY_PAIR_GEN, Op: CKM_ML_DSA,
		Extra:   []uint{CKM_HASH_ML_DSA},
		KeyType: CKK_ML_DSA,
		Sets: []ParamSet{
			{"ML-DSA-44", CKP_ML_DSA_44},
			{"ML-DSA-65", CKP_ML_DSA_65},
			{"ML-DSA-87", CKP_ML_DSA_87},
		},
	},
	{
		Name: "SLH-DSA", Kind: "signature", FIPS: "FIPS 205",
		KeyGen: CKM_SLH_DSA_KEY_PAIR_GEN, Op: CKM_SLH_DSA,
		Extra:   []uint{CKM_HASH_SLH_DSA},
		KeyType: CKK_SLH_DSA,
		Sets: []ParamSet{
			{"SLH-DSA-SHA2-128s", CKP_SLH_DSA_SHA2_128S},
			{"SLH-DSA-SHAKE-128s", CKP_SLH_DSA_SHAKE_128S},
			{"SLH-DSA-SHA2-128f", CKP_SLH_DSA_SHA2_128F},
			{"SLH-DSA-SHAKE-128f", CKP_SLH_DSA_SHAKE_128F},
			{"SLH-DSA-SHA2-192s", CKP_SLH_DSA_SHA2_192S},
			{"SLH-DSA-SHAKE-192s", CKP_SLH_DSA_SHAKE_192S},
			{"SLH-DSA-SHA2-192f", CKP_SLH_DSA_SHA2_192F},
			{"SLH-DSA-SHAKE-192f", CKP_SLH_DSA_SHAKE_192F},
			{"SLH-DSA-SHA2-256s", CKP_SLH_DSA_SHA2_256S},
			{"SLH-DSA-SHAKE-256s", CKP_SLH_DSA_SHAKE_256S},
			{"SLH-DSA-SHA2-256f", CKP_SLH_DSA_SHA2_256F},
			{"SLH-DSA-SHAKE-256f", CKP_SLH_DSA_SHAKE_256F},
		},
	},
}

// mechanismDisplayNames names the curated PQC mechanisms for reports.
var mechanismDisplayNames = map[uint]string{
	CKM_ML_KEM_KEY_PAIR_GEN:  "CKM_ML_KEM_KEY_PAIR_GEN",
	CKM_ML_KEM:               "CKM_ML_KEM",
	CKM_ML_DSA_KEY_PAIR_GEN:  "CKM_ML_DSA_KEY_PAIR_GEN",
	CKM_ML_DSA:               "CKM_ML_DSA",
	CKM_HASH_ML_DSA:          "CKM_HASH_ML_DSA",
	CKM_SLH_DSA_KEY_PAIR_GEN: "CKM_SLH_DSA_KEY_PAIR_GEN",
	CKM_SLH_DSA:              "CKM_SLH_DSA",
	CKM_HASH_SLH_DSA:         "CKM_HASH_SLH_DSA",
}
