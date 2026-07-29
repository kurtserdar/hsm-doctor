package pqc

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

// Verdict summarizes token-level PQC readiness.
type Verdict string

const (
	VerdictReady    Verdict = "READY"     // ML-KEM and ML-DSA both available
	VerdictPartial  Verdict = "PARTIAL"   // at least one family available
	VerdictNotReady Verdict = "NOT READY" // no PQC mechanisms at all
)

// FamilyStatus is the detection result for one algorithm family.
type FamilyStatus struct {
	Family     string   `json:"family"`
	Kind       string   `json:"kind"`
	FIPS       string   `json:"fips"`
	Advertised bool     `json:"advertised"`
	Mechanisms []string `json:"mechanisms,omitempty"`
	// KeyGenOnly is true when the token can generate keys but does not
	// advertise the operation mechanism (or vice versa) — a red flag worth
	// surfacing instead of a plain "no".
	Incomplete bool `json:"incomplete,omitempty"`
}

// Detection is the mechanism-level PQC picture of one token.
type Detection struct {
	CryptokiVersion string         `json:"cryptoki_version,omitempty"`
	Families        []FamilyStatus `json:"families"`
	// VendorDefined lists vendor-range mechanism codes advertised by the
	// token. Pre-standard PQC implementations live in this range, but the
	// codes are vendor-specific: consult vendor documentation.
	VendorDefined []string `json:"vendor_defined,omitempty"`
	Verdict       Verdict  `json:"verdict"`
}

// Detect analyzes a token's mechanism list. The caller supplies the
// mechanisms already collected during discovery or scan.
func Detect(mechs []p11.Mechanism) *Detection {
	available := map[uint]bool{}
	var vendor []string
	for _, m := range mechs {
		available[m.Code] = true
		if m.Code >= 0x80000000 {
			vendor = append(vendor, fmt.Sprintf("0x%08X", m.Code))
		}
	}

	d := &Detection{VendorDefined: vendor}
	for _, f := range Families {
		st := FamilyStatus{Family: f.Name, Kind: f.Kind, FIPS: f.FIPS}
		hasKeyGen := available[f.KeyGen]
		hasOp := available[f.Op]
		if hasKeyGen {
			st.Mechanisms = append(st.Mechanisms, mechanismDisplayNames[f.KeyGen])
		}
		if hasOp {
			st.Mechanisms = append(st.Mechanisms, mechanismDisplayNames[f.Op])
		}
		for _, extra := range f.Extra {
			if available[extra] {
				st.Mechanisms = append(st.Mechanisms, mechanismDisplayNames[extra])
			}
		}
		st.Advertised = hasKeyGen && hasOp
		st.Incomplete = (hasKeyGen || hasOp) && !st.Advertised
		d.Families = append(d.Families, st)
	}

	d.Verdict = verdict(d.Families)
	return d
}

func verdict(families []FamilyStatus) Verdict {
	byName := map[string]bool{}
	any := false
	for _, f := range families {
		byName[f.Family] = f.Advertised
		if f.Advertised {
			any = true
		}
	}
	switch {
	case byName["ML-KEM"] && byName["ML-DSA"]:
		return VerdictReady
	case any:
		return VerdictPartial
	default:
		return VerdictNotReady
	}
}
