package trace

import "sort"

// RecordableFunctions is the set of PKCS#11 functions the Flight Recorder shim
// instruments — the denominator for coverage. A function the shim does not wrap
// can never appear in a trace, so coverage is measured against what the
// recorder can actually observe, not the full PKCS#11 API.
//
// Keep this in sync with the wrappers in shim/shim.c; update both together.
var RecordableFunctions = []string{
	"C_Initialize", "C_Finalize", "C_GetInfo",
	"C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo",
	"C_GetMechanismList", "C_GetMechanismInfo",
	"C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
	"C_Login", "C_Logout",
	"C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
	"C_GetAttributeValue",
	"C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt",
	"C_DigestInit",
	"C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify",
	"C_GenerateKey", "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey",
	"C_GenerateRandom",
}

// FuncCoverage is one exercised function and how many times it was called.
type FuncCoverage struct {
	Function string `json:"function"`
	Calls    int    `json:"calls"`
}

// Coverage summarizes which recordable PKCS#11 functions a trace exercised.
type Coverage struct {
	Total    int            `json:"total"`   // size of the recordable universe
	Covered  int            `json:"covered"` // distinct recordable functions seen
	Percent  float64        `json:"percent"` // 0..100
	Exercise []FuncCoverage `json:"exercised_functions"`
	Missing  []string       `json:"missing_functions"`
	// Unexpected are functions present in the trace but not in the recordable
	// set — a signal that this list has drifted from the shim.
	Unexpected []string `json:"unexpected_functions,omitempty"`
}

// CoverageOf computes function coverage for a trace.
func CoverageOf(events []Event) *Coverage {
	recordable := make(map[string]bool, len(RecordableFunctions))
	for _, fn := range RecordableFunctions {
		recordable[fn] = true
	}

	counts := make(map[string]int)
	for _, e := range events {
		if e.Function != "" {
			counts[e.Function]++
		}
	}

	cov := &Coverage{Total: len(RecordableFunctions)}
	for _, fn := range RecordableFunctions {
		if n := counts[fn]; n > 0 {
			cov.Exercise = append(cov.Exercise, FuncCoverage{Function: fn, Calls: n})
		} else {
			cov.Missing = append(cov.Missing, fn)
		}
	}
	for fn := range counts {
		if !recordable[fn] {
			cov.Unexpected = append(cov.Unexpected, fn)
		}
	}

	sort.Slice(cov.Exercise, func(i, j int) bool { return cov.Exercise[i].Function < cov.Exercise[j].Function })
	sort.Strings(cov.Missing)
	sort.Strings(cov.Unexpected)

	cov.Covered = len(cov.Exercise)
	if cov.Total > 0 {
		cov.Percent = float64(cov.Covered) / float64(cov.Total) * 100
	}
	return cov
}
