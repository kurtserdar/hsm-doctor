package trace

import (
	"fmt"
	"sort"
	"time"
)

// Severity ranks analyzer findings.
type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
	SevInfo    Severity = "info"
)

// Finding is one issue the analyzer detected in a trace.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	// Seqs points at the offending events by sequence number.
	Seqs []uint64 `json:"seqs,omitempty"`
}

// FuncStat summarizes calls to one PKCS#11 function.
type FuncStat struct {
	Function string `json:"function"`
	Calls    int    `json:"calls"`
	Errors   int    `json:"errors"`
	TotalNS  int64  `json:"total_ns"`
	MaxNS    int64  `json:"max_ns"`
}

// Analysis is the full result of analyzing a trace.
type Analysis struct {
	Events   int        `json:"events"`
	Findings []Finding  `json:"findings"`
	Stats    []FuncStat `json:"stats"`
}

// slowCallThreshold flags individual calls taking longer than this.
const slowCallThreshold = 500 * time.Millisecond

// Analyze runs every detector over the events.
func Analyze(events []Event) *Analysis {
	a := &Analysis{Events: len(events)}
	a.Findings = append(a.Findings, checkInitialize(events)...)
	a.Findings = append(a.Findings, checkSessionLeaks(events)...)
	a.Findings = append(a.Findings, checkOperationPairs(events)...)
	a.Findings = append(a.Findings, checkLoginOrdering(events)...)
	a.Findings = append(a.Findings, checkErrors(events)...)
	a.Findings = append(a.Findings, checkSlowCalls(events)...)
	a.Stats = functionStats(events)

	sort.SliceStable(a.Findings, func(i, j int) bool {
		return sevRank(a.Findings[i].Severity) < sevRank(a.Findings[j].Severity)
	})
	return a
}

func sevRank(s Severity) int {
	switch s {
	case SevError:
		return 0
	case SevWarning:
		return 1
	default:
		return 2
	}
}

// checkInitialize verifies the library was initialized and finalized cleanly.
func checkInitialize(events []Event) []Finding {
	var findings []Finding
	init, final := 0, 0
	firstNonInitSeq := uint64(0)
	sawInit := false
	for _, e := range events {
		switch e.Function {
		case "C_Initialize":
			init++
			sawInit = true
		case "C_Finalize":
			final++
		default:
			if !sawInit && firstNonInitSeq == 0 {
				firstNonInitSeq = e.Seq
			}
		}
	}
	if init == 0 && len(events) > 0 {
		findings = append(findings, Finding{
			Check: "initialize", Severity: SevError,
			Message: "trace contains PKCS#11 calls but no C_Initialize",
			Seqs:    []uint64{firstNonInitSeq},
		})
	}
	if init > 0 && final == 0 {
		findings = append(findings, Finding{
			Check: "initialize", Severity: SevWarning,
			Message: "C_Initialize was never matched by C_Finalize (library not cleanly shut down)",
		})
	}
	return findings
}

// checkSessionLeaks pairs C_OpenSession with C_CloseSession.
func checkSessionLeaks(events []Event) []Finding {
	open := map[uint64]uint64{} // session handle -> opening seq
	var findings []Finding
	closedAll := false
	for _, e := range events {
		switch e.Function {
		case "C_OpenSession":
			if e.OK() && e.Session != nil {
				open[*e.Session] = e.Seq
			}
		case "C_CloseSession":
			if e.Session != nil {
				delete(open, *e.Session)
			}
		case "C_CloseAllSessions":
			closedAll = true
			open = map[uint64]uint64{}
		}
	}
	if closedAll {
		return findings
	}
	// Report leaked sessions deterministically (by opening seq).
	var leaked []uint64
	for _, seq := range open {
		leaked = append(leaked, seq)
	}
	sort.Slice(leaked, func(i, j int) bool { return leaked[i] < leaked[j] })
	for _, seq := range leaked {
		findings = append(findings, Finding{
			Check: "session-leak", Severity: SevWarning,
			Message: "session opened but never closed",
			Seqs:    []uint64{seq},
		})
	}
	return findings
}

// operationPairs maps an *Init function to the operation it must precede and
// the multi-part variant that also closes the operation state.
var operationPairs = []struct {
	initFn string
	ops    []string
}{
	{"C_FindObjectsInit", []string{"C_FindObjectsFinal"}},
	{"C_SignInit", []string{"C_Sign", "C_SignFinal"}},
	{"C_VerifyInit", []string{"C_Verify", "C_VerifyFinal"}},
	{"C_EncryptInit", []string{"C_Encrypt", "C_EncryptFinal"}},
	{"C_DecryptInit", []string{"C_Decrypt", "C_DecryptFinal"}},
	{"C_DigestInit", []string{"C_Digest", "C_DigestFinal"}},
}

// checkOperationPairs finds *Init calls with no terminating operation on the
// same session, a common source of "operation active" errors and leaks.
func checkOperationPairs(events []Event) []Finding {
	var findings []Finding
	for _, pair := range operationPairs {
		// pending: session handle -> seq of the dangling Init.
		pending := map[uint64]uint64{}
		terminators := map[string]bool{}
		for _, op := range pair.ops {
			terminators[op] = true
		}
		for _, e := range events {
			sess := uint64(0)
			if e.Session != nil {
				sess = *e.Session
			}
			switch {
			case e.Function == pair.initFn && e.OK():
				pending[sess] = e.Seq
			case terminators[e.Function]:
				delete(pending, sess)
			}
		}
		var seqs []uint64
		for _, seq := range pending {
			seqs = append(seqs, seq)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, seq := range seqs {
			findings = append(findings, Finding{
				Check: "operation-leak", Severity: SevWarning,
				Message: fmt.Sprintf("%s not followed by %v on the same session", pair.initFn, pair.ops),
				Seqs:    []uint64{seq},
			})
		}
	}
	return findings
}

// loginRequiring lists operations that need an authenticated session.
var loginRequiring = map[string]bool{
	"C_SignInit": true, "C_DecryptInit": true, "C_UnwrapKey": true,
	"C_GenerateKey": true, "C_GenerateKeyPair": true,
}

// checkLoginOrdering flags login-requiring operations that returned
// CKR_USER_NOT_LOGGED_IN, and operations attempted before any C_Login.
func checkLoginOrdering(events []Event) []Finding {
	var findings []Finding
	loggedIn := false
	for _, e := range events {
		if e.Function == "C_Login" && e.OK() {
			loggedIn = true
		}
		if e.RVName == "CKR_USER_NOT_LOGGED_IN" {
			findings = append(findings, Finding{
				Check: "login-ordering", Severity: SevError,
				Message: fmt.Sprintf("%s failed with CKR_USER_NOT_LOGGED_IN", e.Function),
				Seqs:    []uint64{e.Seq},
			})
			continue
		}
		if !loggedIn && loginRequiring[e.Function] && e.OK() {
			findings = append(findings, Finding{
				Check: "login-ordering", Severity: SevInfo,
				Message: fmt.Sprintf("%s succeeded before any C_Login (public session?)", e.Function),
				Seqs:    []uint64{e.Seq},
			})
		}
	}
	return findings
}

// checkErrors surfaces the first error and any error that repeats, with a
// special note for mechanism-parameter errors.
func checkErrors(events []Event) []Finding {
	var findings []Finding
	counts := map[string]int{}
	firstSeq := map[string]uint64{}
	for _, e := range events {
		if e.OK() {
			continue
		}
		counts[e.RVName]++
		if _, ok := firstSeq[e.RVName]; !ok {
			firstSeq[e.RVName] = e.Seq
		}
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return firstSeq[names[i]] < firstSeq[names[j]] })
	for _, name := range names {
		sev := SevWarning
		msg := fmt.Sprintf("%s returned %d time(s)", name, counts[name])
		if name == "CKR_MECHANISM_PARAM_INVALID" || name == "CKR_MECHANISM_INVALID" {
			sev = SevError
			msg += " — check the mechanism and its parameters against the token's supported list"
		}
		findings = append(findings, Finding{
			Check: "errors", Severity: sev, Message: msg, Seqs: []uint64{firstSeq[name]},
		})
	}
	return findings
}

// checkSlowCalls flags individual calls above the slow threshold.
func checkSlowCalls(events []Event) []Finding {
	var findings []Finding
	for _, e := range events {
		if e.Duration() >= slowCallThreshold {
			findings = append(findings, Finding{
				Check: "performance", Severity: SevInfo,
				Message: fmt.Sprintf("%s took %s", e.Function, e.Duration().Round(time.Millisecond)),
				Seqs:    []uint64{e.Seq},
			})
		}
	}
	return findings
}

// functionStats aggregates per-function call counts and timing.
func functionStats(events []Event) []FuncStat {
	byFn := map[string]*FuncStat{}
	for _, e := range events {
		s := byFn[e.Function]
		if s == nil {
			s = &FuncStat{Function: e.Function}
			byFn[e.Function] = s
		}
		s.Calls++
		if !e.OK() {
			s.Errors++
		}
		s.TotalNS += e.DurationNS
		if e.DurationNS > s.MaxNS {
			s.MaxNS = e.DurationNS
		}
	}
	stats := make([]FuncStat, 0, len(byFn))
	for _, s := range byFn {
		stats = append(stats, *s)
	}
	// Busiest functions first.
	sort.SliceStable(stats, func(i, j int) bool {
		if stats[i].TotalNS != stats[j].TotalNS {
			return stats[i].TotalNS > stats[j].TotalNS
		}
		return stats[i].Function < stats[j].Function
	})
	return stats
}
