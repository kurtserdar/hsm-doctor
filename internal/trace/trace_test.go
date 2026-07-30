package trace

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func u64(v uint64) *uint64 { return &v }

// ev builds a minimal successful event.
func ev(seq uint64, fn string, sess uint64) Event {
	return Event{Seq: seq, Function: fn, Session: u64(sess), RVName: "CKR_OK"}
}

func TestWriteReadRoundTrip(t *testing.T) {
	events := []Event{
		{Seq: 1, TS: time.Unix(0, 0).UTC(), Function: "C_Initialize", RVName: "CKR_OK"},
		ev(2, "C_OpenSession", 5),
	}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for i := range events {
		if err := w.Write(&events[i]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// One JSON object per line.
	if lines := strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") + 1; lines != 2 {
		t.Errorf("expected 2 lines, got %d", lines)
	}

	got, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got[1].Function != "C_OpenSession" || *got[1].Session != 5 {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestReadRejectsMalformedLine(t *testing.T) {
	_, err := Read(strings.NewReader(`{"seq":1,"function":"C_Initialize","rv_name":"CKR_OK"}` + "\n{bad json}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("malformed line should error with its number, got %v", err)
	}
}

func TestDetectInitializeMissing(t *testing.T) {
	a := Analyze([]Event{ev(1, "C_OpenSession", 1)})
	if !hasCheck(a, "initialize", SevError) {
		t.Errorf("missing C_Initialize should be an error: %+v", a.Findings)
	}
}

func TestDetectSessionLeak(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		ev(2, "C_OpenSession", 10),
		ev(3, "C_OpenSession", 11),
		ev(4, "C_CloseSession", 10),
		{Seq: 5, Function: "C_Finalize", RVName: "CKR_OK"},
	}
	a := Analyze(events)
	leaks := findingsFor(a, "session-leak")
	if len(leaks) != 1 || leaks[0].Seqs[0] != 3 {
		t.Errorf("session 11 should be reported leaked: %+v", leaks)
	}
}

func TestCloseAllSessionsClearsLeaks(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		ev(2, "C_OpenSession", 10),
		{Seq: 3, Function: "C_CloseAllSessions", RVName: "CKR_OK"},
		{Seq: 4, Function: "C_Finalize", RVName: "CKR_OK"},
	}
	if findingsFor(Analyze(events), "session-leak") != nil {
		t.Error("C_CloseAllSessions should clear session-leak findings")
	}
}

func TestDetectOperationLeak(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		ev(2, "C_SignInit", 7),
		// No C_Sign / C_SignFinal on session 7.
		ev(3, "C_FindObjectsInit", 7),
		ev(4, "C_FindObjectsFinal", 7),
	}
	a := Analyze(events)
	ops := findingsFor(a, "operation-leak")
	if len(ops) != 1 || ops[0].Seqs[0] != 2 {
		t.Errorf("dangling C_SignInit should be reported once: %+v", ops)
	}
}

func TestDetectLoginNotLoggedIn(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		{Seq: 2, Function: "C_SignInit", Session: u64(1), RVName: "CKR_USER_NOT_LOGGED_IN", RV: 0x101},
	}
	a := Analyze(events)
	f := findingsFor(a, "login-ordering")
	if len(f) != 1 || f[0].Severity != SevError {
		t.Errorf("CKR_USER_NOT_LOGGED_IN should be an error finding: %+v", f)
	}
}

func TestDetectMechanismParamError(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		{Seq: 2, Function: "C_SignInit", Session: u64(1), RVName: "CKR_MECHANISM_PARAM_INVALID", RV: 0x71},
	}
	a := Analyze(events)
	errs := findingsFor(a, "errors")
	if len(errs) != 1 || errs[0].Severity != SevError || !strings.Contains(errs[0].Message, "mechanism") {
		t.Errorf("mechanism param error should be flagged: %+v", errs)
	}
}

func TestSlowCallAndStats(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK", DurationNS: int64(time.Second)},
		{Seq: 2, Function: "C_Initialize", RVName: "CKR_OK", DurationNS: int64(time.Millisecond)},
	}
	a := Analyze(events)
	if len(findingsFor(a, "performance")) != 1 {
		t.Errorf("one slow call expected: %+v", a.Findings)
	}
	if len(a.Stats) != 1 || a.Stats[0].Calls != 2 || a.Stats[0].Function != "C_Initialize" {
		t.Errorf("stats wrong: %+v", a.Stats)
	}
}

func TestCleanTraceHasNoFindings(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		ev(2, "C_OpenSession", 1),
		{Seq: 3, Function: "C_Login", Session: u64(1), RVName: "CKR_OK"},
		ev(4, "C_SignInit", 1),
		ev(5, "C_Sign", 1),
		ev(6, "C_CloseSession", 1),
		{Seq: 7, Function: "C_Finalize", RVName: "CKR_OK"},
	}
	a := Analyze(events)
	if len(a.Findings) != 0 {
		t.Errorf("clean trace should produce no findings: %+v", a.Findings)
	}
}

func hasCheck(a *Analysis, check string, sev Severity) bool {
	for _, f := range a.Findings {
		if f.Check == check && f.Severity == sev {
			return true
		}
	}
	return false
}

func findingsFor(a *Analysis, check string) []Finding {
	var out []Finding
	for _, f := range a.Findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}
