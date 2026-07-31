package trace

import "testing"

// RecordableFunctions must mirror the shim's wrappers (shim/shim.c). This
// tripwire fails if the list is edited without a conscious update.
func TestRecordableFunctionsSet(t *testing.T) {
	if len(RecordableFunctions) != 32 {
		t.Errorf("RecordableFunctions has %d entries, expected 32 (keep in sync with shim/shim.c)", len(RecordableFunctions))
	}
	seen := map[string]bool{}
	for _, fn := range RecordableFunctions {
		if seen[fn] {
			t.Errorf("duplicate function in RecordableFunctions: %s", fn)
		}
		seen[fn] = true
	}
	for _, must := range []string{"C_Initialize", "C_Sign", "C_GenerateKeyPair", "C_GenerateRandom"} {
		if !seen[must] {
			t.Errorf("RecordableFunctions is missing %s", must)
		}
	}
}

func TestCoverageOf(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		{Seq: 2, Function: "C_OpenSession", RVName: "CKR_OK"},
		{Seq: 3, Function: "C_OpenSession", RVName: "CKR_OK"},
		{Seq: 4, Function: "C_SignInit", RVName: "CKR_OK"},
		{Seq: 5, Function: "C_Sign", RVName: "CKR_OK"},
	}
	cov := CoverageOf(events)

	if cov.Total != 32 {
		t.Errorf("Total = %d, want 32", cov.Total)
	}
	if cov.Covered != 4 {
		t.Errorf("Covered = %d, want 4 (distinct functions)", cov.Covered)
	}
	if len(cov.Missing) != 28 {
		t.Errorf("Missing = %d, want 28", len(cov.Missing))
	}
	// Exercised is sorted with call counts.
	if cov.Exercise[0].Function != "C_Initialize" || cov.Exercise[0].Calls != 1 {
		t.Errorf("unexpected first exercised entry: %+v", cov.Exercise[0])
	}
	var openCalls int
	for _, e := range cov.Exercise {
		if e.Function == "C_OpenSession" {
			openCalls = e.Calls
		}
	}
	if openCalls != 2 {
		t.Errorf("C_OpenSession calls = %d, want 2", openCalls)
	}
	if cov.Percent < 12 || cov.Percent > 13 { // 4/32 = 12.5%
		t.Errorf("Percent = %.2f, want ~12.5", cov.Percent)
	}
	if len(cov.Unexpected) != 0 {
		t.Errorf("no unexpected functions expected: %v", cov.Unexpected)
	}
}

func TestCoverageUnexpectedFunction(t *testing.T) {
	events := []Event{
		{Seq: 1, Function: "C_Initialize", RVName: "CKR_OK"},
		{Seq: 2, Function: "C_NotARealFunction", RVName: "CKR_OK"},
	}
	cov := CoverageOf(events)
	if len(cov.Unexpected) != 1 || cov.Unexpected[0] != "C_NotARealFunction" {
		t.Errorf("expected the unknown function to be flagged: %v", cov.Unexpected)
	}
	if cov.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (only C_Initialize counts)", cov.Covered)
	}
}

func TestCoverageEmpty(t *testing.T) {
	cov := CoverageOf(nil)
	if cov.Covered != 0 || len(cov.Missing) != 32 || cov.Percent != 0 {
		t.Errorf("empty trace should have 0 coverage: covered=%d missing=%d pct=%.1f",
			cov.Covered, len(cov.Missing), cov.Percent)
	}
}
