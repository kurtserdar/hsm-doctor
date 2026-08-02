// Package trace defines the PKCS#11 call-trace format shared by the shim
// (which produces traces) and the analyzer (which consumes them), plus the
// JSON Lines reader and writer.
//
// Traces are metadata only: function names, handles, mechanisms, buffer
// LENGTHS, return codes and timings. PINs, key material and plaintext are
// never recorded. See the shim for the masking rules at the source.
package trace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Event is one PKCS#11 call: a paired entry/exit collapsed into a single
// record with its duration and result.
type Event struct {
	// Seq is a monotonic per-process sequence number.
	Seq uint64 `json:"seq"`
	// TS is the call start time.
	TS time.Time `json:"ts"`
	// Function is the PKCS#11 function name, e.g. "C_SignInit".
	Function string `json:"function"`
	// Thread identifies the calling OS thread, to spot cross-thread misuse.
	Thread int `json:"thread"`
	// Session is the session handle when the call carries one.
	Session *uint64 `json:"session,omitempty"`
	// Slot is the slot ID when the call carries one.
	Slot *uint64 `json:"slot,omitempty"`
	// Object is an object handle when the call carries one (the key of an
	// operation-init call, or the first handle returned by C_FindObjects).
	Object *uint64 `json:"object,omitempty"`
	// Label and KeyID carry the CKA_LABEL / CKA_ID search values of a
	// C_FindObjectsInit template. They are identifiers, not key material, and
	// let the analyzer map a used handle back to a named key. Everything else
	// stays masked (no PINs, key bytes or plaintext are ever recorded).
	Label string `json:"label,omitempty"`
	KeyID string `json:"key_id,omitempty"`
	// Mechanism is the CKM_* name for calls that take a mechanism.
	Mechanism string `json:"mechanism,omitempty"`
	// DataLen and OutLen record buffer sizes without their contents.
	DataLen *int `json:"data_len,omitempty"`
	OutLen  *int `json:"out_len,omitempty"`
	// RV is the numeric CK_RV return value; RVName its CKR_* name.
	RV     uint64 `json:"rv"`
	RVName string `json:"rv_name"`
	// DurationNS is the wall-clock duration of the call.
	DurationNS int64 `json:"duration_ns"`
	// Attrs lists CKA_* attribute names touched (types only, never values).
	Attrs []string `json:"attrs,omitempty"`
}

// Duration returns the call duration.
func (e Event) Duration() time.Duration { return time.Duration(e.DurationNS) }

// OK reports whether the call returned CKR_OK (0).
func (e Event) OK() bool { return e.RV == 0 }

// Writer emits events as JSON Lines.
type Writer struct {
	w   *bufio.Writer
	enc *json.Encoder
}

// NewWriter wraps w as a JSON Lines event writer.
func NewWriter(w io.Writer) *Writer {
	bw := bufio.NewWriter(w)
	return &Writer{w: bw, enc: json.NewEncoder(bw)}
}

// Write appends one event and flushes, so a crash mid-run still leaves a
// readable prefix of the trace.
func (w *Writer) Write(e *Event) error {
	if err := w.enc.Encode(e); err != nil {
		return err
	}
	return w.w.Flush()
}

// Read parses a JSON Lines trace. Blank lines are skipped; a malformed line
// aborts with its line number so truncated traces are diagnosable.
func Read(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var events []Event
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return events, fmt.Errorf("trace line %d: %w", line, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return events, fmt.Errorf("reading trace: %w", err)
	}
	return events, nil
}
