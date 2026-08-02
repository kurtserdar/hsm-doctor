// Command hsmdoctor-trace is the PKCS#11 Flight Recorder shim, built as a
// c-shared library. An application loads it in place of the real PKCS#11
// module; the shim forwards every call to the real module (named by
// HSMDOCTOR_TRACE_MODULE) and records metadata as a JSON Lines trace.
//
// By construction the shim can never leak secrets: the C layer forwards
// buffer pointers straight to the real module and passes only lengths,
// handles, mechanism codes and return codes up to this Go layer. PIN and
// key-material buffers are never dereferenced for logging.
package main

/*
#include "shim.h"
*/
import "C"

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11names"
	"github.com/kurtserdar/hsm-doctor/internal/trace"
	"golang.org/x/sys/unix"
)

var (
	seq       atomic.Uint64
	writerMu  sync.Mutex
	writer    *trace.Writer
	writerSet bool
)

// out lazily opens the trace destination: HSMDOCTOR_TRACE_OUT (appended) or
// stderr. Callers hold writerMu.
func out() *trace.Writer {
	if writerSet {
		return writer
	}
	writerSet = true
	if path := os.Getenv("HSMDOCTOR_TRACE_OUT"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			writer = trace.NewWriter(f)
			return writer
		}
		// Fall back to stderr on error rather than losing the trace.
	}
	writer = trace.NewWriter(os.Stderr)
	return writer
}

//export goEmit
func goEmit(fn *C.char, hasSession C.int, session C.ulong,
	hasObject C.int, object C.ulong,
	hasMech C.int, mech C.ulong, dataLen C.long, outLen C.long,
	label *C.char, keyID *C.char,
	rv C.ulong, durNs C.longlong) {

	e := trace.Event{
		Seq:        seq.Add(1),
		TS:         time.Now().UTC(),
		Function:   C.GoString(fn),
		Thread:     unix.Gettid(),
		RV:         uint64(rv),
		RVName:     p11names.ReturnCode(uint(rv)),
		DurationNS: int64(durNs),
	}
	if hasSession != 0 {
		s := uint64(session)
		e.Session = &s
	}
	if hasObject != 0 {
		o := uint64(object)
		e.Object = &o
	}
	if hasMech != 0 {
		e.Mechanism = p11names.Mechanism(uint(mech))
	}
	if label != nil {
		e.Label = C.GoString(label)
	}
	if keyID != nil {
		e.KeyID = C.GoString(keyID)
	}
	if dataLen >= 0 {
		d := int(dataLen)
		e.DataLen = &d
	}
	if outLen >= 0 {
		o := int(outLen)
		e.OutLen = &o
	}

	writerMu.Lock()
	_ = out().Write(&e)
	writerMu.Unlock()
}

func main() {}
