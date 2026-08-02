# PKCS#11 Flight Recorder

The Flight Recorder is a shim library that sits between an application and
its PKCS#11 module, recording every call as a trace you can analyze for
leaks, ordering bugs, errors and performance problems.

```
application ──▶ hsmdoctor-trace.so ──▶ real PKCS#11 module ──▶ HSM
                       │
                       ▼
                 trace (JSON Lines)
```

## Safety by construction

The shim can never leak secrets. Its C layer forwards buffer pointers
straight to the real module and passes only **metadata** up to the trace:
function names, session/object handles, mechanism codes, buffer **lengths**,
return codes and timings. PIN and key-material buffers are never
dereferenced for logging — there is no flag that turns secret capture on,
because the data never reaches the recording layer.

The one attribute *values* recorded are the `CKA_LABEL` and `CKA_ID` a
`C_FindObjectsInit` searches for. These are key **identifiers**, not key
material, and they let `trace keys` map a used handle back to a named key. No
other attribute value — and never a `CKA_VALUE`, PIN or plaintext — is read.

## Building

The shim is a cgo `c-shared` artifact, separate from the main binary:

```sh
make shim          # produces ./hsmdoctor-trace.so (Linux)
```

## Recording a trace

Point the application at the shim instead of the vendor module, and tell the
shim where the real module is and where to write the trace:

```sh
export HSMDOCTOR_TRACE_MODULE=/usr/lib/libCryptoki2_64.so   # the real module
export HSMDOCTOR_TRACE_OUT=/tmp/app-trace.jsonl             # default: stderr

# Example: run any PKCS#11 application against the shim.
pkcs11-tool --module ./hsmdoctor-trace.so --login --pin ****  --sign ...
```

Configure your application's PKCS#11 module path to
`hsmdoctor-trace.so` the same way you would point it at the vendor library
(OpenSSL `pkcs11` provider, Java `SunPKCS11`, nginx, etc.).

## Analyzing a trace

```sh
hsmdoctor trace analyze /tmp/app-trace.jsonl      # findings + per-function stats
hsmdoctor trace summary /tmp/app-trace.jsonl      # stats only
hsmdoctor trace analyze --json trace.jsonl        # machine-readable
hsmdoctor trace analyze --fail-on-error trace.jsonl   # CI/CD gate
```

The analyzer detects:

- **Session leaks** — `C_OpenSession` without a matching close.
- **Operation leaks** — `C_SignInit`/`C_FindObjectsInit`/... never followed
  by their terminating call on the same session.
- **Initialize/Finalize balance** — calls before `C_Initialize`, or a
  library never finalized.
- **Login ordering** — `CKR_USER_NOT_LOGGED_IN`, or login-requiring
  operations attempted before `C_Login`.
- **Error patterns** — the first occurrence and repeat count of each
  `CKR_*`, with extra emphasis on mechanism/parameter errors.
- **Performance** — slow individual calls and a per-function
  count/total/max summary.

## Coverage

The shim instruments a curated, high-traffic subset of the PKCS#11 API
(initialization, slots/tokens, sessions, login, object find/attributes, key
generation, sign/verify, encrypt/decrypt, digest, wrap/unwrap, random).
Functions outside that set are forwarded to the real module untraced, so
applications keep working; coverage grows over time. The shim currently
targets Linux.

`trace coverage` reports how much of that recordable set a given trace
exercised — useful for gauging how thoroughly a test suite drives its PKCS#11
module:

```sh
hsmdoctor trace coverage /tmp/app-trace.jsonl     # exercised vs not-exercised
hsmdoctor trace coverage --json trace.jsonl       # machine-readable
```

It lists the functions that were called (with counts) and those that were
not, measured against the functions the recorder can observe (not the full
PKCS#11 API — a function the shim does not wrap can never appear in a trace).

## Key usage

`trace keys` summarizes which keys the application actually put to work: for
each key, the operations it was used for (sign, verify, encrypt, decrypt,
wrap, unwrap) and the mechanisms seen.

```sh
hsmdoctor trace keys /tmp/app-trace.jsonl         # per-key usage summary
hsmdoctor trace keys --json trace.jsonl           # machine-readable
```

It reconstructs each key's identity by tying the `CKA_LABEL`/`CKA_ID` a
`C_FindObjectsInit` searched for to the handle the following `C_FindObjects`
returned, then attributing later operation-init calls on that handle to the
named key. Operations on a handle the trace never located that way are grouped
as **unresolved**.

This reflects only the trace window: a key that does not appear was simply not
used *during the trace*, which is not proof it is never used. Capture a
representative workload, then compare the used keys against the token inventory
(`hsmdoctor scan`) to spot keys that sit idle — candidates for review or
retirement.
