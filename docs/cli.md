# Command reference

Generated from `hsmdoctor --help`. Every command supports `--help` for full details.

```
  agent       Continuously scan local tokens and push reports to a central server
  bench       Measure token performance with strictly bounded load
  certs       List certificates on a token with their expiry status
  completion  Generate the autocompletion script for the specified shell
  diff        Compare two snapshots and report drift
  discover    Discover slots, tokens and mechanisms of a PKCS#11 module
  help        Help about any command
  packs       List the built-in policy packs
  pqc         Assess post-quantum readiness of a token
  scan        Scan a token: inventory, security posture and health score
  serve       Serve the local web interface and REST API
  server      Run the central server collecting reports from agents
  snapshot    Record the current state of a token for later drift detection
  test        Run a safe functional test profile against a token
  trace       Work with PKCS#11 call traces from the Flight Recorder shim
  vendor      Collect vendor appliance health for a token
  version     Print version information
```

## hsmdoctor discover

```
Loads a PKCS#11 library, lists its slots and tokens, and optionally the
mechanisms supported by each token. No login is required.

Usage:
  hsmdoctor discover [flags]

Flags:
  -h, --help            help for discover
      --json            output as JSON
      --mechanisms      list mechanisms supported by each token
      --module string   path to the PKCS#11 library
      --uri string      RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

## hsmdoctor doctor

```
Runs the core checks against a token and distills them into a single
prioritized diagnosis: an overall verdict (healthy / attention / critical), the
health score and the most important issues first, each with a suggested action.

By default it is read-only and fast (inventory, posture, certificate expiry and
post-quantum exposure). --with-tests adds an ephemeral key-generation and
signing smoke test; --vendor-config folds in appliance health.

Only object metadata is read; private key material never leaves the HSM.

Usage:
  hsmdoctor doctor [flags]

Flags:
      --fail-on string         exit non-zero when the verdict is at or above this level (attention or critical)
      --format string          output format: text or json (default "text")
  -h, --help                   help for doctor
      --module string          path to the PKCS#11 library
      --pack stringArray       policy pack to apply (embedded name or file path; repeatable)
      --pin string             user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string         name of the environment variable holding the user PIN
      --slot uint              slot ID to operate on
      --uri string             RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
      --vendor-config string   vendor configuration file enabling appliance-level checks
      --with-tests             also run an ephemeral key-generation and signing smoke test
```

`doctor` aggregates the other checks rather than adding new ones — a control it
reports as critical is the same finding `scan` would produce. Certificate
expiry surfaces through the posture rules (the default and standard packs carry
expiry rules), so it is not double-counted.

## hsmdoctor scan

```
Collects the metadata inventory of a token, evaluates it against the
security posture rules and reports findings with a health score.

Only object metadata is read; private key material never leaves the HSM.

Usage:
  hsmdoctor scan [flags]

Flags:
      --baseline string         compare against a saved JSON report (from --format json) and exit non-zero on posture regression
      --baseline-max-drop int   health-score drop that counts as a regression for --baseline (default 10)
      --ca-bundle string        PEM trust anchors; enables certificate chain validation (HSM-019)
      --fail-on string          exit non-zero if findings at or above this severity exist (critical, high, medium, low)
      --format string           output format: text, json, html, sarif or cbom (default "text")
  -h, --help                    help for scan
      --module string           path to the PKCS#11 library
      --out string              output file ('-' for stdout) (default "-")
      --pack stringArray        policy pack to apply (embedded name or file path; repeatable, see 'hsmdoctor packs')
      --pin string              user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string          name of the environment variable holding the user PIN
      --rules string            path to a custom rules YAML file replacing all packs
      --slot uint               slot ID to operate on
      --uri string              RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
      --vendor-config string    vendor configuration file enabling appliance-level checks
```

**Regression gating in CI.** Save a baseline on your known-good branch and
compare later scans against it — the run fails when the posture regresses
(health score drops by `--baseline-max-drop` points, default 10, or a new
critical/high finding appears). The baseline is an ordinary JSON report:

```sh
# On the trusted branch: record the baseline.
hsmdoctor scan --slot 0 --pin-env PIN --format json --out baseline.json

# In CI / on a PR: fail if the posture got worse.
hsmdoctor scan --slot 0 --pin-env PIN --baseline baseline.json
```

`--baseline` gates on *relative* worsening; `--fail-on` gates on *absolute*
severity. They compose — either can fail the run. This is the offline
counterpart of the fleet server's posture-regression events.

## hsmdoctor certs

```
Lists every X.509 certificate stored on the token together with its
expiry status, most urgent first. Designed for cron and CI usage via
--fail-on.

Usage:
  hsmdoctor certs [flags]

Flags:
      --fail-on string   exit non-zero on: expired (only expired) or expiring (expired + expiring)
  -h, --help             help for certs
      --json             output as JSON
      --module string    path to the PKCS#11 library
      --pin string       user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string   name of the environment variable holding the user PIN
      --slot uint        slot ID to operate on
      --uri string       RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
      --warn-days int    days before expiry to flag a certificate as expiring (default 30)
```

## hsmdoctor evidence

```
Evaluates a token against one or more compliance packs and produces an
evidence report with a pass / fail / not-applicable verdict per control and the
objects behind each failure.

Controls map directly to the pack's rules: a control fails when a scan with the
same pack produces a finding for its rule. The report is guidance, not a
certification statement.

Only object metadata is read; private key material never leaves the HSM.

Usage:
  hsmdoctor evidence [flags]

Flags:
      --format string      output format: html or json (default "html")
  -h, --help               help for evidence
      --module string      path to the PKCS#11 library
      --out string         output file ('-' for stdout) (default "-")
      --pack stringArray   compliance pack to assess (embedded name or file path; repeatable, required)
      --pin string         user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string     name of the environment variable holding the user PIN
      --slot uint          slot ID to operate on
      --uri string         RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

A control is **not-applicable** when the token holds no object of the kind it
checks (for example a certificate rule on a token with no certificates), which
keeps a trivial pass distinct from an actively satisfied one.

## hsmdoctor preflight

```
Runs a fast readiness gate against a token: the module loads, the
token is present and initialized, the PIN logs in, the required mechanisms are
available and enough sessions are free. With --probe it also runs an ephemeral
key-generation and signing smoke test. With --vendor-config it factors in
tamper state and HA member health.

Intended as the gate a certificate-lifecycle system calls before starting an
HSM-backed renewal. Exit codes: 0 = ready, 4 = postpone (not ready, retry
later), 1 = error talking to the module.

Usage:
  hsmdoctor preflight [flags]

Flags:
  -h, --help                    help for preflight
      --json                    output as JSON
      --mechanism stringArray   required mechanism by CKM_* name or hex code (repeatable), e.g. CKM_RSA_PKCS_KEY_PAIR_GEN
      --min-free-sessions int   require at least this many free sessions on the token
      --module string           path to the PKCS#11 library
      --pin string              user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string          name of the environment variable holding the user PIN
      --probe                   run an ephemeral key-generation and signing smoke test
      --slot uint               slot ID to operate on
      --uri string              RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
      --vendor-config string    vendor config file; factors tamper and HA state into the verdict
```

A "postpone" verdict (exit 4) means the token is not ready right now — retry
later; it is deliberately distinct from a general error (exit 1) so an
orchestrator can tell "wait and retry" apart from "a human must intervene".

## hsmdoctor test

```
Runs a functional test profile (key generation, signing, encryption)
using ephemeral session objects only. Nothing is persisted on the token and
all created objects are destroyed when the test finishes.

Usage:
  hsmdoctor test [flags]

Flags:
  -h, --help             help for test
      --json             output as JSON
      --module string    path to the PKCS#11 library
      --pin string       user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string   name of the environment variable holding the user PIN
      --profile string   test profile to run (available: key-wrapping, sign-verify) (default "sign-verify")
      --slot uint        slot ID to operate on
      --uri string       RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

## hsmdoctor bench

```
Measures signing and encryption throughput using ephemeral session
objects. Every run is capped by both duration and an absolute operation
budget per primitive, so a benchmark cannot overload a token indefinitely.

Avoid running benchmarks against production HSMs serving live traffic.

Usage:
  hsmdoctor bench [flags]

Flags:
      --duration duration   max duration per primitive (capped at 1m0s) (default 3s)
  -h, --help                help for bench
      --json                output as JSON
      --max-ops int         max operations per primitive (capped at 1000000) (default 5000)
      --module string       path to the PKCS#11 library
      --pin string          user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string      name of the environment variable holding the user PIN
      --sessions int        concurrent sessions (capped at 32) (default 1)
      --slot uint           slot ID to operate on
      --uri string          RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

## hsmdoctor pqc

```
Checks which NIST post-quantum families (ML-KEM, ML-DSA, SLH-DSA) the
token advertises, how exposed the current inventory is to a future quantum
adversary, and whether the host OpenSSL installation is PQC-capable.

With --test, advertised families are functionally probed using ephemeral
session objects that leave no trace on the token.

Usage:
  hsmdoctor pqc [flags]

Flags:
  -h, --help             help for pqc
      --json             output as JSON
      --module string    path to the PKCS#11 library
      --no-host          skip the host OpenSSL capability check
      --pin string       user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string   name of the environment variable holding the user PIN
      --slot uint        slot ID to operate on
      --test             functionally probe advertised families with ephemeral session objects
      --uri string       RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

## hsmdoctor snapshot

```
Collects the metadata inventory of a token and writes it to a JSON file.
Compare two snapshots later with "hsmdoctor diff" to detect drift.

Usage:
  hsmdoctor snapshot [flags]

Flags:
  -h, --help             help for snapshot
      --module string    path to the PKCS#11 library
      --out string       output file ('-' for stdout) (default "-")
      --pin string       user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string   name of the environment variable holding the user PIN
      --slot uint        slot ID to operate on
      --uri string       RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
```

## hsmdoctor diff

```
Compare two snapshots and report drift

Usage:
  hsmdoctor diff <old-snapshot.json> <new-snapshot.json> [flags]

Flags:
      --exit-code   exit non-zero when drift is detected (for scripting)
  -h, --help        help for diff
      --json        output as JSON
```

## hsmdoctor vendor

```
Detects the HSM vendor behind a token and collects appliance-level
health that PKCS#11 cannot expose: device resources, HA status, partition
utilization, tamper and backup state.

Some providers are experimental and have not been validated against real
hardware; their output is labeled accordingly. List providers with --list.

Usage:
  hsmdoctor vendor [flags]

Flags:
  -h, --help                   help for vendor
      --json                   output as JSON
      --list                   list available vendor providers and exit
      --module string          path to the PKCS#11 library
      --pin string             user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string         name of the environment variable holding the user PIN
      --slot uint              slot ID to operate on
      --uri string             RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"
      --vendor-config string   vendor configuration file
```

## hsmdoctor trace

```
Analyze PKCS#11 call traces produced by the HSM Doctor Flight Recorder
shim (see docs/trace.md). Traces are metadata only — no PINs, key material
or plaintext are ever recorded.

Usage:
  hsmdoctor trace [command]

Available Commands:
  analyze     Analyze a trace for leaks, ordering issues and errors
  summary     Show per-function call counts and timing

Flags:
  -h, --help   help for trace

Use "hsmdoctor trace [command] --help" for more information about a command.
```

## hsmdoctor packs

```
List the built-in policy packs

Usage:
  hsmdoctor packs [flags]

Flags:
  -h, --help   help for packs
```

## hsmdoctor serve

```
Starts a local HTTP server exposing HSM Doctor's functionality as a
REST API under /api/v1 plus the embedded web interface.

The server is meant for local, single-operator use: it binds to loopback by
default and the PIN is taken once at startup (prefer --pin-env), never per
request and never logged. Think twice before exposing it beyond localhost.

Usage:
  hsmdoctor serve [flags]

Flags:
      --auth-config string     YAML file with API bearer tokens and roles (default: no authentication)
      --client-ca string       require client certificates signed by this CA (mutual TLS; requires --tls-cert/--tls-key)
      --db string              SQLite path or postgres:// DSN (default: ~/.local/share/hsmdoctor/hsmdoctor.db; or HSMDOCTOR_DB)
  -h, --help                   help for serve
      --listen string          listen address (default "127.0.0.1:8080")
      --module string          path to the PKCS#11 library (required)
      --no-db                  disable scan history persistence
      --notify-config string   e-mail notification config file (SMTP + recipients)
      --pack stringArray       policy pack to apply (embedded name or file path; repeatable)
      --pin string             user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string         name of the environment variable holding the user PIN
      --rules string           path to a custom rules YAML file replacing all packs
      --schedule string        cron expression for automatic scans of all tokens (e.g. "0 */6 * * *")
      --tls-cert string        TLS certificate file (requires --tls-key)
      --tls-key string         TLS private key file (requires --tls-cert)
      --vendor-config string   vendor configuration file enabling appliance-level checks
      --webhook-url string     POST drift notifications to this URL
```

## hsmdoctor server

```
Runs HSM Doctor in central mode: no local PKCS#11 module is loaded.
Agents enrolled with the shared enrollment token push their scan reports
here; the server stores history, detects drift and serves the fleet
dashboard, REST API and Prometheus metrics.

The default listen address is loopback. When exposing the server to agents
on other hosts, front it with TLS and change --listen deliberately.

Usage:
  hsmdoctor server [flags]

Flags:
      --auth-config string        YAML file with API bearer tokens and roles (default: no authentication)
      --client-ca string          require agent/client certificates signed by this CA (mutual TLS; requires --tls-cert/--tls-key)
      --db string                 SQLite path or postgres:// DSN (default: ~/.local/share/hsmdoctor/hsmdoctor.db; or HSMDOCTOR_DB)
      --enroll-token string       shared token agents use to enroll (WARNING: visible in process list; prefer --enroll-token-env)
      --enroll-token-env string   name of the environment variable holding the enrollment token
  -h, --help                      help for server
      --listen string             listen address (default "127.0.0.1:8080")
      --notify-config string      e-mail notification config file (SMTP + recipients)
      --tls-cert string           TLS certificate file (requires --tls-key)
      --tls-key string            TLS private key file (requires --tls-cert)
      --webhook-url string        POST drift notifications to this URL
```

## hsmdoctor agent

```
Runs on a host with the vendor PKCS#11 client installed. Scans all
token-bearing slots (or one specific --slot) on an interval and pushes the
reports to a central HSM Doctor server.

The PIN never leaves this host; only finished reports (metadata, findings,
scores) are transmitted. On first run the agent enrolls using the shared
enrollment token and stores its permanent token in --token-file.

Usage:
  hsmdoctor agent [flags]

Flags:
      --enroll-token string       enrollment token for first registration (prefer --enroll-token-env)
      --enroll-token-env string   name of the environment variable holding the enrollment token
  -h, --help                      help for agent
      --interval duration         time between scans (default 15m0s)
      --module string             path to the PKCS#11 library (required)
      --name string               agent name (default: hostname)
      --once                      scan and push once, then exit (for cron)
      --pack stringArray          policy pack to apply (embedded name or file path; repeatable)
      --pin string                user PIN (WARNING: visible in shell history; prefer --pin-env)
      --pin-env string            name of the environment variable holding the user PIN
      --rules string              path to a custom rules YAML file replacing all packs
      --server string             central server base URL, e.g. https://hsmdoctor.example.com (required)
      --server-ca string          trust this CA for the server's certificate instead of the system roots
      --slot uint                 scan only this slot (default: all slots with tokens)
      --tls-client-cert string    client certificate for mutual TLS to the server
      --tls-client-key string     client private key for mutual TLS (requires --tls-client-cert)
      --token-file string         file storing the permanent agent token (default: ~/.local/share/hsmdoctor/agent.token)
      --vendor-config string      vendor configuration file enabling appliance-level checks
```

## hsmdoctor version

```
Print version information

Usage:
  hsmdoctor version [flags]

Flags:
  -h, --help   help for version
```

## hsmdoctor trace analyze

```
Analyze a trace for leaks, ordering issues and errors

Usage:
  hsmdoctor trace analyze [trace.jsonl] [flags]

Flags:
      --fail-on-error   exit non-zero when error-level findings exist
  -h, --help            help for analyze
      --json            output as JSON
```

## hsmdoctor trace summary

```
Show per-function call counts and timing

Usage:
  hsmdoctor trace summary [trace.jsonl] [flags]

Flags:
  -h, --help   help for summary
      --json   output as JSON
```

