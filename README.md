# HSM Doctor

[![Version](https://img.shields.io/badge/version-v1.0.0-brightgreen.svg)](https://github.com/kurtserdar/hsm-doctor/releases/tag/v1.0.0)
[![Release](https://img.shields.io/github/v/release/kurtserdar/hsm-doctor?sort=semver&label=release)](https://github.com/kurtserdar/hsm-doctor/releases/latest)
[![CI](https://github.com/kurtserdar/hsm-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/kurtserdar/hsm-doctor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/kurtserdar/hsm-doctor.svg)](https://pkg.go.dev/github.com/kurtserdar/hsm-doctor)

**The open-source toolbox for HSM health, security posture and PKCS#11 diagnostics.**

HSM Doctor is a vendor-neutral CLI for discovering, testing and assessing the
security posture of Hardware Security Modules. It talks to any HSM through
the standard PKCS#11 interface — Thales Luna, Entrust nShield, Utimaco,
Procenne, AWS CloudHSM, SoftHSM, BouncyHSM and others — and turns raw token
data into an understandable risk and operations report.

Excellent low-level PKCS#11 tools already exist. HSM Doctor focuses on the
questions an HSM administrator actually asks:

- What keys and certificates live on this token, and are they configured safely?
- Are there extractable private keys, weak key sizes, expiring certificates?
- Does this HSM still behave the way it did yesterday? **What changed?**
- Can my workload (signing, encryption, key generation) actually run on this device?

**Metadata only, by design:** private key material is never read, and
functional tests use ephemeral session objects that leave no trace on the token.

## Highlights

- **Security posture scoring** — a metadata-only inventory evaluated against
  customizable YAML rules and curated **policy packs** (`nist`, `cabf`,
  `strict`, `pqc-migration`), producing a health score and text/JSON/HTML
  reports.
- **Drift detection** — snapshot a token and diff it later to catch new or
  removed objects, attribute flips, and mechanism or firmware changes.
- **Post-quantum readiness** — an ML-KEM/ML-DSA/SLH-DSA support matrix,
  functional probes and quantum-exposure analysis of your existing keys.
- **PKCS#11 Flight Recorder** — a shim records a **secret-safe** call trace
  that the analyzer inspects for session/operation leaks, ordering bugs,
  errors and slow calls.
- **Vendor appliance health** — device, HA, partition and tamper status
  through pluggable providers (SoftHSM stable; Luna/nShield/CloudHSM
  experimental), folded into the health score.
- **Fleet platform** — local and central servers with a web UI and REST API,
  push agents, **SQLite or PostgreSQL** storage, Prometheus metrics, drift
  webhooks and e-mail notifications.
- **Enterprise-ready security** — bearer-token auth (admin/viewer), **OIDC
  Single Sign-On** and **mutual TLS**; secrets never leave the HSM or reach
  logs and traces.
- **One binary, everywhere** — the CLI, embedded web UI and every feature
  ship as a single Go binary for Linux, macOS and Windows.

## Features

| Command | What it does |
|---|---|
| `hsmdoctor discover` | Module, slot, token and mechanism discovery |
| `hsmdoctor scan` | Key/certificate inventory + security posture rules + health score; text, JSON or single-file HTML report |
| `hsmdoctor certs` | Certificate expiry monitor with cron/CI-friendly exit codes |
| `hsmdoctor test` | Safe functional test profiles (key generation, sign/verify, AES-GCM) with ephemeral session objects |
| `hsmdoctor bench` | Performance measurement with strictly bounded load (duration + op budget caps) |
| `hsmdoctor snapshot` | Record the full metadata state of a token as JSON |
| `hsmdoctor diff` | Compare two snapshots and report drift: new/removed objects, attribute flips, mechanism and firmware changes |
| `hsmdoctor pqc` | Post-quantum readiness: ML-KEM/ML-DSA/SLH-DSA support matrix, quantum-vulnerable inventory exposure, host OpenSSL check |
| `hsmdoctor vendor` | Appliance-level health via vendor providers: device, HA, partitions, tamper, backup (SoftHSM stable; Luna/nShield/CloudHSM experimental) |
| `hsmdoctor trace` | Analyze PKCS#11 call traces from the Flight Recorder shim: session/operation leaks, ordering bugs, errors, performance |
| `hsmdoctor serve` | Local web interface + REST API with scan history, automatic drift detection, Prometheus metrics and cron-scheduled scans |
| `hsmdoctor server` | Central fleet server: collects reports pushed by agents, stores history, detects drift, serves the fleet dashboard |
| `hsmdoctor agent` | Runs where the vendor PKCS#11 client lives; scans on an interval and pushes reports to the central server |

Tokens can be addressed classically (`--module` + `--slot`) or with an
RFC 7512 PKCS#11 URI:

```sh
hsmdoctor scan --uri "pkcs11:token=PROD-PARTITION?module-path=/usr/lib/libCryptoki2_64.so" --pin-env HSM_PIN
```

## Install

Pre-built binaries for Linux, macOS and Windows are on the
[releases page](https://github.com/kurtserdar/hsm-doctor/releases).

Building from source requires cgo (the PKCS#11 wrapper uses dlopen), so a C
compiler must be present:

```sh
git clone https://github.com/kurtserdar/hsm-doctor.git
cd hsm-doctor
make build          # CLI only
make ui build       # CLI + embedded web interface (requires Node.js)
```

or

```sh
go install github.com/kurtserdar/hsm-doctor/cmd/hsmdoctor@latest
```

## Quick start (with SoftHSM)

No HSM at hand? SoftHSM works out of the box:

```sh
sudo apt-get install softhsm2
softhsm2-util --init-token --free --label DEMO --so-pin 12345678 --pin 123456

# discover slots and tokens
hsmdoctor discover --module /usr/lib/softhsm/libsofthsm2.so

# full scan: inventory + posture + health score
hsmdoctor scan --module /usr/lib/softhsm/libsofthsm2.so --slot <SLOT-ID> --pin-env HSM_PIN
```

Example scan output:

```
Health Score: 43/100

CRITICAL (1)
  [HSM-001] Extractable private key
          private-key legacy-signing (id 01)
          CKA_EXTRACTABLE=true

HIGH (1)
  [HSM-003] Weak RSA key
          private-key legacy-signing (id 01)
          key size 1024 < 2048 bits

MEDIUM (4)
  [HSM-005] Certificate expiring soon
          certificate api-cert (id 03)
          expires 2026-08-08 (9 days left)
  ...
```

Generate a self-contained HTML report instead:

```sh
hsmdoctor scan --module ... --slot ... --format html --out report.html
```

### PIN handling

`--pin-env HSM_PIN` (recommended) reads the PIN from an environment
variable; with neither `--pin` nor `--pin-env` set, hsmdoctor prompts on the
terminal. Avoid `--pin <value>`: it lands in your shell history. Scans
without a PIN work but only see public objects.

## Security posture rules

Ten built-in rules cover extractable/non-sensitive private keys, weak RSA
sizes, expired and expiring certificates, duplicate labels, orphan objects,
role-mixing keys and legacy mechanisms. Beyond the default set, curated
**policy packs** ship in the binary and combine freely:

```sh
hsmdoctor packs                              # list built-in packs
hsmdoctor scan --pack nist --pack strict ... # combine packs (and/or your own file)
```

`nist` (SP 800-57/800-131A aligned), `cabf` (CA/Browser Forum BR inspired),
`strict` (attribute hygiene) and `pqc-migration` (score-neutral post-quantum
advisories). Rules are plain YAML and fully customizable — see
[docs/rules.md](docs/rules.md):

```yaml
rules:
  - id: ORG-001
    title: RSA below corporate minimum
    severity: high
    match:
      class: private-key
      key_type: RSA
      key_size_lt: 3072
```

```sh
hsmdoctor scan --rules corporate.yaml --fail-on high ...   # non-zero exit for CI/CD gates
```

## Drift detection

```sh
hsmdoctor snapshot --module ... --slot ... --out monday.json
# ... a day and one incident later ...
hsmdoctor snapshot --module ... --slot ... --out tuesday.json
hsmdoctor diff monday.json tuesday.json --exit-code
```

```
! firmware version changed 7.8.1 -> 7.8.2
+ private-key drift-key (id 05) added
- certificate api-cert (id 03) removed
! private-key app-key (id 01): CKA_EXTRACTABLE changed false -> true

4 change(s) detected.
```

## Functional tests

```sh
hsmdoctor test --module ... --slot ... --profile sign-verify
```

```
RSA-2048 generate                PASS           (43ms)
SHA256-RSA sign/verify           PASS           (41ms)
RSA-PSS (SHA256) sign/verify     PASS           (12ms)
ECDSA P-256 sign/verify          PASS
AES-256 generate                 PASS
AES-GCM encrypt/decrypt          PASS

6 passed, 0 failed, 0 not supported
```

Steps whose mechanisms the token does not advertise are reported as
`NOT SUPPORTED` instead of failing.

## Performance testing

```sh
hsmdoctor bench --module ... --slot ... --sessions 4
```

```
RSA-2048 sign (SHA256-RSA)       6415.2 ops/sec  (5000 ops in 779ms)
ECDSA P-256 sign                47109.4 ops/sec  (5000 ops in 106ms)
AES-256-GCM encrypt (1 KiB)     56305.7 ops/sec  (5000 ops in 89ms)
```

Every run is capped by both duration and an absolute operation budget per
primitive, so a benchmark cannot overload a token indefinitely. Still, avoid
benchmarking production HSMs serving live traffic.

## Web interface & REST API

```sh
export HSM_PIN=123456
hsmdoctor serve --module /usr/lib/softhsm/libsofthsm2.so --pin-env HSM_PIN
# → http://127.0.0.1:8080
```

The embedded web interface (Vue 3) covers dashboard with health score and
findings, inventory browsing, certificate expiry, functional tests,
benchmarks and the fleet view with score history and drift feeds. Scans are
persisted to SQLite, consecutive scans are diffed automatically, and
`/metrics` exposes Prometheus gauges per HSM. Everything is also available
as a JSON API under `/api/v1` — see [docs/api.md](docs/api.md).

Optional hardening: `--auth-config` (bearer tokens with admin/viewer
roles), `--tls-cert`/`--tls-key`, `--webhook-url` for drift notifications
and `--schedule "0 */6 * * *"` for automatic scans.

## PKCS#11 Flight Recorder

A shim library sits between an application and its PKCS#11 module and records
every call as a trace, which the analyzer inspects for leaks, ordering bugs,
errors and slow calls:

```sh
make shim                                             # build hsmdoctor-trace.so
export HSMDOCTOR_TRACE_MODULE=/usr/lib/libpkcs11.so   # the real module
export HSMDOCTOR_TRACE_OUT=/tmp/trace.jsonl
myapp --pkcs11-module ./hsmdoctor-trace.so ...        # run any PKCS#11 app
hsmdoctor trace analyze /tmp/trace.jsonl
```

The shim **cannot leak secrets by construction**: its C layer forwards
buffer pointers straight to the real module and passes only metadata
(names, handles, mechanism codes, buffer lengths, return codes, timings) to
the trace. See [docs/trace.md](docs/trace.md).

## Vendor appliance health

PKCS#11 cannot report device resources, HA state, partition utilization or
tamper status. Vendor providers collect these through vendor tooling and
fold the findings into the health score:

```sh
hsmdoctor vendor --list
hsmdoctor scan --module ... --slot ... --vendor-config vendor.yaml
```

The **SoftHSM** reference provider is stable and doubles as a template;
**Luna**, **nShield** and **CloudHSM** ship as clearly-labeled experimental
skeletons built against public documentation. See
[docs/vendors.md](docs/vendors.md) for configuration and for writing your
own provider.

## Post-quantum readiness

```sh
hsmdoctor pqc --uri "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so" --pin-env HSM_PIN --test
```

```
FAMILY     STANDARD   ADVERTISED   MECHANISMS
ML-KEM     FIPS 203   YES          CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM
ML-DSA     FIPS 204   YES          CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA
SLH-DSA    FIPS 205   no

Quantum exposure:
  Private keys:      14 total, 14 classical, 0 post-quantum
  HNDL exposure:     3 classical decrypt/unwrap key(s)
  Summary:           14 of 14 private keys (100%) use quantum-vulnerable
                     algorithms; 3 of them can decrypt or unwrap and are
                     exposed to harvest-now-decrypt-later attacks. ...

Verdict: READY
```

Detection uses the PKCS#11 3.2 mechanism assignments; `--test` proves
advertised families with ephemeral session objects (ML-DSA/SLH-DSA
keygen+sign+verify per parameter set). Quantum-vulnerable inventory
exposure — with special attention to decrypt/unwrap keys threatened by
harvest-now-decrypt-later — also appears as an informational block in
every scan report and as Prometheus series.

## Fleet monitoring (central mode)

Monitor many HSMs across hosts: run a central server, then enroll an agent
on every machine that has a vendor PKCS#11 client installed. PINs never
leave the agent hosts — only finished reports are pushed.

```sh
# On the central host
export HSMDOCTOR_ENROLL=$(openssl rand -hex 16)
hsmdoctor server --listen 0.0.0.0:8443 --tls-cert srv.pem --tls-key srv.key \
  --auth-config auth.yaml --enroll-token-env HSMDOCTOR_ENROLL

# On each HSM client host
hsmdoctor agent --server https://doctor.example.com:8443 \
  --enroll-token-env HSMDOCTOR_ENROLL \
  --module /usr/lib/libCryptoki2_64.so --pin-env HSM_PIN --interval 15m
```

Alerts reach both machines and people: `--webhook-url` POSTs on drift, and
`--notify-config` e-mails drift alerts and certificate-expiry reminders over
SMTP (reminders deduplicated per certificate and threshold).

The server persists history to SQLite by default, or to PostgreSQL when
`--db` (or `HSMDOCTOR_DB`) is a `postgres://` DSN — recommended for fleets:

```sh
hsmdoctor server --db "postgres://hsmdoctor:***@db:5432/hsmdoctor?sslmode=require" ...
```

Human operators can sign in with **OIDC Single Sign-On** (Keycloak, Okta,
Azure AD, ...): the server runs the authorization-code flow and maps group
claims to admin/viewer, while static tokens keep working for automation.
Configure it in the `--auth-config` file.

Optionally require **mutual TLS**: `--client-ca` on the server accepts only
agents presenting a certificate signed by your CA (a transport factor on top
of the bearer token), with `--tls-client-cert`/`--server-ca` on the agent.

See [docs/deployment.md](docs/deployment.md) for the full setup including
storage backends, authentication, mutual TLS, webhooks, e-mail notifications
and systemd units.

## Documentation

Full documentation lives in [docs/](docs/) — start with the
[documentation index](docs/README.md). Highlights: the
[command reference](docs/cli.md), the [deployment guide](docs/deployment.md),
[policy rules](docs/rules.md), the [REST API](docs/api.md),
[vendor providers](docs/vendors.md), the [Flight Recorder](docs/trace.md) and
the [architecture overview](docs/architecture.md).

## Stability

From 1.0, HSM Doctor follows [Semantic Versioning](https://semver.org). CLI
flags, JSON output, the trace format and config file formats are stable
within a major version; the Luna/nShield/CloudHSM vendor providers and the
Flight Recorder's function coverage are explicitly experimental. See the
[compatibility policy](docs/compatibility.md).

## Roadmap

- **Beyond 1.0** — validating the experimental vendor providers against real hardware, broader Flight Recorder coverage with simulator replay, and a stable vendor plugin API.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for build
and test instructions and [docs/testing.md](docs/testing.md) for the test
layers. Report security issues privately per [SECURITY.md](SECURITY.md). Every
push runs unit, integration, PostgreSQL, Flight Recorder and post-quantum
tests plus `govulncheck` in CI.

## License

Licensed under the [Apache License 2.0](LICENSE).
