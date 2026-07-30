# Architecture

HSM Doctor is a single Go binary (plus an optional c-shared shim) built
around a vendor-neutral core over PKCS#11.

```
                         hsmdoctor (single binary)
   ┌───────────────────────────┴───────────────────────────┐
   │  CLI (Cobra)          serve / server (REST + web UI)   │
   └───────────────────────────┬───────────────────────────┘
                               │
   inventory ─ policy ─ pqc ─ certmon ─ funtest ─ bench ─ snapshot ─ vendors
                               │
                        p11 (miekg/pkcs11)
                               │
                     vendor PKCS#11 module ─ HSM

   store (SQLite | PostgreSQL)      notify (SMTP)      trace (analyzer)
                                                            ▲
                              hsmdoctor-trace.so (shim) ────┘
```

## Core packages (`internal/`)

- **p11** — a thin, diagnostics-oriented wrapper over `miekg/pkcs11`:
  module/slot/token/mechanism info and safe session helpers. Never reads
  private key material. **p11names** holds the cgo-free CKM/CKR name tables
  (also used by the shim).
- **inventory** — metadata-only collection of keys and certificates.
- **policy** — the YAML rule engine, health scoring and policy-pack merging
  (`rules/` embeds the default set and packs).
- **pqc** — post-quantum readiness detection, functional probes and
  quantum-exposure analysis.
- **certmon**, **funtest**, **bench**, **snapshot** — certificate expiry,
  functional test profiles, bounded benchmarks, and drift diffing.
- **report** — text, JSON and self-contained HTML reports.
- **vendors** — the vendor provider registry and providers (SoftHSM stable;
  Luna/nShield/CloudHSM experimental) for appliance-level health.
- **trace** — the Flight Recorder trace format and analyzer.

## Server, fleet and platform

- **server** — the REST API and embedded Vue web UI. In *local* mode it
  scans its own module; in *central* mode it has no module and ingests
  reports pushed by agents.
- **agent** — runs where the vendor PKCS#11 client lives, scans on an
  interval and pushes reports to the central server. The PIN never leaves the
  agent host.
- **store** — persistence behind one `Store` interface with SQLite and
  PostgreSQL implementations, verified by a shared conformance suite. Holds
  scan history, drift events, agents and the notification ledger.
- **notify** — SMTP e-mail for drift alerts and certificate-expiry reminders.
- Authentication: static bearer tokens (admin/viewer), OIDC Single Sign-On,
  and mutual TLS — see [deployment.md](deployment.md).

## The trace shim (`shim/`)

A separate cgo `c-shared` library the application loads in place of its real
PKCS#11 module. It forwards each call to the real module and records
metadata as a JSON Lines trace. The C layer passes only lengths, handles,
mechanism and return codes to Go, so the shim cannot capture secrets by
construction. See [trace.md](trace.md).

## Design principles

- **Metadata only** — private key material and secrets never leave the HSM
  or reach logs, traces or reports.
- **Vendor-neutral core, vendor plugins at the edge** — everything possible
  is done through standard PKCS#11; vendor-specific appliance data lives in
  pluggable providers.
- **Single binary** — the CLI, web UI (embedded) and every feature ship in
  one artifact; only the trace shim is built separately.
- **The same behavior, tested** — backends and platforms are covered by
  shared conformance and integration suites in CI (SoftHSM, PostgreSQL,
  Kryoptic for PQC, and the shim end-to-end).
