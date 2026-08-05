# Changelog

All notable changes to HSM Doctor are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and from 1.0.0 the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the guarantees in [docs/compatibility.md](docs/compatibility.md).

## [1.24.1] - 2026-08-05

### Fixed

- Restored a green CI: `internal/store/store.go` had drifted out of `gofmt`
  format after the Go 1.25 toolchain bump, failing the CI formatting gate (the
  release workflow does not run it, so it went unnoticed). Reformatted it, and
  resolved the lint findings that the failing gate had been masking (errcheck on
  deferred `store.Store`/`kmip.Client` cleanup via `.golangci.yml`, a `net.Conn`
  close in a test, and a staticcheck tagged-switch suggestion in `internal/pqc`).
- Documentation: added the `packs` and `version` commands to the README command
  table.

## [1.24.0] - 2026-08-05

### Added

- Monitoring bundle under `deploy/monitoring/`: ready-made Prometheus alert
  rules (health score, critical findings, certificate expiry, posture
  regression, shared private keys, vendor tamper, HA degradation, stale scans,
  PQC exposure) and an importable Grafana fleet dashboard. Either drop them into
  your own Prometheus/Grafana, or start the turnkey stack with
  `docker compose --profile monitoring up -d` (Prometheus + Grafana,
  datasource and dashboard auto-provisioned).

### Fixed

- `deploy/.env.example` is now tracked in the repository. A broad `.env.*`
  gitignore rule had excluded it, so fresh clones were missing the template the
  deploy guide tells you to copy.

## [1.23.0] - 2026-08-05

### Added

- `kmip scan` gains output-pipeline parity with `scan`: `--format sarif` emits
  SARIF 2.1.0 (each finding qualified by the server endpoint), and `--baseline
  FILE` / `--baseline-max-drop N` gate CI on a KMIP posture regression using the
  same detection logic as `scan --baseline`. The SARIF emitter was refactored
  into a reusable `report.FindingsSARIF` so every scanner emits identical SARIF.

## [1.22.1] - 2026-08-05

### Fixed

- Web UI: the sidebar language picker no longer renders with a white background
  in the light theme; it now matches the dark rail (in both themes), including
  its option list.

## [1.22.0] - 2026-08-05

### Added

- `hsmdoctor doctor` — a one-shot health diagnosis that aggregates the core
  checks (inventory, posture, certificate expiry, post-quantum exposure, and
  optionally functional tests with `--with-tests` and vendor health with
  `--vendor-config`) into a single verdict (healthy / attention / critical), the
  health score and the most important issues first, each with a suggested
  action. `--fail-on attention|critical` turns overall health into a CI gate;
  `--format json` for machine consumption. It aggregates the other checks
  rather than adding new ones, so its findings match `scan`.

## [1.21.0] - 2026-08-05

### Added

- `hsmdoctor evidence --pack <name>` — an auditor-facing compliance evidence
  report. Evaluates a token against one or more policy packs and renders, per
  control, a pass / fail / not-applicable verdict with the objects behind each
  failure, as single-file HTML or structured JSON. A control fails exactly when
  a `scan` with the same pack produces a finding for its rule; a control is
  not-applicable when the token holds no object of the kind it checks.
- `docs/how-it-works.md` — a diagram-driven walkthrough of the pieces, the
  journey of a scan, the fleet data path, the Flight Recorder and the reports.

## [1.20.0] - 2026-08-04

### Added

- Fleet shared-key detection — the central server correlates the latest scan of
  every HSM and flags a private key whose public-key fingerprint appears on more
  than one HSM (a sign the key material was copied out of hardware). Exposed via
  `GET /api/v1/shared-keys`, a "Shared private keys" section on the fleet
  dashboard and the `hsmdoctor_shared_private_keys` Prometheus gauge. Uses only
  the public fingerprint already in the inventory; no private key material is
  read. Symmetric secret keys expose no fingerprint and are out of scope.

## [1.19.0] - 2026-08-04

### Added

- `scan --format cbom` — a CycloneDX 1.6 Cryptographic Bill of Materials of the
  token's keys, certificates and the algorithms behind them, with a dependency
  graph and an `hsmdoctor:quantumVulnerable` annotation (plus
  `nistQuantumSecurityLevel` where meaningful) on every algorithm. Only assets
  present on the token are listed; output is deterministic for clean diffing.
  Intended as the starting inventory for a post-quantum migration.

## [1.18.0] - 2026-08-04

### Added

- `hsmdoctor preflight` — a renewal-readiness gate that checks a token is
  present and initialized, the PIN logs in, the required mechanisms are
  available (`--mechanism`) and enough sessions are free (`--min-free-sessions`),
  with an optional ephemeral keygen/sign probe (`--probe`) and vendor tamper/HA
  input (`--vendor-config`). Machine-friendly exit codes: 0 ready, 4 postpone,
  1 error. Intended as the check a certificate-lifecycle system runs before an
  HSM-backed reissue.
- Policy conditions `cert_validity_days_lt` (short-lived certificate) and
  `cert_lifetime_remaining_pct_lt` (percentage-of-lifetime renewal threshold,
  correct across mixed 47/100/200/398-day validities). The `cabf` pack gains
  CABF-007 (past 80% of lifetime) and CABF-008 (short-lived certificate without
  renewal automation).
- `TokenInfo` now reports `max_session_count`/`session_count`.

## [1.17.4] - 2026-08-04

### Changed

- README: removed the hard-coded `v1.0.0` version badge (the dynamic release
  badge already tracks the latest version), listed the `gcp`/`azure-hsm`/
  `bouncyhsm` providers and KMIP in the stability summary, and noted the web
  UI's light/dark theme.

## [1.17.3] - 2026-08-04

### Changed

- Compatibility policy (`docs/compatibility.md`): list the `gcp` and
  `azure-hsm` cloud providers among the experimental providers, note that the
  `scan --format sarif` output follows the OASIS SARIF 2.1.0 schema, and state
  that the embedded web UI is not a stable interface.

## [1.17.2] - 2026-08-04

### Changed

- Documentation: refreshed every README screenshot for the current release —
  the web UI shots (dashboard, inventory, certificates, tests, bench, PQC,
  fleet, HSM history and vendor card) now show the polished design system and
  dark-aware components, and the CLI shots (scan, trace, discover) reflect the
  current output including per-finding remediation.

## [1.17.1] - 2026-08-04

### Changed

- Fitted the Inventory, Certificates, Tests and Bench views into the refreshed
  design system: object flags render as chips (risky ones tinted), benchmark
  throughput shows a proportional mini-bar per primitive, and the views gain
  skeleton loading and proper empty states.

## [1.17.0] - 2026-08-04

### Added

- Fleet view summary strip: total HSMs, how many need attention (score below
  70) and the average score, above the fleet table.

### Changed

- Fitted the PQC and Fleet views onto the refreshed design system (utility
  classes for checkbox labels and mechanism chips, a prominent PQC verdict
  badge, a proper empty state and skeleton loading on Fleet).

## [1.16.0] - 2026-08-04

### Added

- Web UI dark mode with an Auto/Light/Dark switcher in the sidebar; it follows
  the operating-system preference by default and persists the choice.

### Changed

- Web UI visual refresh (no new dependency): a token-driven design system
  (type scale, spacing, elevation), findings shown as severity-striped cards
  with a distribution bar instead of a flat table, softer badges, denser
  tables, skeleton loading and a sparkline area fill. Both themes are styled
  from the same tokens.

## [1.15.1] - 2026-08-03

### Changed

- Documentation: refreshed the README highlights, command table and roadmap to
  cover the current feature set (SARIF/remediation, deep certificate
  validation, posture-regression detection, full ML-KEM probe, `trace keys`,
  the `gcp`/`azure-hsm` cloud providers, compliance packs, the bilingual web UI
  and KMIP), and listed `docs/kmip.md` in the documentation index.

## [1.15.0] - 2026-08-03

### Added

- KMIP diagnostics (experimental): `hsmdoctor kmip scan` connects to a KMIP
  key-management server over (mutual) TLS, inventories its managed objects via
  `Discover Versions`/`Locate`/`Get Attributes`, and evaluates a security
  posture — weak keys (`KMIP-001`), compromised objects (`KMIP-002`),
  deactivated-but-not-destroyed keys (`KMIP-003`), sign+decrypt role mixing
  (`KMIP-004`) and unnamed objects (`KMIP-005`) — with a health score, text and
  JSON output, and `--fail-on` for CI. Read-only: it never creates, modifies or
  destroys keys. KMIP 1.x over TTLV via the gemalto/kmip-go primitives;
  validated against PyKMIP. See [docs/kmip.md](docs/kmip.md).

## [1.14.0] - 2026-08-03

### Added

- Web UI internationalization with English and Turkish. A language switcher in
  the sidebar persists the choice and defaults to the browser's language; the
  document `lang` follows the selection. Translation covers the UI chrome
  across every view (navigation, headings, table headers, buttons, labels and
  static help text) via a small dependency-free composable — no new frontend
  dependency. Text produced by the API (finding titles, remediation, verdicts,
  vendor detail) stays in the language the server produced it in.

## [1.13.0] - 2026-08-03

### Added

- ML-KEM functional probe now runs a full encapsulate/decapsulate round trip
  (`pqc --test`), verifying the two derived shared secrets match, instead of
  stopping at key generation. Because the Go PKCS#11 binding predates the 3.2
  KEM calls, `C_EncapsulateKey`/`C_DecapsulateKey` are reached through a small
  cgo shim that fetches the 3.2 interface and reuses the probe's session. The
  probe falls back to `KEYGEN ONLY` on modules without the 3.2 KEM interface,
  and on Windows or non-cgo builds. Validated against Kryoptic.

## [1.12.0] - 2026-08-03

### Added

- `trace keys --inventory scan.json` completes the unused-key analysis: it
  diffs the keys a trace used against the token's private and secret keys in a
  saved JSON report (from `scan --format json`) and lists the idle keys — those
  never observed used — as candidates for review or retirement. Idle results
  are trace-window evidence, so pair them with a representative trace. The
  usage summary's `--json` output gains an `idle` array.

## [1.11.0] - 2026-08-02

### Added

- `trace keys` summarizes which keys a Flight Recorder trace put to work: for
  each key the operations it was used for (sign, verify, encrypt, decrypt,
  wrap, unwrap) and the mechanisms seen. The shim now records the key handle on
  operation-init calls and the `CKA_LABEL`/`CKA_ID` a `C_FindObjectsInit`
  searched for, so a used handle maps back to a named key; operations on
  handles never located that way are grouped as unresolved. A key absent from
  the summary was simply not used during the trace window — pair a
  representative trace with `hsmdoctor scan` to spot idle keys. The recorded
  label/id are identifiers, not key material; PINs, key bytes and plaintext are
  still never recorded.

## [1.10.0] - 2026-08-02

### Added

- `scan --baseline FILE` gates CI on posture regression without a database:
  it compares the current scan against a saved JSON report (produced by
  `scan --format json --out`) and exits non-zero when the health score drops
  by `--baseline-max-drop` points (default 10) or a new critical/high finding
  appears, printing a summary to stderr. It reuses the same detection engine
  as the fleet server, and composes with `--fail-on` (relative vs absolute
  gating).

## [1.9.0] - 2026-08-02

### Added

- Posture-regression detection for the fleet: when a scan's security posture
  worsens relative to the previous scan — the health score drops by 10 or more
  points, or a new critical/high finding appears — the server records a
  regression event alongside the existing drift event. Regressions are exposed
  at `GET /api/v1/hsms/{id}/regressions`, shown in the HSM detail view, counted
  by the `hsmdoctor_posture_regressions_total` metric, and delivered through
  the webhook (`posture_regression` event) and e-mail (new `regression` toggle,
  default on). The score-history sparkline already visualises the trend.

## [1.8.0] - 2026-08-02

### Added

- Remediation guidance on findings: rules gain optional `remediation` (a short,
  actionable fix) and `reference` (a URL) fields, carried through to each
  finding. Every built-in rule — the default set and all seven policy packs —
  now ships remediation text, shown under each finding in text and HTML
  reports. Vendor findings can set the fields too.
- SARIF output: `scan --format sarif` writes a SARIF 2.1.0 log for upload to
  code-scanning dashboards (for example GitHub Advanced Security). Each rule
  maps its severity to a SARIF level and a `security-severity` score and
  carries its remediation as `help`/`helpUri`; each finding carries the
  offending object as a logical location. Posture and vendor findings are both
  included.

## [1.7.0] - 2026-08-02

### Added

- Two experimental cloud-HSM vendor providers, both driven through the vendor
  CLI (which also handles authentication): `gcp` for Google Cloud HSM (Cloud
  KMS via `libkmsp11`) reads `gcloud kms keys list` and flags software-protected
  keys, disabled or destruction-scheduled versions and symmetric keys without
  automatic rotation (`GCP-001`..`GCP-004`); `azure-hsm` for Azure Key Vault
  Managed HSM reads `az keyvault show` and flags an inactive security domain,
  incomplete provisioning, disabled purge protection and public network access
  (`AZUREHSM-001`..`AZUREHSM-004`).

## [1.6.0] - 2026-08-02

### Added

- Deeper certificate validation — structural per-certificate checks. New
  default posture rules (and match conditions) for self-signed leaf
  certificates (`HSM-014`), not-yet-valid certificates (`HSM-015`), weak RSA
  certificate keys (`HSM-016`) and CA certificates missing `keyCertSign`
  (`HSM-017`). The inventory now records each certificate's public-key size,
  self-signed flag and key usage.
- Certificate/key correspondence: `HSM-018` flags a certificate whose public
  key does not match the key sharing its `CKA_ID` (public-key fingerprint
  comparison, RSA and EC).
- Certificate chain validation (opt-in): `scan --ca-bundle FILE` verifies each
  certificate against the supplied trust anchors, using token CA certificates
  as intermediates; `HSM-019` flags certificates that do not chain.
- The `certs` command reports per-certificate validation warnings (self-signed,
  not-yet-valid, weak key, key mismatch, unverified chain) alongside expiry.

## [1.5.0] - 2026-08-02

### Added

- Three compliance-inspired policy packs: `fips-140-3` (FIPS 140-3 approved
  algorithms and key strengths), `pci-hsm` (PCI HSM / PCI PIN key protection
  and role separation) and `cnsa-2.0` (NSA CNSA 2.0 RSA-3072+/P-384 plus
  ML-KEM/ML-DSA migration). Guidance only — not a compliance or certification
  statement.
- Three default posture rules: certificate signed with SHA-1/MD5 (`HSM-011`),
  non-sensitive secret key (`HSM-012`) and extractable secret key (`HSM-013`).

## [1.4.1] - 2026-08-02

### Changed

- Documented the versioning cadence in `docs/compatibility.md`: MAJOR for a
  breaking change to a stable interface, MINOR for new user-facing
  functionality, PATCH for everything else (docs, CI, refactors, and
  behavior-neutral dependency/toolchain upgrades).

## [1.4.0] - 2026-08-02

### Changed

- Documented the extension model: vendor providers are added in-tree via pull
  request, and the provider interface is intentionally internal for now — not
  a stable public plugin API. A SemVer-stable provider API may follow if there
  is demand for out-of-tree providers (`docs/compatibility.md`, `docs/vendors.md`).

## [1.3.1] - 2026-08-01

### Changed

- Compatibility policy (`docs/compatibility.md`): list the `bouncyhsm` vendor
  provider as experimental, note that release/distribution artifacts
  (container image, cosign signatures, SBOM) are not compatibility interfaces,
  and clarify that `trace coverage` ratios can shift as the shim's function
  set grows.

## [1.3.0] - 2026-08-01

### Changed

- Web UI toolchain upgraded: Vite 7 → 8, vue-router 4 → 5, TypeScript 5.8 →
  6.0 (each verified with a build and a runtime pass of the embedded UI).
  TypeScript 7 is deliberately held — its native compiler drops the entry
  point `vue-tsc` relies on, so `vue-tsc` is not yet compatible.

## [1.2.0] - 2026-07-31

### Added

- `hsmdoctor trace coverage` — reports which PKCS#11 functions a Flight
  Recorder trace exercised (with call counts) and which it did not, measured
  against the functions the shim can observe; `--json` for machine output.
- `bouncyhsm` vendor provider (experimental) for
  [BouncyHsm](https://github.com/harrison314/BouncyHsm), the software HSM /
  PKCS#11 simulator. It reads BouncyHsm's REST API for version and object
  statistics — the first HTTP-based vendor provider — and always flags the
  simulator as non-production (`BOUNCYHSM-001`).

## [1.1.0] - 2026-07-31

### Added

- Docker image on GHCR with SoftHSM2 and OpenSC baked in, signed with cosign.
- Release hardening: checksums signed with keyless cosign and a CycloneDX SBOM
  attached to every release (see [SECURITY.md](SECURITY.md)).
- Dependabot updates for Go, npm and GitHub Actions.
- Illustrated getting-started guide ([docs/getting-started.html](docs/getting-started.html)),
  published via GitHub Pages.
- Example central-server deployment ([deploy/](deploy/)): a Docker Compose stack
  (PostgreSQL + fleet server) with a multi-vendor setup guide.
- nShield: security-world "not usable" finding (`NSHIELD-002`).
- CloudHSM: cross-availability-zone redundancy check (`CLOUDHSM-004`).

### Changed

- Hardened the experimental Luna/nShield/CloudHSM providers: more robust
  parsing, graceful degradation when secondary commands fail, and fixture-based
  tests covering error and edge cases.

### Fixed

- Luna: a bare `No` tamper state is no longer misread as a tamper condition
  (previously raised a false critical finding).

## [1.0.0]

First stable release. No functional change from 0.12.0 — this release marks
the point from which the interfaces listed in the compatibility policy are
covered by Semantic Versioning. See
[docs/compatibility.md](docs/compatibility.md) for what is stable and what
remains experimental (the Luna/nShield/CloudHSM vendor providers and the
Flight Recorder shim's function coverage).

### Added

- Community and contribution files: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue and pull-request templates.
- Compatibility and stability policy.
- `govulncheck` dependency scanning in CI.

## [0.12.0]

### Added

- E-mail notifications (`--notify-config`) for drift alerts and
  certificate-expiry reminders over SMTP (STARTTLS, implicit TLS or
  plaintext). Reminders are deduplicated per certificate and day threshold via
  a new store `notifications` table.

## [0.11.0]

### Added

- OIDC Single Sign-On: the central server acts as an OIDC Relying Party
  (authorization-code + PKCE, signed HttpOnly session cookies). Group claims
  map to admin/viewer; static tokens keep working alongside SSO.

## [0.10.0]

### Added

- Mutual TLS between agents and the central server: `--client-ca` on the
  server, `--tls-client-cert`/`--tls-client-key`/`--server-ca` on the agent.

## [0.9.0]

### Added

- PostgreSQL storage backend, selected by a `postgres://` DSN in `--db` (or
  `HSMDOCTOR_DB`). Both backends satisfy the same conformance suite.

## [0.8.0]

### Added

- PKCS#11 Flight Recorder: a shim library that records a JSON Lines call
  trace, and `hsmdoctor trace analyze`/`summary` to detect session and
  operation leaks, ordering bugs, errors and slow calls. Secret-safe by
  construction.

## [0.7.0]

### Added

- Vendor appliance data surfaced through `serve`/`server`/`agent`
  (`--vendor-config`), Prometheus vendor gauges and a web UI vendor card.

## [0.6.0]

### Added

- Vendor provider framework and the SoftHSM reference provider, plus
  experimental Luna, nShield and CloudHSM providers. Vendor findings feed the
  health score.

## [0.5.0]

### Added

- Policy packs: curated, combinable rule sets (`nist`, `cabf`, `strict`,
  `pqc-migration`) and `--pack`; new rule conditions and a score-neutral
  `info` severity.

## [0.4.1]

### Fixed

- Reference-count shared token logins so closing one authenticated session no
  longer logs out concurrent sessions.

## [0.4.0]

### Added

- Post-quantum readiness assessment (`hsmdoctor pqc`): ML-KEM/ML-DSA/SLH-DSA
  support matrix, functional probes, quantum-vulnerable inventory exposure and
  a host OpenSSL check.

## [0.3.0]

### Added

- Fleet platform: SQLite scan history with automatic drift detection, central
  server mode with enrollable push agents, a fleet dashboard, Prometheus
  metrics, bearer-token authentication (admin/viewer) and TLS, drift webhooks
  and cron-scheduled scans. RFC 7512 PKCS#11 URI addressing and a
  key-wrapping test profile.

## [0.2.0]

### Added

- Certificate expiry monitor (`certs`), bounded performance benchmarking
  (`bench`), a local REST API and an embedded Vue web interface (`serve`).
- Multi-platform release binaries.

## [0.1.0]

### Added

- First release: `discover`, `scan` (metadata-only inventory, YAML security
  posture rules with a health score, text/JSON/HTML reports), `test`
  (functional profiles with ephemeral session objects) and `snapshot`/`diff`
  drift detection. SoftHSM-backed integration tests and CI.

[1.0.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v1.0.0
[0.12.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.12.0
[0.11.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.11.0
[0.10.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.10.0
[0.9.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.9.0
[0.8.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.8.0
[0.7.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.7.0
[0.6.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.6.0
[0.5.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.5.0
[0.4.1]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.4.1
[0.4.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.4.0
[0.3.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.3.0
[0.2.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.2.0
[0.1.0]: https://github.com/kurtserdar/hsm-doctor/releases/tag/v0.1.0
