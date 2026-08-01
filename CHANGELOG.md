# Changelog

All notable changes to HSM Doctor are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and from 1.0.0 the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the guarantees in [docs/compatibility.md](docs/compatibility.md).

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
