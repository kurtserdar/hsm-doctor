# Compatibility and stability policy

From **1.0.0**, HSM Doctor follows [Semantic
Versioning](https://semver.org/spec/v2.0.0.html): within a major version,
the stable interfaces below do not change in backward-incompatible ways.
Breaking changes are reserved for a new major version.

## Versioning cadence

Which part of the version bumps follows directly from the interfaces below:

- **MAJOR** (`X.0.0`) — a backward-incompatible change to a stable interface:
  removing or repurposing a CLI flag, removing or changing the meaning of a
  JSON/REST field, removing a config key, breaking the trace or snapshot
  format, or dropping forward migration of a 1.x database.
- **MINOR** (`1.X.0`) — backward-compatible new user-facing functionality: a
  new command or flag, new JSON fields, a new vendor provider, new rules or
  policy packs, a new report format.
- **PATCH** (`1.x.Y`) — everything else that is backward-compatible and adds
  no new functionality: bug fixes, documentation, CI, internal refactors, and
  dependency or toolchain upgrades that do not change behavior.

## Stable (covered by SemVer)

- **CLI commands and flags.** Existing commands and flags keep their meaning.
  Flags may be added; existing ones are not removed or repurposed within a
  major version. Deprecated flags keep working (with a warning) for at least
  one minor release before removal in the next major.
- **JSON output.** The JSON produced by `--json`/`--format json` for `scan`,
  `certs`, `pqc`, `test`, `bench`, `snapshot`, `diff`, `vendor`, `trace` and
  the `/api/v1` REST endpoints. Fields may be **added**; existing fields keep
  their name and meaning. Consumers should ignore unknown fields.
- **SARIF output.** `scan --format sarif` conforms to the OASIS SARIF 2.1.0
  schema, so its shape is fixed by that standard; the mapping of severities to
  SARIF levels and `security-severity` scores is stable within a major version.
- **Trace format.** The Flight Recorder JSON Lines schema (`internal/trace`
  `Event`). New fields may be added; existing ones are stable.
- **Configuration file formats.** The rules/policy-pack YAML, the auth config
  (including the `oidc` section), the vendor config and the notify config.
  New keys may be added; existing keys keep their meaning. Unknown keys are
  rejected, so add keys only in a compatible way.
- **Snapshot format.** `hsmdoctor snapshot` output remains readable by
  `hsmdoctor diff` across a major version.
- **Storage schema migrations.** Databases created by an older 1.x are
  migrated forward automatically; downgrades are not supported.

## Experimental (not covered by SemVer)

These may change or be replaced in a minor release. They are clearly labeled
in output and docs:

- **Vendor providers `luna`, `nshield`, `cloudhsm`, `gcp`, `azure-hsm` and
  `bouncyhsm`.** `luna`, `nshield` and `cloudhsm` are built against public
  documentation and **not validated against real hardware**; `gcp` (Google
  Cloud HSM) and `azure-hsm` (Azure Managed HSM) shell out to the cloud CLI and
  are **not validated against live accounts**; `bouncyhsm` targets a software
  simulator through its REST API. Their findings, parsing and configuration
  keys may change as they are hardened. The `softhsm` reference provider is
  stable.
- **Flight Recorder shim function coverage.** The shim instruments a curated,
  growing subset of the PKCS#11 API. Which functions are traced may expand
  between minor releases (the trace *format* is stable). Because that set is
  the denominator, `trace coverage` ratios may shift across releases even for
  the same trace.
- **PQC functional probes for ML-KEM.** On a PKCS#11 3.2 module the probe now
  runs a full encapsulate/decapsulate round trip; it reports `KEYGEN ONLY` when
  the module offers no `C_EncapsulateKey` (pre-3.2), and on Windows or non-cgo
  builds, where the round trip is unavailable.
- **KMIP diagnostics (`kmip scan`).** A first-pass KMIP 1.x integration
  validated against PyKMIP; its `KMIP-00x` rules, attribute mapping and flags
  may change as it is validated against more servers.

## Distribution artifacts

Release binaries, the `ghcr.io/kurtserdar/hsm-doctor` container image and its
tags (`:vX.Y.Z`, `:latest`), the keyless cosign signatures and the CycloneDX
SBOM are distribution conveniences, not compatibility interfaces: their
presence, naming and contents may change between releases. Verify downloads
against the signed `SHA256SUMS.txt` — see [SECURITY.md](../SECURITY.md).

## Not an interface

Log line wording, human-readable text/HTML report layout, the embedded web UI
(its layout, styling, themes and translations), exact wording of error
messages, and internal Go packages (`internal/...`) are not stable interfaces
and may change at any time.

## Go module

The module path is `github.com/kurtserdar/hsm-doctor`. Only `cmd/hsmdoctor`
is a supported entry point; the `internal/` packages are implementation
detail and carry no compatibility guarantee.

## Extending

New vendor providers are added **in-tree**: implement the provider interface
under `internal/vendors/<name>` and open a pull request (see
[vendors.md](vendors.md) and [CONTRIBUTING.md](../CONTRIBUTING.md)). The
provider interface is intentionally internal for now and is **not** a stable
public plugin API — it may still change as the vendor layer evolves. A public,
SemVer-stable provider API may follow if there is demand for out-of-tree
providers.
