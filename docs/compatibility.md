# Compatibility and stability policy

From **1.0.0**, HSM Doctor follows [Semantic
Versioning](https://semver.org/spec/v2.0.0.html): within a major version,
the stable interfaces below do not change in backward-incompatible ways.
Breaking changes are reserved for a new major version.

## Stable (covered by SemVer)

- **CLI commands and flags.** Existing commands and flags keep their meaning.
  Flags may be added; existing ones are not removed or repurposed within a
  major version. Deprecated flags keep working (with a warning) for at least
  one minor release before removal in the next major.
- **JSON output.** The JSON produced by `--json`/`--format json` for `scan`,
  `certs`, `pqc`, `test`, `bench`, `snapshot`, `diff`, `vendor`, `trace` and
  the `/api/v1` REST endpoints. Fields may be **added**; existing fields keep
  their name and meaning. Consumers should ignore unknown fields.
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

- **Vendor providers `luna`, `nshield`, `cloudhsm` and `bouncyhsm`.** The
  first three are built against public documentation and **not validated
  against real hardware**; `bouncyhsm` targets a software simulator through
  its REST API. Their findings, parsing and configuration keys may change as
  they are hardened. The `softhsm` reference provider is stable.
- **Flight Recorder shim function coverage.** The shim instruments a curated,
  growing subset of the PKCS#11 API. Which functions are traced may expand
  between minor releases (the trace *format* is stable). Because that set is
  the denominator, `trace coverage` ratios may shift across releases even for
  the same trace.
- **PQC functional probes for ML-KEM.** Reported as `KEYGEN ONLY` until
  key-encapsulation is wired through the underlying wrapper; this may change
  to a full probe.

## Distribution artifacts

Release binaries, the `ghcr.io/kurtserdar/hsm-doctor` container image and its
tags (`:vX.Y.Z`, `:latest`), the keyless cosign signatures and the CycloneDX
SBOM are distribution conveniences, not compatibility interfaces: their
presence, naming and contents may change between releases. Verify downloads
against the signed `SHA256SUMS.txt` — see [SECURITY.md](../SECURITY.md).

## Not an interface

Log line wording, human-readable text/HTML report layout, exact wording of
error messages, and internal Go packages (`internal/...`) are not stable
interfaces and may change at any time.

## Go module

The module path is `github.com/kurtserdar/hsm-doctor`. Only `cmd/hsmdoctor`
is a supported entry point; the `internal/` packages are implementation
detail and carry no compatibility guarantee.
