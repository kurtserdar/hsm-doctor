# HSM Doctor

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

## Features (v0.1)

| Command | What it does |
|---|---|
| `hsmdoctor discover` | Module, slot, token and mechanism discovery |
| `hsmdoctor scan` | Key/certificate inventory + security posture rules + health score; text, JSON or single-file HTML report |
| `hsmdoctor test` | Safe functional test profiles (key generation, sign/verify, AES-GCM) with ephemeral session objects |
| `hsmdoctor snapshot` | Record the full metadata state of a token as JSON |
| `hsmdoctor diff` | Compare two snapshots and report drift: new/removed objects, attribute flips, mechanism and firmware changes |

## Install

Binaries require cgo (the PKCS#11 wrapper uses dlopen), so build with a C
compiler present:

```sh
git clone https://github.com/kurtserdar/hsm-doctor.git
cd hsm-doctor
make build          # produces ./hsmdoctor
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
role-mixing keys and legacy mechanisms. Rules are plain YAML and fully
customizable — see [docs/rules.md](docs/rules.md):

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

## Roadmap

- **v0.2** — certificate expiration monitoring, performance testing (rate-limited by default), REST API, local web UI
- **v0.3** — central server mode, agent architecture, multi-HSM dashboard, Prometheus metrics
- **v1.0** — vendor plugins (Luna, nShield, ...) for HA/appliance/partition health, PQC readiness checks (ML-DSA, ML-KEM), PKCS#11 call tracing, policy packs

## Development

See [docs/testing.md](docs/testing.md). Every push runs unit tests plus
SoftHSM-backed integration tests in CI.

## License

Licensed under the [Apache License 2.0](LICENSE).
