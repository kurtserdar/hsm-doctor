# HSM Doctor

**The open-source toolbox for HSM health, security posture and PKCS#11 diagnostics.**

HSM Doctor is an open-source, vendor-neutral platform for discovering, testing,
monitoring and assessing the security posture of Hardware Security Modules (HSMs).

It talks to any HSM through the standard PKCS#11 interface — Thales Luna,
Entrust nShield, Utimaco, Procenne, AWS CloudHSM, SoftHSM, BouncyHSM and others —
and turns raw token data into an understandable risk and operations report.

> **Status:** early development, working towards v0.1. Interfaces and output
> formats may change without notice.

## Why?

Excellent low-level PKCS#11 tools already exist for listing objects and running
crypto operations. What is missing is a tool that answers the questions an HSM
administrator actually asks:

- What keys and certificates live on this token, and are they configured safely?
- Are there extractable private keys, weak key sizes, expiring certificates?
- Does this HSM still behave the way it did yesterday? What changed?
- Can my application workload (TLS signing, code signing, key wrapping) actually
  run against this device?

## Planned v0.1 features

- **Discovery** — PKCS#11 module, slot, token and mechanism inventory
- **Key inventory** — metadata-only collection (labels, IDs, types, sizes,
  attribute flags, certificate details); private key material is never read
- **Security posture** — YAML-defined rules with severities and a health score
- **Functional tests** — safe sign/verify test profiles using ephemeral session
  objects only
- **Snapshot & drift detection** — record the state of a token and diff it later
- **Reports** — console, JSON and self-contained HTML output

## License

Licensed under the [Apache License 2.0](LICENSE).
