# Security Policy

HSM Doctor is a security tool that interacts with Hardware Security Modules.
We take vulnerabilities in it seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues, discussions or pull requests.**

Instead, report privately through either:

- GitHub's **[private vulnerability reporting](https://github.com/kurtserdar/hsm-doctor/security/advisories/new)**
  (Security → Advisories → Report a vulnerability), or
- e-mail to **serdar.kurt@outlook.com** with the subject line
  `HSM Doctor security report`.

Please include:

- a description of the issue and its impact,
- the affected version(s) or commit,
- steps to reproduce or a proof of concept, and
- any suggested remediation.

You will receive an acknowledgement within a few days. We will work with you
on a fix and a coordinated disclosure timeline, and credit you in the release
notes unless you prefer to remain anonymous.

## Scope

Security-relevant properties this project aims to uphold — reports that these
are violated are in scope:

- **Secrets are never logged or transmitted.** PINs, private key material,
  plaintext, database DSN passwords and SMTP passwords must not appear in
  logs, traces or reports. The PKCS#11 Flight Recorder shim records metadata
  only (function names, handles, mechanism codes, buffer lengths, return
  codes) and never captures buffer contents.
- **Private key material never leaves the HSM.** Inventory and scanning read
  only public metadata attributes.
- **Authentication is enforced correctly.** Static API tokens use
  constant-time comparison; OIDC uses state, nonce and PKCE with signed,
  HttpOnly session cookies; mutual TLS verifies client certificates against
  the configured CA; agent tokens are stored only as hashes.

## Supported versions

Security fixes are provided for the latest released minor version. Please
upgrade to the most recent release before reporting.
