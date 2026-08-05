# KMIP diagnostics

`hsmdoctor kmip scan` connects to a [KMIP](https://docs.oasis-open.org/kmip/)
key-management server over TLS, inventories its managed objects and evaluates
their security posture — the KMIP counterpart of the PKCS#11 `scan`. It is
**read-only**: it never creates, modifies or destroys keys.

This is an experimental, first-pass integration covering KMIP 1.x over TTLV. It
speaks `Discover Versions`, `Locate` and `Get Attributes` and is validated
against PyKMIP; corrections from other servers (Thales CipherTrust, Fortanix,
Vault) are welcome.

## Connecting

```sh
hsmdoctor kmip scan \
  --endpoint kms.example.com:5696 \
  --server-ca ca.pem \
  --client-cert client.pem --client-key client-key.pem   # mutual TLS
```

- `--endpoint host:port` — the KMIP server (default port 5696).
- `--server-ca` — CA bundle to verify the server certificate. Omit and pass
  `--insecure` to skip verification (labs only).
- `--client-cert` / `--client-key` — client certificate for mutual TLS; most
  KMIP servers require it.
- `--format text|json|sarif`, `--out FILE`, `--fail-on <severity>` for CI, and
  `--timeout` behave as they do for `scan`. `--format sarif` emits the same
  SARIF 2.1.0 shape as `scan`, so KMIP findings upload to code-scanning
  dashboards too; each result is qualified by the server endpoint.
- `--baseline FILE` (with `--baseline-max-drop N`, default 10) compares the
  current posture against a saved JSON report and exits non-zero on a
  regression — the KMIP counterpart of `scan --baseline`, sharing the same
  detection logic.

## What it reports

For each managed object it reads the object type, cryptographic algorithm and
length, lifecycle state, cryptographic usage mask, names and initial date, then
applies the KMIP posture rules and computes a 0–100 health score (same scoring
as the PKCS#11 scan).

| Rule | Severity | Fires when |
|---|---|---|
| `KMIP-001` | high | A key is below the accepted strength (RSA/DSA/DH < 2048, ECC < 224, AES < 128, or DES/3DES) |
| `KMIP-002` | critical | An object is in the Compromised state but still present |
| `KMIP-003` | medium | An object is Deactivated but not destroyed |
| `KMIP-004` | medium | A key's usage mask grants both Sign and Decrypt (role mixing) |
| `KMIP-005` | low | A managed object has no Name attribute |

Findings carry remediation text, and `--fail-on` turns them into a non-zero
exit for CI.

## Custom rules

The built-in rules above are a YAML rule set evaluated by a small KMIP engine —
print it with `hsmdoctor kmip rules` as a starting point, and replace it with
your own via `kmip scan --rules FILE`. A rule is metadata plus a `match` whose
conditions must all hold (logical AND):

| Condition | Meaning |
|---|---|
| `object_type_in` | KMIP object type is listed (case-insensitive) |
| `algorithm_in` | Cryptographic algorithm is listed (case-insensitive) |
| `length_lt` | Known key length is below N bits |
| `state_in` | Lifecycle state is listed (case-insensitive) |
| `usage_all_of` | Usage mask grants every listed usage |
| `usage_any_of` | Usage mask grants any listed usage |
| `unnamed` | Object has (or lacks) a Name attribute |
| `weak_key` | Built-in below-minimum-strength heuristic (as in `KMIP-001`) |

```yaml
pack:
  name: strict-kmip
rules:
  - id: ORG-KMIP-001
    title: RSA key below 3072 bits
    severity: high
    remediation: Re-key at RSA-3072 or migrate to ECC P-384.
    match:
      algorithm_in: [RSA]
      length_lt: 3072
```

Unknown fields and rules with an empty `match` are rejected, so typos fail
loudly. `--rules` replaces the built-in set entirely.
