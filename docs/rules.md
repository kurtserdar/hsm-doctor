# Security posture rules

`hsmdoctor scan` evaluates the token inventory against a rule set. The
built-in rules live in [`rules/default.yaml`](../rules/default.yaml) and are
compiled into the binary; pass `--rules my-rules.yaml` to use your own.

## Policy packs

Curated rule sets ship inside the binary — list them with
`hsmdoctor packs`:

| Pack | Focus |
|---|---|
| `default` | Balanced baseline (used when nothing else is selected) |
| `nist` | Key strength and algorithm transitions (SP 800-57 / 800-131A aligned) |
| `cabf` | CA/Browser Forum TLS Baseline Requirements inspired checks |
| `strict` | Attribute hygiene for high-assurance deployments |
| `pqc-migration` | Post-quantum migration advisories (info severity, score-neutral) |
| `fips-140-3` | FIPS 140-3 approved-algorithm alignment (key strength, no SHA-1/MD5/DES) |
| `pci-hsm` | PCI HSM / PCI PIN inspired: non-exportable keys and role separation |
| `cnsa-2.0` | NSA CNSA 2.0: RSA-3072+/P-384 and PQC (ML-KEM/ML-DSA) migration |

Packs combine freely and also accept file paths, so corporate packs ride the
same mechanism:

```sh
hsmdoctor scan --pack nist --pack strict --pack ./corporate.yaml ...
```

Rule IDs must stay unique across combined packs (built-in packs use
NIST-/CABF-/STRICT-/PQCM- prefixes). Reports record the applied packs in
`rule_packs`. The compliance-inspired packs are guidance, not certification
statements. `--rules FILE` still replaces everything for backward
compatibility and is mutually exclusive with `--pack`.

A pack may declare metadata shown by `hsmdoctor packs`:

```yaml
pack:
  name: corporate
  description: ACME internal HSM policy, v3.
```

## File structure

```yaml
scoring:            # optional; defaults shown
  critical: 25      # health score penalty per finding
  high: 10
  medium: 5
  low: 2

rules:
  - id: ORG-001                  # unique, required
    title: Extractable private key
    severity: critical           # critical | high | medium | low
    description: Optional longer explanation shown in reports.
    remediation: Regenerate the key with CKA_EXTRACTABLE=false.  # optional fix
    reference: https://example.com/policy                        # optional URL
    match:                       # all conditions must hold (logical AND)
      class: private-key
      extractable: true
```

The health score starts at 100; every finding subtracts its severity
penalty, with a floor of 0.

`remediation` (a short actionable fix) and `reference` (a URL) are optional.
When set they appear under each finding in text and HTML reports, and populate
the rule `help`/`helpUri` fields in SARIF output.

## Output formats

`scan --format` accepts `text` (default), `json`, `html` and `sarif`. The
SARIF 2.1.0 output (`--format sarif`) lets scan results be uploaded to
code-scanning dashboards such as GitHub Advanced Security: each rule carries
its severity (mapped to a SARIF level and a `security-severity` score) and its
remediation, and each finding carries the offending object as a logical
location. Both posture and vendor findings are included.

Unknown fields anywhere in the file are rejected, so typos fail loudly
instead of producing rules that never match.

## Condition reference

| Condition | Type | Meaning |
|---|---|---|
| `class` | string | Object class: `private-key`, `public-key`, `secret-key`, `certificate` |
| `key_type` | string | Key type as reported in the inventory: `RSA`, `EC`, `AES`, ... |
| `key_type_in` | list | Key type is one of the listed values |
| `extractable` | bool | Matches `CKA_EXTRACTABLE` |
| `sensitive` | bool | Matches `CKA_SENSITIVE` |
| `always_sensitive` | bool | Matches `CKA_ALWAYS_SENSITIVE` |
| `never_extractable` | bool | Matches `CKA_NEVER_EXTRACTABLE` |
| `modifiable` | bool | Matches `CKA_MODIFIABLE` |
| `sign` / `verify` / `encrypt` / `decrypt` / `derive` / `wrap` / `unwrap` | bool | Matches the corresponding `CKA_*` capability |
| `key_size_lt` | int | Key size in bits is known and below this value |
| `curve_in` | list | EC curve name is one of the listed values |
| `curve_not_in` | list | EC curve name is known and outside the listed allow-list |
| `cert_expired` | bool | Certificate validity has ended |
| `cert_expires_within_days` | int | Certificate expires within N days (excludes already-expired) |
| `cert_validity_days_gt` | int | Certificate validity period exceeds N days |
| `cert_validity_days_lt` | int | Certificate total validity period is under N days (short-lived) |
| `cert_lifetime_remaining_pct_lt` | int | Less than N% of the certificate's lifetime remains (renewal threshold; excludes already-expired) |
| `cert_sig_alg_in` | list | Certificate signature algorithm is listed (Go x509 names, e.g. `SHA1-RSA`) |
| `cert_is_ca` | bool | Certificate basic constraints CA flag |
| `cert_self_signed` | bool | Certificate issuer equals subject (self-signed) |
| `cert_not_yet_valid` | bool | Certificate `notBefore` is in the future |
| `cert_key_size_lt` | int | Certificate's own public key is smaller than N bits |
| `cert_pubkey_alg_in` | list | Certificate public-key algorithm is listed (e.g. `RSA`, `ECDSA`) |
| `cert_ca_without_keycertsign` | bool | CA certificate lacking the `keyCertSign` key usage |
| `cert_key_mismatch` | bool | Certificate public key does not match the key sharing its `CKA_ID` |
| `cert_chain_broken` | bool | Certificate fails to build a valid chain to the `--ca-bundle` trust anchors (only checked when a bundle is given) |
| `duplicate_label` | bool | Another object of the same class shares the label |
| `orphan` | bool | Private key with no certificate/public key sharing its `CKA_ID`, or certificate with no private key sharing its `CKA_ID` |
| `mechanism_any_of` | list | Token-scoped: fires when the token advertises any listed `CKM_*` name |
| `mechanism_missing` | list | Token-scoped: fires when the token advertises none of the listed `CKM_*` names |

Severities: `critical`, `high`, `medium`, `low` and `info`. Info findings
are advisory: they appear in reports but never reduce the health score.

Notes:

- Boolean conditions are tri-state: they only match objects that actually
  expose the attribute. An object that hides `CKA_EXTRACTABLE` is never
  matched by `extractable: true` — absence is reported as absence, not
  guessed.
- Keys and their certificates legitimately share labels, so
  `duplicate_label` only counts duplicates within the same object class.
- `mechanism_any_of` cannot be combined with object conditions; it produces
  one token-level finding listing the matched mechanisms.
