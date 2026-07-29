# Security posture rules

`hsmdoctor scan` evaluates the token inventory against a rule set. The
built-in rules live in [`rules/default.yaml`](../rules/default.yaml) and are
compiled into the binary; pass `--rules my-rules.yaml` to use your own.

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
    match:                       # all conditions must hold (logical AND)
      class: private-key
      extractable: true
```

The health score starts at 100; every finding subtracts its severity
penalty, with a floor of 0.

Unknown fields anywhere in the file are rejected, so typos fail loudly
instead of producing rules that never match.

## Condition reference

| Condition | Type | Meaning |
|---|---|---|
| `class` | string | Object class: `private-key`, `public-key`, `secret-key`, `certificate` |
| `key_type` | string | Key type as reported in the inventory: `RSA`, `EC`, `AES`, ... |
| `extractable` | bool | Matches `CKA_EXTRACTABLE` |
| `sensitive` | bool | Matches `CKA_SENSITIVE` |
| `sign` | bool | Matches `CKA_SIGN` |
| `decrypt` | bool | Matches `CKA_DECRYPT` |
| `wrap` | bool | Matches `CKA_WRAP` |
| `unwrap` | bool | Matches `CKA_UNWRAP` |
| `key_size_lt` | int | Key size in bits is known and below this value |
| `cert_expired` | bool | Certificate validity has ended |
| `cert_expires_within_days` | int | Certificate expires within N days (excludes already-expired) |
| `duplicate_label` | bool | Another object of the same class shares the label |
| `orphan` | bool | Private key with no certificate/public key sharing its `CKA_ID`, or certificate with no private key sharing its `CKA_ID` |
| `mechanism_any_of` | list | Token-scoped: fires when the token advertises any listed `CKM_*` name |

Notes:

- Boolean conditions are tri-state: they only match objects that actually
  expose the attribute. An object that hides `CKA_EXTRACTABLE` is never
  matched by `extractable: true` — absence is reported as absence, not
  guessed.
- Keys and their certificates legitimately share labels, so
  `duplicate_label` only counts duplicates within the same object class.
- `mechanism_any_of` cannot be combined with object conditions; it produces
  one token-level finding listing the matched mechanisms.
