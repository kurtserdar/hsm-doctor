# Vendor providers

PKCS#11 exposes tokens and keys, but not appliance-level health: device
resources, HA/cluster state, partition utilization, tamper and backup
status. Vendor providers fill that gap by talking to vendor tooling, and
their findings feed the same health score as the PKCS#11 posture rules.

```sh
hsmdoctor vendor --list                                   # available providers
hsmdoctor vendor --module ... --slot ... --vendor-config vendor.yaml
hsmdoctor scan   --module ... --slot ... --vendor-config vendor.yaml
```

`scan` auto-detects the provider from the token's manufacturer/model and, if
the vendor configuration supplies what it needs, folds the vendor findings
into the report and score. Without `--vendor-config`, a detected provider
that needs settings is skipped with a note.

`serve` and `agent` accept the same `--vendor-config`: the local server and
push agents enrich every scan with vendor data, the central server stores it
with the report, and the web UI shows a vendor card. Prometheus exposes
`hsmdoctor_vendor_tamper`, `hsmdoctor_vendor_disk_percent`,
`hsmdoctor_vendor_ha_members_up` and `hsmdoctor_vendor_ha_members_total`,
labeled by serial, token label and provider.

## Provider status

| Provider | Status | Transport | Notes |
|---|---|---|---|
| `softhsm` | Stable | local filesystem | Reference implementation; token-store disk usage and permissions |
| `luna` | **Experimental** | lunash over SSH | Parses `hsm show` / `partition list`; not validated on real hardware |
| `nshield` | **Experimental** | local `enquiry` / `nfkminfo` | Module mode and security-world state |
| `cloudhsm` | **Experimental** | AWS CLI | `cloudhsmv2 describe-clusters`; cluster/HSM/HA state |
| `bouncyhsm` | **Experimental** | REST API (HTTP) | Software simulator; reads `/HsmInfo/Versions` and `/Stats`; always warns it is non-production (`BOUNCYHSM-001`) |

Experimental providers are built against public documentation and clearly
labeled in every output. Corrections from real hardware are very welcome.

## Configuration

`--vendor-config vendor.yaml` holds per-provider settings. Treat it like a
credential store (mode 0600); values are never logged.

```yaml
providers:
  softhsm:
    conf: /etc/softhsm/softhsm2.conf   # optional; auto-detected otherwise

  luna:
    host: luna1.example.com
    user: admin
    key_file: /etc/hsmdoctor/luna_id_ed25519
    known_hosts: /etc/hsmdoctor/known_hosts   # or insecure_ignore_host_key: true (labs only)

  cloudhsm:
    cluster_id: cluster-abcdef123
    region: eu-west-1
    profile: hsm-audit        # optional AWS CLI profile

  bouncyhsm:
    url: http://bouncy-host:8080   # BouncyHsm REST/management endpoint
```

nShield needs no configuration: it runs the locally installed nShield tools.

## Writing a provider

A provider is a small Go package under `internal/vendors/<name>` that
implements the `Provider` interface and registers itself:

```go
func init() { vendor.Register(&provider{}) }

type Provider interface {
    Name() string
    Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool
    Collect(ctx context.Context, cfg vendor.Config) (*vendor.Info, error)
}
```

**Detect** recognizes the HSM from the module/token manufacturer, model or
description strings. **Collect** gathers data PKCS#11 cannot expose and
returns it as a `vendor.Info` (device resources, HA members, partitions,
tamper and backup state, an `Extra` string map, and `Findings`). Return
`vendor.ErrNotConfigured` when required settings are missing so the caller
skips the provider gracefully.

### Talking to the HSM

Two patterns are supported, both testable without real hardware:

- **External commands** — hold a `vendor.Runner` and call
  `runner.Run(ctx, name, args...)`. In tests inject
  `internal/vendors/vendortest.Runner`, which returns canned output per
  command and can inject errors to exercise failure paths (`softhsm`,
  `nshield`, `luna`, `cloudhsm`).
- **HTTP APIs** — hold an `*http.Client` (nil → a default) and call the
  management API; in tests point the config URL at an `httptest.Server`
  returning real response shapes (`bouncyhsm`).

### Guidance

- **Degrade gracefully.** Treat one fundamental call as required (error out
  if it fails); make secondary calls best-effort so one failure never sinks
  the whole report.
- **Emit findings** as `policy.Finding`s with a `<VENDOR>-NNN` rule ID and an
  appropriate severity — tamper and outages should be `critical`/`high` so
  they move the score. Interpret ambiguous values conservatively rather than
  raising false criticals.
- **Register** the package with a blank import in
  `internal/cli/vendorutil.go` so its `init` runs.
- **Mark experimental** (`Info.Experimental = true`) until validated against
  real hardware.

See any existing provider and its `_test.go` for a complete example.
