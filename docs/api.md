# REST API

`hsmdoctor serve` exposes a local REST API under `/api/v1` alongside the web
interface.

```sh
export HSM_PIN=123456
hsmdoctor serve --module /usr/lib/softhsm/libsofthsm2.so --pin-env HSM_PIN
# → http://127.0.0.1:8080
```

## Security model

The server is designed for **local, single-operator use**:

- Binds to `127.0.0.1` by default (`--listen` to change — think twice).
- The PIN is provided once at startup, never per request and never logged.
- No CORS headers are emitted, so browser pages from other origins cannot
  call the API. For Vite development use the dev-server proxy (already
  configured in `web/vite.config.ts`).
- There is no authentication layer yet; do not expose the port beyond
  localhost. Central/multi-user deployment is a v0.3 topic.

## Endpoints

Local scan endpoints (available in `serve` mode; return 503 in central mode):

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/info` | Tool version, mode (`local`/`central`) and module info |
| GET | `/api/v1/discover` | Slots and tokens (`?mechanisms=true` adds mechanism lists) |
| GET | `/api/v1/slots/{slot}/scan` | Full scan report: inventory, findings, health score |
| GET | `/api/v1/slots/{slot}/certs` | Certificate expiry list (`?warn_days=30`) |
| GET | `/api/v1/slots/{slot}/snapshot` | Snapshot JSON (same format as `hsmdoctor snapshot`) |
| POST | `/api/v1/slots/{slot}/test` | Run a functional test profile: `{"profile":"sign-verify"}` |
| POST | `/api/v1/slots/{slot}/bench` | Bounded benchmark: `{"duration_ms":3000,"max_ops":5000,"sessions":1}` |
| GET | `/api/v1/slots/{slot}/pqc` | PQC readiness (`?test=true` functional probes, `?host=true` server-host OpenSSL check) |
| POST | `/api/v1/diff` | Compare two snapshots: `{"old":<snapshot>,"new":<snapshot>}` |

History and fleet endpoints (need persistence; both modes):

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/hsms` | Fleet listing with latest score and last-seen |
| GET | `/api/v1/hsms/{id}` | One HSM's identity record |
| GET | `/api/v1/hsms/{id}/scans` | Scan history summaries (`?limit=100`) |
| GET | `/api/v1/hsms/{id}/scans/{scanID}` | One stored scan with the full report |
| GET | `/api/v1/hsms/{id}/drift` | Drift events, newest first (`?limit=100`) |

Agent ingest endpoints (authenticated by agent credentials, exempt from
user bearer tokens):

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/ingest/enroll` | `{"name":..., "enroll_token":...}` → `{"agent_token":...}` |
| POST | `/api/v1/ingest/report` | Push one scan report (`Authorization: Bearer <agent_token>`) |

Monitoring:

| Method | Path | Description |
|---|---|---|
| GET | `/metrics` | Prometheus metrics: `hsmdoctor_health_score`, `hsmdoctor_findings{severity}`, `hsmdoctor_objects{class}`, `hsmdoctor_certificate_min_days_to_expiry`, `hsmdoctor_last_scan_timestamp_seconds`, `hsmdoctor_scans_total` |

## Authentication

Without `--auth-config` the API is open (loopback-only usage). With it,
every `/api/*` and `/metrics` request needs `Authorization: Bearer <token>`:

```yaml
# auth.yaml (chmod 600)
tokens:
  - name: ops
    token: c1f0e5b2a99d47d0b5b7e2f4a1c39e58
    role: admin      # full access
  - name: grafana
    token: 7d02b6c4f8a34e91bd63a0c5e7f21b44
    role: viewer     # GET/HEAD only
```

Static UI assets stay public (application code only); all data flows
through the protected API. Agent ingest endpoints authenticate with their
own tokens and are exempt from user bearer tokens.

Errors are returned as `{"error": "..."}` with an appropriate HTTP status.
Benchmark parameters are clamped to the same safety limits as the CLI
(60 s, 1,000,000 ops, 32 sessions).

## Examples

```sh
# Health score only
curl -s localhost:8080/api/v1/slots/0/scan | jq .score

# Expired certificates
curl -s "localhost:8080/api/v1/slots/0/certs?warn_days=14" | jq '.counts'

# Drift between two snapshots taken over time
curl -s localhost:8080/api/v1/slots/0/snapshot > monday.json
curl -s localhost:8080/api/v1/slots/0/snapshot > tuesday.json
jq -n --slurpfile o monday.json --slurpfile n tuesday.json \
   '{old: $o[0], new: $n[0]}' |
  curl -s -X POST -d @- localhost:8080/api/v1/diff | jq
```
