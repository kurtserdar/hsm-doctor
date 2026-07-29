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

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/info` | Tool version and module info |
| GET | `/api/v1/discover` | Slots and tokens (`?mechanisms=true` adds mechanism lists) |
| GET | `/api/v1/slots/{slot}/scan` | Full scan report: inventory, findings, health score |
| GET | `/api/v1/slots/{slot}/certs` | Certificate expiry list (`?warn_days=30`) |
| GET | `/api/v1/slots/{slot}/snapshot` | Snapshot JSON (same format as `hsmdoctor snapshot`) |
| POST | `/api/v1/slots/{slot}/test` | Run a functional test profile: `{"profile":"sign-verify"}` |
| POST | `/api/v1/slots/{slot}/bench` | Bounded benchmark: `{"duration_ms":3000,"max_ops":5000,"sessions":1}` |
| POST | `/api/v1/diff` | Compare two snapshots: `{"old":<snapshot>,"new":<snapshot>}` |

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
