# Deployment guide

Three ways to run HSM Doctor:

| Mode | Command | Use case |
|---|---|---|
| One-shot CLI | `scan`, `certs`, `test`, `bench`, `snapshot`/`diff` | Ad-hoc checks, CI/CD gates, cron jobs |
| Local server | `serve` | One host, web UI + API + history + metrics for its own tokens |
| Central + agents | `server` + `agent` | Fleet of HSMs across many hosts |

## Local server

```sh
export HSM_PIN=...
hsmdoctor serve --module /usr/lib/libCryptoki2_64.so --pin-env HSM_PIN \
  --schedule "0 */6 * * *" \          # scan all tokens every 6 hours
  --webhook-url https://hooks.example.com/hsm-drift
```

Scan history lands in `~/.local/share/hsmdoctor/hsmdoctor.db` (override
with `--db`, disable with `--no-db`). Every scan is compared with the
previous one; drift produces an event (and a webhook POST when configured).

## Central server + agents

### 1. Central host

```sh
export HSMDOCTOR_ENROLL=$(openssl rand -hex 16)
hsmdoctor server \
  --listen 0.0.0.0:8443 \
  --tls-cert /etc/hsmdoctor/server.pem --tls-key /etc/hsmdoctor/server.key \
  --auth-config /etc/hsmdoctor/auth.yaml \
  --enroll-token-env HSMDOCTOR_ENROLL \
  --webhook-url https://hooks.example.com/hsm-drift
```

The central server loads no PKCS#11 module. Always front it with TLS and
`--auth-config` before leaving loopback (see [api.md](api.md) for the
token file format).

### 2. Every HSM client host

```sh
export HSM_PIN=...
export HSMDOCTOR_ENROLL=...   # the shared enrollment token, first run only
hsmdoctor agent \
  --server https://doctor.example.com:8443 \
  --name $(hostname) \
  --enroll-token-env HSMDOCTOR_ENROLL \
  --module /usr/lib/libCryptoki2_64.so --pin-env HSM_PIN \
  --interval 15m
```

First run: the agent exchanges the enrollment token for a permanent agent
token stored in `~/.local/share/hsmdoctor/agent.token` (0600). Subsequent
runs need no enrollment token. Re-enrolling the same name rotates the
token.

Security properties:

- The PIN stays on the agent host; only finished reports (metadata,
  findings, scores) are pushed.
- Agents push outbound HTTPS only — no inbound firewall holes on HSM
  client hosts.
- The server stores only SHA-256 hashes of agent tokens.

For cron-style operation use `--once` instead of `--interval`.

### systemd units

`/etc/systemd/system/hsmdoctor-agent.service`:

```ini
[Unit]
Description=HSM Doctor agent
After=network-online.target

[Service]
User=hsmdoctor
EnvironmentFile=/etc/hsmdoctor/agent.env   # HSM_PIN=...
ExecStart=/usr/local/bin/hsmdoctor agent \
  --server https://doctor.example.com:8443 \
  --module /usr/lib/libCryptoki2_64.so --pin-env HSM_PIN \
  --token-file /var/lib/hsmdoctor/agent.token \
  --interval 15m
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

A matching `hsmdoctor-server.service` runs `hsmdoctor server ...` on the
central host.

## Prometheus

Scrape `/metrics` on the local server or the central server (fleet-wide
series, labeled by token serial and label):

```yaml
scrape_configs:
  - job_name: hsmdoctor
    static_configs: [{ targets: ["doctor.example.com:8443"] }]
    scheme: https
    authorization:
      credentials: <viewer token>
```

Useful alerts: `hsmdoctor_health_score < 70`,
`hsmdoctor_findings{severity="critical"} > 0`,
`hsmdoctor_certificate_min_days_to_expiry < 14`,
`time() - hsmdoctor_last_scan_timestamp_seconds > 3600`.

## Webhooks

`--webhook-url` receives a POST per drift event:

```json
{
  "event": "drift_detected",
  "hsm": {"id": 3, "serial": "7000123", "label": "PROD-PARTITION", "source": "edge-01"},
  "detected_at": "2026-07-29T16:20:11Z",
  "changes": 2,
  "diff": {"object_changes": [{"object": "private-key app-key (id 01)",
            "field": "CKA_EXTRACTABLE", "old": "false", "new": "true"}]}
}
```

Delivery is retried three times with backoff; failures are logged and
never block scanning.
