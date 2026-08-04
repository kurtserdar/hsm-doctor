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

### Mutual TLS (optional)

Bearer tokens already authenticate agents. Mutual TLS adds a transport-layer
factor: the server only accepts connections presenting a client certificate
signed by a CA you control, so a stolen token cannot be replayed from an
untrusted host. Enable it with `--client-ca` on the server and client
certificates on the agents.

Generate a CA, a server certificate and per-agent client certificates with
openssl (there is no built-in PKI command — use your existing CA in
production):

```sh
# 1. A private CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=HSM Doctor CA"

# 2. Server certificate (SAN must match how agents address the server)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=doctor.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:doctor.example.com\nextendedKeyUsage=serverAuth")

# 3. One client certificate per agent
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout edge-01.key -out edge-01.csr -subj "/CN=edge-01"
openssl x509 -req -in edge-01.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out edge-01.crt -days 825 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
```

Server:

```sh
hsmdoctor server --listen 0.0.0.0:8443 \
  --tls-cert server.crt --tls-key server.key \
  --client-ca ca.crt \
  --auth-config auth.yaml --enroll-token-env HSMDOCTOR_ENROLL
```

Agent:

```sh
hsmdoctor agent --server https://doctor.example.com:8443 \
  --tls-client-cert edge-01.crt --tls-client-key edge-01.key \
  --server-ca ca.crt \
  --enroll-token-env HSMDOCTOR_ENROLL \
  --module /usr/lib/libCryptoki2_64.so --pin-env HSM_PIN
```

`--client-ca` requires `--tls-cert`/`--tls-key` and applies to **all**
connections, including the web UI — browser access then needs a client
certificate imported into the browser, so mTLS deployments are typically
API/agent-only. `--server-ca` lets an agent trust a private server CA
without installing it system-wide.

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

## Storage backend

`serve` and `server` persist scan history, drift events and agents. The
`--db` value selects the backend by its form:

- **SQLite** (default) — a file path. Zero setup; ideal for a single host.
  Defaults to `~/.local/share/hsmdoctor/hsmdoctor.db`.
- **PostgreSQL** — a `postgres://` (or `postgresql://`) DSN. Recommended for
  a central server serving a fleet, or when you want managed backups and
  concurrent access.

```sh
# SQLite (default)
hsmdoctor server --db /var/lib/hsmdoctor/fleet.db ...

# PostgreSQL
hsmdoctor server \
  --db "postgres://hsmdoctor:secret@db.example.com:5432/hsmdoctor?sslmode=require" ...
```

The schema is created and migrated automatically on first connect (under a
PostgreSQL advisory lock, so multiple servers can start against one
database safely). Both backends implement the exact same behavior — the
same conformance test suite runs against both in CI.

Keep a password-bearing DSN out of the process list by setting
`HSMDOCTOR_DB` (in a systemd `EnvironmentFile`, for example) instead of
passing `--db`; the flag takes precedence when both are set. The DSN's
password is redacted in log output.

## Authentication and Single Sign-On

`--auth-config` points at a YAML file with static bearer tokens, an OIDC
Single Sign-On section, or both. Static tokens suit automation and CI; OIDC
gives human operators an interactive login through your identity provider
(Keycloak, Okta, Azure AD, Google, ...).

```yaml
# auth.yaml (chmod 600)
tokens:
  - name: ci
    token: c1f0e5b2a99d47d0b5b7e2f4a1c39e58   # >= 16 chars
    role: admin      # or viewer

oidc:
  issuer: https://keycloak.example.com/realms/corp
  client_id: hsmdoctor
  client_secret: "${OIDC_SECRET}"           # from your IdP
  redirect_url: https://doctor.example.com:8443/auth/callback
  groups_claim: groups                       # default "groups"
  admin_groups: [hsm-admins]                 # matching group → admin; others → viewer
  # cookie_key: optional 32+ byte key; random per start (sessions reset on restart) if unset
```

- Register `redirect_url` as an allowed redirect URI in the IdP and grant
  the client the `openid`, `profile`, `email` and `groups` scopes.
- Users in an `admin_groups` group get the admin role; any other
  authenticated user is a viewer (read-only). Static tokens keep their
  configured role and keep working alongside SSO — so scripts are unaffected.
- The web UI shows a **Sign in with SSO** button when OIDC is configured,
  with an API-token fallback. Login is `/auth/login`, logout `/auth/logout`.
- Sessions are signed HttpOnly/SameSite cookies scoped to the ID token's
  lifetime; set `cookie_key` to keep sessions valid across restarts.
- Agent ingest endpoints are never gated by user auth — agents authenticate
  with their own tokens (and optionally mTLS).

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
`time() - hsmdoctor_last_scan_timestamp_seconds > 3600`,
`increase(hsmdoctor_posture_regressions_total[1h]) > 0` (posture worsened),
`hsmdoctor_shared_private_keys > 0` (a private key was found on more than one
HSM — see `GET /api/v1/shared-keys` and the fleet dashboard for the locations).

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

A `posture_regression` event fires when a scan's security posture worsens
relative to the previous scan — the health score drops by 10 or more points,
or a new critical/high finding appears (`X-HSMDoctor-Event: posture_regression`):

```json
{
  "event": "posture_regression",
  "hsm": {"id": 3, "serial": "7000123", "label": "PROD-PARTITION", "source": "edge-01"},
  "detected_at": "2026-07-29T16:20:11Z",
  "score_delta": -25,
  "detail": {"score_delta": -25, "score_dropped": true,
             "new_severe": [{"rule_id": "HSM-001", "title": "Extractable private key",
                             "severity": "critical"}],
             "reasons": ["health score dropped 25 points (90 → 65)",
                         "new critical finding HSM-001: Extractable private key"]}
}
```

Regression is posture-level (score and findings); drift is inventory-level
(objects and attributes). The two are independent — a scan can raise either,
both or neither. Delivery is retried three times with backoff; failures are
logged and never block scanning.

## E-mail notifications

Where the webhook targets machines, e-mail targets people. `--notify-config`
points at a YAML file with SMTP settings and recipients; the server then
e-mails **drift alerts**, **posture-regression alerts** (same events as the
webhook) and **certificate expiry reminders**.

```yaml
# notify.yaml (chmod 600)
smtp:
  host: smtp.example.com
  port: 587
  username: hsmdoctor
  password: "${SMTP_PASSWORD}"
  from: hsmdoctor@example.com
  to: [hsm-team@example.com, oncall@example.com]
  tls: starttls          # starttls (587), implicit (465) or none (localhost relay)

# Optional — all default to true:
drift: true
regression: true
cert_expiry: true
cert_warn_days: [30, 14, 1]   # e-mail once as a cert crosses each threshold
```

```sh
hsmdoctor server --notify-config notify.yaml ... \
  --schedule "0 8 * * *"     # a daily scan drives the expiry reminders
```

- **Certificate reminders** are deduplicated per certificate and threshold
  using a `notifications` table in the store, so a daily scan does not resend
  the same warning — an operator gets one mail as a certificate first enters
  the 30-, 14- and 1-day windows. Persistence (`--db`, not `--no-db`) is
  required for this dedup; without it drift mail still works but reminders
  could repeat.
- Reminders ride the scheduled scans, so pair `--notify-config` with
  `--schedule` (or an agent interval) to see them.
- E-mail and the webhook are independent channels — enable either or both.
- Delivery failures are logged and never block scanning. Keep the SMTP
  password in the file (chmod 600) or an environment variable, not on the
  command line.

Works with any SMTP server or relay (corporate smarthost, Gmail with an app
password, Amazon SES SMTP endpoint, ...).
