# Central deployment (Docker Compose)

A ready-to-run **central fleet server** for HSM Doctor: PostgreSQL + the
`hsmdoctor server`. It aggregates reports from any mix of HSM vendors into one
web dashboard and REST API.

The split matters:

```
        You  ──(browser / CLI)──►  ┌───────────────────────────┐
                                   │  hsmdoctor SERVER (Docker) │  ← no vendor lib
                                   │  fleet dashboard + REST+DB │
                                   └───────▲───────────▲───────┘
                       push (neutral report) │           │ push
                                 ┌────────────┴┐   ┌──────┴────────┐
                                 │ AGENT: Luna │   │ AGENT: nShield│  ← each host's own .so
                                 └──────┬──────┘   └──────┬────────┘
                                    Luna HSM          nShield HSM
```

- The **central server** (this compose) holds **no PKCS#11 module** and never
  touches an HSM — it only ingests reports. That is why it containerizes
  cleanly.
- **Agents** run on your HSM hosts, next to each vendor's PKCS#11 library and
  client. The **PIN never leaves the agent host**; only neutral scan reports are
  pushed to the server.

## 1. Start the central server

```sh
cd deploy

cp .env.example .env            # set DB_PASSWORD and ENROLL_TOKEN
#   ENROLL_TOKEN: openssl rand -hex 16
cp auth.yaml.example auth.yaml  # set your admin/viewer tokens (>=16 chars)
./gen-tls.sh hsm-central.acme.internal   # self-signed cert for testing,
                                         # or drop real certs in ./tls/

docker compose up -d --build
docker compose logs -f server            # watch it come up
```

The dashboard is now on `https://localhost:8443` (and on your server's
hostname). Sign in with an `admin` or `viewer` token from `auth.yaml`.

> **File permissions:** the server runs as a non-root user (uid 10001) inside
> the container, so `auth.yaml` and the files in `tls/` must be readable by it
> (`gen-tls.sh` already sets `0644`). For production, prefer real CA certs and a
> secrets manager over files on disk.

## 2. Run an agent on each HSM host

Agents run **where the vendor client already works** — the simplest form is the
native binary. Install `hsmdoctor` on the HSM host, then:

**Luna host**

```sh
export HSMDOCTOR_ENROLL='<ENROLL_TOKEN from .env>'
export HSM_PIN='<Luna partition PIN>'

# Optional: appliance health (HA/tamper/partitions). See vendor.yaml.example.
#   /etc/hsmdoctor/vendor.yaml  ->  providers: { luna: { host: ..., user: ... } }

hsmdoctor agent \
  --server https://hsm-central.acme.internal:8443 \
  --server-ca /etc/hsmdoctor/server.crt \       # only for a self-signed server cert
  --enroll-token-env HSMDOCTOR_ENROLL \
  --name luna-prod-1 \
  --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  --pin-env HSM_PIN \
  --vendor-config /etc/hsmdoctor/vendor.yaml \
  --interval 15m
```

**nShield host** — same pattern, just the module and name change:

```sh
hsmdoctor agent \
  --server https://hsm-central.acme.internal:8443 \
  --server-ca /etc/hsmdoctor/server.crt \
  --enroll-token-env HSMDOCTOR_ENROLL \
  --name nshield-prod-1 \
  --module /opt/nfast/toolkits/pkcs11/libcknfast.so \
  --pin-env HSM_PIN \
  --vendor-config /etc/hsmdoctor/vendor.yaml \
  --interval 15m
```

Notes:

- One agent scans **all tokens on its module** (narrow with `--slot`). If a
  single host has **two different vendors**, run **two agents** — one per
  `--module`, each with its own `--name` and `--token-file`.
- First run enrolls with the shared token and stores a permanent agent token in
  `--token-file` (default `~/.local/share/hsmdoctor/agent.token`); later starts
  skip enrollment.
- Use `--once` instead of `--interval` to scan once and exit (cron / systemd
  timer).

### Containerizing an agent (optional)

The published image contains SoftHSM/OpenSC but **not** proprietary vendor
clients. To run an agent in a container, build an image `FROM` this one that
adds the vendor client, and mount the host's vendor config and sockets (e.g. the
nShield hardserver socket, or Luna's `Chrystoki.conf` and network config). In
practice, running agents **natively** and only the **server in a container** is
the least friction.

## 3. See everything centrally

**Web UI** — `https://hsm-central.acme.internal:8443` → sign in → **Fleet**:
every enrolled HSM (Luna, nShield, …) in one table with score, serial,
firmware, last-seen, drift and appliance health.

**CLI / REST / metrics**

```sh
TOKEN='<admin or viewer token>'
curl -H "Authorization: Bearer $TOKEN" https://hsm-central.acme.internal:8443/api/v1/hsms
curl -H "Authorization: Bearer $TOKEN" https://hsm-central.acme.internal:8443/metrics   # Prometheus
```

**Prometheus + Grafana** — for a turnkey monitoring stack (alert rules + a fleet
dashboard, or drop-in artifacts for your own Prometheus/Grafana):

```sh
cp monitoring/prometheus.token.example monitoring/prometheus.token   # a viewer token
docker compose --profile monitoring up -d      # Grafana on :3000, dashboard preloaded
```

See [monitoring/README.md](monitoring/README.md).

## Production hardening

- Real TLS certificates from your CA (replace `./tls`), not the self-signed one.
- Optionally require **mutual TLS** from agents: add `--client-ca` to the server
  and `--tls-client-cert`/`--tls-client-key` to each agent.
- **OIDC single sign-on** for human access — see
  [../docs/deployment.md](../docs/deployment.md).
- Keep `.env`, `auth.yaml`, `vendor.yaml` and `tls/` out of version control
  (this directory's `.gitignore` already excludes them).

See [../docs/deployment.md](../docs/deployment.md) for the full reference
(storage backends, SSO, mTLS, webhooks, e-mail notifications, systemd).
