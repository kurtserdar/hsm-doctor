# Monitoring: Prometheus alerts + Grafana dashboard

HSM Doctor's `server`/`serve` already exposes fleet metrics at `/metrics`
(labeled by token serial and label). This directory turns those metrics into a
ready-to-run monitoring stack, or into drop-in artifacts for a Prometheus and
Grafana you already run.

Contents:

| File | What it is |
|---|---|
| `prometheus-alerts.yml` | Prometheus alerting rules (health, findings, certificate expiry, regression, shared keys, tamper, HA, stale scans, PQC exposure) |
| `grafana-dashboard` → `grafana/dashboards/hsmdoctor.json` | An importable Grafana dashboard for the fleet |
| `prometheus.yml` | Scrape config used by the bundled stack |
| `grafana/provisioning/` | Auto-provisions the Prometheus datasource and the dashboard |

## Option A — turnkey stack (Prometheus + Grafana)

From the `deploy/` directory, alongside the central server:

```sh
# one viewer token from your auth.yaml lets Prometheus scrape /metrics
cp monitoring/prometheus.token.example monitoring/prometheus.token
$EDITOR monitoring/prometheus.token          # paste a viewer token

docker compose --profile monitoring up -d
```

- Prometheus scrapes `server:8443/metrics` over HTTPS and loads the alert rules.
- Grafana comes up on <http://localhost:3000> (admin password from
  `GRAFANA_PASSWORD` in `.env`), with the Prometheus datasource and the **HSM
  Doctor — Fleet** dashboard already provisioned.

The bundled Prometheus trusts the server's self-signed certificate on the
internal Docker network (`insecure_skip_verify`). With real certificates, mount
your CA into the prometheus container and set `ca_file` in `prometheus.yml`
instead.

## Option B — drop into your own Prometheus/Grafana

- **Prometheus:** add `prometheus-alerts.yml` to your `rule_files:`, and scrape
  the server with a viewer bearer token:

  ```yaml
  scrape_configs:
    - job_name: hsmdoctor
      scheme: https
      authorization: { credentials: <viewer token> }
      static_configs: [{ targets: ["doctor.example.com:8443"] }]
  ```

- **Grafana:** import `grafana/dashboards/hsmdoctor.json` and pick your
  Prometheus datasource when prompted.
