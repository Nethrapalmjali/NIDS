# Security policy

## Reporting a vulnerability

Please report security issues **privately**, using GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository. Do not open a
public issue. Include the affected version, steps to reproduce, and the impact. You should get a
response within 7 days.

## Security model

| Area | Control |
|---|---|
| Authentication | Flask-Login; salted scrypt password hashes; minimum 10 characters; 5 failed logins per IP lead to a 5-minute lockout; session ID rotated at login; idle timeout (`NIDS_SESSION_MINUTES`) |
| Authorisation | Roles viewer < analyst < admin, checked server-side on every route; disabled accounts cannot log in; the last active admin cannot be demoted or disabled |
| Web | CSRF token on every POST; strict Content-Security-Policy (no inline script); X-Frame-Options DENY; nosniff; no-referrer; `Cache-Control: no-store` on authenticated pages; HSTS and Secure cookies when `NIDS_HTTPS=1`; 64 KB request body limit |
| Data | Parameterised SQL only; database triggers make the audit log append-only and incidents undeletable; CSV exports neutralise spreadsheet-formula injection |
| Models | Every `.joblib` file is SHA-256-verified against `nids/models/manifest.json` before loading, because unpickling a tampered file executes code. Library versions are checked against the training versions |
| Privacy | Only flow metadata (addresses, ports, sizes, timings, flags) is processed; packet payloads are never stored |
| Availability | Capture never blocks: a full queue drops flows and counts them (`nids_flows_dropped_total`); the flow table and de-duplication caches are memory-bounded; webhook delivery is asynchronous with a timeout |
| Deployment | Binds to 127.0.0.1 by default; the container runs as a non-root user with a read-only filesystem and no capabilities (replay mode); `/metrics` is loopback-only unless `NIDS_METRICS_TOKEN` is set |

## Hardening checklist for a real deployment

- Put NIDS behind an HTTPS reverse proxy (nginx, Caddy, Traefik), then set `NIDS_HTTPS=1` and `NIDS_TRUST_PROXY=1`.
- Set `NIDS_SECRET_KEY` from a secrets manager, or protect the generated `secret_key` file in the instance folder.
- Back up the instance folder (`nids.sqlite3`, `alerts.jsonl`). CERT-In directions require logs to be kept for 180 days.
- Forward `alerts.jsonl` to a SIEM, and scrape `/metrics` with Prometheus (set `NIDS_METRICS_TOKEN`).
- Monitor only networks you own or are authorised to monitor (IT Act 2000, §43).
