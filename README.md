# NIDS: Machine-Learning Network Intrusion Detection System

[![CI](https://github.com/Nethrapalmjali/NIDS/actions/workflows/ci.yml/badge.svg)](https://github.com/Nethrapalmjali/NIDS/actions/workflows/ci.yml)
[![Website](https://github.com/Nethrapalmjali/NIDS/actions/workflows/pages.yml/badge.svg)](https://nethrapalmjali.github.io/NIDS/)
![Python](https://img.shields.io/badge/python-3.10–3.12-blue) ![License](https://img.shields.io/badge/license-MIT-green)

**Live site and real-time demo: https://nethrapalmjali.github.io/NIDS/**

NIDS monitors network traffic, turns it into flow-level features, and classifies each flow as
**benign or one of 12 attack types** using an ensemble of **LightGBM, XGBoost and CatBoost**. It
is trained and evaluated on the **CIC-IDS2017** benchmark. Every alert includes a plain-language
explanation of *why* the flow was flagged, which features drove the decision, the matching
MITRE ATT&CK technique, and a recommended response. Alerts appear on a real-time dashboard.

> **Try it without installing anything.** The website runs the trained model in your browser.
> It streams real CIC-IDS2017 flows the model never saw during training, and you can launch any
> of the 12 attacks and watch them get detected, explained, and checked against ground truth.
> Add `?autodemo` to the URL to start a random attack mix automatically.

---

## Results

All numbers are measured on a **held-out, stratified test set of 86,823 flows** that the models
never saw in training (`nids/reports/metrics.json`). Duplicate flows were removed *before* splitting,
so no flow appears in both training and test sets.

| Model | Accuracy | Macro precision | Macro recall | Macro F1 | False-positive rate | Detection rate | Inference / flow |
|---|---|---|---|---|---|---|---|
| LightGBM | 99.66% | 88.68% | 88.99% | 88.83% | 0.170% | 99.88% | 78.5 µs |
| XGBoost | **99.70%** | **93.56%** | 90.08% | 91.17% | **0.168%** | 99.92% | 14.9 µs |
| CatBoost | 99.57% | 88.79% | 91.59% | 90.08% | 0.364% | **99.96%** | **1.3 µs** |
| **Ensemble (soft voting)** | 99.69% | 93.29% | **91.77%** | **92.37%** | 0.172% | 99.92% | 94.7 µs |

*False-positive rate* is the share of benign flows flagged as attacks. *Detection rate* is the share
of attack flows flagged as any attack. *Macro* scores weight all 13 classes equally, so they show how
well the rare attacks are handled.

**Per class (ensemble):** DDoS, DoS Hulk, DoS GoldenEye, Port Scan, and SSH/FTP brute force all
reach **F1 ≥ 99.7%**; Slowloris and Slowhttptest 99.4 to 99.6%; Botnet 96.4%. The weak spot is
**web attacks**: Web Brute Force has 75.4% F1 and XSS 44.9%. These attacks hit the same server and
port with similar flow shapes, and most of their errors are confusion *with each other*. Separating
them reliably needs HTTP payload inspection, which a flow-level NIDS deliberately does not do.

## The CIC-IDS2017 dataset

CIC-IDS2017 was published by the Canadian Institute for Cybersecurity (University of New Brunswick).
It was recorded over five working days, 3–7 July 2017, on a testbed with separate victim and attacker
networks. Packets were converted into bidirectional flows with CICFlowMeter.

| Day | Traffic |
|---|---|
| Mon 3 Jul | Benign only |
| Tue 4 Jul | FTP-Patator, SSH-Patator (brute force) |
| Wed 5 Jul | DoS Slowloris, Slowhttptest, Hulk, GoldenEye; Heartbleed |
| Thu 6 Jul | Web brute force, XSS, SQL injection; infiltration |
| Fri 7 Jul | Botnet (Ares), port scans, DDoS (LOIC) |

**Preprocessing** (`nids/train.py`):
1. Load all 8 daily CSVs (2,827,829 labelled flows).
2. Map labels to 13 classes, dropping Infiltration (36 flows) and Heartbleed (11).
3. Drop NaN and ±∞ values.
4. Remove 378,461 duplicate rows.
5. Cap benign at 250k and each attack class at 50k.
6. Make a stratified 80/20 split with seed 42.
7. Apply square-root inverse-frequency class weights.

**Features:** 28 of CICFlowMeter's features, chosen because a lightweight sensor can compute them
**live from packet headers**:
- destination port
- forward/backward packet and byte counts
- packet-size statistics
- bytes/s and packets/s
- inter-arrival times
- TCP flag counts
- initial TCP window sizes
- down/up ratio

Payloads are never inspected.

## Architecture

```
 IP traffic ──► Capture ──────────► Flow builder ──► Feature vector ──► ML ensemble ──► Alert engine ──► Dashboard
               Scapy (live) or       bidirectional    28 features       LightGBM          severity,        Flask + Chart.js
               held-out replay       FIN/RST/timeout                    XGBoost           de-duplication,  login + RBAC
                                                                        CatBoost          SHAP explanation SQLite incident log
```

Security is layered (defense in depth) and follows least privilege:

| Layer | Controls |
|---|---|
| Access | Flask-Login sessions; salted scrypt password hashes; 5 failed logins per IP → 5-minute lockout |
| Authorisation | Roles viewer < analyst < admin, checked on every route, deny by default |
| Web | CSRF token on every POST; strict Content-Security-Policy (no inline scripts); X-Frame-Options DENY; HttpOnly/SameSite cookies (`NIDS_HTTPS=1` adds Secure); binds to 127.0.0.1 by default |
| Data | Parameterised SQL only; database triggers make the audit log append-only and incidents undeletable |
| Model integrity | Every model file is SHA-256-verified against `manifest.json` before loading (a tampered joblib file could execute code) |
| Privacy | Only flow metadata is processed; payloads are never stored |

## Repository layout

```
index.html, assets/           project website (GitHub Pages)
  assets/live.js              in-browser real-time analyser (tree walker + Saabas explanations)
  assets/data/model.json      compact LightGBM exported for the browser (99.69% test accuracy)
  assets/data/flows.json      3,134 held-out CIC-IDS2017 flows streamed by the live demo
nids/features.py              28 live-computable features + bidirectional flow builder
nids/train.py                 data pipeline, training, evaluation, SHA-256 model manifest
nids/export_web.py            trains/verifies/exports the browser model
nids/detector.py              integrity-checked model loading, ensemble scoring, SHAP explanations
nids/capture.py               live Scapy capture, held-out replay and attack simulation
nids/app.py                   Flask dashboard + CLI: auth, RBAC, CSRF, incidents, audit, health, metrics
nids/config.py                environment-variable configuration
nids/alerts.py                JSON-lines SIEM feed and async webhook
nids/models/                  trained models, manifest.json, replay flows
nids/reports/metrics.json     complete evaluation output
tests/test_nids.py            23 unit/integration tests
Dockerfile, docker-compose.yml  hardened container (non-root, read-only, healthcheck)
.github/workflows/           CI (lint, tests, Docker smoke test) and website publishing
```

## Run it

### Option A: Docker (recommended for production)

```bash
docker compose build
docker compose run --rm -e NIDS_ADMIN_PASSWORD='choose-a-strong-one' nids init   # first run only
docker compose up -d                                                            # http://127.0.0.1:5000
docker compose --profile live up -d nids-live                                   # live capture on the host network (Linux)
```

The container runs as a non-root user with a read-only filesystem and all Linux capabilities
dropped (replay mode). It has a built-in health check against `/readyz`, and data persists in the
`nids-data` volume.

### Option B: Python

Requires Python 3.10–3.12. Dependencies are pinned to the exact versions the bundled models were
trained with.

```bash
python -m venv .venv
.venv\Scripts\activate                 # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

python -m nids.app init                # create the database and an admin account
python -m nids.app check               # verify model integrity, library versions, database
python -m nids.app serve               # production server (Waitress) on http://127.0.0.1:5000
```

| Mode | Command | What it does |
|---|---|---|
| Replay (default) | `python -m nids.app serve` | Streams held-out CIC-IDS2017 flows in real time. Analysts can inject any of the 12 attacks, and the dashboard shows live agreement with ground truth |
| Live capture | `python -m nids.app serve --source live [--iface eth0]` | Captures real packets with Scapy, assembles flows, and scores them as they close. Needs [Npcap](https://npcap.com) on Windows, or root/`CAP_NET_RAW` on Linux |

### Administration CLI

```bash
python -m nids.app create-user alice --role analyst    # viewer | analyst | admin
python -m nids.app reset-password alice
python -m nids.app serve --dev                         # Flask development server, for debugging only
```

### Configuration

All settings are environment variables (see `nids/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `NIDS_INSTANCE` | `nids/instance` | Database, secret key, rotating logs, alert feed |
| `NIDS_HOST` / `NIDS_PORT` | `127.0.0.1` / `5000` | Bind address |
| `NIDS_SOURCE` / `NIDS_IFACE` | `replay` / all | Traffic source and capture interface |
| `NIDS_THRESHOLD` | `0.6` | Minimum ensemble confidence to raise an incident |
| `NIDS_HTTPS` / `NIDS_TRUST_PROXY` | `0` / `0` | Behind a TLS reverse proxy: Secure cookies, HSTS, X-Forwarded-* |
| `NIDS_SESSION_MINUTES` | `60` | Session lifetime |
| `NIDS_WEBHOOK_URL` | off | POST each new incident as JSON (Slack, Teams, SOAR) |
| `NIDS_METRICS_TOKEN` | off | Bearer token for `/metrics` (otherwise loopback only) |
| `NIDS_SECRET_KEY` | generated | Session signing key |
| `NIDS_LOG_LEVEL` / `NIDS_THREADS` | `INFO` / `8` | Logging level, Waitress worker threads |

### HTTP API

| Endpoint | Access | Purpose |
|---|---|---|
| `GET /healthz` | public | Liveness |
| `GET /readyz` | public | Readiness: engine heartbeat and database (503 if unhealthy) |
| `GET /metrics` | token / loopback | Prometheus metrics: flows, per-class counts, incidents, drops, queue depth, webhook deliveries |
| `GET /api/stats` | viewer | Live counters and the 60-second traffic series |
| `GET /api/incidents?status=&severity=&label=&since=&limit=` | viewer | Filtered incident list (JSON) |
| `GET /api/incidents.csv` | analyst | CSV export (formula-injection safe) |
| `POST /api/incidents/<id>/ack` | analyst | Acknowledge an incident with a note |
| `POST /api/simulate` | analyst | Inject held-out flows of an attack class (replay mode) |

All POSTs require the session's CSRF token (`X-CSRF-Token` header).

### Monitoring and SIEM integration

- **Alerts:** each new incident is appended to `alerts.jsonl` as one JSON object per line, ready for
  Filebeat, Wazuh or a Splunk forwarder. It can also be pushed to `NIDS_WEBHOOK_URL`.
- **Metrics:** scrape `/metrics` with Prometheus. Alert on `nids_engine_heartbeat_age_seconds > 5`
  and on increases in `nids_flows_dropped_total`.
- **Logs:** `nids.log` in the instance folder rotates at 5 MB and keeps 5 files.
- **Audit:** every login, failed login, lockout, acknowledgement, export, simulation and user change
  is recorded in an append-only audit table, which admins can view on the dashboard.

### Retrain from scratch

Download `MachineLearningCSV.zip` (CIC-IDS2017) into `data/raw/`, then:

```bash
python -m nids.train          # trains all models, writes metrics, manifest and website results (~10 min)
python -m nids.export_web     # rebuilds and verifies the browser model
python -m unittest discover -s tests
```

### Quality gates

GitHub Actions runs on every push:
- lint
- 23 unit and integration tests: flow features, model integrity and accuracy, the detection engine, authentication, RBAC, CSRF, lockout, CSV export, health and metrics, and migrations
- a Docker build with a container readiness smoke test

It then republishes the website automatically.

## Limitations

- **Domain shift.** The live flow builder approximates CICFlowMeter, and some strong features
  (initial TCP window, destination port) partly fingerprint the dataset's own tools and hosts. Accuracy
  on a different network will be lower than the test-set figures until the model is retrained on local
  labelled traffic.
- **Web attacks** (XSS vs web brute force) are hard to tell apart without payload inspection.
- **Detection only.** NIDS raises and explains alerts; blocking is left to an analyst (no automatic
  IPS actions).
- **Single sensor.** One capture point can itself be overloaded by a large flood.

## Citation

If you use this project, please cite the dataset:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion
> Detection Dataset and Intrusion Traffic Characterization", *4th International Conference on
> Information Systems Security and Privacy (ICISSP)*, Portugal, January 2018.

## License

MIT; see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
