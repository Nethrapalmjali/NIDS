# NIDS – ML-Based Network Intrusion Detection System

Project website for a lightweight Network Intrusion Detection System. It captures network traffic,
extracts flow features, detects one-directional anomalies, and classifies traffic into 12 attack
classes with a LightGBM / XGBoost / CatBoost ensemble. Each alert comes with an AI-generated
explanation.

## What's on the site

| Section | Contents |
|---|---|
| Problem | Why rule-based monitoring misses modern attacks |
| Architecture | Defense-in-depth layers, trust zones, least-privilege design (diagram) |
| Workflow | 7-stage pipeline, key flow features, the 5 system modules |
| Security controls | Authentication, RBAC, TLS, input validation, model integrity; tech stack |
| Threats | 12 attack classes with attack vectors, signals and MITRE ATT&CK mapping |
| Live demo | In-browser simulation of DDoS, port scan, brute force, exfiltration and botnet detection |
| Evaluation | Model metrics, model comparison, NIDS vs Snort / Suricata / Zeek / commercial NDR |
| Risk & compliance | Risk register, NIST CSF 2.0, ISO 27001:2022, IT Act / DPDP Act / CERT-In, ethics |
| Incident response | NIST SP 800-61 lifecycle, strengths and limitations |
| Innovation | What's new, roadmap |

## Run locally

Open `index.html` in a browser. There is no build step and no dependencies.

## Add your model results

Edit `assets/results.js` and replace each `null` with your measured value (fractions, e.g. `0.987`).
Values left as `null` show as "pending".

## Publish with GitHub Pages

Repo **Settings → Pages → Build and deployment → Deploy from a branch → `main` / root**.
