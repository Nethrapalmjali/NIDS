"""Runtime configuration, read from environment variables (12-factor style).

| Variable              | Default                 | Meaning                                                  |
|-----------------------|-------------------------|----------------------------------------------------------|
| NIDS_INSTANCE         | nids/instance           | Folder for the database, secret key, logs and alert feed  |
| NIDS_SECRET_KEY       | generated, stored       | Flask session signing key                                |
| NIDS_HOST / NIDS_PORT | 127.0.0.1 / 5000        | Bind address                                             |
| NIDS_SOURCE           | replay                  | replay or live                                           |
| NIDS_IFACE            | (all)                   | Interface for live capture                               |
| NIDS_THRESHOLD        | 0.6                     | Minimum ensemble confidence to raise an incident         |
| NIDS_HTTPS            | 0                       | 1 = behind TLS: mark cookies Secure, send HSTS           |
| NIDS_TRUST_PROXY      | 0                       | Number of reverse proxies to trust for X-Forwarded-*     |
| NIDS_SESSION_MINUTES  | 60                      | Idle session lifetime                                    |
| NIDS_WEBHOOK_URL      | (off)                   | POST each new incident as JSON (Slack/Teams/SOAR)        |
| NIDS_METRICS_TOKEN    | (off)                   | Bearer token for /metrics; without it, loopback only     |
| NIDS_LOG_LEVEL        | INFO                    | Logging level                                            |
| NIDS_THREADS          | 8                       | Waitress worker threads                                  |
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _bool(name: str) -> bool:
    return os.environ.get(name, "0").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    instance: Path = field(default_factory=lambda: Path(os.environ.get("NIDS_INSTANCE", BASE / "instance")))
    host: str = field(default_factory=lambda: os.environ.get("NIDS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("NIDS_PORT", "5000")))
    source: str = field(default_factory=lambda: os.environ.get("NIDS_SOURCE", "replay"))
    iface: str | None = field(default_factory=lambda: os.environ.get("NIDS_IFACE") or None)
    threshold: float = field(default_factory=lambda: float(os.environ.get("NIDS_THRESHOLD", "0.6")))
    https: bool = field(default_factory=lambda: _bool("NIDS_HTTPS"))
    trust_proxy: int = field(default_factory=lambda: int(os.environ.get("NIDS_TRUST_PROXY", "0")))
    session_minutes: int = field(default_factory=lambda: int(os.environ.get("NIDS_SESSION_MINUTES", "60")))
    webhook_url: str | None = field(default_factory=lambda: os.environ.get("NIDS_WEBHOOK_URL") or None)
    metrics_token: str | None = field(default_factory=lambda: os.environ.get("NIDS_METRICS_TOKEN") or None)
    log_level: str = field(default_factory=lambda: os.environ.get("NIDS_LOG_LEVEL", "INFO").upper())
    threads: int = field(default_factory=lambda: int(os.environ.get("NIDS_THREADS", "8")))

    @property
    def db(self) -> Path:
        return self.instance / "nids.sqlite3"

    @property
    def alert_log(self) -> Path:
        return self.instance / "alerts.jsonl"

    def validate(self):
        if self.source not in {"replay", "live"}:
            raise ValueError("NIDS_SOURCE must be 'replay' or 'live'")
        if not 0.0 < self.threshold <= 1.0:
            raise ValueError("NIDS_THRESHOLD must be in (0, 1]")
        if self.webhook_url and not self.webhook_url.startswith(("https://", "http://")):
            raise ValueError("NIDS_WEBHOOK_URL must be an http(s) URL")
        return self
