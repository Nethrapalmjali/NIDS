"""Alert forwarding: JSON-lines feed for SIEM ingestion and an optional webhook.

alerts.jsonl  one JSON object per new incident; point Filebeat / Wazuh / Splunk UF at it
webhook       POSTs the same JSON to NIDS_WEBHOOK_URL from a background thread with a bounded
              queue and timeout, so a slow or failing endpoint can never stall detection
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.request
from pathlib import Path

log = logging.getLogger("nids.alerts")


class AlertSink:
    def __init__(self, jsonl_path: Path, webhook_url: str | None = None):
        self.path = jsonl_path
        self.webhook_url = webhook_url
        self._lock = threading.Lock()
        self.sent = self.failed = self.dropped = 0
        self._q: queue.Queue = queue.Queue(maxsize=1000)
        if webhook_url:
            threading.Thread(target=self._webhook_loop, name="webhook", daemon=True).start()

    def publish(self, incident: dict):
        line = json.dumps(incident, separators=(",", ":"), default=str)
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.webhook_url:
            try:
                self._q.put_nowait(line)
            except queue.Full:
                self.dropped += 1

    def _webhook_loop(self):
        while True:
            body = self._q.get().encode()
            for attempt in (1, 2):
                try:
                    req = urllib.request.Request(self.webhook_url, body, {"Content-Type": "application/json",
                                                                          "User-Agent": "nids/1.0"})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if 200 <= resp.status < 300:
                            self.sent += 1
                            break
                except Exception as e:  # noqa: BLE001
                    if attempt == 2:
                        self.failed += 1
                        log.warning("webhook delivery failed: %s", e)
