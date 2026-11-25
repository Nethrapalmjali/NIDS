"""Traffic sources feeding the detection engine.

live    – real packet capture with Scapy (needs Npcap on Windows / root or CAP_NET_RAW on Linux)
replay  – streams held-out CIC-IDS2017 flows the model never saw, in real time, as background
          traffic; attack simulations inject flows of a chosen class

Sources never block: if the engine falls behind and the queue is full, flows are dropped and
counted (exposed on the dashboard and /metrics) rather than stalling packet capture.
"""
from __future__ import annotations

import logging
import os
import queue
import random
import threading
import time
from pathlib import Path

import pandas as pd

from .features import FEATURES, FlowTable

MODELS = Path(__file__).resolve().parent / "models"
log = logging.getLogger("nids.capture")


class Source:
    name = "base"

    def __init__(self, out: queue.Queue):
        self.out = out
        self.dropped = 0
        self._stop = threading.Event()

    def emit(self, item: dict):
        try:
            self.out.put_nowait(item)
        except queue.Full:
            self.dropped += 1

    def stop(self):
        self._stop.set()


class LiveCapture(Source):
    name = "live"

    def __init__(self, out: queue.Queue, iface: str | None = None):
        super().__init__(out)
        self.iface = iface
        self.table = FlowTable()
        self.sniffer = None

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            from scapy.all import conf
            if os.name == "nt" and not conf.use_pcap:
                return False, "Npcap is not installed; install it from npcap.com to enable live capture"
            return True, "ok"
        except Exception as e:  # noqa: BLE001
            return False, f"Scapy unavailable: {e}"

    def _on_packet(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP
        if IP not in pkt:
            return
        ip = pkt[IP]
        sport = dport = 0
        flags, window, proto = "", None, "other"
        if TCP in pkt:
            t = pkt[TCP]; sport, dport, proto = t.sport, t.dport, "tcp"
            flags, window = str(t.flags), int(t.window)
        elif UDP in pkt:
            u = pkt[UDP]; sport, dport, proto = u.sport, u.dport, "udp"
        for flow in self.table.packet(float(pkt.time), ip.src, ip.dst, sport, dport, proto,
                                      int(ip.len), flags, window):
            self._emit_flow(flow)

    def _emit_flow(self, flow):
        self.emit({"features": flow.features(), "src": flow.src, "dst": flow.dst,
                   "dport": flow.dport, "proto": flow.proto, "truth": None})

    def _expiry(self):
        while not self._stop.is_set():
            for f in self.table.expire():
                self._emit_flow(f)
            time.sleep(1)

    def start(self):
        from scapy.all import AsyncSniffer
        threading.Thread(target=self._expiry, name="flow-expiry", daemon=True).start()
        self.sniffer = AsyncSniffer(iface=self.iface, filter="ip", prn=self._on_packet, store=False)
        self.sniffer.start()
        log.info("live capture started on %s", self.iface or "all interfaces")

    def stop(self):
        super().stop()
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:  # noqa: BLE001
                pass


class Replay(Source):
    name = "replay"

    def __init__(self, out: queue.Queue, rate: float = 15.0):
        super().__init__(out)
        self.rate = rate
        df = pd.read_csv(MODELS / "replay.csv.gz")
        self.by_class = {k: g[FEATURES].to_dict("records") for k, g in df.groupby("Label")}

    def _host(self):
        return f"10.0.{random.randint(0, 3)}.{random.randint(2, 250)}"

    def _put(self, label, src=None, dst=None):
        row = random.choice(self.by_class[label])
        self.emit({"features": row, "src": src or self._host(), "dst": dst or "10.0.0.10",
                   "dport": int(row["Destination Port"]), "proto": "tcp", "truth": label})

    def simulate(self, label: str, flows: int = 40, seconds: float = 4.0):
        if label not in self.by_class:
            raise ValueError(label)
        attacker = f"203.0.113.{random.randint(2, 250)}"

        def run():
            for _ in range(flows):
                src = f"198.51.100.{random.randint(2, 250)}" if label == "DDoS" else attacker
                self._put(label, src=src)
                time.sleep(seconds / flows)
        threading.Thread(target=run, name=f"simulate-{label}", daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            self._put("Benign")
            time.sleep(random.expovariate(self.rate))

    def start(self):
        threading.Thread(target=self._loop, name="replay", daemon=True).start()
        log.info("replay source started (%.0f benign flows/s)", self.rate)
