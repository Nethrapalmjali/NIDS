"""Flow feature definitions and a live bidirectional flow builder.

The model is trained on CIC-IDS2017 (CICFlowMeter features). We deliberately use only the
subset of features that a lightweight sensor can compute from packet headers in real time,
so the same model can score both the dataset and live traffic.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Bwd IAT Mean",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Down/Up Ratio", "Average Packet Size",
]

# Collapse CIC-IDS2017 labels into the 12 attack classes + benign used by this project.
# Infiltration (36 rows) and Heartbleed (11 rows) are too small to learn and are excluded.
def map_label(raw: str) -> str | None:
    r = raw.strip()
    if r == "BENIGN":
        return "Benign"
    if "Brute Force" in r:
        return "Web Brute Force"
    if "XSS" in r:
        return "Web XSS"
    if "Sql Injection" in r:
        return "Web SQL Injection"
    return {
        "DDoS": "DDoS", "DoS Hulk": "DoS Hulk", "DoS GoldenEye": "DoS GoldenEye",
        "DoS slowloris": "DoS Slowloris", "DoS Slowhttptest": "DoS Slowhttptest",
        "PortScan": "Port Scan", "SSH-Patator": "SSH Brute Force",
        "FTP-Patator": "FTP Brute Force", "Bot": "Botnet",
    }.get(r)


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _std(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def _iats(ts):
    return [(b - a) * 1e6 for a, b in zip(ts, ts[1:])]  # microseconds, like CICFlowMeter


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first: float
    last: float
    fwd_len: list = field(default_factory=list)
    bwd_len: list = field(default_factory=list)
    fwd_ts: list = field(default_factory=list)
    bwd_ts: list = field(default_factory=list)
    all_ts: list = field(default_factory=list)
    flags: dict = field(default_factory=lambda: {"F": 0, "S": 0, "R": 0, "P": 0, "A": 0})
    init_win_fwd: int = -1
    init_win_bwd: int = -1

    def add(self, ts: float, length: int, forward: bool, tcp_flags: str = "", window: int | None = None):
        self.last = ts
        self.all_ts.append(ts)
        if forward:
            self.fwd_len.append(length); self.fwd_ts.append(ts)
            if window is not None and self.init_win_fwd < 0:
                self.init_win_fwd = window
        else:
            self.bwd_len.append(length); self.bwd_ts.append(ts)
            if window is not None and self.init_win_bwd < 0:
                self.init_win_bwd = window
        for f in self.flags:
            if f in tcp_flags:
                self.flags[f] += 1

    def features(self) -> dict:
        dur_us = max((self.last - self.first) * 1e6, 1.0)
        nf, nb = len(self.fwd_len), len(self.bwd_len)
        bytes_total = sum(self.fwd_len) + sum(self.bwd_len)
        iat = _iats(self.all_ts)
        return {
            "Destination Port": self.dport,
            "Flow Duration": dur_us,
            "Total Fwd Packets": nf,
            "Total Backward Packets": nb,
            "Total Length of Fwd Packets": sum(self.fwd_len),
            "Total Length of Bwd Packets": sum(self.bwd_len),
            "Fwd Packet Length Max": max(self.fwd_len, default=0),
            "Fwd Packet Length Min": min(self.fwd_len, default=0),
            "Fwd Packet Length Mean": _mean(self.fwd_len),
            "Bwd Packet Length Max": max(self.bwd_len, default=0),
            "Bwd Packet Length Mean": _mean(self.bwd_len),
            "Flow Bytes/s": bytes_total / (dur_us / 1e6),
            "Flow Packets/s": (nf + nb) / (dur_us / 1e6),
            "Flow IAT Mean": _mean(iat),
            "Flow IAT Std": _std(iat),
            "Flow IAT Max": max(iat, default=0),
            "Flow IAT Min": min(iat, default=0),
            "Fwd IAT Mean": _mean(_iats(self.fwd_ts)),
            "Bwd IAT Mean": _mean(_iats(self.bwd_ts)),
            "FIN Flag Count": self.flags["F"],
            "SYN Flag Count": self.flags["S"],
            "RST Flag Count": self.flags["R"],
            "PSH Flag Count": self.flags["P"],
            "ACK Flag Count": self.flags["A"],
            "Init_Win_bytes_forward": self.init_win_fwd,
            "Init_Win_bytes_backward": self.init_win_bwd,
            "Down/Up Ratio": (nb // nf) if nf else 0,
            "Average Packet Size": bytes_total / max(nf + nb, 1),
        }


class FlowTable:
    """Groups packets into bidirectional flows; expires them on FIN/RST, idle or active timeout."""

    def __init__(self, idle_timeout: float = 15.0, active_timeout: float = 60.0, max_flows: int = 100_000):
        self.flows: dict[tuple, Flow] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows   # memory bound: a port scan opens thousands of flows per second
        self.evicted = 0

    def packet(self, ts, src, dst, sport, dport, proto, length, tcp_flags="", window=None) -> list[Flow]:
        """Add a packet; returns flows that finished as a result (closed, or evicted under memory pressure)."""
        done: list[Flow] = []
        fkey = (src, dst, sport, dport, proto)
        bkey = (dst, src, dport, sport, proto)
        if fkey in self.flows:
            flow, fwd = self.flows[fkey], True
        elif bkey in self.flows:
            flow, fwd = self.flows[bkey], False
        else:
            if len(self.flows) >= self.max_flows:
                # dicts keep insertion order, so the first key is the oldest flow
                done.append(self._pop(self.flows[next(iter(self.flows))]))
                self.evicted += 1
            flow, fwd = Flow(src, dst, sport, dport, proto, ts, ts), True
            self.flows[fkey] = flow
        flow.add(ts, length, fwd, tcp_flags, window)
        if "F" in tcp_flags or "R" in tcp_flags:
            done.append(self._pop(flow))
        return done

    def _pop(self, flow: Flow):
        self.flows.pop((flow.src, flow.dst, flow.sport, flow.dport, flow.proto), None)
        return flow

    def expire(self, now: float | None = None):
        now = now or time.time()
        done = [f for f in self.flows.values()
                if now - f.last > self.idle_timeout or now - f.first > self.active_timeout]
        return [self._pop(f) for f in done]
