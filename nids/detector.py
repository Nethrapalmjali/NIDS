"""Loads the trained ensemble (with integrity checks) and classifies + explains flows."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

MODELS = Path(__file__).resolve().parent / "models"

THREATS = {
    "DDoS": ("T1498", "high", "a distributed flood aimed at exhausting the target's bandwidth or connection table",
             "Rate-limit or blackhole the target upstream and block the top source subnets at the firewall."),
    "DoS Hulk": ("T1499.002", "high", "an HTTP flood generating large numbers of unique requests",
                 "Rate-limit HTTP per source, enable the web server's request throttling and block the source."),
    "DoS GoldenEye": ("T1499.002", "high", "a keep-alive HTTP flood that pins server worker threads",
                      "Lower keep-alive timeouts, cap connections per IP and block the source."),
    "DoS Slowloris": ("T1499.002", "medium", "a slow-header attack that holds connections open with partial requests",
                      "Reduce header read timeouts, cap concurrent connections per IP, use a reverse proxy."),
    "DoS Slowhttptest": ("T1499.002", "medium", "a slow-body / slow-read attack that starves the server of sockets",
                         "Set minimum data-rate limits on request bodies and block the source."),
    "Port Scan": ("T1046", "medium", "reconnaissance probing many ports to discover exposed services",
                  "Block the scanner, review which ports answered and close anything not meant to be public."),
    "SSH Brute Force": ("T1110.001", "high", "repeated SSH login attempts guessing credentials",
                        "Block the source, enforce key-only SSH, and check auth logs for any successful login."),
    "FTP Brute Force": ("T1110.001", "high", "repeated FTP login attempts guessing credentials",
                        "Block the source, disable plain FTP in favour of SFTP, and audit FTP accounts."),
    "Web Brute Force": ("T1110", "medium", "automated guessing against a web login form",
                        "Add login rate-limiting / CAPTCHA, block the source, and force resets on targeted accounts."),
    "Web XSS": ("T1189", "medium", "attempts to inject scripts into web application parameters",
                "Review the targeted endpoint's output encoding and add a Content-Security-Policy."),
    "Web SQL Injection": ("T1190", "high", "attempts to inject SQL through web application input",
                          "Block the source, review the endpoint for unparameterised queries, check DB logs."),
    "Botnet": ("T1071", "high", "command-and-control communication from a likely compromised host",
               "Isolate the internal host, scan it for malware and block the C2 address network-wide."),
}

FRIENDLY = {
    "Destination Port": "destination port", "Flow Duration": "flow duration (µs)",
    "Total Fwd Packets": "forward packets", "Total Backward Packets": "return packets",
    "Total Length of Fwd Packets": "forward bytes", "Total Length of Bwd Packets": "return bytes",
    "Flow Bytes/s": "bytes per second", "Flow Packets/s": "packets per second",
    "Init_Win_bytes_forward": "initial TCP window (client)", "Init_Win_bytes_backward": "initial TCP window (server)",
    "Down/Up Ratio": "download/upload ratio", "Average Packet Size": "average packet size",
    "Fwd Packet Length Max": "largest forward packet (bytes)", "Fwd Packet Length Min": "smallest forward packet (bytes)",
    "Fwd Packet Length Mean": "mean forward packet size (bytes)", "Bwd Packet Length Max": "largest return packet (bytes)",
    "Bwd Packet Length Mean": "mean return packet size (bytes)",
    "Flow IAT Mean": "mean gap between packets (µs)", "Flow IAT Std": "packet-gap variation (µs)",
    "Flow IAT Max": "longest gap between packets (µs)", "Flow IAT Min": "shortest gap between packets (µs)",
    "Fwd IAT Mean": "mean gap between forward packets (µs)", "Bwd IAT Mean": "mean gap between return packets (µs)",
    "SYN Flag Count": "SYN flags", "FIN Flag Count": "FIN flags", "RST Flag Count": "RST flags",
    "PSH Flag Count": "PSH flags", "ACK Flag Count": "ACK flags",
}


class IntegrityError(RuntimeError):
    pass


class Detector:
    def __init__(self, model_dir: Path = MODELS, threshold: float = 0.6):
        self.manifest = json.loads((model_dir / "manifest.json").read_text())
        self.classes = self.manifest["classes"]
        self.features = self.manifest["features"]
        self.benign_median = self.manifest["benign_median"]
        self.threshold = threshold
        self.models = {}
        for fname, expected in self.manifest["files"].items():
            path = model_dir / fname
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:  # joblib files execute code on load: never load a modified one
                raise IntegrityError(f"{fname} failed SHA-256 verification")
            self.models[path.stem] = joblib.load(path)
        self.benign = self.classes.index("Benign")

    def vectorize(self, rows: list[dict]) -> np.ndarray:
        return np.array([[float(r.get(f, 0.0)) for f in self.features] for r in rows], dtype=np.float32)

    def predict(self, X: np.ndarray):
        proba = np.mean([m.predict_proba(X) for m in self.models.values()], axis=0)
        return proba.argmax(1), proba.max(1), proba

    def explain(self, x: np.ndarray, cls: int, conf: float, meta: dict) -> str:
        """Plain-language explanation from LightGBM SHAP contributions for the predicted class."""
        label = self.classes[cls]
        contrib = self.models["lightgbm"].predict(x.reshape(1, -1), pred_contrib=True)
        contrib = np.asarray(contrib).reshape(len(self.classes), len(self.features) + 1)[cls, :-1]
        top = np.argsort(-contrib)[:3]
        reasons = []
        for i in top:
            if contrib[i] <= 0:
                continue
            f = self.features[i]
            v, med = float(x[i]), float(self.benign_median.get(f, 0))
            name = FRIENDLY.get(f, f.lower())
            if f == "Destination Port":
                reasons.append(f"it targets port {int(v)}")
            elif med > 0 and v > med * 2:
                ratio = v / med
                how = f"~{ratio:,.0f}× the normal median of {med:,.0f}" if ratio < 1000 else \
                      f"far above the normal median of {med:,.0f}"
                reasons.append(f"{name} is {v:,.0f} ({how})")
            elif v < med / 2:
                reasons.append(f"{name} is only {v:,.0f} (normal median {med:,.0f})")
            else:
                reasons.append(f"{name} = {v:,.0f}")
        technique, severity, what, action = THREATS.get(label, ("-", "medium", "suspicious traffic", "Investigate."))
        where = f"{meta.get('src', '?')} → {meta.get('dst', '?')}:{meta.get('dport', '?')}"
        why = "; ".join(reasons) if reasons else "its overall feature profile matches known attack flows"
        return (f"{label} detected on {where} with {conf:.0%} ensemble confidence. "
                f"The flow was flagged mainly because {why}. This is consistent with {what} "
                f"(MITRE ATT&CK {technique}). Recommended action: {action}")

    def severity(self, label: str) -> str:
        return THREATS.get(label, ("", "medium"))[1]

    def technique(self, label: str) -> str:
        return THREATS.get(label, ("-",))[0]
