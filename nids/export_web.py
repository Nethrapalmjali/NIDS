"""Export a compact LightGBM model + held-out CIC-IDS2017 flows for the website's in-browser
real-time analyser.

Usage:  python -m nids.export_web

The browser model is trained on exactly the same de-duplicated, stratified training split as
nids/train.py (same seed), evaluated on the same held-out test split, and its trees are exported
as flat arrays so assets/live.js can score flows and compute per-feature contributions
(Saabas path attribution) without a server.
"""
from __future__ import annotations

import json
import time

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from .detector import THREATS
from .features import FEATURES
from .train import ROOT, SEED, load, sample

OUT = ROOT / "assets" / "data"


def flatten(tree: dict):
    """Pre-order flatten: f=feature (-1 leaf), t=threshold, l/r=child index, v=node value."""
    f, t, l, r, v = [], [], [], [], []

    def walk(n):
        i = len(f)
        f.append(-1); t.append(0.0); l.append(-1); r.append(-1)
        if "leaf_value" in n:
            v.append(n["leaf_value"])
            return i
        assert n["decision_type"] == "<=", n["decision_type"]
        f[i] = n["split_feature"]; t[i] = n["threshold"]; v.append(n["internal_value"])
        l[i] = walk(n["left_child"])
        r[i] = walk(n["right_child"])
        return i

    walk(tree)
    return {"f": f, "t": t, "l": l, "r": r, "v": [round(x, 6) for x in v]}


def predict_raw(trees, k, x):
    """Reference implementation of the JS scorer, used to verify the export."""
    out = np.zeros(k)
    for i, tr in enumerate(trees):
        n = 0
        while tr["f"][n] >= 0:
            n = tr["l"][n] if x[tr["f"][n]] <= tr["t"][n] else tr["r"][n]
        out[i % k] += tr["v"][n]
    return out


def main():
    print("Loading CIC-IDS2017 ...")
    data = sample(load(ROOT / "data" / "raw" / "MachineLearningCSV.zip"))
    classes = sorted(data["Label"].unique(), key=lambda c: (c != "Benign", c))
    cidx = {c: i for i, c in enumerate(classes)}
    X = data[FEATURES].to_numpy(np.float32)
    y = data["Label"].map(cidx).to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    counts = np.bincount(y_tr, minlength=len(classes))
    w = np.sqrt(counts.max() / counts)[y_tr]

    t0 = time.perf_counter()
    m = LGBMClassifier(n_estimators=160, learning_rate=0.05, num_leaves=24,
                       subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                       random_state=SEED, n_jobs=-1, verbose=-1)
    m.fit(X_tr, y_tr, sample_weight=w)
    train_s = time.perf_counter() - t0
    pred = m.predict(X_te)
    p, r, f, _ = precision_recall_fscore_support(y_te, pred, average="macro", zero_division=0)
    benign = cidx["Benign"]
    metrics = {"accuracy": accuracy_score(y_te, pred), "precision": p, "recall": r, "f1": f,
               "fpr": float(np.mean(pred[y_te == benign] != benign)),
               "trainSeconds": round(train_s, 1), "testRows": int(len(y_te))}
    print("  browser model:", {k: round(v, 4) if isinstance(v, float) else v for k, v in metrics.items()})

    assert f > 0.85, f"browser model underperforms (macro F1 {f:.3f}); not exporting"
    trees = [flatten(ti["tree_structure"]) for ti in m.booster_.dump_model()["tree_info"]]

    # Held-out flows for the browser stream: all classes, never seen in training.
    rng = np.random.default_rng(SEED + 1)
    pick = []
    for k in range(len(classes)):
        idx = np.where(y_te == k)[0]
        pick.append(rng.choice(idx, size=min(1500 if k == benign else 150, len(idx)), replace=False))
    pick = np.concatenate(pick)
    flows = [[float(v) for v in X_te[i]] for i in pick]
    labels = [int(y_te[i]) for i in pick]

    # Verify the flattened trees reproduce LightGBM's own predictions exactly.
    sub = pick[:400]
    ref = m.predict_proba(X_te[sub]).argmax(1)
    mine = np.array([predict_raw(trees, len(classes), X_te[i].astype(np.float64)).argmax() for i in sub])
    agree = float(np.mean(ref == mine))
    print(f"  export check: flattened trees agree with LightGBM on {agree:.2%} of flows")
    assert agree == 1.0

    benign_median = np.median(X_tr[y_tr == benign], axis=0).tolist()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "model.json").write_text(json.dumps({
        "classes": classes, "features": FEATURES, "numClass": len(classes), "trees": trees,
        "benignMedian": benign_median, "metrics": metrics,
        "threats": {k: {"technique": v[0], "severity": v[1], "what": v[2], "action": v[3]}
                    for k, v in THREATS.items()},
    }, separators=(",", ":")), encoding="utf-8")
    (OUT / "flows.json").write_text(json.dumps({"x": flows, "y": labels}, separators=(",", ":")),
                                    encoding="utf-8")
    for fn in ("model.json", "flows.json"):
        print(f"  wrote assets/data/{fn}  {(OUT / fn).stat().st_size / 1e6:.2f} MB")


if __name__ == "__main__":
    main()
