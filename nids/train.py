"""Train and evaluate the NIDS ensemble on CIC-IDS2017.

Usage:  python -m nids.train  [--zip data/raw/MachineLearningCSV.zip]

Outputs
  nids/models/*.joblib, manifest.json   trained models + SHA-256 integrity hashes
  nids/models/replay.csv.gz              held-out flows for the dashboard's replay mode
  nids/reports/metrics.json              every number shown on the website
  assets/results.js, assets/report.js    the same numbers, for the website
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from .features import FEATURES, map_label

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "nids" / "models"
REPORTS = ROOT / "nids" / "reports"
SEED = 42
BENIGN_CAP = 250_000   # benign flows kept after de-duplication
ATTACK_CAP = 50_000    # per attack class


def load(zip_path: Path) -> pd.DataFrame:
    wanted = set(FEATURES) | {"Label"}
    frames = []
    with zipfile.ZipFile(zip_path) as z:
        for name in sorted(n for n in z.namelist() if n.endswith(".csv")):
            with z.open(name) as fh:
                df = pd.read_csv(fh, usecols=lambda c: c.strip() in wanted,
                                 encoding="latin-1", low_memory=False)
            df.columns = [c.strip() for c in df.columns]
            print(f"  {Path(name).name:<70} {len(df):>9,} rows")
            frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["Label"] = df["Label"].map(map_label)
    df = df.dropna(subset=["Label"])
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    df = pd.concat([X.astype("float32"), df["Label"]], axis=1).dropna()
    return df


def sample(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.drop_duplicates()
    print(f"  removed {before - len(df):,} duplicate flows")
    parts = []
    for label, g in df.groupby("Label"):
        cap = BENIGN_CAP if label == "Benign" else ATTACK_CAP
        parts.append(g.sample(n=min(len(g), cap), random_state=SEED))
    return pd.concat(parts).sample(frac=1, random_state=SEED).reset_index(drop=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(name, y_true, y_pred, benign_idx, infer_s, n):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    benign = y_true == benign_idx
    fpr = float(np.mean(y_pred[benign] != benign_idx))
    attack = ~benign
    detection = float(np.mean(y_pred[attack] != benign_idx))
    return {"model": name, "accuracy": accuracy_score(y_true, y_pred), "precision": p, "recall": r,
            "f1": f, "fpr": fpr, "detectionRate": detection,
            "inferenceMs": round(infer_s / n * 1000, 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default=str(ROOT / "data" / "raw" / "MachineLearningCSV.zip"))
    args = ap.parse_args()
    MODELS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    print("Loading CIC-IDS2017 ...")
    full = load(Path(args.zip))
    raw_counts = full["Label"].value_counts().to_dict()
    data = sample(full)
    del full
    classes = sorted(data["Label"].unique(), key=lambda c: (c != "Benign", c))
    cidx = {c: i for i, c in enumerate(classes)}
    X = data[FEATURES].to_numpy(np.float32)
    y = data["Label"].map(cidx).to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    print(f"  train {len(X_tr):,}  test {len(X_te):,}  classes {len(classes)}")

    # Square-root inverse-frequency weights: rare classes (SQLi, XSS) matter without dominating.
    counts = np.bincount(y_tr, minlength=len(classes))
    w = np.sqrt(counts.max() / counts)[y_tr]

    models = {
        "LightGBM": LGBMClassifier(n_estimators=400, learning_rate=0.08, num_leaves=63,
                                   subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                                   random_state=SEED, n_jobs=-1, verbose=-1),
        "XGBoost": XGBClassifier(n_estimators=400, learning_rate=0.1, max_depth=8,
                                 subsample=0.8, colsample_bytree=0.8, tree_method="hist",
                                 random_state=SEED, n_jobs=-1),
        "CatBoost": CatBoostClassifier(iterations=600, learning_rate=0.15, depth=8,
                                       random_seed=SEED, verbose=0, thread_count=-1),
    }

    results, probas, train_times = [], {}, {}
    benign_idx = cidx["Benign"]
    for name, m in models.items():
        t0 = time.perf_counter()
        m.fit(X_tr, y_tr, sample_weight=w)
        train_times[name] = round(time.perf_counter() - t0, 1)
        t0 = time.perf_counter()
        pr = m.predict_proba(X_te)
        infer = time.perf_counter() - t0
        probas[name] = pr
        res = evaluate(name, y_te, pr.argmax(1), benign_idx, infer, len(X_te))
        res["trainSeconds"] = train_times[name]
        results.append(res)
        print(f"  {name:<9} acc={res['accuracy']:.4f} f1={res['f1']:.4f} fpr={res['fpr']:.4f} "
              f"train={train_times[name]}s")
        joblib.dump(m, MODELS / f"{name.lower()}.joblib", compress=3)

    # Soft-voting ensemble: average class probabilities of the three models.
    ens_p = np.mean(list(probas.values()), axis=0)
    ens_pred = ens_p.argmax(1)
    infer_total = sum(r["inferenceMs"] for r in results) / 1000 * len(X_te)
    ens = evaluate("Ensemble (soft voting)", y_te, ens_pred, benign_idx, infer_total, len(X_te))
    ens["trainSeconds"] = round(sum(train_times.values()), 1)
    results.append(ens)
    print(f"  Ensemble  acc={ens['accuracy']:.4f} f1={ens['f1']:.4f} fpr={ens['fpr']:.4f}")

    # Per-class report and confusion matrix for the ensemble.
    p, r, f, s = precision_recall_fscore_support(y_te, ens_pred, labels=range(len(classes)), zero_division=0)
    per_class = [{"label": c, "precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                  "support": int(s[i])} for i, c in enumerate(classes)]
    cm = confusion_matrix(y_te, ens_pred, labels=range(len(classes))).tolist()

    lgb = models["LightGBM"]
    imp = lgb.booster_.feature_importance(importance_type="gain")
    importance = sorted(({"feature": FEATURES[i], "gain": float(imp[i] / imp.sum())}
                         for i in range(len(FEATURES))), key=lambda d: -d["gain"])

    # Benign medians: used by the explainer to say how far a flow deviates from normal.
    benign_median = dict(zip(FEATURES, np.median(X_tr[y_tr == benign_idx], axis=0).tolist()))

    manifest = {"classes": classes, "features": FEATURES, "benign_median": benign_median,
                "files": {}}
    for name in models:
        fp = MODELS / f"{name.lower()}.joblib"
        manifest["files"][fp.name] = sha256(fp)
    (MODELS / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Held-out flows for replay mode (never seen in training).
    rng = np.random.default_rng(SEED)
    pick = np.concatenate([rng.choice(np.where(y_te == k)[0], size=min(300 if k == benign_idx else 40,
                                                                        (y_te == k).sum()), replace=False)
                           for k in range(len(classes))])
    replay = pd.DataFrame(X_te[pick], columns=FEATURES)
    replay["Label"] = [classes[k] for k in y_te[pick]]
    replay.sample(frac=1, random_state=SEED).to_csv(MODELS / "replay.csv.gz", index=False)

    report = {
        "dataset": "CIC-IDS2017 (MachineLearningCSV)",
        "rawCounts": {k: int(v) for k, v in raw_counts.items()},
        "trainRows": int(len(X_tr)), "testRows": int(len(X_te)),
        "features": len(FEATURES), "classes": classes,
        "results": results, "perClass": per_class, "confusion": cm, "importance": importance,
        "environment": {"python": platform.python_version(), "cpu": platform.processor(),
                        "os": platform.platform()},
        "generated": time.strftime("%Y-%m-%d %H:%M"),
    }
    (REPORTS / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (ROOT / "assets" / "results.js").write_text(
        "// Generated by nids/train.py - measured on the CIC-IDS2017 held-out test split.\n"
        f"window.NIDS_RESULTS = {json.dumps(results, indent=2)};\n", encoding="utf-8")
    (ROOT / "assets" / "report.js").write_text(
        "// Generated by nids/train.py\n"
        f"window.NIDS_REPORT = {json.dumps({k: report[k] for k in ['dataset','rawCounts','trainRows','testRows','features','classes','perClass','confusion','importance','environment','generated']})};\n", encoding="utf-8")
    print("Done. Reports written to nids/reports/metrics.json and assets/.")


if __name__ == "__main__":
    main()
