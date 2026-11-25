"""Run with:  python -m unittest discover -s tests -v"""
import json
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import pandas as pd

from nids import app as nids_app
from nids.config import Settings
from nids.detector import MODELS, Detector, IntegrityError
from nids.features import FEATURES, FlowTable, map_label


class FlowFeatureTests(unittest.TestCase):
    def test_bidirectional_flow_features(self):
        t = FlowTable()
        t.packet(0.0, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 60, "S", 64240)
        t.packet(0.1, "10.0.0.9", "10.0.0.5", 22, 50000, "tcp", 60, "SA", 65160)
        t.packet(0.2, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 500, "PA", 502)
        done = t.packet(0.5, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 40, "FA", 502)
        self.assertEqual(len(done), 1, "FIN should close the flow")
        f = done[0].features()
        self.assertEqual(set(f), set(FEATURES))
        self.assertEqual(f["Destination Port"], 22)
        self.assertEqual(f["Total Fwd Packets"], 3)
        self.assertEqual(f["Total Backward Packets"], 1)
        self.assertEqual(f["Total Length of Fwd Packets"], 600)
        self.assertAlmostEqual(f["Flow Duration"], 500_000, delta=1)
        self.assertEqual(f["Init_Win_bytes_forward"], 64240)
        self.assertEqual(f["Init_Win_bytes_backward"], 65160)
        self.assertEqual(f["SYN Flag Count"], 2)
        self.assertEqual(f["FIN Flag Count"], 1)
        self.assertAlmostEqual(f["Flow Packets/s"], 8.0)

    def test_idle_expiry(self):
        t = FlowTable(idle_timeout=5)
        t.packet(100.0, "1.1.1.1", "2.2.2.2", 1, 53, "udp", 80)
        self.assertEqual(t.expire(now=103), [])
        self.assertEqual(len(t.expire(now=106)), 1)

    def test_flow_table_is_memory_bounded(self):
        t = FlowTable(max_flows=100)
        evicted = []
        for port in range(1, 1001):   # a port scan: one new flow per port
            evicted += t.packet(float(port), "6.6.6.6", "10.0.0.1", 40000, port, "tcp", 60, "S")
        self.assertEqual(len(t.flows), 100)
        self.assertEqual(len(evicted), 900)
        self.assertEqual(evicted[0].dport, 1, "oldest flow is evicted first")

    def test_label_mapping(self):
        self.assertEqual(map_label("BENIGN"), "Benign")
        self.assertEqual(map_label("Web Attack \x96 Sql Injection"), "Web SQL Injection")
        self.assertEqual(map_label("SSH-Patator"), "SSH Brute Force")
        self.assertIsNone(map_label("Heartbleed"))


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = Detector()

    def test_models_verified_and_versions_match(self):
        self.assertEqual(set(self.det.models), {"lightgbm", "xgboost", "catboost"})
        self.assertEqual(self.det.version_warnings, [])

    def test_accuracy_on_held_out_replay_flows(self):
        df = pd.read_csv(MODELS / "replay.csv.gz")
        pred, _, _ = self.det.predict(df[FEATURES].to_numpy("float32"))
        acc = (pd.Series([self.det.classes[p] for p in pred]) == df["Label"]).mean()
        self.assertGreater(acc, 0.95)

    def test_explanation_mentions_class_and_technique(self):
        df = pd.read_csv(MODELS / "replay.csv.gz")
        row = df[df["Label"] == "SSH Brute Force"].iloc[0]
        x = row[FEATURES].to_numpy("float32")
        cls = self.det.classes.index("SSH Brute Force")
        text = self.det.explain(x, cls, 0.99, {"src": "1.2.3.4", "dst": "10.0.0.10", "dport": 22})
        self.assertIn("SSH Brute Force", text)
        self.assertIn("T1110.001", text)

    def test_tampered_model_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for f in MODELS.iterdir():
                shutil.copy(f, d / f.name)
            blob = bytearray((d / "xgboost.joblib").read_bytes())
            blob[-10] ^= 0xFF
            (d / "xgboost.joblib").write_bytes(bytes(blob))
            with self.assertRaises(IntegrityError):
                Detector(model_dir=d)


class TempInstance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = Settings(instance=Path(self.tmp.name))
        nids_app.configure(self.settings)
        nids_app.migrate()
        nids_app.create_user("admin", "correct-horse-battery", "admin")

    def tearDown(self):
        self.tmp.cleanup()


class EngineTests(TempInstance):
    def test_attack_flows_raise_one_deduplicated_incident_and_alert(self):
        engine = nids_app.Engine(self.settings)
        df = pd.read_csv(MODELS / "replay.csv.gz")
        rows = df[df["Label"] == "DDoS"].head(20)
        batch = [{"features": r[FEATURES].to_dict(), "src": f"198.51.100.{i}", "dst": "10.0.0.10",
                  "dport": 80, "proto": "tcp", "truth": "DDoS"} for i, (_, r) in enumerate(rows.iterrows())]
        engine._process(batch)
        with nids_app.db() as con:
            inc = con.execute("SELECT * FROM incidents").fetchall()
        self.assertEqual(len(inc), 1, "DDoS flows from many sources group into one incident")
        self.assertEqual(inc[0]["label"], "DDoS")
        self.assertGreaterEqual(inc[0]["flows"], 18)
        lines = self.settings.alert_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["technique"], "T1498")
        self.assertEqual(engine.stats()["flows"], 20)


class FakeEngine:
    class det:
        classes = ["Benign", "DDoS"]

    class sink:
        sent = failed = dropped = 0

    src = type("S", (), {"name": "replay", "dropped": 0})()
    incidents = 0

    def __init__(self):
        self.heartbeat = time.time()

    def stats(self):
        return {"flows": 5, "classCounts": {"Benign": 5, "DDoS": 0}, "dropped": 0, "queue": 0,
                "heartbeatAge": 0.1}


class DashboardTests(TempInstance):
    def setUp(self):
        super().setUp()
        self.engine = FakeEngine()
        self.client = nids_app.create_app(self.engine, self.settings).test_client()

    def csrf(self, path="/login"):
        html = self.client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)

    def login(self, user="admin", pw="correct-horse-battery"):
        return self.client.post("/login", data={"username": user, "password": pw, "csrf": self.csrf()})

    def add_incident(self, explanation="x", label="DDoS"):
        with nids_app.db() as con:
            con.execute("INSERT INTO incidents (ts,label,severity,technique,confidence,src,dst,dport,last_ts,explanation)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)", (time.time(), label, "high", "T1498", 0.99, "*",
                                                          "10.0.0.10", 80, time.time(), explanation))

    def test_requires_login(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self.client.get("/api/stats").status_code, 401)

    def test_post_without_csrf_rejected(self):
        self.client.get("/login")
        r = self.client.post("/login", data={"username": "admin", "password": "correct-horse-battery"})
        self.assertEqual(r.status_code, 400)

    def test_login_and_security_headers(self):
        self.assertEqual(self.login().status_code, 302)
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 200)
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_lockout_after_five_failures(self):
        for _ in range(5):
            self.login(pw="wrong-password")
        r = self.login()
        self.assertIn("Too many failed attempts", r.get_data(as_text=True))

    def test_disabled_user_cannot_login(self):
        nids_app.create_user("bob", "bob-password-1", "analyst")
        with nids_app.db() as con:
            con.execute("UPDATE users SET active=0 WHERE username='bob'")
        r = self.login("bob", "bob-password-1")
        self.assertIn("Invalid username or password", r.get_data(as_text=True))

    def test_viewer_cannot_simulate_or_export(self):
        nids_app.create_user("viewer1", "viewer-password", "viewer")
        self.login("viewer1", "viewer-password")
        token = self.csrf("/")
        r = self.client.post("/api/simulate", json={"label": "DDoS"}, headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.get("/api/incidents.csv").status_code, 403)

    def test_incident_filters_and_validation(self):
        self.add_incident()
        self.login()
        self.assertEqual(len(self.client.get("/api/incidents?status=open").get_json()), 1)
        self.assertEqual(len(self.client.get("/api/incidents?status=acknowledged").get_json()), 0)
        self.assertEqual(self.client.get("/api/incidents?status=bogus").status_code, 400)
        self.assertEqual(self.client.get("/api/incidents?limit=abc").status_code, 400)

    def test_csv_export_neutralises_formula_injection(self):
        self.add_incident(explanation="=HYPERLINK(\"http://evil\")")
        self.login()
        r = self.client.get("/api/incidents.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("'=HYPERLINK", r.get_data(as_text=True))

    def test_acknowledge_flow(self):
        self.add_incident()
        self.login()
        token = self.csrf("/")
        r = self.client.post("/api/incidents/1/ack", json={"note": "checked"}, headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 200)
        r = self.client.post("/api/incidents/1/ack", json={}, headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 404, "already acknowledged")

    def test_change_password(self):
        self.login()
        token = self.csrf("/account")
        r = self.client.post("/account", data={"csrf": token, "current": "correct-horse-battery",
                                               "new": "even-better-password", "confirm": "even-better-password"})
        self.assertIn("Password changed", r.get_data(as_text=True))
        with nids_app.db() as con:
            h = con.execute("SELECT pw_hash FROM users WHERE username='admin'").fetchone()[0]
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(h, "even-better-password"))

    def test_last_admin_cannot_be_demoted(self):
        self.login()
        token = self.csrf("/admin")
        r = self.client.post("/admin/users/1", data={"csrf": token, "role": "viewer", "active": "1"},
                             follow_redirects=True)
        self.assertIn("last active admin", r.get_data(as_text=True))
        with nids_app.db() as con:
            self.assertEqual(con.execute("SELECT role FROM users WHERE id=1").fetchone()[0], "admin")

    def test_health_ready_and_metrics(self):
        self.assertEqual(self.client.get("/healthz").get_json()["status"], "ok")
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.engine.heartbeat = time.time() - 60
        self.assertEqual(self.client.get("/readyz").status_code, 503)
        m = self.client.get("/metrics")   # test client connects from loopback
        self.assertEqual(m.status_code, 200)
        self.assertIn("nids_flows_total 5", m.get_data(as_text=True))
        r = self.client.get("/metrics", environ_base={"REMOTE_ADDR": "203.0.113.9"})
        self.assertEqual(r.status_code, 403)

    def test_audit_log_is_append_only(self):
        nids_app.audit("admin", "test")
        with self.assertRaises(Exception):
            with nids_app.db() as con:
                con.execute("DELETE FROM audit")

    def test_migrations_are_idempotent(self):
        nids_app.migrate()
        with nids_app.db() as con:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], len(nids_app.MIGRATIONS))


if __name__ == "__main__":
    unittest.main()
