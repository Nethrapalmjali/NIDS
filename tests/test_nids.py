"""Run with:  python -m unittest discover -s tests -v"""
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nids import app as nids_app
from nids.features import FEATURES, FlowTable, map_label


class FlowFeatureTests(unittest.TestCase):
    def test_bidirectional_flow_features(self):
        t = FlowTable()
        t.packet(0.0, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 60, "S", 64240)
        t.packet(0.1, "10.0.0.9", "10.0.0.5", 22, 50000, "tcp", 60, "SA", 65160)
        t.packet(0.2, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 500, "PA", 502)
        flow = t.packet(0.5, "10.0.0.5", "10.0.0.9", 50000, 22, "tcp", 40, "FA", 502)
        self.assertIsNotNone(flow, "FIN should close the flow")
        f = flow.features()
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

    def test_label_mapping(self):
        self.assertEqual(map_label("BENIGN"), "Benign")
        self.assertEqual(map_label("Web Attack \x96 Sql Injection"), "Web SQL Injection")
        self.assertEqual(map_label("SSH-Patator"), "SSH Brute Force")
        self.assertIsNone(map_label("Heartbleed"))


class FakeEngine:
    class det:
        classes = ["Benign", "DDoS"]
    src = type("S", (), {"name": "replay"})()

    def stats(self):
        return {"flows": 0}


class DashboardSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = mock.patch.multiple(nids_app, INSTANCE=Path(self.tmp.name), DB=Path(self.tmp.name) / "t.db")
        p.start(); self.addCleanup(p.stop)
        nids_app.init_db("admin", "correct-horse-battery")
        self.client = nids_app.create_app(FakeEngine()).test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self, path="/login"):
        html = self.client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)

    def login(self, pw):
        return self.client.post("/login", data={"username": "admin", "password": pw, "csrf": self.csrf()})

    def test_requires_login(self):
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_post_without_csrf_rejected(self):
        self.client.get("/login")
        r = self.client.post("/login", data={"username": "admin", "password": "correct-horse-battery"})
        self.assertEqual(r.status_code, 400)

    def test_login_and_security_headers(self):
        r = self.login("correct-horse-battery")
        self.assertEqual(r.status_code, 302)
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 200)
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_lockout_after_five_failures(self):
        for _ in range(5):
            self.login("wrong-password")
        r = self.login("correct-horse-battery")
        self.assertIn("Too many failed attempts", r.get_data(as_text=True))

    def test_viewer_cannot_simulate(self):
        with nids_app.db() as con:
            from werkzeug.security import generate_password_hash
            con.execute("INSERT INTO users (username, pw_hash, role) VALUES (?,?,?)",
                        ("viewer1", generate_password_hash("viewer-password"), "viewer"))
        token = self.csrf()
        self.client.post("/login", data={"username": "viewer1", "password": "viewer-password", "csrf": token})
        r = self.client.post("/api/simulate", json={"label": "DDoS"}, headers={"X-CSRF-Token": self.csrf("/")})
        self.assertEqual(r.status_code, 403)

    def test_audit_log_is_append_only(self):
        nids_app.audit("admin", "test")
        with self.assertRaises(Exception):
            with nids_app.db() as con:
                con.execute("DELETE FROM audit")


if __name__ == "__main__":
    unittest.main()
