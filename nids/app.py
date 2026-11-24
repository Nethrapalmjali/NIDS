"""NIDS real-time dashboard.

  python -m nids.app init            create the database and the first admin account
  python -m nids.app run [--source replay|live] [--iface NAME] [--port 5000]
"""
from __future__ import annotations

import argparse
import getpass
import os
import queue
import secrets
import sqlite3
import threading
import time
from collections import deque
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

import psutil
from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required, login_user,
                         logout_user)
from werkzeug.security import check_password_hash, generate_password_hash

from .capture import LiveCapture, Replay
from .detector import Detector

BASE = Path(__file__).resolve().parent
INSTANCE = Path(os.environ.get("NIDS_INSTANCE", BASE / "instance"))
DB = INSTANCE / "nids.sqlite3"
ROLES = {"viewer": 1, "analyst": 2, "admin": 3}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')));
CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, ts REAL NOT NULL, label TEXT NOT NULL,
  severity TEXT NOT NULL, technique TEXT, confidence REAL, src TEXT, dst TEXT, dport INTEGER,
  flows INTEGER DEFAULT 1, last_ts REAL, explanation TEXT, truth TEXT,
  status TEXT DEFAULT 'open', ack_by TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts REAL NOT NULL, user TEXT, action TEXT, detail TEXT);
-- incidents and audit are append-only for detection data: only status/ack fields may change
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incidents_no_delete BEFORE DELETE ON incidents BEGIN SELECT RAISE(ABORT,'incidents are append-only'); END;
"""


@contextmanager
def db():
    """Connection that commits on success, rolls back on error, and is always closed."""
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()


def audit(user, action, detail=""):
    with db() as con:
        con.execute("INSERT INTO audit (ts, user, action, detail) VALUES (?,?,?,?)",
                    (time.time(), user, action, detail))


# ---------------------------------------------------------------- detection engine
class Engine:
    def __init__(self, source: str, iface: str | None):
        self.q: queue.Queue = queue.Queue(maxsize=20000)
        self.det = Detector()
        self.lock = threading.Lock()
        self.flows = 0
        self.correct = self.labelled = 0
        self.class_counts = {c: 0 for c in self.det.classes}
        self.series = deque(maxlen=60)          # (t, benign flows, malicious flows, kB/s)
        self.recent: dict[tuple, int] = {}       # (label, src) -> incident id for de-duplication
        self.source_note = ""
        self.src = self._make_source(source, iface)
        self._last_net = psutil.net_io_counters()

    def _make_source(self, source, iface):
        if source == "live":
            ok, msg = LiveCapture.available()
            if ok:
                self.source_note = "Live packet capture"
                return LiveCapture(self.q, iface)
            self.source_note = f"Live capture unavailable ({msg}) — using replay"
        else:
            self.source_note = "Replay of held-out CIC-IDS2017 flows"
        return Replay(self.q)

    def start(self):
        self.src.start()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            t_end = time.time() + 1.0
            batch = []
            while time.time() < t_end:
                try:
                    batch.append(self.q.get(timeout=max(0.0, t_end - time.time())))
                except queue.Empty:
                    break
            self._process(batch)

    def _process(self, batch):
        net = psutil.net_io_counters()
        kbps = ((net.bytes_sent + net.bytes_recv) - (self._last_net.bytes_sent + self._last_net.bytes_recv)) / 1024
        self._last_net = net
        mal = 0
        if batch:
            X = self.det.vectorize([b["features"] for b in batch])
            pred, conf, _ = self.det.predict(X)
            for i, item in enumerate(batch):
                label = self.det.classes[pred[i]]
                with self.lock:
                    self.flows += 1
                    self.class_counts[label] += 1
                    if item["truth"]:
                        self.labelled += 1
                        self.correct += int(item["truth"] == label)
                if pred[i] != self.det.benign and conf[i] >= self.det.threshold:
                    mal += 1
                    self._incident(X[i], pred[i], float(conf[i]), item, label)
        with self.lock:
            self.series.append((time.time(), len(batch) - mal, mal, round(kbps, 1)))

    def _incident(self, x, cls, conf, item, label):
        key = (label, item["src"] if label != "DDoS" else "*")
        now = time.time()
        with db() as con:
            iid = self.recent.get(key)
            if iid:
                row = con.execute("SELECT last_ts FROM incidents WHERE id=?", (iid,)).fetchone()
                if row and now - row["last_ts"] < 60:
                    con.execute("UPDATE incidents SET flows=flows+1, last_ts=?, confidence=MAX(confidence,?) "
                                "WHERE id=?", (now, conf, iid))
                    return
            text = self.det.explain(x, cls, conf, item)
            cur = con.execute(
                "INSERT INTO incidents (ts,label,severity,technique,confidence,src,dst,dport,last_ts,explanation,truth)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (now, label, self.det.severity(label), self.det.technique(label), conf,
                 key[1] if key[1] == "*" else item["src"], item["dst"], item["dport"], now, text, item["truth"]))
            self.recent[key] = cur.lastrowid

    def stats(self):
        with self.lock:
            return {"flows": self.flows, "source": self.src.name, "sourceNote": self.source_note,
                    "replayAccuracy": (self.correct / self.labelled) if self.labelled else None,
                    "classCounts": self.class_counts,
                    "series": list(self.series), "threshold": self.det.threshold}


# ---------------------------------------------------------------- web app
class User(UserMixin):
    def __init__(self, row):
        self.id, self.username, self.role = str(row["id"]), row["username"], row["role"]


def create_app(engine: Engine) -> Flask:
    app = Flask(__name__)
    key_file = INSTANCE / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    app.config.update(
        SECRET_KEY=os.environ.get("NIDS_SECRET_KEY") or key_file.read_text(),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("NIDS_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=3600,
    )
    lm = LoginManager(app)
    lm.login_view = "login"
    failures: dict[str, list[float]] = {}

    @lm.user_loader
    def load_user(uid):
        with db() as con:
            row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return User(row) if row else None

    def role_required(role):
        def deco(fn):
            @wraps(fn)
            @login_required
            def inner(*a, **kw):
                if ROLES[current_user.role] < ROLES[role]:
                    audit(current_user.username, "denied", request.path)
                    abort(403)
                return fn(*a, **kw)
            return inner
        return deco

    @app.before_request
    def csrf_protect():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        if request.method == "POST":
            token = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
            if not token or not secrets.compare_digest(token, session["csrf"]):
                abort(400, "CSRF token missing or invalid")

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                   "style-src 'self'; script-src 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.context_processor
    def inject():
        return {"csrf": session.get("csrf", "")}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            recent = [t for t in failures.get(ip, []) if time.time() - t < 300]
            failures[ip] = recent
            if len(recent) >= 5:
                error = "Too many failed attempts. Try again in 5 minutes."
            else:
                username = request.form.get("username", "")[:64]
                password = request.form.get("password", "")[:256]
                with db() as con:
                    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if row and check_password_hash(row["pw_hash"], password):
                    session.clear()
                    login_user(User(row))
                    audit(username, "login", ip)
                    return redirect(url_for("dashboard"))
                failures[ip].append(time.time())
                audit(username, "login_failed", ip)
                error = "Invalid username or password."
        return render_template("login.html", error=error)

    @app.post("/logout")
    @login_required
    def logout():
        audit(current_user.username, "logout")
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user, classes=engine.det.classes,
                               can_act=ROLES[current_user.role] >= ROLES["analyst"],
                               is_admin=current_user.role == "admin", source=engine.src.name)

    @app.get("/api/stats")
    @login_required
    def api_stats():
        return jsonify(engine.stats())

    @app.get("/api/incidents")
    @login_required
    def api_incidents():
        try:
            limit = max(1, min(int(request.args.get("limit", 50)), 500))
        except ValueError:
            abort(400)
        with db() as con:
            rows = con.execute("SELECT * FROM incidents ORDER BY last_ts DESC LIMIT ?", (limit,)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/incidents/<int:iid>/ack")
    @role_required("analyst")
    def api_ack(iid):
        note = (request.get_json(silent=True) or {}).get("note", "")[:500]
        with db() as con:
            con.execute("UPDATE incidents SET status='acknowledged', ack_by=?, note=? WHERE id=?",
                        (current_user.username, note, iid))
        audit(current_user.username, "ack_incident", str(iid))
        return jsonify(ok=True)

    @app.post("/api/simulate")
    @role_required("analyst")
    def api_simulate():
        label = (request.get_json(silent=True) or {}).get("label", "")
        if label not in engine.det.classes or label == "Benign":
            abort(400, "unknown attack class")
        if not isinstance(engine.src, Replay):
            abort(409, "simulation is only available in replay mode")
        engine.src.simulate(label)
        audit(current_user.username, "simulate", label)
        return jsonify(ok=True)

    @app.get("/admin")
    @role_required("admin")
    def admin():
        with db() as con:
            users = con.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
            log = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
        return render_template("admin.html", users=users, log=log, user=current_user, msg=request.args.get("msg"))

    @app.post("/admin/users")
    @role_required("admin")
    def admin_create_user():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if not (3 <= len(username) <= 32 and username.isalnum()) or role not in ROLES or len(password) < 10:
            return redirect(url_for("admin", msg="Username: 3-32 letters/digits; password: 10+ characters."))
        try:
            with db() as con:
                con.execute("INSERT INTO users (username, pw_hash, role) VALUES (?,?,?)",
                            (username, generate_password_hash(password), role))
        except sqlite3.IntegrityError:
            return redirect(url_for("admin", msg="That username already exists."))
        audit(current_user.username, "create_user", f"{username}:{role}")
        return redirect(url_for("admin", msg=f"Created {username} ({role})."))

    return app


def init_db(admin_user: str, password: str | None):
    INSTANCE.mkdir(exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("Database already initialised.")
            return
        password = password or getpass.getpass(f"Password for {admin_user} (10+ chars): ")
        if len(password) < 10:
            raise SystemExit("Password must be at least 10 characters.")
        con.execute("INSERT INTO users (username, pw_hash, role) VALUES (?,?,?)",
                    (admin_user, generate_password_hash(password), "admin"))
    print(f"Created admin user '{admin_user}'.")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--user", default="admin")
    r = sub.add_parser("run")
    r.add_argument("--source", choices=["replay", "live"], default="replay")
    r.add_argument("--iface"); r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    if args.cmd == "init":
        init_db(args.user, os.environ.get("NIDS_ADMIN_PASSWORD"))
        return
    if not DB.exists():
        raise SystemExit("Run `python -m nids.app init` first.")
    engine = Engine(args.source, args.iface)
    engine.start()
    print(f"Source: {engine.source_note}")
    create_app(engine).run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
