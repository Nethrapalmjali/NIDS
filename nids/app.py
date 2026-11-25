"""NIDS real-time dashboard.

  python -m nids.app init [--user admin]           create the database and the first admin account
  python -m nids.app serve [--source replay|live]  production server (Waitress)
  python -m nids.app serve --dev                   Flask development server (auto-reload off)
  python -m nids.app create-user NAME --role analyst
  python -m nids.app reset-password NAME
  python -m nids.app check                         verify models, library versions and database

All settings can also be given as environment variables; see nids/config.py.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import io
import logging
import logging.handlers
import os
import queue
import secrets
import sqlite3
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps

import psutil
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, session, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required, login_user,
                         logout_user)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from .alerts import AlertSink
from .capture import LiveCapture, Replay
from .config import Settings
from .detector import Detector

log = logging.getLogger("nids")
ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
MIN_PASSWORD = 10
VERSION = "1.0.0"

SETTINGS = Settings()
INSTANCE = SETTINGS.instance
DB = SETTINGS.db


def configure(settings: Settings):
    global SETTINGS, INSTANCE, DB
    SETTINGS, INSTANCE, DB = settings, settings.instance, settings.db


# ---------------------------------------------------------------- database
MIGRATIONS = [
    # v1: base schema
    """
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')));
    CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, ts REAL NOT NULL, label TEXT NOT NULL,
      severity TEXT NOT NULL, technique TEXT, confidence REAL, src TEXT, dst TEXT, dport INTEGER,
      flows INTEGER DEFAULT 1, last_ts REAL, explanation TEXT, truth TEXT,
      status TEXT DEFAULT 'open', ack_by TEXT, note TEXT);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts REAL NOT NULL, user TEXT, action TEXT, detail TEXT);
    CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS incidents_no_delete BEFORE DELETE ON incidents BEGIN SELECT RAISE(ABORT,'incidents are append-only'); END;
    """,
    # v2: account state + query indexes
    """
    ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE users ADD COLUMN created REAL;
    CREATE INDEX IF NOT EXISTS ix_incidents_last_ts ON incidents(last_ts);
    CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
    """,
]


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


def migrate():
    INSTANCE.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")  # readers don't block the engine's writes
        current = con.execute("PRAGMA user_version").fetchone()[0]
        for version, script in enumerate(MIGRATIONS, start=1):
            if version > current:
                con.executescript(script)
                con.execute(f"PRAGMA user_version = {version}")
                log.info("database migrated to schema v%d", version)


def audit(user, action, detail=""):
    with db() as con:
        con.execute("INSERT INTO audit (ts, user, action, detail) VALUES (?,?,?,?)",
                    (time.time(), user, action, detail))


def create_user(username: str, password: str, role: str):
    if not (3 <= len(username) <= 32 and username.isalnum()):
        raise ValueError("username must be 3-32 letters or digits")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    with db() as con:
        con.execute("INSERT INTO users (username, pw_hash, role, created) VALUES (?,?,?,?)",
                    (username, generate_password_hash(password), role, time.time()))


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


# ---------------------------------------------------------------- detection engine
class Engine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.q: queue.Queue = queue.Queue(maxsize=20000)
        self.det = Detector(threshold=settings.threshold)
        self.sink = AlertSink(settings.alert_log, settings.webhook_url)
        self.lock = threading.Lock()
        self.flows = self.incidents = 0
        self.correct = self.labelled = 0
        self.class_counts = {c: 0 for c in self.det.classes}
        self.series = deque(maxlen=60)          # (t, benign flows, malicious flows, kB/s)
        self.recent: dict[tuple, int] = {}       # (label, src) -> open incident id, for de-duplication
        self.heartbeat = 0.0
        self.started = time.time()
        self.source_note = ""
        self.src = self._make_source(settings.source, settings.iface)
        self._last_net = psutil.net_io_counters()
        self._stop = threading.Event()

    def _make_source(self, source, iface):
        if source == "live":
            ok, msg = LiveCapture.available()
            if ok:
                self.source_note = "Live packet capture"
                return LiveCapture(self.q, iface)
            self.source_note = f"Live capture unavailable ({msg}); using replay"
            log.warning(self.source_note)
        else:
            self.source_note = "Replay of held-out CIC-IDS2017 flows"
        return Replay(self.q)

    def start(self):
        self.src.start()
        threading.Thread(target=self._loop, name="engine", daemon=True).start()
        log.info("engine started: %s, threshold %.2f", self.source_note, self.det.threshold)

    def stop(self):
        self._stop.set()
        self.src.stop()

    def _loop(self):
        while not self._stop.is_set():
            t_end = time.time() + 1.0
            batch = []
            while time.time() < t_end and len(batch) < 5000:
                try:
                    batch.append(self.q.get(timeout=max(0.0, t_end - time.time())))
                except queue.Empty:
                    break
            try:
                self._process(batch)
            except Exception:  # never let one bad batch kill detection
                log.exception("error while processing a batch of %d flows", len(batch))
            self.heartbeat = time.time()

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
        self._prune()

    def _prune(self):
        if len(self.recent) > 5000:   # bound memory: forget de-dup keys for old incidents
            self.recent = dict(list(self.recent.items())[-1000:])

    def _incident(self, x, cls, conf, item, label):
        key = (label, item["src"] if label != "DDoS" else "*")
        now = time.time()
        with db() as con:
            iid = self.recent.get(key)
            if iid:
                row = con.execute("SELECT last_ts, status FROM incidents WHERE id=?", (iid,)).fetchone()
                if row and row["status"] == "open" and now - row["last_ts"] < 60:
                    con.execute("UPDATE incidents SET flows=flows+1, last_ts=?, confidence=MAX(confidence,?) "
                                "WHERE id=?", (now, conf, iid))
                    return
            text = self.det.explain(x, cls, conf, item)
            src = "*" if key[1] == "*" else item["src"]
            cur = con.execute(
                "INSERT INTO incidents (ts,label,severity,technique,confidence,src,dst,dport,last_ts,explanation,truth)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (now, label, self.det.severity(label), self.det.technique(label), conf,
                 src, item["dst"], item["dport"], now, text, item["truth"]))
            self.recent[key] = cur.lastrowid
        with self.lock:
            self.incidents += 1
        self.sink.publish({"id": cur.lastrowid, "time": iso(now), "label": label,
                           "severity": self.det.severity(label), "technique": self.det.technique(label),
                           "confidence": round(conf, 4), "src": src, "dst": item["dst"], "dport": item["dport"],
                           "explanation": text, "sensor": self.src.name})
        log.info("incident %d: %s from %s (conf %.2f)", cur.lastrowid, label, src, conf)

    def stats(self):
        with self.lock:
            return {"flows": self.flows, "source": self.src.name, "sourceNote": self.source_note,
                    "replayAccuracy": (self.correct / self.labelled) if self.labelled else None,
                    "classCounts": dict(self.class_counts), "dropped": self.src.dropped,
                    "queue": self.q.qsize(), "series": list(self.series),
                    "threshold": self.det.threshold, "heartbeatAge": round(time.time() - self.heartbeat, 1),
                    "uptime": round(time.time() - self.started)}


# ---------------------------------------------------------------- web app
class User(UserMixin):
    def __init__(self, row):
        self.id, self.username, self.role = str(row["id"]), row["username"], row["role"]
        self._active = bool(row["active"])

    @property
    def is_active(self):
        return self._active


def csv_safe(value):
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def create_app(engine, settings: Settings | None = None) -> Flask:
    settings = settings or SETTINGS
    app = Flask(__name__)
    if settings.trust_proxy:
        n = settings.trust_proxy
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)
    key_file = INSTANCE / "secret_key"
    if not os.environ.get("NIDS_SECRET_KEY") and not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    app.config.update(
        SECRET_KEY=os.environ.get("NIDS_SECRET_KEY") or key_file.read_text().strip(),
        SESSION_COOKIE_NAME="nids_session",
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.https,
        PERMANENT_SESSION_LIFETIME=settings.session_minutes * 60,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    lm = LoginManager(app)
    lm.login_view = "login"
    lm.session_protection = "strong"
    failures: dict[str, list[float]] = {}
    fail_lock = threading.Lock()

    @lm.user_loader
    def load_user(uid):
        with db() as con:
            row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return User(row) if row and row["active"] else None

    @lm.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="authentication required"), 401
        return redirect(url_for("login"))

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
        session.permanent = True
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        if request.method == "POST":
            token = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
            if not token or not secrets.compare_digest(token, session["csrf"]):
                abort(400, "CSRF token missing or invalid")

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                   "style-src 'self'; script-src 'self'; frame-ancestors 'none'; "
                                                   "base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/") or request.path in ("/", "/admin", "/account"):
            resp.headers["Cache-Control"] = "no-store"
        if settings.https:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    def http_error(e):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description), e.code
        return render_template("error.html", code=e.code, message=e.description), e.code

    @app.context_processor
    def inject():
        return {"csrf": session.get("csrf", ""), "version": VERSION}

    # ---- health & metrics (no session needed) ----
    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=VERSION)

    @app.get("/readyz")
    def readyz():
        problems = []
        if time.time() - engine.heartbeat > 5:
            problems.append("detection engine heartbeat is stale")
        try:
            with db() as con:
                con.execute("SELECT 1").fetchone()
        except sqlite3.Error as e:
            problems.append(f"database: {e}")
        if problems:
            return jsonify(status="not ready", problems=problems), 503
        return jsonify(status="ready", source=engine.src.name)

    @app.get("/metrics")
    def metrics():
        token = settings.metrics_token
        auth = request.headers.get("Authorization", "")
        if token:
            if not secrets.compare_digest(auth, f"Bearer {token}"):
                abort(401)
        elif request.remote_addr not in ("127.0.0.1", "::1"):
            abort(403, "set NIDS_METRICS_TOKEN to expose /metrics remotely")
        s = engine.stats()
        lines = [
            "# HELP nids_flows_total Flows classified.", "# TYPE nids_flows_total counter",
            f"nids_flows_total {s['flows']}",
            "# HELP nids_flows_by_class_total Flows by predicted class.", "# TYPE nids_flows_by_class_total counter",
            *[f'nids_flows_by_class_total{{class="{k}"}} {v}' for k, v in s["classCounts"].items()],
            "# HELP nids_incidents_total Incidents raised.", "# TYPE nids_incidents_total counter",
            f"nids_incidents_total {engine.incidents}",
            "# HELP nids_flows_dropped_total Flows dropped because the engine queue was full.",
            "# TYPE nids_flows_dropped_total counter", f"nids_flows_dropped_total {s['dropped']}",
            "# HELP nids_queue_depth Flows waiting to be classified.", "# TYPE nids_queue_depth gauge",
            f"nids_queue_depth {s['queue']}",
            "# HELP nids_engine_heartbeat_age_seconds Seconds since the engine last completed a batch.",
            "# TYPE nids_engine_heartbeat_age_seconds gauge", f"nids_engine_heartbeat_age_seconds {s['heartbeatAge']}",
            "# HELP nids_webhook_deliveries_total Webhook deliveries.", "# TYPE nids_webhook_deliveries_total counter",
            f'nids_webhook_deliveries_total{{result="sent"}} {engine.sink.sent}',
            f'nids_webhook_deliveries_total{{result="failed"}} {engine.sink.failed}',
            f'nids_webhook_deliveries_total{{result="dropped"}} {engine.sink.dropped}',
            "# HELP nids_info Build information.", "# TYPE nids_info gauge",
            f'nids_info{{version="{VERSION}",source="{engine.src.name}"}} 1',
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    # ---- authentication ----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            now = time.time()
            with fail_lock:
                if len(failures) > 10000:   # bound memory under a distributed brute-force attempt
                    for k in [k for k, v in failures.items() if not v or now - v[-1] > 300]:
                        failures.pop(k, None)
                recent = [t for t in failures.get(ip, []) if now - t < 300]
                failures[ip] = recent
            if len(recent) >= 5:
                error = "Too many failed attempts. Try again in 5 minutes."
                audit(request.form.get("username", "")[:64], "login_locked", ip)
            else:
                username = request.form.get("username", "")[:64]
                password = request.form.get("password", "")[:256]
                with db() as con:
                    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if row and row["active"] and check_password_hash(row["pw_hash"], password):
                    session.clear()
                    login_user(User(row))
                    session["csrf"] = secrets.token_hex(16)
                    audit(username, "login", ip)
                    return redirect(url_for("dashboard"))
                with fail_lock:
                    failures.setdefault(ip, []).append(now)
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

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        msg = err = None
        if request.method == "POST":
            current = request.form.get("current", "")
            new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
            with db() as con:
                row = con.execute("SELECT pw_hash FROM users WHERE id=?", (current_user.id,)).fetchone()
            if not check_password_hash(row["pw_hash"], current):
                err = "Current password is incorrect."
            elif new != confirm:
                err = "New passwords do not match."
            elif len(new) < MIN_PASSWORD:
                err = f"New password must be at least {MIN_PASSWORD} characters."
            elif new == current:
                err = "New password must differ from the current one."
            else:
                with db() as con:
                    con.execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), current_user.id))
                audit(current_user.username, "password_changed")
                msg = "Password changed."
        return render_template("account.html", user=current_user, msg=msg, err=err)

    # ---- dashboard & API ----
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

    def incident_query():
        clauses, params = [], []
        status = request.args.get("status", "")
        if status:
            if status not in ("open", "acknowledged"):
                abort(400, "status must be open or acknowledged")
            clauses.append("status=?"); params.append(status)
        severity = request.args.get("severity", "")
        if severity:
            if severity not in ("high", "medium"):
                abort(400, "severity must be high or medium")
            clauses.append("severity=?"); params.append(severity)
        label = request.args.get("label", "")
        if label:
            if label not in engine.det.classes:
                abort(400, "unknown label")
            clauses.append("label=?"); params.append(label)
        try:
            since = float(request.args.get("since", 0))
            limit = max(1, min(int(request.args.get("limit", 100)), 10000))
        except ValueError:
            abort(400, "since and limit must be numbers")
        if since:
            clauses.append("last_ts>=?"); params.append(since)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with db() as con:
            rows = con.execute(f"SELECT * FROM incidents {where} ORDER BY last_ts DESC LIMIT ?",
                               (*params, limit)).fetchall()
        return [dict(r) for r in rows]

    @app.get("/api/incidents")
    @login_required
    def api_incidents():
        return jsonify(incident_query())

    @app.get("/api/incidents.csv")
    @role_required("analyst")
    def api_incidents_csv():
        rows = incident_query()
        buf = io.StringIO()
        cols = ["id", "first_seen", "last_seen", "label", "severity", "technique", "confidence", "src", "dst",
                "dport", "flows", "status", "ack_by", "note", "explanation"]
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            r = dict(r, first_seen=iso(r["ts"]), last_seen=iso(r["last_ts"]))
            w.writerow([csv_safe(r.get(c)) for c in cols])
        audit(current_user.username, "export_csv", f"{len(rows)} incidents")
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=nids-incidents.csv"})

    @app.post("/api/incidents/<int:iid>/ack")
    @role_required("analyst")
    def api_ack(iid):
        note = str((request.get_json(silent=True) or {}).get("note", ""))[:500]
        with db() as con:
            cur = con.execute("UPDATE incidents SET status='acknowledged', ack_by=?, note=? WHERE id=? AND status='open'",
                              (current_user.username, note, iid))
        if not cur.rowcount:
            abort(404, "no open incident with that id")
        audit(current_user.username, "ack_incident", str(iid))
        return jsonify(ok=True)

    @app.post("/api/simulate")
    @role_required("analyst")
    def api_simulate():
        label = str((request.get_json(silent=True) or {}).get("label", ""))
        if label not in engine.det.classes or label == "Benign":
            abort(400, "unknown attack class")
        if not isinstance(engine.src, Replay):
            abort(409, "simulation is only available in replay mode")
        engine.src.simulate(label)
        audit(current_user.username, "simulate", label)
        return jsonify(ok=True)

    # ---- administration ----
    @app.get("/admin")
    @role_required("admin")
    def admin():
        with db() as con:
            users = con.execute("SELECT id, username, role, active FROM users ORDER BY id").fetchall()
            log_rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        return render_template("admin.html", users=users, log=log_rows, user=current_user,
                               msg=request.args.get("msg"), iso=iso, roles=list(ROLES))

    @app.post("/admin/users")
    @role_required("admin")
    def admin_create_user():
        username = request.form.get("username", "").strip()
        try:
            create_user(username, request.form.get("password", ""), request.form.get("role", ""))
        except ValueError as e:
            return redirect(url_for("admin", msg=str(e)))
        except sqlite3.IntegrityError:
            return redirect(url_for("admin", msg="That username already exists."))
        audit(current_user.username, "create_user", f"{username}:{request.form.get('role')}")
        return redirect(url_for("admin", msg=f"Created {username}."))

    @app.post("/admin/users/<int:uid>")
    @role_required("admin")
    def admin_update_user(uid):
        role = request.form.get("role", "")
        active = 1 if request.form.get("active") == "1" else 0
        if role not in ROLES:
            abort(400, "invalid role")
        with db() as con:
            target = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not target:
                abort(404, "no such user")
            admins = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id<>?",
                                 (uid,)).fetchone()[0]
            if (role != "admin" or not active) and target["role"] == "admin" and admins == 0:
                return redirect(url_for("admin", msg="Refused: this is the last active admin."))
            con.execute("UPDATE users SET role=?, active=? WHERE id=?", (role, active, uid))
        audit(current_user.username, "update_user", f"{target['username']}: role={role} active={active}")
        return redirect(url_for("admin", msg=f"Updated {target['username']}."))

    return app


# ---------------------------------------------------------------- CLI
def setup_logging(settings: Settings):
    settings.instance.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(settings.log_level)
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        fh = logging.handlers.RotatingFileHandler(settings.instance / "nids.log", maxBytes=5_000_000,
                                                  backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(fh); root.addHandler(sh)


def cmd_check() -> int:
    ok = True
    try:
        det = Detector()
        print(f"[ok] {len(det.models)} models loaded, SHA-256 verified ({', '.join(det.models)})")
        for w in det.version_warnings:
            print(f"[warn] {w}"); ok = False
    except Exception as e:  # noqa: BLE001
        print(f"[fail] models: {e}"); ok = False
    if DB.exists():
        with db() as con:
            v = con.execute("PRAGMA user_version").fetchone()[0]
            admins = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
        print(f"[{'ok' if v == len(MIGRATIONS) else 'warn'}] database schema v{v}, {admins} active admin(s)")
    else:
        print("[fail] database missing: run `python -m nids.app init`"); ok = False
    live_ok, msg = LiveCapture.available()
    print(f"[{'ok' if live_ok else 'info'}] live capture: {msg}")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nids", description="ML-based Network Intrusion Detection System")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="create database and first admin"); i.add_argument("--user", default="admin")
    for name in ("serve", "run"):
        r = sub.add_parser(name, help="start the dashboard and detection engine")
        r.add_argument("--source", choices=["replay", "live"]); r.add_argument("--iface")
        r.add_argument("--host"); r.add_argument("--port", type=int)
        r.add_argument("--dev", action="store_true", help="use the Flask development server")
    c = sub.add_parser("create-user"); c.add_argument("username")
    c.add_argument("--role", choices=list(ROLES), default="viewer")
    rp = sub.add_parser("reset-password"); rp.add_argument("username")
    sub.add_parser("check", help="verify models, versions and database")
    args = ap.parse_args(argv)

    overrides = {k: v for k, v in {"NIDS_SOURCE": getattr(args, "source", None),
                                   "NIDS_IFACE": getattr(args, "iface", None),
                                   "NIDS_HOST": getattr(args, "host", None),
                                   "NIDS_PORT": str(args.port) if getattr(args, "port", None) else None}.items() if v}
    os.environ.update(overrides)
    settings = Settings().validate()
    configure(settings)
    setup_logging(settings)

    if args.cmd == "check":
        sys.exit(cmd_check())
    migrate()
    if args.cmd == "init":
        with db() as con:
            if con.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                print("Database already initialised."); return
        password = os.environ.get("NIDS_ADMIN_PASSWORD") or getpass.getpass(f"Password for {args.user} ({MIN_PASSWORD}+ chars): ")
        try:
            create_user(args.user, password, "admin")
        except ValueError as e:
            raise SystemExit(str(e))
        print(f"Created admin user '{args.user}'.")
        return
    if args.cmd == "create-user":
        password = os.environ.get("NIDS_NEW_PASSWORD") or getpass.getpass(f"Password for {args.username}: ")
        try:
            create_user(args.username, password, args.role)
        except (ValueError, sqlite3.IntegrityError) as e:
            raise SystemExit(str(e))
        audit("cli", "create_user", f"{args.username}:{args.role}")
        print(f"Created {args.role} '{args.username}'."); return
    if args.cmd == "reset-password":
        password = os.environ.get("NIDS_NEW_PASSWORD") or getpass.getpass(f"New password for {args.username}: ")
        if len(password) < MIN_PASSWORD:
            raise SystemExit(f"password must be at least {MIN_PASSWORD} characters")
        with db() as con:
            n = con.execute("UPDATE users SET pw_hash=? WHERE username=?",
                            (generate_password_hash(password), args.username)).rowcount
        if not n:
            raise SystemExit("no such user")
        audit("cli", "reset_password", args.username)
        print("Password reset."); return

    with db() as con:
        if not con.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise SystemExit("No users yet: run `python -m nids.app init` first.")
    engine = Engine(settings)
    engine.start()
    app = create_app(engine, settings)
    log.info("NIDS %s listening on http://%s:%d", VERSION, settings.host, settings.port)
    try:
        if args.dev:
            app.run(host=settings.host, port=settings.port, threaded=True, use_reloader=False)
        else:
            from waitress import serve
            serve(app, host=settings.host, port=settings.port, threads=settings.threads, ident="nids")
    finally:
        engine.stop()
        log.info("NIDS stopped")


if __name__ == "__main__":
    main()
