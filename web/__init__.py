"""Flask version of the biometric card lab.

Pages are rendered by Flask with Jinja templates, and every rule (fingerprint unlock,
TOTP CVV, approvals, attacks, fraud monitor and the scikit-learn model) runs in Python
on the server in ``web.lab``. The browser only draws the card, runs the hold-to-scan
animation and Touch ID, and calls the JSON API below.

Run locally:   python -m web            (http://127.0.0.1:8000)
Production:    gunicorn "web:create_app()" --workers 1 --threads 8
Labs are kept in memory, so run a single worker process.
"""

import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from bank import fraud

from .content import BRIEF, FLOW, MISSIONS
from .lab import CARD_PAN, SessionStore

ROUTE_TO_MISSION = {m["route"]: n for n, m in MISSIONS.items()}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'; object-src 'none'")


class RateLimiter:
    """At most ``limit`` requests per ``window`` seconds from one address (in memory, per process)."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.hits) > 20_000:            # forget idle addresses
                for k in [k for k, v in self.hits.items() if not v or now - v[-1] > self.window][:10_000]:
                    del self.hits[k]
            return True


def _hour(key: str = "hour") -> int:
    """The visitor's local hour, sent by the page, so the fraud model isn't fooled by the server's time zone."""
    data = request.get_json(silent=True) or {}
    try:
        h = int(data.get(key, 12))
    except (TypeError, ValueError):
        abort(400)
    if not 0 <= h <= 23:
        abort(400)
    return h


def _amount(data: dict, default: float) -> float:
    try:
        a = round(float(data.get("amount", default)), 2)
    except (TypeError, ValueError):
        abort(400)
    if not 0 < a <= 100_000:   # checked after rounding, so $0.001 can't become a $0 payment
        abort(400)
    return a


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development" and "RENDER" in os.environ,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=16 * 1024,
        LABS=SessionStore(),
        RATE_LIMIT=(120, 60.0),     # requests per minute per address; the page itself uses about 30
    )
    if config:
        app.config.update(config)
    if "RENDER" in os.environ:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)   # real visitor address behind Render's proxy
    limiter = RateLimiter(*app.config["RATE_LIMIT"])

    @app.before_request
    def load_lab():
        if request.endpoint in ("static", "healthz"):
            return
        if not limiter.allow(request.remote_addr or "unknown"):
            return jsonify(error="Too many requests. Slow down and try again in a minute."), 429
        if request.method == "POST" and not request.is_json:
            abort(415)       # JSON only, which also stops plain cross-site form posts
        sid, lab = app.config["LABS"].get(session.get("sid"))
        session.permanent = True
        session["sid"] = sid
        g.lab = lab

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Robots-Tag", "noindex, nofollow")   # a prototype, not a service to be found
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), "
                                "publickey-credentials-get=(self), publickey-credentials-create=(self)")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    def page(template: str, active: str, **kw):
        lab = g.lab
        with lab.lock:
            lab.expire_pending()
            stats = lab.stats()
        return render_template(template, active=active, missions=MISSIONS, stats=stats, done=lab.done,
                               alerts=lab.alerts, **kw)

    # ------------------------------------------------------------------ pages
    @app.get("/")
    def home():
        first = next((m for m in MISSIONS if m not in g.lab.done), None)
        return page("home.html", "home", next_mission=first)

    @app.get("/mission/<route>")
    def mission(route: str):
        m = ROUTE_TO_MISSION.get(route)
        if m is None:
            abort(404)
        return page("mission.html", route, m=m, mission=MISSIONS[m], brief=BRIEF[m],
                    prev=MISSIONS.get(m - 1), next=MISSIONS.get(m + 1), pan=CARD_PAN)

    @app.get("/store")
    @app.get("/online")
    @app.get("/attack")
    @app.get("/fraud-ai")
    def mission_short():
        return redirect(url_for("mission", route=request.path.strip("/")))

    @app.get("/bank")
    def bank_page():
        with g.lab.lock:
            ledger, reports = list(reversed(g.lab.ledger)), g.lab.reports()
        return page("bank.html", "bank", ledger=ledger, reports=reports)

    @app.get("/how")
    def how():
        return page("how.html", "how", brief=BRIEF, flow=FLOW)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ------------------------------------------------------------------ API
    @app.get("/api/state")
    def state():
        with g.lab.lock:
            return jsonify(g.lab.state())

    @app.post("/api/scan")
    def scan():
        data = request.get_json()
        owner = data.get("finger") == "owner" if "finger" in data else bool(data.get("touch_id_match"))
        with g.lab.lock:
            return jsonify(result=g.lab.scan(owner), state=g.lab.state())

    @app.post("/api/tap")
    def tap():
        data = request.get_json()
        with g.lab.lock:
            e = g.lab.tap(_amount(data, 42.5), _hour())
            return jsonify(entry=e.public(), state=g.lab.state())

    @app.post("/api/pay")
    def pay():
        data = request.get_json()
        with g.lab.lock:
            res = g.lab.pay_online(str(data.get("pan", ""))[:32], str(data.get("cvv", "")).strip()[:8],
                                   _amount(data, 249.99), _hour())
            if "entry" in res:
                res["entry"] = res["entry"].public()
            return jsonify({**res, "state": g.lab.state()})

    @app.post("/api/approve")
    def approve():
        decision = request.get_json().get("decision")
        if decision not in ("approve", "badfinger", "deny"):
            abort(400)
        with g.lab.lock:
            e = g.lab.decide(decision)
            return jsonify(entry=e.public() if e else None, state=g.lab.state())

    @app.post("/api/attack/<kind>")
    def attack(kind: str):
        hour = _hour()
        with g.lab.lock:
            if kind == "replay":
                res = g.lab.attack_replay(hour)
                res.pop("entry", None)
            elif kind == "testing":
                res = dict(entries=[e.public() for e in g.lab.attack_card_testing(hour)])
            elif kind == "guess":
                res = dict(tries=[dict(code=t["code"], status=t["status"], message=t["message"])
                                  for t in g.lab.attack_guess(hour)])
            else:
                abort(404)
            return jsonify({**res, "state": g.lab.state()})

    @app.post("/api/judge")
    def judge():
        data = request.get_json()
        amount = _amount(data, 42.5)
        online = bool(data.get("online"))
        hour = _hour("at_hour")
        with g.lab.lock:
            fn = g.lab.judge_preset if data.get("preset") else g.lab.judge
            return jsonify({**fn(amount, hour, online), "done": sorted(g.lab.done)})

    @app.get("/api/history")
    def history():
        resp = jsonify(fraud.history())
        resp.cache_control.max_age = 3600
        return resp

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return jsonify(error="not found"), 404
        return page("404.html", ""), 404

    return app
