"""Local-only UI, reusing the same scan service as the CLI. No AWS write paths."""

import json
import secrets
import threading

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for

from drift_detector.baseline.loader import load_baseline
from drift_detector.config import live_scan
from drift_detector.demo import demo_inputs, run_demo
from drift_detector.models import SEVERITIES, DetectorError


def create_app(baseline_path, profile=None, region=None, demo=False, cloudtrail=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=4096,
        TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"],
    )
    current = {"report": None, "error": None}
    lock = threading.Lock()

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "mode": "offline-demo" if demo else "live",
            "meaning": "UI process health only; not an AWS scan",
        }

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        error, baseline = current["error"], None
        try:
            baseline = demo_inputs(True)[0] if demo else load_baseline(baseline_path)
        except DetectorError as exc:
            error = str(exc)
        report = current["report"]
        items = report.to_dict()["findings"] if report else []
        severity, resource_type = request.args.get("severity", ""), request.args.get("resource", "")
        if severity in SEVERITIES:
            items = [f for f in items if SEVERITIES[f["severity"]] >= SEVERITIES[severity]]
        if resource_type:
            items = [f for f in items if f["resource_type"] == resource_type]
        return render_template(
            "index.html",
            demo=demo,
            baseline=baseline,
            report=report.to_dict() if report else None,
            findings=items,
            error=error,
            severity=severity,
            resource_type=resource_type,
            levels=list(reversed(SEVERITIES)),
        )

    @app.post("/scan")
    def scan():
        token = request.form.get("csrf", "")
        if not token or not secrets.compare_digest(token, session.get("csrf", "")):
            abort(403)
        if not lock.acquire(blocking=False):
            abort(409, "A scan is already running; wait for it to finish.")
        try:
            current["report"] = None
            current["error"] = None
            current["report"] = (
                run_demo(clean=request.form.get("scenario") == "clean")
                if demo
                else live_scan(baseline_path, profile, region, cloudtrail=cloudtrail)
            )
        except DetectorError as exc:
            current["error"] = str(exc)
        finally:
            lock.release()
        return redirect(url_for("index"))

    @app.get("/report.json")
    def download():
        if current["report"] is None:
            abort(404, "Run a scan first.")
        return Response(
            json.dumps(current["report"].to_dict(), indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": 'attachment; filename="drift-report.json"'},
        )

    return app
