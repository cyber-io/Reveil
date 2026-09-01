"""
Web dashboard for the vulnerability scanner.

Runs a Flask server with a form to configure and launch a scan, and an
API that the frontend polls/calls to run scans and fetch results. Scan
history is kept in memory for the life of the process - this is a
local/single-operator tool, not a multi-tenant service. See the
"Deploying the scanner" section of the README before hosting this
anywhere reachable by anyone other than you.

Usage (local dev):
    python3 webui.py
    -> open http://127.0.0.1:5050
    -> log in with the operator credentials printed on startup

Usage (production, e.g. Render): run under gunicorn with a single
worker (see Procfile) - `gunicorn webui:app --workers 1`. Set
SCANNER_USERNAME / SCANNER_PASSWORD / SCANNER_SECRET_KEY in the
environment; never deploy with the defaults reachable by the public
internet.
"""
import os
import re
import secrets
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from scanner import run_scan

app = Flask(__name__)
app.secret_key = os.environ.get("SCANNER_SECRET_KEY") or secrets.token_hex(32)

# Render (and most PaaS hosts) terminate TLS in front of the app and
# set RENDER=true in the environment - use that to turn on Secure
# session cookies automatically in production without breaking local
# http://127.0.0.1 development.
_ON_RENDER = os.environ.get("RENDER") == "true"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_ON_RENDER,
)

# Operator credentials for the scanner dashboard itself - this gates who
# can drive the scanner. Override via env vars for anything beyond local
# single-user use; MUST be overridden before deploying publicly, since
# whoever holds them can point this scanner at arbitrary URLs.
SCANNER_USERNAME = os.environ.get("SCANNER_USERNAME", "scanadmin")
_SCANNER_PASSWORD = os.environ.get("SCANNER_PASSWORD", "scan123")
SCANNER_PASSWORD_HASH = generate_password_hash(_SCANNER_PASSWORD)
_USING_DEFAULT_CREDS = not os.environ.get("SCANNER_PASSWORD")

if _ON_RENDER and _USING_DEFAULT_CREDS:
    print(
        "[!] WARNING: running on Render with the default scanadmin/scan123 "
        "operator credentials. Set SCANNER_USERNAME and SCANNER_PASSWORD "
        "in the service's environment variables immediately."
    )

# In-memory scan history: {scan_id: {"report_dict": ..., "pdf": ..., "log": [...]}}
# Resets on every restart/redeploy, and isn't shared across worker
# processes - run with a single worker (see Procfile) so this stays
# consistent for the one operator using it.
HISTORY = {}
HISTORY_ORDER = []  # most recent first


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == SCANNER_USERNAME and check_password_hash(SCANNER_PASSWORD_HASH, password):
            session["authenticated"] = True
            session["operator"] = username
            return redirect(url_for("index"))
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", operator=session.get("operator"))


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json(force=True) or {}
    target = (data.get("target") or "").strip()
    max_pages = int(data.get("max_pages") or 25)

    if not target:
        return jsonify({"error": "Target URL is required."}), 400
    if not target.startswith(("http://", "https://")):
        # Local/loopback targets (the bundled demo app) default to plain
        # http; anything else is assumed to be a real hosted target
        # served over TLS.
        is_local = re.match(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(:|/|$)", target, re.I)
        target = ("http://" if is_local else "https://") + target

    log_lines = []

    def on_log(msg):
        log_lines.append({"time": datetime.now().strftime("%H:%M:%S"), "text": msg})

    try:
        report = run_scan(
            target,
            max_pages=max_pages,
            on_log=on_log,
        )
    except Exception as e:
        return jsonify({"error": f"Scan failed: {e}", "log": log_lines}), 500

    scan_id = str(uuid.uuid4())[:8]
    report_dict = report.to_dict()
    report_dict["id"] = scan_id

    HISTORY[scan_id] = {
        "report_dict": report_dict,
        "pdf": report.to_pdf(),
        "log": log_lines,
    }
    HISTORY_ORDER.insert(0, scan_id)

    return jsonify({"scan": report_dict, "log": log_lines})


@app.route("/api/history")
@login_required
def api_history():
    summaries = []
    for scan_id in HISTORY_ORDER:
        rd = HISTORY[scan_id]["report_dict"]
        summaries.append({
            "id": scan_id,
            "target": rd["target"],
            "started_at": rd["started_at"],
            "total_findings": rd["total_findings"],
            "severity_counts": rd["severity_counts"],
        })
    return jsonify(summaries)


@app.route("/api/history/<scan_id>")
@login_required
def api_history_detail(scan_id):
    entry = HISTORY.get(scan_id)
    if not entry:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan": entry["report_dict"], "log": entry["log"]})


@app.route("/api/report/<scan_id>/download")
@login_required
def api_download(scan_id):
    entry = HISTORY.get(scan_id)
    if not entry:
        return jsonify({"error": "Scan not found"}), 404
    return Response(
        entry["pdf"],
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"VulnScan dashboard running at http://127.0.0.1:{port}")
    if _USING_DEFAULT_CREDS:
        print(f"[*] Operator login: {SCANNER_USERNAME} / {_SCANNER_PASSWORD} "
              f"(set SCANNER_USERNAME / SCANNER_PASSWORD env vars to change)")
    app.run(host="0.0.0.0", port=port, debug=not _ON_RENDER)
