"""
Web dashboard for the vulnerability scanner.

Runs a local Flask server with a form to configure and launch a scan,
and an API that the frontend polls/calls to run scans and fetch
results. Scan history is kept in memory for the life of the process -
this is a local single-user tool, not a multi-tenant service.

Usage:
    python3 webui.py
    -> open http://127.0.0.1:5050
"""
import uuid
from datetime import datetime

from flask import Flask, render_template, request, jsonify, Response

from scanner import run_scan

app = Flask(__name__)

# In-memory scan history: {scan_id: {"report_dict": ..., "html": ..., "log": [...]}}
HISTORY = {}
HISTORY_ORDER = []  # most recent first


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True) or {}
    target = (data.get("target") or "").strip()
    login_url = (data.get("login_url") or "").strip() or None
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    max_pages = int(data.get("max_pages") or 25)

    if not target:
        return jsonify({"error": "Target URL is required."}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    credentials = f"{username}:{password}" if username else None

    log_lines = []

    def on_log(msg):
        log_lines.append({"time": datetime.now().strftime("%H:%M:%S"), "text": msg})

    try:
        report = run_scan(
            target,
            login_url=login_url,
            credentials=credentials,
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
        "html": report.to_html(),
        "log": log_lines,
    }
    HISTORY_ORDER.insert(0, scan_id)

    return jsonify({"scan": report_dict, "log": log_lines})


@app.route("/api/history")
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
def api_history_detail(scan_id):
    entry = HISTORY.get(scan_id)
    if not entry:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan": entry["report_dict"], "log": entry["log"]})


@app.route("/api/report/<scan_id>/download")
def api_download(scan_id):
    entry = HISTORY.get(scan_id)
    if not entry:
        return jsonify({"error": "Scan not found"}), 404
    return Response(
        entry["html"],
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.html"},
    )


if __name__ == "__main__":
    print("VulnScan dashboard running at http://127.0.0.1:5050")
    app.run(debug=True, port=5050)
