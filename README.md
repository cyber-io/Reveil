# Web App Security Lab

A self-contained project with two parts:

1. **`vulnerable-app/`** — VulnBank, a small Flask app with four real,
   deliberately-introduced vulnerabilities.
2. **`scanner/`** — a Python vulnerability scanner that crawls a target
   and automatically detects those bug classes, producing a console
   report and a standalone HTML report.

Built as a portfolio project to demonstrate both offensive (finding
bugs) and defensive (understanding why they happen, how to fix them)
web security skills. Because the scanner only ever targets your own
local app, there's no authorization/legal concern — you're not
scanning anything you don't own.

## Quick start

```bash
# Terminal 1: run the vulnerable app
cd vulnerable-app
pip install -r requirements.txt
python3 app.py
# -> running at http://127.0.0.1:5000
# seeded users: alice/alice123, bob/bobpass, admin/admin_super_secret

# Terminal 2: run the scanner
cd scanner
pip install -r requirements.txt

# Option A - CLI:
python3 scanner.py http://127.0.0.1:5000 --login-url /login --login alice:alice123
# -> prints findings to console and writes scan_report.html

# Option B - web dashboard:
python3 webui.py
# -> open http://127.0.0.1:5050
```

### Web dashboard (`webui.py`)

A local Flask GUI for the scanner: fill in the target, login path, and
credentials, hit Run Scan, and watch a live terminal-style log stream
in as the scan progresses, followed by a severity-coded findings view.
Scan history is kept for the session and each report can be downloaded
as standalone HTML.

```
scanner/
├── webui.py           # Flask app: /api/scan, /api/history, /api/report/<id>/download
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

The dashboard reuses `run_scan()` from `scanner.py` directly (via an
`on_log` callback that streams progress lines) - the CLI and GUI share
the exact same detection logic, they're just two front ends on top of
it.

## What the scanner finds (and why)

| Vulnerability | Where | How the scanner detects it |
|---|---|---|
| SQL Injection | `/login` | Injects a lone `'` into each form field and looks for SQL error strings in the response. Also tries classic auth-bypass payloads (`admin'--`) and checks whether that logs in without a valid password. |
| Reflected XSS | `/search` | Injects a unique `<script>` marker into each input/query param and checks whether it comes back **unescaped** in the HTML. |
| IDOR | `/profile/<id>` | Finds URLs with a numeric path segment, then (as one logged-in user) requests nearby IDs and flags it if multiple IDs return distinct HTTP 200 content with no ownership check. |
| Missing security headers | site-wide | Checks every crawled page for `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`. |
| Weak cookie flags | site-wide | Flags session cookies missing `HttpOnly` / `Secure`. |

## The vulnerabilities, explained

### 1. SQL Injection (`app.py`, `/login`)
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```
User input is concatenated directly into the SQL string. Submitting
`admin'--` as the username comments out the password check entirely,
logging you in as admin with no valid password.

**Fix:** use parameterized queries —
`cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))`.
The database driver handles escaping; injection becomes impossible.

### 2. Reflected XSS (`templates/search.html`)
```jinja2
<p>You searched for: {{ query|safe }}</p>
```
Jinja2 auto-escapes by default — the `|safe` filter explicitly turns
that protection off, so anything in `?q=` renders as raw HTML/JS.

**Fix:** remove `|safe` unless you have a specific, sanitized-HTML use
case (and if you do, run it through a library like `bleach` first).

### 3. IDOR (`app.py`, `/profile/<user_id>`)
```python
cur.execute("SELECT ... FROM users WHERE id = ?", (user_id,))
```
This query is parameterized (no SQLi), but there's no check that
`user_id` belongs to the logged-in user — any authenticated user can
view any account's email and balance by changing the URL.

**Fix:** check ownership before returning data, e.g.
`if user_id != session["user_id"] and not is_admin(session): abort(403)`.

### 4. Broken Auth (`app.py`, throughout)
Passwords are stored in plaintext, and the Flask session secret is a
hardcoded string committed to source.

**Fix:** hash passwords with `bcrypt`/`argon2` before storing them and
compare hashes on login; load `app.secret_key` from an environment
variable or secrets manager, never hardcode it.

## Project structure
```
webapp-security-lab/
├── vulnerable-app/
│   ├── app.py              # Flask app with the 4 vulnerabilities
│   ├── requirements.txt
│   └── templates/
├── scanner/
│   ├── scanner.py           # CLI entry point / orchestrator + run_scan()
│   ├── webui.py              # Flask web dashboard (GUI)
│   ├── crawler.py            # discovers pages + forms
│   ├── checks_sqli.py        # SQLi detection
│   ├── checks_xss.py         # XSS detection
│   ├── checks_idor.py        # IDOR detection
│   ├── checks_headers.py     # headers + cookie flag checks
│   ├── report.py              # console + HTML report generation, JSON serialization
│   ├── templates/index.html   # dashboard page
│   ├── static/style.css       # dashboard styling
│   ├── static/app.js          # dashboard frontend logic
│   └── requirements.txt
└── README.md
```

## Talking points for interviews

- Why parameterized queries defeat SQLi at the database layer, not just
  by "escaping quotes."
- The difference between auto-escaping (Jinja2's default) and why
  developers sometimes disable it — and why that's dangerous.
- Why IDOR isn't caught by "is this SQL query parameterized" checks —
  it's an authorization bug, not an injection bug.
- Limitations of this scanner vs. a real one (no JS-rendered page
  support, no blind/time-based SQLi, heuristic-based IDOR detection
  that a human should verify, no auth token/CSRF testing yet) — good
  material for a "future work" section.

## ⚠️ Responsible use

Only run the scanner against `vulnerable-app` or other systems you own
or have explicit written permission to test. Scanning systems without
authorization is illegal in most jurisdictions (e.g. the U.S. Computer
Fraud and Abuse Act).
