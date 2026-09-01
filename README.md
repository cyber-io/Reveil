# Reveil Vuln Scanner

A self-contained project with two parts:

1. **`vulnerable-app/`** — VulnBank, a small Flask app with six real,
   deliberately-introduced vulnerabilities.
2. **`scanner/`** — a Python vulnerability scanner, gated behind its own
   operator login, that crawls a target and automatically detects those
   bug classes, producing a console report and a downloadable PDF report.

Built as a portfolio project to demonstrate both offensive (finding
bugs) and defensive (understanding why they happen, how to fix them)
web security skills. The scanner isn't limited to the bundled local
app — point it at any web application you own or have explicit written
authorization to test. Scanning systems without that authorization is
illegal in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse
Act).

## Quick start

```bash
# Terminal 1: run the vulnerable app
cd vulnerable-app
pip3 install -r requirements.txt
python3 app.py
# -> running at http://127.0.0.1:5000
# seeded users: alice/alice123, bob/bobpass, admin/admin_super_secret

# Terminal 2: run the scanner
cd scanner
pip3 install -r requirements.txt

# Option A - CLI:
python3 scanner.py http://127.0.0.1:5000 --login-url /login --login alice:alice123
# -> prints findings to console and writes scan_report.html

# Option B - web dashboard:
python3 webui.py
# -> open http://127.0.0.1:5050
# -> log in with the operator credentials printed on startup
#    (default scanadmin/scan123 - override with SCANNER_USERNAME/SCANNER_PASSWORD)
```

### Web dashboard (`webui.py`)

A local Flask GUI for the scanner, gated behind its own operator login
page (separate from any credentials you enter for the target being
scanned). Sign in, fill in the target URL and - optionally - a
username/password for the target site (submitted to its `/login`
endpoint before crawling starts), hit Run Scan, and watch a live
terminal-style log stream in as the scan progresses, followed by a
severity-coded findings view. Scan history is kept for the session and
each report can be downloaded as a detailed PDF.

```
scanner/
├── webui.py           # Flask app: /login, /api/scan, /api/history, /api/report/<id>/download
├── templates/
│   ├── index.html
│   └── login.html
└── static/
    ├── style.css
    └── app.js
```

The dashboard reuses `run_scan()` from `scanner.py` directly (via an
`on_log` callback that streams progress lines) - the CLI and GUI share
the exact same detection logic, they're just two front ends on top of
it.

### What's in a report

Every scan produces the same findings in three places - the live
console log, the in-browser Findings tab, and the downloadable PDF -
and each finding is more than a one-line alert. Per vulnerability you
get:

- **Analysis & impact** - what was specifically observed on *this*
  target and endpoint.
- **How this vulnerability works** - a plain-language explanation of
  the underlying mechanism (why the bug class is exploitable at all),
  not just a name.
- **Technical evidence & test vector** - the exact payload/request
  that triggered the finding, so it can be reproduced or verified.
- **CWE / OWASP mapping** and a **concrete remediation** step.

## What the scanner finds (and why)

| Vulnerability | Where | How the scanner detects it |
|---|---|---|
| SQL Injection | `/login` | Injects a lone `'` into each form field and looks for SQL error strings in the response. Also tries classic auth-bypass payloads (`admin'--`) and checks whether that logs in without a valid password. |
| Reflected XSS | `/search` | Injects a unique `<script>` marker into each input/query param and checks whether it comes back **unescaped** in the HTML. |
| IDOR | `/profile/<id>` | Finds URLs with a numeric path segment, then (as one logged-in user) requests nearby IDs and flags it if multiple IDs return distinct HTTP 200 content with no ownership check. |
| CSRF | `/transfer`, `/login` | Flags any state-changing (POST) form discovered by the crawler that has no hidden anti-CSRF token field. |
| Broken Access Control | `/admin` | Flags admin/privileged-looking endpoints that return HTTP 200 for an authenticated non-admin session, with no role check enforced. |
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

### 5. CSRF (`app.py`, `/transfer`)
```python
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    ...  # moves money based only on session["user_id"], no CSRF token
```
This is a state-changing POST authenticated purely by the session
cookie, with no anti-CSRF token. A malicious page visited by a
logged-in victim could auto-submit this exact form.

**Fix:** add anti-CSRF tokens to state-changing forms (e.g. Flask-WTF's
`CSRFProtect`) and set session cookies with `SameSite=Lax` or `Strict`.

### 6. Broken Access Control (`app.py`, `/admin`)
```python
@app.route("/admin")
def admin():
    if "username" not in session:
        return redirect("/login")
    ...  # no is_admin check - any logged-in user gets in
```
The route checks that *someone* is logged in, but never that they hold
the admin role, so any user can browse straight to `/admin` and see
every account's PII and balance.

**Fix:** enforce server-side role/permission checks on every privileged
route - deny by default, then verify the session user's role.

## Project structure
```
webapp-security-lab/
├── vulnerable-app/
│   ├── app.py              # Flask app with the 6 vulnerabilities
│   ├── requirements.txt    # Flask + gunicorn
│   ├── Procfile            # gunicorn start command for Render/Heroku-style hosts
│   └── templates/
├── render.yaml              # Render blueprint (rootDir: vulnerable-app)
├── .gitignore
├── scanner/
│   ├── scanner.py           # CLI entry point / orchestrator + run_scan()
│   ├── webui.py              # Flask web dashboard (GUI), gated behind operator login
│   ├── crawler.py            # discovers pages + forms
│   ├── checks_sqli.py        # SQLi detection
│   ├── checks_xss.py         # XSS detection
│   ├── checks_idor.py        # IDOR detection
│   ├── checks_csrf.py        # CSRF detection
│   ├── checks_bac.py         # Broken Access Control detection
│   ├── checks_headers.py     # headers + cookie flag checks
│   ├── report.py              # console + HTML + PDF report generation, JSON serialization
│   ├── templates/index.html   # dashboard page
│   ├── templates/login.html   # operator sign-in page
│   ├── static/style.css       # dashboard styling
│   ├── static/app.js          # dashboard frontend logic
│   └── requirements.txt
└── README.md
```

## Deploying `vulnerable-app` to Render

`vulnerable-app/app.py` is set up to run under a production WSGI
server:

- The Flask instance is the module-level `app` object in `app.py` -
  i.e. `app = Flask(__name__)` - so the WSGI target is **`app:app`**
  (module `app`, attribute `app`).
- `init_db()` now runs unconditionally at import time (not just inside
  `if __name__ == "__main__"`), so the seeded SQLite DB exists as soon
  as a WSGI server imports the module - `python app.py` never needs to
  run for the DB to be created.
- The dev server binds `0.0.0.0` and reads `PORT` from the environment
  (Render sets this automatically), for parity with the WSGI deploy.

**Steps on Render** (Web Service):
1. Push this repo to GitHub and create a new Render Web Service from it.
2. Root directory: `vulnerable-app`
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`

A `render.yaml` blueprint and a `Procfile` (both already in this repo)
encode the same settings, so Render can also pick the service up
automatically via "New > Blueprint".

**Why `--workers 1`:** the app resets and reseeds its SQLite file
(`vulnbank.db`) on startup. Multiple worker processes would each try
to recreate that file concurrently. One worker with a few threads is
plenty for a demo/lab app - it isn't built for concurrent production
traffic.

**Hosting a deliberately vulnerable app publicly - be deliberate about it:**
- Don't put any real data in it - it only ever holds the three seeded
  demo accounts.
- Expect it to get scanned/attacked automatically the moment it's
  public; that's fine for this app (that's the point), but don't reuse
  any of its secrets, passwords, or session key elsewhere.
- Consider Render's IP allowlisting or a "private service" plan if you
  only want your own scanner to reach it.
- Redeploy resets the database back to the seeded state (handy after
  someone's been poking at `/transfer`).

## Talking points for interviews

- Why parameterized queries defeat SQLi at the database layer, not just
  by "escaping quotes."
- The difference between auto-escaping (Jinja2's default) and why
  developers sometimes disable it — and why that's dangerous.
- Why IDOR isn't caught by "is this SQL query parameterized" checks —
  it's an authorization bug, not an injection bug.
- The difference between IDOR (horizontal privilege escalation - one
  user reaching another user's data) and Broken Access Control as
  implemented here (vertical privilege escalation - a regular user
  reaching admin-only functionality).
- Why CSRF is possible even when the session cookie itself can't be
  stolen: the browser attaches it automatically, so the attacker never
  needs to see it.
- Limitations of this scanner vs. a real one (no JS-rendered page
  support, no blind/time-based SQLi, heuristic-based IDOR/CSRF/BAC
  detection that a human should verify) — good material for a "future
  work" section.

## ⚠️ Responsible use

Only run the scanner against `vulnerable-app` or other systems you own
or have explicit written permission to test. Scanning systems without
authorization is illegal in most jurisdictions (e.g. the U.S. Computer
Fraud and Abuse Act).
