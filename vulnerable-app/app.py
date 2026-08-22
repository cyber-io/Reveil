"""
VulnBank - Intentionally Vulnerable Web App
=============================================
Built for security research / portfolio purposes ONLY.
Do not deploy this publicly or reuse this code in production.

Vulnerabilities included (each marked with # VULN: in the code):
  1. SQL Injection       - /login
  2. Reflected XSS       - /search
  3. IDOR                - /profile/<id>
  4. Broken Auth         - weak session secret + no password hashing
  5. Missing security headers (checked by the scanner, not fixed here)
"""

from flask import Flask, request, render_template, redirect, session, g
import sqlite3
import os

app = Flask(__name__)

# VULN 4: Broken Auth - hardcoded, weak session secret
app.secret_key = "supersecret123"

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnbank.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            balance INTEGER NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)
    # VULN 4: passwords stored in plaintext, no hashing
    cur.executemany(
        "INSERT INTO users (username, password, email, balance, is_admin) VALUES (?, ?, ?, ?, ?)",
        [
            ("alice", "alice123", "alice@example.com", 5000, 0),
            ("bob", "bobpass", "bob@example.com", 1200, 0),
            ("admin", "admin_super_secret", "admin@vulnbank.local", 999999, 1),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN 1: SQL Injection - raw string formatting into SQL query.
        # Try username:  admin' -- 
        # with any password to bypass auth.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(query)
            user = cur.fetchone()
        except sqlite3.Error as e:
            error = f"Database error: {e}"
            user = None

        if user:
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        else:
            error = error or "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session["username"], user_id=session["user_id"])


@app.route("/profile/<int:user_id>")
def profile(user_id):
    # VULN 3: IDOR - no check that the logged-in user owns this profile.
    # Any logged-in user can view any other user's balance/email by
    # changing the ID in the URL, e.g. /profile/3 for the admin account.
    if "username" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, email, balance FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", user=user)


@app.route("/search")
def search():
    # VULN 2: Reflected XSS - the query is echoed back into the page
    # without escaping. Try: /search?q=<script>alert(1)</script>
    query = request.args.get("q", "")
    return render_template("search.html", query=query)


if __name__ == "__main__":
    init_db()
    print("VulnBank running at http://127.0.0.1:5000")
    print("Seeded users: alice/alice123, bob/bobpass, admin/admin_super_secret")
    app.run(debug=True, port=5000)
