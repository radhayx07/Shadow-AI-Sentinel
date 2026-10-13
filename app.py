# app.py - Flask routes for Shadow AI Sentinel.
import os, re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import Error
from database import get_connection, query_all, query_one, execute
from detector import detect, risk_level
from redactor import redact

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")

ACTIVE_RULES_SQL = """SELECT r.rule_id, r.regex_pattern, c.category_id, c.category_name, c.severity_weight
                      FROM SecurityRules r INNER JOIN DetectionCategories c ON r.category_id = c.category_id
                      WHERE r.is_active = 1"""

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

@app.errorhandler(Error)
def db_error(err):
    return render_template("about.html", db_error=str(err)), 503

@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

# ---------- Login / Register ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif query_one("SELECT user_id FROM Users WHERE username=%s OR email=%s", (username, email)):
            flash("Username or email already exists.", "error")
        else:
            execute("INSERT INTO Users (username, email, password_hash) VALUES (%s,%s,%s)",
                    (username, email, generate_password_hash(password)))
            flash("Registered! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = query_one("SELECT * FROM Users WHERE username=%s", (request.form["username"].strip(),))
        if user and check_password_hash(user["password_hash"], request.form["password"]):
            session["user_id"], session["username"] = user["user_id"], user["username"]
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Dashboard (all numbers come from SQL) ----------
@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    totals = query_one("""SELECT COUNT(*) AS total,
                                 COALESCE(SUM(risk_level='High'),0) AS high,
                                 COALESCE(SUM(action_taken='Redacted'),0) AS redacted
                          FROM Scans WHERE user_id=%s""", (uid,))
    by_category = query_all("""SELECT c.category_name,
                                      COALESCE(SUM(CASE WHEN s.scan_id IS NOT NULL THEN f.match_count ELSE 0 END),0) AS total
                               FROM DetectionCategories c
                               LEFT JOIN ScanFindings f ON f.category_id = c.category_id
                               LEFT JOIN Scans s ON s.scan_id = f.scan_id AND s.user_id = %s
                               GROUP BY c.category_id, c.category_name ORDER BY total DESC""", (uid,))
    return render_template("dashboard.html", totals=totals, by_category=by_category)

# ---------- Scanner ----------
@app.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    result = None
    if request.method == "POST":
        text = request.form["text"]
        action = request.form["action"]                 # "scan" or "redact"
        rules = query_all(ACTIVE_RULES_SQL)
        found = detect(text, rules)
        level = risk_level(found)
        redacted = redact(text, rules) if action == "redact" else None
        conn = get_connection()                          # one transaction: Scans + ScanFindings together
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO Scans (user_id, risk_level, action_taken) VALUES (%s,%s,%s)",
                        (session["user_id"], level, "Redacted" if redacted is not None else "Scanned only"))
            scan_id = cur.lastrowid
            for cat_id, item in found.items():
                cur.execute("INSERT INTO ScanFindings (scan_id, category_id, match_count) VALUES (%s,%s,%s)",
                            (scan_id, cat_id, item["count"]))
            conn.commit()
        except Error:
            conn.rollback()
            raise
        finally:
            conn.close()
        result = {"found": found, "level": level, "redacted": redacted, "scan_id": scan_id}
    return render_template("scanner.html", result=result)

# ---------- History ----------
@app.route("/history")
@login_required
def history():
    scans = query_all("""SELECT s.scan_id, s.scan_time, s.risk_level, s.action_taken,
                                GROUP_CONCAT(c.category_name SEPARATOR ', ') AS categories
                         FROM Scans s
                         LEFT JOIN ScanFindings f ON f.scan_id = s.scan_id
                         LEFT JOIN DetectionCategories c ON c.category_id = f.category_id
                         WHERE s.user_id=%s GROUP BY s.scan_id ORDER BY s.scan_time DESC""", (session["user_id"],))
    return render_template("history.html", scans=scans)

@app.route("/history/<int:scan_id>")
@login_required
def scan_details(scan_id):
    scan = query_one("SELECT * FROM Scans WHERE scan_id=%s AND user_id=%s", (scan_id, session["user_id"]))
    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("history"))
    findings = query_all("""SELECT c.category_name, c.severity_weight, f.match_count
                            FROM ScanFindings f INNER JOIN DetectionCategories c ON c.category_id = f.category_id
                            WHERE f.scan_id=%s""", (scan_id,))
    return render_template("scan_details.html", scan=scan, findings=findings)

# ---------- Security rules (view / add / update / disable) ----------
@app.route("/rules", methods=["GET", "POST"])
@login_required
def rules():
    if request.method == "POST":
        name, pattern = request.form["rule_name"].strip(), request.form["regex_pattern"].strip()
        try:
            re.compile(pattern)
            execute("INSERT INTO SecurityRules (category_id, rule_name, regex_pattern) VALUES (%s,%s,%s)",
                    (request.form["category_id"], name, pattern))
            flash("Rule added.", "success")
        except re.error as e:
            flash(f"Invalid regex: {e}", "error")
        except Error as e:
            flash(f"Could not add rule: {e}", "error")
        return redirect(url_for("rules"))
    rows = query_all("""SELECT r.*, c.category_name FROM SecurityRules r
                        INNER JOIN DetectionCategories c ON c.category_id = r.category_id ORDER BY r.rule_id""")
    return render_template("rules.html", rules=rows, categories=query_all("SELECT * FROM DetectionCategories"))

@app.route("/rules/<int:rule_id>/update", methods=["POST"])
@login_required
def update_rule(rule_id):
    pattern = request.form["regex_pattern"].strip()
    try:
        re.compile(pattern)
        execute("UPDATE SecurityRules SET regex_pattern=%s, is_active=%s WHERE rule_id=%s",
                (pattern, 1 if request.form.get("is_active") else 0, rule_id))
        flash("Rule updated.", "success")
    except re.error as e:
        flash(f"Invalid regex: {e}", "error")
    return redirect(url_for("rules"))

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001)
