#!/usr/bin/env python3
"""
HTTP Honeypot
====================================
A Flask-based web honeypot that mimics a WordPress wp-admin login page.
Logs all HTTP requests, login attempts, and payloads as NDJSON.

Runs alongside ssh_honeypot.py — both write to the same log directory
so your SIEM can ingest from one path.
"""

import argparse
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import Flask, request, render_template_string, redirect, url_for

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_DIR = "/var/log/honeypot"
LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.log")
MAX_LOG_SIZE = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# ---------------------------------------------------------------------------
# JSON Logger (same pattern as SSH honeypot)
# ---------------------------------------------------------------------------
class JSONHoneypotLogger:
    def __init__(self, log_path: str = LOG_FILE):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.logger = logging.getLogger("http_honeypot_json")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        handler = RotatingFileHandler(
            log_path, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)

    def log(self, event_type: str, src_ip: str, **extra):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "src_ip": src_ip,
            "sensor": "http_honeypot",
        }
        record.update(extra)
        self.logger.info(json.dumps(record, default=str))


hp_logger = JSONHoneypotLogger()

# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Suppress default Flask request logging (we handle our own)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# WordPress-style login page
WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In &lsaquo; MyCompany Blog &#8212; WordPress</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #f1f1f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; min-height: 100vh; }
        #login { width: 320px; margin: 8% auto 0; padding: 20px 0; }
        #login h1 { text-align: center; margin-bottom: 24px; }
        #login h1 a { background-image: url('data:image/svg+xml;charset=utf-8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80"><circle cx="40" cy="40" r="38" fill="%232271b1"/><text x="40" y="52" text-anchor="middle" fill="white" font-size="32" font-family="sans-serif" font-weight="bold">W</text></svg>'); background-size: 84px; background-position: center; width: 84px; height: 84px; display: block; margin: 0 auto; text-indent: -9999px; }
        .login-form { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 26px 24px; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
        .login-form label { display: block; margin-bottom: 3px; font-size: 14px; color: #1e1e1e; font-weight: 600; }
        .login-form input[type="text"], .login-form input[type="password"] { width: 100%; padding: 4px 8px; font-size: 24px; margin-bottom: 16px; border: 1px solid #8c8f94; border-radius: 4px; min-height: 40px; }
        .login-form input[type="text"]:focus, .login-form input[type="password"]:focus { border-color: #2271b1; box-shadow: 0 0 0 1px #2271b1; outline: none; }
        .forgetmenot { float: left; margin-bottom: 16px; }
        .forgetmenot label { font-size: 13px; font-weight: 400; }
        .submit { float: right; }
        .submit input { background: #2271b1; border: 1px solid #2271b1; color: #fff; padding: 0 12px; border-radius: 3px; min-height: 32px; font-size: 13px; cursor: pointer; }
        .submit input:hover { background: #135e96; }
        .clear { clear: both; }
        #nav { text-align: center; margin-top: 16px; }
        #nav a { color: #50575e; font-size: 13px; text-decoration: none; }
        #nav a:hover { color: #2271b1; }
        {% if error %}
        .login-error { background: #fcf0f1; border: 1px solid #d63638; border-radius: 4px; padding: 12px; margin-bottom: 16px; color: #d63638; font-size: 13px; }
        {% endif %}
    </style>
</head>
<body>
    <div id="login">
        <h1><a href="#">MyCompany Blog</a></h1>
        <div class="login-form">
            {% if error %}
            <div class="login-error">
                <strong>Error:</strong> The username or password you entered is incorrect. <a href="#">Lost your password?</a>
            </div>
            {% endif %}
            <form method="post" action="/wp-login.php">
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" autocomplete="username" value="">
                <label for="user_pass">Password</label>
                <input type="password" name="pwd" id="user_pass" autocomplete="current-password">
                <div class="forgetmenot">
                    <label><input type="checkbox" name="rememberme" value="forever"> Remember Me</label>
                </div>
                <div class="submit">
                    <input type="submit" value="Log In">
                </div>
                <div class="clear"></div>
            </form>
        </div>
        <p id="nav"><a href="#">Lost your password?</a></p>
    </div>
</body>
</html>"""

WP_DASHBOARD = """<!DOCTYPE html>
<html><head><title>Dashboard &lsaquo; MyCompany Blog &#8212; WordPress</title>
<meta http-equiv="refresh" content="3;url=/wp-login.php">
<style>body{font-family:sans-serif;text-align:center;padding:60px;background:#f1f1f1;}
.spinner{border:4px solid #f3f3f3;border-top:4px solid #2271b1;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto;}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style></head>
<body><div class="spinner"></div><p>Loading dashboard...</p></body></html>"""


@app.before_request
def log_every_request():
    """Log all HTTP requests — gives visibility into scanning/probing."""
    hp_logger.log(
        event_type="http_request",
        src_ip=request.remote_addr,
        method=request.method,
        path=request.path,
        user_agent=request.headers.get("User-Agent", ""),
        referrer=request.headers.get("Referer", ""),
        query_string=request.query_string.decode("utf-8", errors="replace"),
    )


@app.route("/")
def index():
    return redirect("/wp-login.php")


@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")

        hp_logger.log(
            event_type="login_attempt",
            src_ip=request.remote_addr,
            username=username,
            password=password,
            user_agent=request.headers.get("User-Agent", ""),
        )

        # Always "fail" — shows error page to bait more attempts
        # Optionally: accept specific creds to see what attackers do post-login
        return render_template_string(WP_LOGIN_PAGE, error=True)

    return render_template_string(WP_LOGIN_PAGE, error=False)


@app.route("/wp-admin/")
@app.route("/wp-admin")
def wp_admin():
    hp_logger.log(
        event_type="admin_access",
        src_ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    return WP_DASHBOARD


@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    """WordPress XML-RPC endpoint — commonly targeted for brute force."""
    hp_logger.log(
        event_type="xmlrpc_probe",
        src_ip=request.remote_addr,
        method=request.method,
        content_length=request.content_length,
        payload=request.get_data(as_text=True)[:2000],  # truncate large payloads
    )
    return '<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct><member><n>faultCode</n><value><int>403</int></value></member></struct></value></fault></methodResponse>', 200


# Catch-all for scanning bots probing random paths
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    hp_logger.log(
        event_type="probe",
        src_ip=request.remote_addr,
        method=request.method,
        path=f"/{path}",
        user_agent=request.headers.get("User-Agent", ""),
        payload=request.get_data(as_text=True)[:2000] if request.method != "GET" else "",
    )
    return "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>", 404


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="HTTP Honeypot — SIEM-Ready Edition")
    parser.add_argument("-a", "--address", default="0.0.0.0", help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("-l", "--log-file", default=LOG_FILE, help="Log file path")
    args = parser.parse_args()

    global hp_logger
    if args.log_file != LOG_FILE:
        hp_logger = JSONHoneypotLogger(args.log_file)

    print(f"HTTP Honeypot listening on {args.address}:{args.port}")
    print(f"Logging JSON events to {args.log_file}")
    app.run(host=args.address, port=args.port, debug=False)


if __name__ == "__main__":
    main()
