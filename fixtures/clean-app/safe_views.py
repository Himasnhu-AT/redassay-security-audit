"""The control fixture: idiomatic, safe code.

Every construct here is the *correct* form of something the scanners flag
elsewhere. If any rule fires on this file, that rule has a false positive, and
the test suite says so by name.
"""

import hashlib
import hmac
import os
import secrets
import subprocess
from pathlib import Path

import requests
import yaml
from flask import Flask, abort, redirect, render_template, request, url_for
from flask_login import login_required

app = Flask(__name__)

SECRET_KEY = os.environ["APP_SECRET_KEY"]
UPLOAD_ROOT = Path("/srv/uploads").resolve()
ALLOWED_FETCH_HOSTS = frozenset({"api.internal.example"})


@app.route("/user")
def get_user():
    # Parameterized: the driver binds the value, the query text is fixed.
    name = request.args.get("name", "")
    cursor = get_connection().cursor()
    cursor.execute("SELECT id, email FROM users WHERE name = %s", (name,))
    return {"rows": cursor.fetchall()}


@app.route("/ping")
def ping():
    # Argument list, no shell. Metacharacters are just characters.
    host = request.args.get("host", "localhost")
    if not host.replace(".", "").replace("-", "").isalnum():
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5, check=False)
    return result.stdout.decode()


@app.route("/render")
def render():
    # Fixed template, data passed as context - autoescaping applies.
    return render_template("greeting.html", greeting=request.args.get("greeting", "hi"))


@app.route("/download")
def download():
    # Resolve, then prove the result is still inside the root.
    name = request.args.get("file", "")
    target = (UPLOAD_ROOT / name).resolve()
    if not target.is_relative_to(UPLOAD_ROOT) or not target.is_file():
        abort(404)
    return target.read_bytes()


@app.route("/fetch")
def fetch():
    # Allowlisted host, no redirects, bounded time.
    from urllib.parse import urlparse

    target = request.args.get("url", "")
    if urlparse(target).hostname not in ALLOWED_FETCH_HOSTS:
        abort(400)
    return requests.get(target, timeout=5, allow_redirects=False).text


@app.route("/import", methods=["POST"])
@login_required
def import_config():
    return str(yaml.safe_load(request.data))


@app.route("/go")
def go():
    # Only ever a route name we control.
    return redirect(url_for("get_user"))


def hash_password(password: str, salt: bytes) -> bytes:
    # Slow KDF with a per-password salt.
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32)


def reset_token() -> str:
    return secrets.token_urlsafe(32)


def verify_signature(body: bytes, signature: str) -> bool:
    expected = hmac.new(SECRET_KEY.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def promote(user):
    if not user.is_admin:
        raise PermissionError("not an admin")
    user.role = "admin"


def get_connection():
    raise NotImplementedError
