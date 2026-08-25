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


def authenticate(username: str, password: str) -> bool:
    """The safe form of the exposure pack's first rule.

    Log that a credential was present, never what it was - logs outlive the
    credential and are read by people who were never granted it.
    """
    import logging

    logging.getLogger(__name__).info(
        "login attempt user=%s credential_present=%s", username, bool(password)
    )
    return _verify(username, password)


def handle_error(exc: Exception, correlation_id: str) -> dict:
    """Trace to the log, identifier to the client."""
    import logging

    logging.getLogger(__name__).exception("request %s failed", correlation_id)
    return {"error": "internal error", "correlation_id": correlation_id}


def promote_to_admin(actor, target) -> dict:
    """Every privilege change leaves a record naming who, what and when."""
    import logging

    if not actor.is_admin:
        raise PermissionError("not an admin")
    previous, target.role = target.role, "admin"
    logging.getLogger("audit").info(
        "role_change actor=%s target=%s from=%s to=%s", actor.id, target.id, previous, target.role
    )
    return {"ok": True}


def _verify(username: str, password: str) -> bool:
    raise NotImplementedError
