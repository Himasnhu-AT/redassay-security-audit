"""Deliberately vulnerable Flask handlers. Not a real application."""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request, render_template_string, send_file

app = Flask(__name__)

# VULN: config.django-secret-key-literal / secret.hardcoded-assignment
API_TOKEN = "s3rv1ce_t0k3n_9fA2xQ7bLmZ4pR8wN6yT1uV3cE5hJ0kD"


def db():
    return sqlite3.connect("app.db")


@app.route("/user")
def get_user():
    # VULN: py.sql-dynamic - request.args flows into an f-string query
    name = request.args.get("name")
    query = f"SELECT id, email FROM users WHERE name = '{name}'"
    cursor = db().cursor()
    cursor.execute(query)
    return {"rows": cursor.fetchall()}


@app.route("/ping")
def ping():
    # VULN: py.shell-dynamic - request data reaches a shell
    host = request.args.get("host", "localhost")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output.decode()


@app.route("/render")
def render():
    # VULN: py.ssti - template compiled from request data
    template = "<h1>" + request.args.get("greeting", "hi") + "</h1>"
    return render_template_string(template)


@app.route("/download")
def download():
    # VULN: py.path-tainted - path traversal
    name = request.args.get("file")
    return send_file(os.path.join("/srv/uploads", name))


@app.route("/fetch")
def fetch():
    # VULN: py.ssrf - server-side request forgery
    target = request.args.get("url")
    return requests.get(target).text


@app.route("/restore", methods=["POST"])
def restore():
    # VULN: py.pickle-load - deserialization RCE
    return str(pickle.loads(request.data))


@app.route("/import", methods=["POST"])
def import_config():
    # VULN: py.yaml-unsafe-load
    return str(yaml.load(request.data))


@app.route("/go")
def go():
    # VULN: py.open-redirect
    return redirect(request.args.get("next"))


def hash_password(password):
    # VULN: py.weak-hash + crypto.weak-hash-password
    return hashlib.md5(password.encode()).hexdigest()


def reset_token():
    # VULN: py.weak-random - predictable token
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def call_internal(path):
    # VULN: py.tls-verify-off
    return requests.get("https://internal.example/" + path, verify=False)


def promote(user):
    # VULN: py.assert-security - stripped under python -O
    assert user.is_admin, "not an admin"
    user.role = "admin"


if __name__ == "__main__":
    # VULN: py.flask-debug
    app.run(host="0.0.0.0", debug=True)
