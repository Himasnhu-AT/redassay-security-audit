"""The board's HTTP server.

Bound to loopback by default and never anything else without an explicit --host,
because the board serves file contents from the repository it is pointed at.

Security notes, since this is a security tool and the irony would be expensive:

* Static files are served from a single directory resolved at import time; the
  request path never reaches the filesystem un-normalized.
* `/api/source` resolves through realpath and refuses anything outside the repo
  root, which blocks both `..` and symlinks pointing out of the tree.
* State-changing endpoints require a JSON content type and reject cross-origin
  requests, which stops a page in another tab from driving the board through the
  browser's ambient authority.
"""

from __future__ import annotations

import json
import mimetypes
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..config import Config
from .api import Api, router
from .router import MethodNotAllowed

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 2 * 1024 * 1024


class Request:
    """What a handler gets. Deliberately small."""

    def __init__(self, api: Api, method: str, path: str, query: Dict[str, str], body: bytes, headers: Any):
        self.api = api
        self.method = method
        self.path = path
        self.query = query
        self.body = body
        self.headers = headers

    @property
    def json(self) -> Dict[str, Any]:
        if not self.body:
            return {}
        try:
            payload = json.loads(self.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}


class BoardHandler(BaseHTTPRequestHandler):
    server_version = "redassay"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    api: Api                      # injected by build_server
    verbose: bool = False

    # -- plumbing ------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:
        if self.verbose:
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", {"Cache-Control": "no-store"})

    # -- request handling ----------------------------------------------------
    def do_GET(self) -> None:     # noqa: N802 - BaseHTTPRequestHandler's contract
        self._handle("GET")

    def do_HEAD(self) -> None:    # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:    # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}

        if path.startswith("/api/"):
            self._handle_api(method, path, query)
            return
        if method != "GET":
            self._json(405, {"error": "method not allowed"})
            return
        self._serve_static(path)

    def _handle_api(self, method: str, path: str, query: Dict[str, str]) -> None:
        if method == "POST" and not self._origin_ok():
            self._json(403, {"error": "cross-origin request refused"})
            return

        body = b""
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._json(400, {"error": "bad Content-Length"})
                return
            if length > MAX_BODY:
                self._json(413, {"error": "body too large"})
                return
            body = self.rfile.read(length) if length else b""

        try:
            resolved = router.resolve(method, path)
        except MethodNotAllowed:
            self._json(405, {"error": "method not allowed"})
            return
        if resolved is None:
            self._json(404, {"error": "no such endpoint"})
            return

        handler, captures = resolved
        request = Request(self.api, method, path, query, body, self.headers)
        try:
            status, payload = handler(request, **captures)
        except Exception as exc:                       # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            return
        self._json(status, payload)

    def _origin_ok(self) -> bool:
        """Reject writes initiated by another origin.

        The board has no cookies, but a same-site page could still POST to it,
        so mutations require a JSON content type (which forces a preflight) and
        an Origin header that matches where the board is listening.
        """
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if content_type != "application/json":
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True                                 # same-origin fetch or a CLI
        host = self.headers.get("Host") or ""
        return origin in (f"http://{host}", f"https://{host}")

    def _serve_static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        relative = path.lstrip("/")
        target = os.path.realpath(os.path.join(STATIC_DIR, relative))
        root = os.path.realpath(STATIC_DIR)
        if target != root and not target.startswith(root + os.sep):
            self._json(403, {"error": "forbidden"})
            return
        if not os.path.isfile(target):
            self._json(404, {"error": "not found"})
            return
        content_type, _ = mimetypes.guess_type(target)
        with open(target, "rb") as handle:
            body = handle.read()
        self._send(200, body, content_type or "application/octet-stream",
                   {"Cache-Control": "no-cache"})


def build_server(config: Config, verbose: bool = False) -> ThreadingHTTPServer:
    api = Api(config)
    handler = type("BoundBoardHandler", (BoardHandler,), {"api": api, "verbose": verbose})
    server = ThreadingHTTPServer((config.host, config.port), handler)
    server.daemon_threads = True
    return server


def serve(config: Config, open_browser: bool = True, once: bool = False, verbose: bool = False) -> int:
    try:
        server = build_server(config, verbose=verbose)
    except OSError as exc:
        print(f"cannot bind {config.host}:{config.port} - {exc}")
        print("Another board may already be running. Try --port 7718.")
        return 2

    host, port = server.server_address[0], server.server_address[1]
    url = f"http://{host}:{port}/"
    print(f"redassay board  {url}")
    print(f"  repository    {config.root}")
    print("  Ctrl-C to stop")

    if once:
        server.handle_request()
        server.server_close()
        return 0

    if open_browser:
        threading.Timer(0.4, lambda: _try_open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


def _try_open(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass
