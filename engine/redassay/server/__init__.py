"""The review board: a local HTTP server and a static UI.

No framework. http.server is unfashionable and entirely adequate for a
single-user board bound to loopback, and it keeps the zero-dependency promise
that makes this tool easy to point at a repository you do not trust yet.
"""

from .app import serve, build_server  # noqa: F401
