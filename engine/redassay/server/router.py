"""A tiny path router.

Routes are (method, regex) -> handler. Handlers take (request, **captures) and
return (status, payload) where payload is a dict (serialized as JSON) or bytes.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

Handler = Callable[..., Tuple[int, Any]]


class Router:
    def __init__(self) -> None:
        self.routes: List[Tuple[str, Pattern[str], Handler]] = []

    def add(self, method: str, pattern: str, handler: Handler) -> None:
        self.routes.append((method.upper(), re.compile(f"^{pattern}$"), handler))

    def get(self, pattern: str) -> Callable[[Handler], Handler]:
        def decorate(handler: Handler) -> Handler:
            self.add("GET", pattern, handler)
            return handler
        return decorate

    def post(self, pattern: str) -> Callable[[Handler], Handler]:
        def decorate(handler: Handler) -> Handler:
            self.add("POST", pattern, handler)
            return handler
        return decorate

    def resolve(self, method: str, path: str) -> Optional[Tuple[Handler, Dict[str, str]]]:
        method = method.upper()
        path_matched = False
        for route_method, pattern, handler in self.routes:
            match = pattern.match(path)
            if not match:
                continue
            path_matched = True
            if route_method == method:
                return handler, match.groupdict()
        if path_matched:
            raise MethodNotAllowed(path)
        return None


class MethodNotAllowed(Exception):
    pass
