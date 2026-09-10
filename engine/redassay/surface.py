"""The attack surface inventory: every place untrusted data enters.

A vulnerability scanner answers "does this line look dangerous". A reviewer
needs the opposite question answered first: "what can a stranger reach, and what
stands in front of it". That list is what an audit should start from, and until
now redassay made the model grep for it - which means the audit is only as
complete as the greps somebody thought of.

So the engine builds the list instead. For each detected framework, find its
handler registrations; for each one, record what it is, where it is, and whether
anything that looks like an authorization check sits near it. The `auth`
determination is deliberately a *hint*, not a verdict: proximity is not proof,
and a scanner that claimed otherwise would be wrong in the direction that gets
people hurt.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .tech import Detection
from .walker import SourceFile

# --- kinds -------------------------------------------------------------------
HTTP = "http"
SERVER_ACTION = "server-action"
QUEUE = "queue"
SOCKET = "socket"
GRAPHQL = "graphql"
CLI = "cli"
WEBHOOK = "webhook"
SCHEDULED = "scheduled"

#: Kinds reachable by someone who is not already inside the system.
EXTERNALLY_REACHABLE = {HTTP, SERVER_ACTION, SOCKET, GRAPHQL, WEBHOOK}

#: Anything resembling an authorization gate. Deliberately broad: a false
#: "guarded" here only lowers a hint, while a false "unguarded" sends a reviewer
#: on a pointless errand and teaches them to ignore the column.
AUTH_MARKERS = re.compile(
    r"(?i)("
    r"login_required|permission_required|requires?[_-]?auth|authenticate|authoriz|"
    r"@jwt_required|current_user|is_?authenticated|is_?logged_?in|logged_?in|"
    r"has_perm|permission_classes|IsAuthenticated|Depends\s*\(|@UseGuards|"
    r"before_action|authorize_resource|ensure[_-]?(auth|logged|user|admin)|"
    r"require[_-]?(auth|login|user|admin|role)|must[_-]?be[_-]?(auth|logged)|"
    r"verify[_-]?(token|user|session)|check[_-]?(auth|permission|access|role)|"
    r"with[_-]?auth|protect\b|passport\.authenticate|auth\.middleware|"
    r"guard|policy|@PreAuthorize|@Secured|@RolesAllowed|is[_-]?admin|"
    r"session\s*\[|req\.user|request\.user"
    r")"
)

#: For Express-style registrations, anything between the path and the final
#: handler is middleware. We usually cannot tell what it does - but "something
#: is there" and "nothing is there" are different enough to be worth separating,
#: and guessing wrong in the "nothing is there" direction sends reviewers on
#: errands and teaches them to ignore the column.
def _arguments_after_path(remainder: str, limit: int = 400) -> int:
    """How many further arguments the registration passes.

    Counting commas naively does not work: `app.get("/x", (req, res) => {})`
    has a comma inside the handler's own parameter list, and reading that as
    middleware marks every plain route as protected - the exact direction a
    security tool must not be wrong in.

    So walk the text tracking bracket depth and string state, and count only the
    commas that actually separate arguments of this call.
    """
    depth = 0
    count = 0
    quote = ""
    escaped = False
    for char in remainder[:limit]:
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "\"'`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                break                      # end of the registration call
            depth -= 1
        elif char == "," and depth == 0:
            count += 1
    return count

#: Markers that say a route is deliberately public. Worth distinguishing from
#: "nothing found" - one is a decision, the other is a gap.
PUBLIC_MARKERS = re.compile(
    # redassay: ignore config.csrf-disabled - this is the pattern that detects it
    r"(?i)(@Public\b|AllowAny|permitAll|csrf_exempt|public\s*[:=]\s*true|"
    r"skip_before_action|@AnonymousAllowed|login_not_required)"
)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class EntryPoint:
    kind: str
    name: str                       # route path, handler name, task name
    path: str                       # file
    line: int
    framework: str = ""
    method: str = ""                # HTTP verb where it applies
    auth: str = "unknown"           # "guarded" | "public" | "none-found" | "unknown"
    snippet: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @property
    def label(self) -> str:
        verb = f"{self.method} " if self.method else ""
        return f"{verb}{self.name}".strip()

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"

    @property
    def is_mutating(self) -> bool:
        return self.method.upper() in MUTATING_METHODS

    @property
    def externally_reachable(self) -> bool:
        return self.kind in EXTERNALLY_REACHABLE

    @property
    def expected_public(self) -> bool:
        """True for endpoints whose job requires them to be unauthenticated.

        A login route with no auth guard is not a finding; it is a login route.
        """
        return bool(EXPECTED_PUBLIC.search(self.name or ""))


# --- extractors --------------------------------------------------------------
# (tech tag or "" for always-on, kind, compiled pattern, group layout)
# Group layout names which capture holds the method and which the route.

@dataclass(frozen=True)
class Extractor:
    tech: str
    kind: str
    pattern: re.Pattern
    framework: str
    languages: Tuple[str, ...] = ()
    method_group: Optional[str] = "method"
    name_group: Optional[str] = "name"
    #: True when the guard travels in the registration's argument list rather
    #: than on a decorator line of its own.
    call_style: bool = True


def _compile(source: str) -> re.Pattern:
    return re.compile(source)


EXTRACTORS: List[Extractor] = [
    # --- Python ---
    Extractor("flask", HTTP, _compile(
        r"@(?:\w+)\.route\s*\(\s*['\"](?P<name>[^'\"]+)['\"]"
        r"(?:[^)]*methods\s*=\s*\[(?P<method>[^\]]*)\])?"),
        "Flask", ("python",), call_style=False),
    Extractor("fastapi", HTTP, _compile(
        r"@(?:\w+)\.(?P<method>get|post|put|patch|delete|head|options|websocket)\s*\(\s*['\"](?P<name>[^'\"]+)['\"]"),
        "FastAPI", ("python",), call_style=False),
    Extractor("django", HTTP, _compile(
        r"(?:path|re_path|url)\s*\(\s*r?['\"](?P<name>[^'\"]*)['\"]\s*,"),
        "Django", ("python",), method_group=None),
    Extractor("drf", HTTP, _compile(
        r"class\s+(?P<name>\w+)\s*\(\s*[^)]*(?:APIView|ViewSet|GenericAPIView|ModelViewSet)"),
        "DRF", ("python",), method_group=None, call_style=False),
    Extractor("celery", QUEUE, _compile(
        r"@(?:\w+\.)?(?:shared_)?task[\s(][\s\S]{0,120}?def\s+(?P<name>\w+)"),
        "Celery", ("python",), method_group=None, call_style=False),

    # --- JavaScript / TypeScript ---
    Extractor("express", HTTP, _compile(
        r"\b(?:app|router|api|server)\s*\.\s*(?P<method>get|post|put|patch|delete|all|use)\s*\(\s*['\"`](?P<name>[^'\"`]+)['\"`]"),
        "Express", ("javascript", "typescript")),
    Extractor("fastify", HTTP, _compile(
        r"\bfastify\s*\.\s*(?P<method>get|post|put|patch|delete|route)\s*\(\s*['\"`](?P<name>[^'\"`]+)['\"`]"),
        "Fastify", ("javascript", "typescript")),
    Extractor("hono", HTTP, _compile(
        r"\bapp\s*\.\s*(?P<method>get|post|put|patch|delete|on)\s*\(\s*['\"`](?P<name>[^'\"`]+)['\"`]"),
        "Hono", ("javascript", "typescript")),
    Extractor("nestjs", HTTP, _compile(
        r"@(?P<method>Get|Post|Put|Patch|Delete)\s*\(\s*['\"`]?(?P<name>[^'\"`)]*)['\"`]?\s*\)"),
        "NestJS", ("typescript",), call_style=False),
    Extractor("socketio", SOCKET, _compile(
        r"\bsocket\s*\.\s*on\s*\(\s*['\"`](?P<name>[^'\"`]+)['\"`]"),
        "Socket.IO", ("javascript", "typescript"), method_group=None),
    Extractor("bullmq", QUEUE, _compile(
        r"new\s+Worker\s*\(\s*['\"`](?P<name>[^'\"`]+)['\"`]"),
        "BullMQ", ("javascript", "typescript"), method_group=None),

    # --- Ruby / PHP / Go ---
    Extractor("rails", HTTP, _compile(
        r"^\s*(?P<method>get|post|put|patch|delete)\s+['\"](?P<name>[^'\"]+)['\"]"),
        "Rails", ("ruby",)),
    Extractor("laravel", HTTP, _compile(
        r"Route::(?P<method>get|post|put|patch|delete|any|match)\s*\(\s*['\"](?P<name>[^'\"]+)['\"]"),
        "Laravel", ("php",)),
    Extractor("gin", HTTP, _compile(
        r"\b\w+\s*\.\s*(?P<method>GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*\"(?P<name>[^\"]+)\""),
        "Gin", ("go",)),
    Extractor("echo", HTTP, _compile(
        r"\b[eg]\s*\.\s*(?P<method>GET|POST|PUT|PATCH|DELETE)\s*\(\s*\"(?P<name>[^\"]+)\""),
        "Echo", ("go",)),
    Extractor("chi", HTTP, _compile(
        r"\br\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete|Mount)\s*\(\s*\"(?P<name>[^\"]+)\""),
        "chi", ("go",)),

    # --- always-on, framework-independent ---
    Extractor("", HTTP, _compile(
        r"\bhttp\.HandleFunc\s*\(\s*\"(?P<name>[^\"]+)\""),
        "net/http", ("go",), method_group=None),
    Extractor("", GRAPHQL, _compile(
        r"^\s*(?P<name>\w+)\s*:\s*(?:async\s*)?\([^)]*\)\s*=>|^\s*(?:Query|Mutation)\s*:\s*\{"),
        "GraphQL", ("javascript", "typescript"), method_group=None),
    Extractor("", SCHEDULED, _compile(
        r"(?:@scheduled|@Scheduled|cron\s*[:=]|schedule\.every|CronJob)\s*\(?\s*['\"]?(?P<name>[^'\")\n]{0,40})"),
        "scheduler", (), method_group=None),
    Extractor("", WEBHOOK, _compile(
        r"['\"`](?P<name>/[\w/-]*(?:webhook|callback|hook)[\w/-]*)['\"`]"),
        "webhook", (), method_group=None),
]

#: Next.js and similar put the route in the *path*, not in a call.
FILE_ROUTE_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    ("nextjs", HTTP, "Next.js route handler",
     re.compile(r"(?:^|/)app/(?P<name>.*)/route\.(?:ts|js|tsx|jsx)$")),
    ("nextjs", HTTP, "Next.js API route",
     re.compile(r"(?:^|/)pages/api/(?P<name>.*)\.(?:ts|js|tsx|jsx)$")),
]

USE_SERVER = re.compile(r"^\s*['\"]use server['\"]")
EXPORTED_ASYNC = re.compile(r"^\s*export\s+(?:async\s+)?function\s+(?P<name>\w+)", re.MULTILINE)


#: Paths that are unauthenticated because that is what they are for. Counting
#: them as findings buries the ones that matter - on one real application 137
#: "unprotected" entry points were mostly login and signup pages.
EXPECTED_PUBLIC = re.compile(
    r"(?i)(^|/)(login|signin|sign-in|logout|signout|signup|sign-up|register|"
    r"auth|oauth|sso|callback|token|refresh|forgot|reset|verify|confirm|"
    r"health|healthz|readyz|livez|ping|status|metrics|robots\.txt|favicon|"
    r"webhooks?|public|static|assets|docs|openapi|swagger)(/|$|\.)"
)


def _decorator_block(lines: Sequence[str], index: int, radius: int = 8) -> str:
    """The decorators attached to this handler, and its signature.

    A symmetric window is the obvious implementation and the wrong one: it
    reaches imports. `from flask_login import login_required` at the top of a
    module made every route in that module read as guarded, which is the
    failure direction that hides work.
    """
    collected: List[str] = []
    if 0 <= index < len(lines):
        collected.append(lines[index])

    # Upward: contiguous decorators and comments only.
    cursor = index - 1
    while cursor >= 0 and index - cursor <= radius:
        stripped = lines[cursor].strip()
        if stripped.startswith("@") or stripped.startswith("#") or not stripped:
            collected.append(lines[cursor])
            cursor -= 1
            continue
        break

    # Downward: decorators between the route and the function, plus the def.
    cursor = index + 1
    while cursor < len(lines) and cursor - index <= radius:
        stripped = lines[cursor].strip()
        if stripped.startswith("@") or not stripped:
            collected.append(lines[cursor])
            cursor += 1
            continue
        if stripped.startswith(("def ", "async def ", "class ", "func ", "public ")):
            collected.append(lines[cursor])
        break

    return "\n".join(collected)


def _auth_state(lines: Sequence[str], index: int, radius: int = 8,
                remainder: Optional[str] = None) -> str:
    """What, if anything, stands in front of this handler.

    Four answers, in decreasing order of confidence:

    * ``public``      - an explicit opt-out is present, so it is a decision.
    * ``guarded``     - something recognisably auth-shaped is in front of it.
    * ``middleware``  - an unidentified argument sits between the path and the
                        handler. Worth reading; not worth alarming about.
    * ``none-found``  - nothing. This is the list to start from.

    Two shapes of framework need two different answers to "in front of it":

    *Call-style* registration (Express, Gin, Laravel) puts the guard in the
    argument list, so the registration itself is authoritative and neighbouring
    lines are noise. Consulting a window here made adjacent routes disagree -
    `GET /login` reading as guarded because an unrelated `isLoggedIn` sat four
    lines below.

    *Decorator-style* registration (Flask, Django, NestJS) puts the guard on its
    own line, so the decorator block is the only place to look - and only the
    decorator block, because a window wide enough to be useful also reaches the
    imports.
    """
    line = lines[index] if 0 <= index < len(lines) else ""

    if remainder is not None:
        if PUBLIC_MARKERS.search(line):
            return "public"
        if AUTH_MARKERS.search(line):
            return "guarded"
        return "middleware" if _arguments_after_path(remainder) >= 2 else "none-found"

    block = _decorator_block(lines, index, radius)
    if PUBLIC_MARKERS.search(block):
        return "public"
    if AUTH_MARKERS.search(block):
        return "guarded"
    return "none-found"


def _methods(raw: Optional[str]) -> List[str]:
    if not raw:
        return [""]
    found = re.findall(r"[A-Za-z]+", raw)
    return [m.upper() for m in found] or [""]


def inventory(
    files: Sequence[SourceFile],
    detection: Optional[Detection] = None,
    include_ungated: bool = True,
) -> List[EntryPoint]:
    """Every entry point we can find, deduplicated and sorted."""
    tags = set(detection.tags) if detection else set()
    active = [
        extractor for extractor in EXTRACTORS
        if not extractor.tech or extractor.tech in tags or (include_ungated and not tags)
    ]

    found: List[EntryPoint] = []
    seen: Set[Tuple[str, str, int]] = set()

    for source in files:
        # File-path routing, before reading anything.
        for tech_tag, kind, framework, pattern in FILE_ROUTE_PATTERNS:
            if tech_tag and tags and tech_tag not in tags:
                continue
            match = pattern.search(source.path)
            if match:
                route = "/" + match.group("name").strip("/")
                key = (source.path, route, 1)
                if key not in seen:
                    seen.add(key)
                    found.append(EntryPoint(
                        kind=kind, name=route, path=source.path, line=1,
                        framework=framework, snippet=source.path,
                    ))

        if source.language not in {
            "python", "javascript", "typescript", "ruby", "php", "go", "java", "kotlin",
        }:
            continue
        try:
            text = source.read()
        except (OSError, UnicodeDecodeError):
            continue
        lines = text.splitlines()

        # Next.js server actions: any exported function in a 'use server' module.
        if "use server" in text and source.language in {"javascript", "typescript"}:
            module_level = any(USE_SERVER.match(line) for line in lines[:5])
            if module_level:
                for match in EXPORTED_ASYNC.finditer(text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    key = (source.path, match.group("name"), line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(EntryPoint(
                        kind=SERVER_ACTION, name=match.group("name"), path=source.path,
                        line=line_no, framework="Next.js", method="POST",
                        auth=_auth_state(lines, line_no - 1),
                        snippet=lines[line_no - 1].strip()[:160] if line_no <= len(lines) else "",
                    ))

        for extractor in active:
            if extractor.languages and source.language not in extractor.languages:
                continue
            for match in extractor.pattern.finditer(text):
                groups = match.groupdict()
                name = (groups.get("name") or "").strip()
                if not name:
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                raw_method = groups.get("method") if extractor.method_group else None
                for method in _methods(raw_method):
                    if method == "USE":
                        continue          # middleware registration, not a route
                    key = (source.path, f"{method}:{name}", line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(EntryPoint(
                        kind=extractor.kind, name=name, path=source.path, line=line_no,
                        framework=extractor.framework, method=method,
                        auth=_auth_state(
                            lines, line_no - 1,
                            remainder=(text[match.end():match.end() + 400]
                                       if extractor.call_style else None),
                        ),
                        snippet=lines[line_no - 1].strip()[:160] if line_no <= len(lines) else "",
                    ))

    return sorted(found, key=lambda e: (e.path, e.line, e.name))


def summarize(entries: Sequence[EntryPoint]) -> Dict[str, object]:
    by_kind: Dict[str, int] = {}
    by_framework: Dict[str, int] = {}
    for entry in entries:
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1
        if entry.framework:
            by_framework[entry.framework] = by_framework.get(entry.framework, 0) + 1

    by_auth: Dict[str, int] = {}
    for entry in entries:
        by_auth[entry.auth] = by_auth.get(entry.auth, 0) + 1

    return {
        "total": len(entries),
        "by_kind": dict(sorted(by_kind.items())),
        "by_framework": dict(sorted(by_framework.items(), key=lambda kv: -kv[1])),
        "by_auth": dict(sorted(by_auth.items())),
        "externally_reachable": sum(1 for e in entries if e.externally_reachable),
        "unprotected": sum(
            1 for e in entries
            if e.auth == "none-found" and e.externally_reachable
            and not e.expected_public and (e.is_mutating or not e.method)
        ),
        "expected_public": sum(1 for e in entries if e.expected_public),
        "explicitly_public": by_auth.get("public", 0),
        "behind_middleware": by_auth.get("middleware", 0),
    }


def needs_review(entries: Sequence[EntryPoint]) -> List[EntryPoint]:
    """Entry points a reviewer should open first.

    A mutating, externally reachable handler with nothing auth-shaped near it is
    the highest-value thing to read in any codebase - and it is exactly what no
    pattern rule can decide on its own.
    """
    order = {"none-found": 0, "public": 1, "middleware": 2}
    return sorted(
        (e for e in entries
         if e.externally_reachable and e.auth in order
         and (e.is_mutating or not e.method or e.kind != HTTP)),
        # Endpoints that are supposed to be public sort last: they are still
        # worth reading, but they are not the reason the list exists.
        key=lambda e: (e.expected_public, order[e.auth], not e.is_mutating, e.path, e.line),
    )
