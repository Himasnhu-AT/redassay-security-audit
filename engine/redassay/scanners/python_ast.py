"""Python scanning that actually parses the code.

Regex can tell you `cursor.execute` appears on line 40. The AST can tell you the
first argument is an f-string whose interpolated name was assigned from
`request.args`, three lines up. That difference is what makes a finding worth
reading, so this scanner carries a small intra-procedural taint tracker.

Scope is deliberate: one function at a time, no cross-file or cross-call
propagation. Anything wider needs a real call graph, and a wrong answer from a
half-built one is worse than no answer.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# Attribute chains that introduce attacker-controlled data.
TAINT_SOURCES = {
    ("request", "args"), ("request", "form"), ("request", "values"),
    ("request", "json"), ("request", "data"), ("request", "cookies"),
    ("request", "headers"), ("request", "files"), ("request", "query_params"),
    ("request", "GET"), ("request", "POST"), ("request", "body"),
    ("self", "request"), ("flask", "request"),
}

TAINT_SOURCE_CALLS = {"input", "get_json", "getvalue"}

SQL_EXECUTORS = {"execute", "executemany", "executescript", "raw", "execute_sql"}

SHELL_FUNCS = {
    ("os", "system"), ("os", "popen"), ("os", "spawnl"), ("os", "spawnv"),
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "check_call"),
    ("subprocess", "check_output"), ("subprocess", "Popen"), ("subprocess", "getoutput"),
    ("commands", "getoutput"),
}

FILE_SINKS = {"open", "read_text", "read_bytes", "send_file", "send_from_directory", "remove", "unlink"}

WEAK_HASHES = {"md5", "sha1"}

RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample", "uniform", "shuffle", "getrandbits"}

SECURITY_NAMES = {
    "is_admin", "is_staff", "is_superuser", "is_authenticated", "has_perm",
    "has_permission", "can_edit", "can_delete", "can_view", "authorized",
    "permission", "role", "owner", "current_user", "verify", "validate_token",
}


def _attr_chain(node: ast.AST) -> Tuple[str, ...]:
    """Flatten a.b.c into ('a','b','c'). Returns () for anything else."""
    parts: List[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return tuple(reversed(parts))
    return ()


def _call_name(node: ast.Call) -> Tuple[str, ...]:
    return _attr_chain(node.func)


def _keyword(node: ast.Call, name: str) -> Optional[ast.AST]:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_literal(node: Optional[ast.AST]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(el) for el in node.elts)
    if isinstance(node, ast.Dict):
        return all(_is_literal(k) for k in node.keys) and all(_is_literal(v) for v in node.values)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    """f-string, concatenation, %-format or .format() - anything not a plain literal."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        chain = _call_name(node)
        return bool(chain) and chain[-1] in {"format", "join", "format_map"}
    return False


class TaintScope:
    """Names known to hold attacker-controlled data inside one function body."""

    def __init__(self) -> None:
        self.names: Dict[str, str] = {}   # name -> human description of the origin

    def mark(self, name: str, origin: str) -> None:
        self.names.setdefault(name, origin)

    def origin(self, node: ast.AST) -> Optional[str]:
        """Return a description of why this expression is tainted, or None."""
        if isinstance(node, ast.Name):
            return self.names.get(node.id)
        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            for length in (2, 3):
                if len(chain) >= length and tuple(chain[:length]) in TAINT_SOURCES:
                    return ".".join(chain[:length])
            if chain and chain[0] in self.names:
                return self.names[chain[0]]
            return self.origin(node.value)
        if isinstance(node, ast.Subscript):
            return self.origin(node.value)
        if isinstance(node, ast.Call):
            chain = _call_name(node)
            if chain and chain[-1] in TAINT_SOURCE_CALLS:
                return ".".join(chain)
            if chain and len(chain) >= 2 and tuple(chain[:2]) in TAINT_SOURCES:
                return ".".join(chain[:2])
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                found = self.origin(arg)
                if found:
                    return found
            return self.origin(node.func) if isinstance(node.func, ast.Attribute) else None
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    found = self.origin(part.value)
                    if found:
                        return found
            return None
        if isinstance(node, ast.BinOp):
            return self.origin(node.left) or self.origin(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                found = self.origin(element)
                if found:
                    return found
        if isinstance(node, ast.Dict):
            for value in node.values:
                found = self.origin(value)
                if found:
                    return found
        if isinstance(node, ast.IfExp):
            return self.origin(node.body) or self.origin(node.orelse)
        return None

    def is_tainted(self, node: ast.AST) -> bool:
        return self.origin(node) is not None


class _Collector(ast.NodeVisitor):
    """One pass over a module, emitting raw (rule, node, extras) tuples."""

    def __init__(self) -> None:
        self.hits: List[Tuple[str, ast.AST, Dict[str, Any]]] = []
        self.scopes: List[TaintScope] = [TaintScope()]
        self.func_stack: List[str] = []

    # -- scope handling ------------------------------------------------------
    @property
    def scope(self) -> TaintScope:
        return self.scopes[-1]

    def _enter_function(self, node) -> None:
        scope = TaintScope()
        # Route parameters in web frameworks are attacker-controlled by definition.
        decorated = any(
            "route" in ".".join(_attr_chain(d.func if isinstance(d, ast.Call) else d))
            or ".".join(_attr_chain(d.func if isinstance(d, ast.Call) else d)).split(".")[-1]
            in {"get", "post", "put", "patch", "delete"}
            for d in node.decorator_list
        )
        if decorated:
            for arg in node.args.args:
                if arg.arg not in {"self", "cls", "request"}:
                    scope.mark(arg.arg, "route parameter")
        self.scopes.append(scope)
        self.func_stack.append(node.name)

    def _exit_function(self) -> None:
        self.scopes.pop()
        self.func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_function(node)
        self.generic_visit(node)
        self._exit_function()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_function(node)
        self.generic_visit(node)
        self._exit_function()

    # -- taint propagation ---------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        origin = self.scope.origin(node.value)
        if origin:
            for target in node.targets:
                for name in _target_names(target):
                    self.scope.mark(name, origin)
        self._check_assign_rules(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            origin = self.scope.origin(node.value)
            if origin:
                for name in _target_names(node.target):
                    self.scope.mark(name, origin)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None and self.scope.is_tainted(item.context_expr):
                origin = self.scope.origin(item.context_expr) or "request"
                for name in _target_names(item.optional_vars):
                    self.scope.mark(name, origin)
        self.generic_visit(node)

    # -- rules ---------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        chain = _call_name(node)
        tail = chain[-1] if chain else ""
        head = chain[0] if chain else ""
        first = node.args[0] if node.args else None

        if tail in {"eval", "exec"} and len(chain) == 1:
            if first is not None and not _is_literal(first):
                self._hit("py.eval-dynamic", node, {
                    "func": tail,
                    "taint": self.scope.origin(first),
                })

        if tail == "compile" and len(chain) == 1 and first is not None and self.scope.is_tainted(first):
            self._hit("py.compile-tainted", node, {"taint": self.scope.origin(first)})

        if tuple(chain) in SHELL_FUNCS or (len(chain) >= 2 and (chain[0], chain[-1]) in SHELL_FUNCS):
            shell = _keyword(node, "shell")
            uses_shell = _is_true(shell) or (chain[0] == "os" and chain[-1] in {"system", "popen"})
            if uses_shell and first is not None:
                if not _is_literal(first):
                    self._hit("py.shell-dynamic", node, {
                        "func": ".".join(chain),
                        "taint": self.scope.origin(first),
                        "dynamic": _is_dynamic_string(first),
                    })
            elif _is_true(shell):
                self._hit("py.shell-true-literal", node, {"func": ".".join(chain)})

        if tail in SQL_EXECUTORS and first is not None:
            if _is_dynamic_string(first) or self.scope.is_tainted(first):
                self._hit("py.sql-dynamic", node, {
                    "func": ".".join(chain) or tail,
                    "taint": self.scope.origin(first),
                    "kind": _string_kind(first),
                })

        if tail in {"loads", "load"} and head in {"pickle", "cPickle", "dill", "marshal", "shelve", "jsonpickle"}:
            self._hit("py.pickle-load", node, {"module": head, "taint": self.scope.origin(first) if first else None})

        if head == "yaml" and tail in {"load", "unsafe_load", "full_load"}:
            loader = _keyword(node, "Loader")
            safe = loader is not None and "Safe" in ".".join(_attr_chain(loader))
            if not safe and tail != "safe_load":
                self._hit("py.yaml-unsafe-load", node, {"taint": self.scope.origin(first) if first else None})

        if head == "hashlib" and tail in WEAK_HASHES:
            self._hit("py.weak-hash", node, {"algo": tail})

        if head == "random" and tail in RANDOM_FUNCS:
            self._hit("py.weak-random", node, {"func": tail})

        if _is_false(_keyword(node, "verify")):
            self._hit("py.tls-verify-off", node, {"func": ".".join(chain) or tail})

        if head in {"requests", "httpx"} and tail in {"get", "post", "put", "delete", "patch", "head", "request"}:
            if _keyword(node, "timeout") is None:
                self._hit("py.request-no-timeout", node, {"func": ".".join(chain)})
            if first is not None and self.scope.is_tainted(first):
                self._hit("py.ssrf", node, {"func": ".".join(chain), "taint": self.scope.origin(first)})

        if tail in FILE_SINKS and first is not None and self.scope.is_tainted(first):
            self._hit("py.path-tainted", node, {"func": ".".join(chain) or tail, "taint": self.scope.origin(first)})

        if head == "tempfile" and tail == "mktemp":
            self._hit("py.mktemp-race", node, {})

        if tail == "run" and head in {"app", "application"} and _is_true(_keyword(node, "debug")):
            self._hit("py.flask-debug", node, {})

        if tail == "chmod" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
            if isinstance(mode, int) and mode & 0o007 == 0o007:
                self._hit("py.world-writable-chmod", node, {"mode": oct(mode)})

        if tail in {"render_template_string", "from_string"} and first is not None and not _is_literal(first):
            self._hit("py.ssti", node, {"taint": self.scope.origin(first)})

        if tail in {"redirect", "url_for"} and first is not None and self.scope.is_tainted(first) and tail == "redirect":
            self._hit("py.open-redirect", node, {"taint": self.scope.origin(first)})

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(node.test) if isinstance(n, ast.Attribute)}
        calls = set()
        for call in ast.walk(node.test):
            if isinstance(call, ast.Call):
                chain = _call_name(call)
                if chain:
                    calls.add(chain[-1])
        if (names | attrs | calls) & SECURITY_NAMES:
            self._hit("py.assert-security", node, {})
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        body = node.body
        swallowed = len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Continue))
        bare = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"})
        if swallowed and bare:
            self._hit("py.swallowed-exception", node, {})
        self.generic_visit(node)

    def _check_assign_rules(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if not name:
                continue
            if name == "ALLOWED_HOSTS" and isinstance(node.value, (ast.List, ast.Tuple)):
                values = [el.value for el in node.value.elts if isinstance(el, ast.Constant)]
                if "*" in values:
                    self._hit("py.django-allowed-hosts-wildcard", node, {})
            if name in {"DEBUG", "DEBUG_PROPAGATE_EXCEPTIONS"} and _is_true(node.value):
                self._hit("py.django-debug-true", node, {"setting": name})

    def _hit(self, rule: str, node: ast.AST, extras: Dict[str, Any]) -> None:
        extras = dict(extras)
        extras["function"] = self.func_stack[-1] if self.func_stack else "<module>"
        self.hits.append((rule, node, extras))


def _target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for element in target.elts:
            names.extend(_target_names(element))
        return names
    return []


def _string_kind(node: ast.AST) -> str:
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.BinOp):
        return "%-format" if isinstance(node.op, ast.Mod) else "concatenation"
    if isinstance(node, ast.Call):
        return ".format()"
    return "dynamic expression"


# --- rule metadata -----------------------------------------------------------
RULES: Dict[str, Dict[str, Any]] = {
    "py.eval-dynamic": {
        "title": "eval()/exec() on a computed expression",
        "severity": "critical", "confidence": "medium",
        "cwe": ["CWE-95"], "owasp": ["A03:2021 Injection"],
        "remediation": "Use ast.literal_eval() for data or a dispatch dictionary for behaviour.",
    },
    "py.compile-tainted": {
        "title": "compile() on attacker-controlled source",
        "severity": "critical", "confidence": "high",
        "cwe": ["CWE-95"], "owasp": ["A03:2021 Injection"],
        "remediation": "Do not compile input. Parse it as data instead.",
    },
    "py.shell-dynamic": {
        "title": "Shell command built from a computed value",
        "severity": "high", "confidence": "medium",
        "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
        "remediation": "Pass an argument list with shell=False so no shell parses the string.",
    },
    "py.shell-true-literal": {
        "title": "subprocess called with shell=True",
        "severity": "low", "confidence": "high",
        "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
        "remediation": "The command is a literal today, but shell=True is a loaded gun for the next edit. Prefer an argument list.",
    },
    "py.sql-dynamic": {
        "title": "SQL statement assembled at runtime",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
        "remediation": "Pass values as bound parameters: cursor.execute(sql, (a, b)).",
    },
    "py.pickle-load": {
        "title": "pickle/marshal load",
        "severity": "critical", "confidence": "medium",
        "cwe": ["CWE-502"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "remediation": "Use JSON, or sign the payload and verify before loading.",
    },
    "py.yaml-unsafe-load": {
        "title": "yaml.load() without a safe loader",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-502"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "remediation": "Call yaml.safe_load().",
    },
    "py.weak-hash": {
        "title": "Weak hash algorithm",
        "severity": "medium", "confidence": "medium",
        "cwe": ["CWE-327"], "owasp": ["A02:2021 Cryptographic Failures"],
        "remediation": "Use SHA-256 for integrity, argon2id/bcrypt for passwords.",
    },
    "py.weak-random": {
        "title": "random module used where a CSPRNG is needed",
        "severity": "medium", "confidence": "low",
        "cwe": ["CWE-338"], "owasp": ["A02:2021 Cryptographic Failures"],
        "remediation": "Use the secrets module for anything security-relevant.",
    },
    "py.tls-verify-off": {
        "title": "TLS verification disabled (verify=False)",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-295"], "owasp": ["A02:2021 Cryptographic Failures"],
        "remediation": "Verify certificates; supply a CA bundle for internal PKI.",
    },
    "py.request-no-timeout": {
        "title": "Outbound request without a timeout",
        "severity": "low", "confidence": "high",
        "cwe": ["CWE-400"], "owasp": ["A05:2021 Security Misconfiguration"],
        "remediation": "Always pass timeout=. Without it a hung peer holds the worker forever.",
    },
    "py.ssrf": {
        "title": "Outbound request to an attacker-controlled URL",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-918"], "owasp": ["A10:2021 Server-Side Request Forgery"],
        "remediation": "Allowlist hosts, resolve and reject private ranges, disable redirects.",
    },
    "py.path-tainted": {
        "title": "Filesystem path derived from request data",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
        "remediation": "Resolve the path and assert it stays under the intended root.",
    },
    "py.mktemp-race": {
        "title": "tempfile.mktemp() is race-prone",
        "severity": "medium", "confidence": "high",
        "cwe": ["CWE-377"], "owasp": ["A05:2021 Security Misconfiguration"],
        "remediation": "Use tempfile.mkstemp() or NamedTemporaryFile().",
    },
    "py.flask-debug": {
        "title": "Flask app started with debug=True",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-489"], "owasp": ["A05:2021 Security Misconfiguration"],
        "remediation": "Never ship debug=True - the Werkzeug debugger is an RCE console over HTTP.",
    },
    "py.world-writable-chmod": {
        "title": "chmod grants world write access",
        "severity": "medium", "confidence": "high",
        "cwe": ["CWE-732"], "owasp": ["A01:2021 Broken Access Control"],
        "remediation": "Grant the narrowest mode that works, usually 0o600 or 0o640.",
    },
    "py.ssti": {
        "title": "Template compiled from a runtime string",
        "severity": "high", "confidence": "high",
        "cwe": ["CWE-1336"], "owasp": ["A03:2021 Injection"],
        "remediation": "Render a fixed template and pass data as context.",
    },
    "py.open-redirect": {
        "title": "redirect() to a request-controlled target",
        "severity": "medium", "confidence": "high",
        "cwe": ["CWE-601"], "owasp": ["A01:2021 Broken Access Control"],
        "remediation": "Redirect only to relative paths or an allowlist.",
    },
    "py.assert-security": {
        "title": "assert used for a security check",
        "severity": "high", "confidence": "medium",
        "cwe": ["CWE-617"], "owasp": ["A04:2021 Insecure Design"],
        "remediation": "Use if/raise - python -O removes asserts.",
    },
    "py.swallowed-exception": {
        "title": "Broad exception silently swallowed",
        "severity": "low", "confidence": "medium",
        "cwe": ["CWE-390"], "owasp": ["A09:2021 Security Logging and Monitoring Failures"],
        "remediation": "Log the exception. A failed security check that raises and is swallowed passes.",
    },
    "py.django-allowed-hosts-wildcard": {
        "title": "ALLOWED_HOSTS = ['*']",
        "severity": "medium", "confidence": "high",
        "cwe": ["CWE-16"], "owasp": ["A05:2021 Security Misconfiguration"],
        "remediation": "List the hostnames you serve. The wildcard enables Host-header attacks on password reset links.",
    },
    "py.django-debug-true": {
        "title": "DEBUG = True in settings",
        "severity": "high", "confidence": "medium",
        "cwe": ["CWE-489"], "owasp": ["A05:2021 Security Misconfiguration"],
        "remediation": "Drive DEBUG from the environment, defaulting to False.",
    },
}


@register
class PythonAstScanner(Scanner):
    name = "python-ast"
    description = "Python AST analysis with intra-procedural taint tracking"
    languages = ("python",)

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        text = source.read()
        try:
            tree = ast.parse(text, filename=source.path)
        except (SyntaxError, ValueError, RecursionError):
            return
        lines = text.splitlines()
        collector = _Collector()
        collector.visit(tree)

        counts: Dict[str, int] = {}
        for rule_id, node, extras in collector.hits:
            meta = RULES.get(rule_id)
            if meta is None:
                continue
            line_no = getattr(node, "lineno", 1)
            snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            from .. import suppress as suppress_mod
            if suppress_mod.suppressed_by_source(lines, line_no, rule_id):
                continue
            seen = counts.get(rule_id, 0)
            counts[rule_id] = seen + 1
            severity, confidence = _adjust(meta, extras)
            yield self.make_finding(
                rule_id=rule_id,
                title=meta["title"],
                source=source,
                line=line_no,
                end_line=getattr(node, "end_lineno", line_no) or line_no,
                snippet=snippet,
                severity=severity,
                confidence=confidence,
                description=_describe(rule_id, meta, extras),
                remediation=meta["remediation"],
                cwe=meta.get("cwe", []),
                owasp=meta.get("owasp", []),
                tags=["python", "ast"],
                scanner=self.name,
                salt="" if seen == 0 else str(seen),
            )


def _adjust(meta: Dict[str, Any], extras: Dict[str, Any]) -> Tuple[str, str]:
    """Confirmed taint raises both severity and confidence - that is the point of tracking it."""
    severity, confidence = meta["severity"], meta["confidence"]
    if extras.get("taint"):
        confidence = "high"
        if severity == "high":
            severity = "critical"
        elif severity == "medium":
            severity = "high"
    return severity, confidence


def _describe(rule_id: str, meta: Dict[str, Any], extras: Dict[str, Any]) -> str:
    parts: List[str] = []
    function = extras.get("function")
    taint = extras.get("taint")
    if taint:
        parts.append(
            f"A value originating from `{taint}` reaches this call inside `{function}()`. "
            "The taint tracker followed it through assignment and string building within the "
            "function, so this is a concrete data path rather than a pattern match."
        )
    elif function and function != "<module>":
        parts.append(f"Found in `{function}()`.")
    if rule_id == "py.sql-dynamic":
        parts.append(f"The statement is built with a {extras.get('kind', 'dynamic expression')}.")
    if rule_id == "py.shell-dynamic":
        parts.append(f"`{extras.get('func')}` runs the string through a shell, so metacharacters are syntax.")
    if rule_id == "py.eval-dynamic":
        parts.append(f"`{extras.get('func')}()` executes whatever the expression evaluates to.")
    if rule_id == "py.weak-hash":
        parts.append(f"`hashlib.{extras.get('algo')}` has practical collision attacks.")
    if rule_id == "py.world-writable-chmod":
        parts.append(f"Mode {extras.get('mode')} lets any local user modify the file.")
    return " ".join(parts) or meta["title"]
