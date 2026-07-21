"""JavaScript and TypeScript scanning.

There is no JS parser in the standard library and vendoring one would break the
zero-dependency rule, so this scanner works on a *normalized* view of the source
instead: comments and string bodies are blanked out first, which removes the bulk
of what makes regex analysis unreliable. On top of that it keeps a file-scoped
taint set for names assigned out of `req.query` / `req.body` / `req.params`.

File-scoped rather than function-scoped is a deliberate over-approximation. In
Express handlers the name is almost always used in the same closure it was bound
in, and the cost of the occasional extra hit is lower than the cost of missing
the injection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING = re.compile(r"""(["'])(?:\\.|(?!\1)[^\\\n])*\1""")

REQ_SOURCE = re.compile(r"\breq(?:uest)?\s*\.\s*(query|body|params|headers|cookies|files|url|originalUrl)\b")

ASSIGN_FROM_REQ = re.compile(
    r"\b(?:const|let|var)\s+(?:\{\s*([\w\s,:]+?)\s*\}|(\w+))\s*=\s*([^;\n]*\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|files)\b[^;\n]*)"
)

TEMPLATE_VARS = re.compile(r"\$\{\s*([\w.$\[\]'\"]+)")


def strip_noise(text: str) -> str:
    """Blank comments and string contents, preserving offsets so line numbers hold."""
    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = _BLOCK_COMMENT.sub(blank, text)
    text = _LINE_COMMENT.sub(blank, text)

    def blank_body(match: re.Match) -> str:
        quote = match.group(1)
        return quote + " " * (len(match.group(0)) - 2) + quote

    return _STRING.sub(blank_body, text)


def collect_tainted(text: str) -> Dict[str, str]:
    """Names bound to request data anywhere in the file."""
    tainted: Dict[str, str] = {}
    for match in ASSIGN_FROM_REQ.finditer(text):
        destructured, single, expression = match.group(1), match.group(2), match.group(3)
        origin_match = REQ_SOURCE.search(expression or "")
        origin = f"req.{origin_match.group(1)}" if origin_match else "req"
        if single:
            tainted[single] = origin
        if destructured:
            for part in destructured.split(","):
                name = part.split(":")[-1].strip()
                if name.isidentifier():
                    tainted[name] = origin
    return tainted


def taint_in(fragment: str, tainted: Dict[str, str]) -> Optional[str]:
    if REQ_SOURCE.search(fragment):
        match = REQ_SOURCE.search(fragment)
        return f"req.{match.group(1)}"
    for name in TEMPLATE_VARS.findall(fragment):
        root = re.split(r"[.\[]", name)[0]
        if root in tainted:
            return tainted[root]
    for name, origin in tainted.items():
        if re.search(rf"\b{re.escape(name)}\b", fragment):
            return origin
    return None


SINKS: List[Tuple[str, str, Dict[str, Any]]] = [
    ("js.exec-tainted", r"\b(?:child_process\s*\.\s*)?(exec|execSync)\s*\(([^)]{0,300})", {
        "title": "Shell command built from request data",
        "severity": "critical", "confidence": "high", "cwe": ["CWE-78"],
        "owasp": ["A03:2021 Injection"],
        "remediation": "Use execFile()/spawn() with an argument array; neither involves a shell.",
    }),
    ("js.eval-tainted", r"\b(eval|Function)\s*\(([^)]{0,300})", {
        "title": "eval()/Function() on request data",
        "severity": "critical", "confidence": "high", "cwe": ["CWE-95"],
        "owasp": ["A03:2021 Injection"],
        "remediation": "Parse with JSON.parse(); dispatch through an allowlisted object map.",
    }),
    ("js.sql-tainted", r"\.\s*(query|execute|raw)\s*\(([^)]{0,400})", {
        "title": "SQL query built from request data",
        "severity": "critical", "confidence": "high", "cwe": ["CWE-89"],
        "owasp": ["A03:2021 Injection"],
        "remediation": "Use placeholders and pass values as the bindings argument.",
    }),
    ("js.path-tainted", r"\b(?:fs\s*\.\s*)?(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|sendFile|createWriteStream)\s*\(([^)]{0,300})", {
        "title": "Filesystem path built from request data",
        "severity": "high", "confidence": "high", "cwe": ["CWE-22"],
        "owasp": ["A01:2021 Broken Access Control"],
        "remediation": "Resolve the path and verify it stays under the intended root before opening it.",
    }),
    ("js.ssrf-tainted", r"\b(axios|fetch|got|request|superagent|http\s*\.\s*get|https\s*\.\s*get)\s*[.(]([^)]{0,300})", {
        "title": "Outbound request to a URL from the request",
        "severity": "high", "confidence": "medium", "cwe": ["CWE-918"],
        "owasp": ["A10:2021 Server-Side Request Forgery"],
        "remediation": "Allowlist destination hosts and reject private address ranges after DNS resolution.",
    }),
    ("js.redirect-tainted", r"\bres(?:ponse)?\s*\.\s*(redirect)\s*\(([^)]{0,200})", {
        "title": "Redirect target taken from the request",
        "severity": "medium", "confidence": "high", "cwe": ["CWE-601"],
        "owasp": ["A01:2021 Broken Access Control"],
        "remediation": "Allow only relative paths, or match against a fixed list of destinations.",
    }),
]

STATIC_RULES: List[Tuple[str, str, Dict[str, Any]]] = [
    ("js.express-trust-proxy-all", r"app\s*\.\s*set\s*\(\s*['\"]trust proxy['\"]\s*,\s*true", {
        "title": "Express trusts every proxy hop",
        "severity": "medium", "confidence": "high", "cwe": ["CWE-348"],
        "owasp": ["A05:2021 Security Misconfiguration"],
        "description": "With trust proxy set to true, req.ip comes from a client-supplied X-Forwarded-For header, so any rate limit or allowlist keyed on it can be bypassed.",
        "remediation": "Set it to the number of proxies in front of the app, or to their specific addresses.",
    }),
    ("js.helmet-missing-csp", r"helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false", {
        "title": "Helmet configured with CSP disabled",
        "severity": "medium", "confidence": "high", "cwe": ["CWE-1021"],
        "owasp": ["A05:2021 Security Misconfiguration"],
        "description": "Helmet is installed but its most valuable header is switched off.",
        "remediation": "Define a policy rather than disabling it; start in report-only mode if you need to measure breakage.",
    }),
    ("js.jwt-hardcoded-secret", r"(jwt|jsonwebtoken)\s*\.\s*(sign|verify)\s*\([^)]*,\s*['\"][^'\"]{6,}['\"]", {
        "title": "JWT signing secret hardcoded in source",
        "severity": "critical", "confidence": "high", "cwe": ["CWE-798"],
        "owasp": ["A02:2021 Cryptographic Failures"],
        "description": "Anyone with the repository can mint tokens for any user.",
        "remediation": "Load the secret from the environment and rotate the one in source.",
    }),
    ("js.prototype-pollution-sink", r"\b(\w+)\s*\[\s*(\w+)\s*\]\s*\[\s*(\w+)\s*\]\s*=", {
        "title": "Nested dynamic property assignment (prototype pollution shape)",
        "severity": "medium", "confidence": "low", "cwe": ["CWE-1321"],
        "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "description": "If either key comes from input, an attacker can set __proto__ and change behaviour for every object in the process.",
        "remediation": "Reject __proto__, constructor and prototype as keys, or use a Map.",
    }),
    ("js.dynamic-require", r"\brequire\s*\(\s*(?!['\"])[^)]{1,120}\)", {
        "title": "require() with a computed path",
        "severity": "high", "confidence": "medium", "cwe": ["CWE-98"],
        "owasp": ["A03:2021 Injection"],
        "description": "A computed module path can be steered to load unintended code, including from node_modules paths an attacker controls.",
        "remediation": "Map input to a fixed table of modules loaded with literal paths.",
    }),
    ("js.set-timeout-string", r"\bset(?:Timeout|Interval)\s*\(\s*[a-zA-Z_$][\w$]*\s*\+", {
        "title": "setTimeout/setInterval given a built string",
        "severity": "high", "confidence": "medium", "cwe": ["CWE-95"],
        "owasp": ["A03:2021 Injection"],
        "description": "A string argument is compiled like eval().",
        "remediation": "Pass a function reference.",
    }),
    ("js.cookie-no-flags", r"res\s*\.\s*cookie\s*\(\s*[^)]*\)", {
        "title": "Cookie set without httpOnly/secure",
        "severity": "medium", "confidence": "low", "cwe": ["CWE-1004"],
        "owasp": ["A05:2021 Security Misconfiguration"],
        "description": "A cookie without httpOnly is readable by any script that runs on the page.",
        "remediation": "Pass { httpOnly: true, secure: true, sameSite: 'lax' }.",
        "not_pattern": r"httpOnly",
    }),
]


@register
class JavaScriptScanner(Scanner):
    name = "javascript"
    description = "JS/TS analysis over a comment- and string-stripped view, with request taint tracking"
    languages = ("javascript", "typescript", "vue", "svelte")

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        raw = source.read()
        if len(raw) > 800_000:
            return
        clean = strip_noise(raw)
        raw_lines = raw.splitlines()
        clean_lines = clean.splitlines()
        tainted = collect_tainted(clean)
        counts: Dict[str, int] = {}
        from .. import suppress as suppress_mod

        def emit(rule_id: str, meta: Dict[str, Any], line_no: int, description: str, severity: str, confidence: str):
            snippet = raw_lines[line_no - 1] if 0 < line_no <= len(raw_lines) else ""
            if suppress_mod.suppressed_by_source(raw_lines, line_no, rule_id):
                return None
            seen = counts.get(rule_id, 0)
            counts[rule_id] = seen + 1
            if seen >= 15:
                return None
            return self.make_finding(
                rule_id=rule_id,
                title=meta["title"],
                source=source,
                line=line_no,
                snippet=snippet,
                severity=severity,
                confidence=confidence,
                description=description,
                remediation=meta["remediation"],
                cwe=meta.get("cwe", []),
                owasp=meta.get("owasp", []),
                tags=["javascript"],
                scanner=self.name,
                salt="" if seen == 0 else str(seen),
            )

        for rule_id, pattern, meta in SINKS:
            for match in re.finditer(pattern, clean):
                fragment = match.group(0)
                line_no = clean.count("\n", 0, match.start()) + 1
                raw_fragment = _raw_window(raw_lines, line_no)
                origin = taint_in(raw_fragment, tainted)
                if origin is None:
                    continue
                description = (
                    f"A value from `{origin}` reaches `{match.group(1)}` here. "
                    "The binding was traced from its assignment in this file."
                )
                finding = emit(rule_id, meta, line_no, description, meta["severity"], meta["confidence"])
                if finding is not None:
                    yield finding

        for rule_id, pattern, meta in STATIC_RULES:
            negative = meta.get("not_pattern")
            for match in re.finditer(pattern, clean):
                line_no = clean.count("\n", 0, match.start()) + 1
                raw_fragment = _raw_window(raw_lines, line_no, radius=1)
                if negative and re.search(negative, raw_fragment):
                    continue
                finding = emit(rule_id, meta, line_no, meta.get("description", meta["title"]),
                               meta["severity"], meta["confidence"])
                if finding is not None:
                    yield finding


def _raw_window(lines: List[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])
