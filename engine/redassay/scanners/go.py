"""Go taint tracking.

Go's line rules catch a request accessor used directly at a sink. They miss the
common shape where the value is bound to a variable first and reaches the sink
through concatenation or `fmt.Sprintf`:

    id := r.URL.Query().Get("id")
    q := "SELECT * FROM users WHERE id = " + id
    db.Query(q)                       // SQL injection the pattern rules never see

There is no Go parser in the standard library, so this scanner works over a
comment- and string-stripped view with a file-scoped set of variables traced back
to a request source, the same design as the PHP and Ruby scanners. Go has no
string interpolation, so the propagation vectors are `+` concatenation and
`fmt.Sprintf`; the normalizer blanks string bodies (both `"..."` and raw
backtick strings) since a keyword inside one is data, not code.

The discriminator that keeps this quiet is the source: a query built from a
constant or a database value has no request assignment to find and never enters
the taint set. SQL sinks inspect only their first argument, so a value passed as
a bound parameter after a `?`/`$1` placeholder is correctly read as safe.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# --- normalized view ---------------------------------------------------------
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
#: Interpreted and raw (backtick) strings, plus rune literals. Go has no
#: interpolation, so bodies are blanked whole; the delimiters are kept so a sink
#: can still tell a string argument from a bare variable.
_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"' + r"|`[^`]*`" + r"|'(?:\\.|[^'\\])'", re.DOTALL)


def _blank_span(match: re.Match) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _string_blanker(match: re.Match) -> str:
    body = match.group(0)
    quote = body[0]
    return quote + re.sub(r"[^\n]", " ", body[1:-1]) + quote


def strip_noise(text: str) -> str:
    """Blank comments and string bodies, preserving offsets and newlines."""
    text = _BLOCK_COMMENT.sub(_blank_span, text)
    text = _LINE_COMMENT.sub(_blank_span, text)
    text = _STRING.sub(_string_blanker, text)
    return text


# --- sources -----------------------------------------------------------------
#: net/http plus the common routers (gorilla/mux, chi, gin, httprouter). Covers
#: query, form, route, header and cookie inputs.
SOURCE = re.compile(
    r"\br\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)"
    r"|\br\s*\.\s*(?:FormValue|PostFormValue|Form|PostForm|Referer|UserAgent)\b"
    r"|\br\s*\.\s*Header\s*\.\s*Get\b"
    r"|\br\s*\.\s*Cookie\s*\("
    r"|\bmux\s*\.\s*Vars\s*\("
    r"|\bchi\s*\.\s*URLParam\b"
    r"|\bps\s*\.\s*ByName\b"
    r"|\bc\s*\.\s*(?:Query|DefaultQuery|Param|PostForm|GetHeader|Cookie)\s*\("
    r"|\bvars\s*\["
)

#: x := rhs / x = rhs / x, err := rhs. Captures the first bound name. `+=` appends.
ASSIGN = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?P<op>:=|\+=|=)(?!=)\s*(?P<rhs>[^\n]+)"
)

#: Coercions that make a value safe for every sink (parsed to a number).
NUMERIC_CLEAN = re.compile(
    r"\bstrconv\s*\.\s*(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\s*\("
)

#: Category-specific neutralisers.
ESCAPERS: Dict[str, re.Pattern] = {
    "xss": re.compile(
        r"\b(?:template\s*\.\s*HTMLEscapeString|template\s*\.\s*HTMLEscaper"
        r"|html\s*\.\s*EscapeString|template\s*\.\s*JSEscapeString)\s*\("
    ),
    "path": re.compile(r"\bfilepath\s*\.\s*(?:Base|Clean)\s*\("),
    "ssrf": re.compile(r"\burl\s*\.\s*(?:QueryEscape|PathEscape)\s*\("),
    "redirect": re.compile(r"\burl\s*\.\s*(?:QueryEscape|PathEscape)\s*\("),
}

#: Go keywords and builtins that scan as identifiers but never carry taint.
_STOPWORDS = frozenset(
    "func var const return if else for range switch case default go defer chan "
    "map struct interface package import type nil true false break continue "
    "select fallthrough r w c ps vars mux chi fmt".split()
)


def _var_refs(fragment: str) -> Set[str]:
    return {
        m.group(1)
        for m in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)", fragment)
        if m.group(1) not in _STOPWORDS
    }


def _first_arg(fragment: str) -> str:
    """The sink call's first argument, respecting bracket nesting.

    A SQL sink's first argument is the query expression; anything after the first
    *top-level* comma is a bound parameter and safe. A naive comma split breaks on
    `db.Query(fmt.Sprintf("... %s", id))`, whose comma sits inside a nested call -
    that value IS spliced into the query. Tracking bracket depth keeps the nested
    call whole while still cutting real bind parameters at the top level.
    """
    depth = 0
    for i, ch in enumerate(fragment):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return fragment[:i]     # the sink call itself closed
            depth -= 1
        elif ch == "," and depth == 0:
            return fragment[:i]
    return fragment


class Taint:
    """File-scoped taint state for Go variables."""

    def __init__(self) -> None:
        self.origin: Dict[str, str] = {}
        self.cleaned: Dict[str, Set[str]] = {}
        self.assigns: Dict[str, List[Tuple[int, bool, Set[str], Optional[str]]]] = {}

    def _source_in(self, fragment: str) -> Optional[str]:
        return "the request" if SOURCE.search(fragment) else None

    def build(self, text: str) -> None:
        assignments = list(ASSIGN.finditer(text))

        for _ in range(3):                          # fixpoint for b := a chains
            changed = False
            for match in assignments:
                var, rhs = match.group("var"), match.group("rhs")
                if var in self.origin:
                    continue
                source = self._source_in(rhs)
                tainted_ref = source or any(ref in self.origin for ref in _var_refs(rhs))
                if not tainted_ref:
                    continue
                if NUMERIC_CLEAN.search(rhs):
                    continue                        # parsed to a number: safe everywhere
                self.origin[var] = source or next(
                    (self.origin[r] for r in _var_refs(rhs) if r in self.origin), "the request"
                )
                cleaned: Set[str] = {c for c, esc in ESCAPERS.items() if esc.search(rhs)}
                for ref in _var_refs(rhs):
                    cleaned |= self.cleaned.get(ref, set())
                self.cleaned[var] = cleaned
                changed = True
            if not changed:
                break

        for match in assignments:
            var, op, rhs = match.group("var"), match.group("op"), match.group("rhs")
            src = self._source_in(rhs)
            tainted = bool(src) or any(r in self.origin for r in _var_refs(rhs))
            if NUMERIC_CLEAN.search(rhs):
                tainted = False
            cleaned = {c for c, esc in ESCAPERS.items() if esc.search(rhs)}
            for ref in _var_refs(rhs):
                cleaned |= self.cleaned.get(ref, set())
            origin = src or next(
                (self.origin[r] for r in _var_refs(rhs) if r in self.origin), None)
            history = self.assigns.setdefault(var, [])
            if op == "+=" and history:
                prev = history[-1]
                tainted = tainted or prev[1]
                cleaned = cleaned & prev[2] if tainted else cleaned
                origin = origin or prev[3]
            history.append((match.start(), tainted, cleaned, origin))

    def _state_at(self, var: str, pos: Optional[int]) -> Tuple[bool, Set[str], Optional[str]]:
        history = self.assigns.get(var)
        if pos is not None and history:
            prior = [a for a in history if a[0] < pos]
            if prior:
                _, tainted, cleaned, origin = prior[-1]
                return tainted, cleaned, origin or self.origin.get(var, "the request")
        if var in self.origin:
            return True, self.cleaned.get(var, set()), self.origin[var]
        return False, set(), None

    def reaches(self, fragment: str, category: str, pos: Optional[int] = None) -> Optional[str]:
        escaper = ESCAPERS.get(category)
        if escaper and escaper.search(fragment):
            return None
        if NUMERIC_CLEAN.search(fragment):
            return None

        source = self._source_in(fragment)
        if source:
            return source
        for var in _var_refs(fragment):
            tainted, cleaned, origin = self._state_at(var, pos)
            if not tainted or category in cleaned:
                continue
            without_lookup = re.sub(r"\w+\s*\[\s*" + re.escape(var) + r"\s*\]", "", fragment)
            if re.search(r"\b" + re.escape(var) + r"\b", without_lookup):
                return origin
        return None


# --- sinks -------------------------------------------------------------------
# (rule_id, category, pattern capturing the sink argument fragment, meta)
SINKS: List[Tuple[str, str, re.Pattern, Dict[str, Any]]] = [
    # SQL sinks capture only the first argument (stop at the first comma), so a
    # value passed as a bound parameter after a placeholder is read as safe while
    # a concatenated or Sprintf'd query string is not.
    ("go.taint-sql", "sql",
     re.compile(r"\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext)\s*\(\s*(?P<arg>[^;\n]{0,300})"),
     {"title": "SQL query built from request data", "first_arg": True,
      "severity": "critical", "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
      "remediation": "Use parameterised queries with placeholders (db.Query(\"... = $1\", value)); "
                     "never concatenate or Sprintf request data into SQL."}),
    ("go.taint-command", "command",
     re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\(\s*(?P<arg>[^;{\n]{0,240})"),
     {"title": "Command executed with request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never pass request data as the program name or as an argument to a shell "
                     "(sh -c). Use a fixed program with validated, allowlisted arguments."}),
    ("go.taint-file-read", "path",
     re.compile(r"\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|Create|Remove)|ioutil\s*\.\s*(?:ReadFile|WriteFile))\s*\(\s*(?P<arg>[^,;\n)]{0,200})"),
     {"title": "Filesystem path built from request data",
      "severity": "high", "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "filepath.Clean the value and confirm the result stays under the intended "
                     "root, or map the input to an allowlist."}),
    ("go.taint-file-read", "path",
     re.compile(r"\bhttp\s*\.\s*ServeFile\s*\(\s*[^,]*,\s*[^,]*,\s*(?P<arg>[^;\n)]{0,200})"),
     {"title": "File served from a request-controlled path",
      "severity": "high", "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "http.ServeFile rejects paths containing '..' but not absolute or symlinked "
                     "paths; map the input to an allowlist and serve from a fixed root."}),
    ("go.taint-ssrf", "ssrf",
     re.compile(r"\b(?:http|client)\s*\.\s*(?:Get|Post|Head|PostForm)\s*\(\s*(?P<arg>[^,;\n)]{0,200})"),
     {"title": "Outbound request to a request-controlled URL (SSRF)",
      "severity": "high", "cwe": ["CWE-918"], "owasp": ["A10:2021 Server-Side Request Forgery"],
      "remediation": "Validate the URL against an allowlist of hosts and schemes before fetching; "
                     "block internal and link-local addresses."}),
    ("go.taint-ssrf", "ssrf",
     re.compile(r"\bhttp\s*\.\s*NewRequest(?:WithContext)?\s*\(\s*[^,]*,\s*(?P<arg>[^,;\n)]{0,200})"),
     {"title": "Outbound request to a request-controlled URL (SSRF)",
      "severity": "high", "cwe": ["CWE-918"], "owasp": ["A10:2021 Server-Side Request Forgery"],
      "remediation": "Validate the URL against an allowlist of hosts and schemes before fetching."}),
    ("go.taint-open-redirect", "redirect",
     re.compile(r"\bhttp\s*\.\s*Redirect\s*\(\s*[^,]*,\s*[^,]*,\s*(?P<arg>[^,;\n)]{0,200})"),
     {"title": "Open redirect to a request-controlled URL",
      "severity": "medium", "cwe": ["CWE-601"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Redirect only to a relative path or an allowlisted host; reject absolute "
                     "URLs to other origins."}),
    ("go.taint-xss", "xss",
     re.compile(r"\bfmt\s*\.\s*Fpr(?:intf|int|intln)\s*\(\s*w\b(?P<arg>[^;{\n]{0,200})"),
     {"title": "Request data written to the response without escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Render through html/template, which auto-escapes, or template.HTMLEscapeString "
                     "the value before writing it."}),
    ("go.taint-xss", "xss",
     re.compile(r"\b(?:io\s*\.\s*WriteString\s*\(\s*w\b|w\s*\.\s*Write\s*\(\s*\[\s*\]\s*byte\s*\()(?P<arg>[^;{\n]{0,200})"),
     {"title": "Request data written to the response without escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Render through html/template, which auto-escapes, or template.HTMLEscapeString "
                     "the value before writing it."}),
    ("go.taint-xss", "xss",
     re.compile(r"\btemplate\s*\.\s*HTML\s*\(\s*(?P<arg>[^;{\n)]{0,200})"),
     {"title": "Request data cast to template.HTML, bypassing escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never cast request data to template.HTML; pass it as a plain string so the "
                     "template escapes it."}),
]


@register
class GoTaintScanner(Scanner):
    name = "go-taint"
    description = "Go taint tracking over a normalized view: request data through variables to sinks"
    languages = ("go",)

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        raw = source.read()
        if "r." not in raw and "c." not in raw and "vars" not in raw and "mux" not in raw:
            return
        clean = strip_noise(raw)
        raw_lines = raw.splitlines()
        taint = Taint()
        taint.build(clean)
        if not taint.origin and not SOURCE.search(clean):
            return

        from .. import suppress as suppress_mod
        counts: Dict[str, int] = {}

        for rule_id, category, pattern, meta in SINKS:
            for match in pattern.finditer(clean):
                fragment = match.group("arg")
                if meta.get("first_arg"):
                    fragment = _first_arg(fragment)
                origin = taint.reaches(fragment, category, match.start())
                if origin is None:
                    continue
                line_no = clean.count("\n", 0, match.start()) + 1
                if suppress_mod.suppressed_by_source(raw_lines, line_no, rule_id):
                    continue
                seen = counts.get(rule_id, 0)
                counts[rule_id] = seen + 1
                if seen >= 20:
                    continue
                snippet = raw_lines[line_no - 1].strip()[:200] if line_no <= len(raw_lines) else ""
                yield self.make_finding(
                    rule_id=rule_id,
                    title=meta["title"],
                    source=source,
                    line=line_no,
                    snippet=snippet,
                    severity=meta["severity"],
                    confidence="high",
                    description=(
                        f"A value from {origin} reaches this sink. The taint tracker followed it "
                        "from its assignment through this file, so it is a concrete data path "
                        "rather than a pattern match."
                    ),
                    remediation=meta["remediation"],
                    cwe=meta.get("cwe", []),
                    owasp=meta.get("owasp", []),
                    tags=["go", "taint"],
                    scanner=self.name,
                    salt="" if seen == 0 else str(seen),
                )
