"""PHP taint tracking.

PHP's line-oriented pattern rules catch a superglobal used directly at a sink -
`echo $_GET['x']`, `include($_GET['id'])`. They miss the far more common shape
where the value is assigned to a variable first:

    $name = trim($_POST["name"]);
    ...
    echo $name;                       // XSS the pattern rules never see

There is no PHP parser in the standard library, and vendoring one would break the
zero-dependency rule, so this scanner works the way the JavaScript one does: over
a comment- and string-stripped view, with a file-scoped set of variables traced
back to a superglobal. File scope over-approximates, which in PHP's mostly-flat
request scripts is the right trade - the assignment and the sink almost always
share a file.

The discriminator that keeps this quiet is the source itself. `echo $title` is
not flagged unless `$title` was assigned from `$_GET`/`$_POST`/... *in this
file*; a value that came from a database or a constant has no superglobal
assignment to find, so it never enters the taint set.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# --- normalized view ---------------------------------------------------------
_LINE_COMMENT = re.compile(r"(?://|#)[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING = re.compile(r"""(["'])(?:\\.|(?!\1)[^\\\n])*\1""")


_PHP_OPEN = re.compile(r"<\?(?:php|=)?")
_PHP_CLOSE = "?>"


def _php_regions(text: str) -> List[Tuple[int, int]]:
    """Character spans that are actual PHP code, not inline HTML.

    PHP is a template language: everything outside `<?php ... ?>` is literal
    output, where a `"` is an HTML attribute quote, not a string delimiter.
    Treating the whole file as PHP blanks `value="<?php echo $x ?>"` as if the
    attribute were a string and loses the echo inside it - which is exactly the
    most common place request data gets reflected. So only the code regions are
    normalised; the HTML between them is left verbatim.
    """
    regions: List[Tuple[int, int]] = []
    pos = 0
    n = len(text)
    while pos < n:
        opener = _PHP_OPEN.search(text, pos)
        if not opener:
            break
        start = opener.end()
        close = text.find(_PHP_CLOSE, start)
        end = close if close != -1 else n
        regions.append((start, end))
        pos = end + len(_PHP_CLOSE) if close != -1 else n
    return regions


def _blank_span(match: re.Match) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _string_blanker(segment: str):
    """Blank string bodies, but keep short array-subscript keys.

    `$_SERVER["HTTP_REFERER"]` needs its key to tell a request-derived server
    variable from a safe one, and `$_GET["id"]` keys are harmless to keep. A SQL
    or HTML string literal, by contrast, must be blanked so a sink keyword inside
    it is not matched. The discriminator is the character before the quote: a `[`
    means this is a subscript key.
    """
    def replace(match: re.Match) -> str:
        start = match.start()
        prev = segment[:start].rstrip()
        body = match.group(0)
        if prev.endswith("[") and len(body) <= 40:
            return body
        quote = match.group(1)
        return quote + " " * (len(body) - 2) + quote
    return replace


def strip_noise(text: str) -> str:
    """Blank comments and string bodies inside PHP code only, preserving offsets.

    HTML regions pass through untouched, so a `<?= $x ?>` or `<?php echo $x ?>`
    embedded in markup keeps its sink visible while the surrounding attribute
    quotes are not mistaken for string delimiters.
    """
    regions = _php_regions(text)
    if not regions:
        # No PHP tags at all: nothing to strip, and treating HTML as PHP would
        # blank attribute quotes. Leave it.
        return text
    out = list(text)
    for start, end in regions:
        segment = text[start:end]
        segment = _BLOCK_COMMENT.sub(_blank_span, segment)
        segment = _LINE_COMMENT.sub(_blank_span, segment)
        segment = _STRING.sub(_string_blanker(segment), segment)
        out[start:end] = segment
    return "".join(out)


# --- sources -----------------------------------------------------------------
SUPERGLOBAL = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b")
#: $_SERVER carries some attacker-controlled keys and many that are not; only the
#: request-derived ones are a source.
SERVER_TAINTED = re.compile(
    r"\$_SERVER\s*\[\s*['\"](HTTP_[A-Z_]+|REQUEST_URI|QUERY_STRING|PATH_INFO|"
    r"PHP_SELF|HTTP_REFERER|HTTP_USER_AGENT|HTTP_HOST|HTTP_X_FORWARDED_FOR)['\"]"
)
RAW_INPUT = re.compile(r"php://input|file_get_contents\s*\(\s*['\"]php://input")

#: $name = <rhs>  — capture the variable, the operator, and the right-hand side.
#: The operator matters: `.=` appends (taint carries), `=` overwrites (a constant
#: right-hand side *kills* any earlier taint on the variable).
ASSIGN = re.compile(r"\$(?P<var>[A-Za-z_]\w*)\s*(?P<op>\.=|=)\s*(?P<rhs>[^;{}]+)")

#: Functions that fully neutralise a value for every sink (a number is safe
#: everywhere). If one wraps the source, the variable is not tainted at all.
NUMERIC_CLEAN = re.compile(
    r"\b(intval|floatval|absint|abs|count|sizeof|strlen|boolval)\s*\(|\((int|integer|float|double|bool|boolean)\)"
)

#: Category-specific escapers. A value cleaned for one category is still tainted
#: for the others (htmlspecialchars stops XSS, not SQL injection).
ESCAPERS: Dict[str, re.Pattern] = {
    # Native PHP escapers plus the framework ones that dominate real code -
    # WordPress `esc_*`/`sanitize_*`/`wp_kses`, Laravel's `e()`. Without these a
    # scan of any CMS is a wall of false positives on correctly-escaped output.
    "xss": re.compile(
        r"\b(htmlspecialchars|htmlentities|strip_tags|urlencode|rawurlencode|json_encode"
        r"|esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|esc_html__|esc_html_e"
        r"|esc_attr__|esc_attr_e|sanitize_text_field|sanitize_email|sanitize_key"
        r"|sanitize_file_name|wp_kses|wp_kses_post|wp_kses_data|tag_escape"
        r"|filter_var|htmlspecialchars_decode|number_format)\s*\("
        r"|\be\s*\("                     # Laravel blade escaper
    ),
    "sql": re.compile(r"\b(\w*real_escape_string|pg_escape_\w+|quote|esc_sql|prepare)\s*\(|->prepare\s*\("),
    "command": re.compile(r"\b(escapeshellarg|escapeshellcmd)\s*\("),
    "path": re.compile(r"\b(basename|sanitize_file_name)\s*\("),
}


def _var_refs(fragment: str) -> Set[str]:
    return set(re.findall(r"\$([A-Za-z_]\w*)", fragment))


class Taint:
    """File-scoped taint state: which variables reach back to a source, and what
    they have been cleaned for on the way."""

    def __init__(self) -> None:
        self.origin: Dict[str, str] = {}
        self.cleaned: Dict[str, Set[str]] = {}
        #: Per variable, the ordered assignments seen in the file as
        #: (position, is_tainted, cleaned_categories, origin). Lets a sink ask
        #: "what was written to this variable *last, before me*" instead of
        #: trusting the whole-file taint set - so a reassignment to a constant
        #: kills earlier taint, the way it does at runtime.
        self.assigns: Dict[str, List[Tuple[int, bool, Set[str], Optional[str]]]] = {}

    def _source_in(self, fragment: str) -> Optional[str]:
        match = SUPERGLOBAL.search(fragment)
        if match:
            if match.group(1) == "FILES":
                # Only the client-supplied filename and MIME type are attacker
                # controlled. tmp_name is the server's temp path, and size/error
                # are set by PHP - reading those is not a taint source.
                safe_only = re.search(
                    r"\$_FILES\s*\[[^\]]*\]\s*\[\s*['\"](tmp_name|size|error)['\"]", fragment)
                controlled = re.search(
                    r"\$_FILES\s*\[[^\]]*\]\s*\[\s*['\"](name|type)['\"]", fragment)
                if safe_only and not controlled:
                    return None
            return f"$_{match.group(1)}"
        if SERVER_TAINTED.search(fragment):
            return "$_SERVER"
        if RAW_INPUT.search(fragment):
            return "php://input"
        return None

    def build(self, text: str) -> None:
        """Two passes plus propagation: direct source assignments, then variables
        assigned from already-tainted variables."""
        assignments = list(ASSIGN.finditer(text))

        for _ in range(3):                          # small fixpoint for $b = $a chains
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
                    continue                        # coerced to a number: safe everywhere
                self.origin[var] = source or next(
                    (self.origin[r] for r in _var_refs(rhs) if r in self.origin), "$_REQUEST"
                )
                cleaned: Set[str] = set()
                for category, escaper in ESCAPERS.items():
                    if escaper.search(rhs):
                        cleaned.add(category)
                # A value carries forward the cleaning applied to the tainted
                # variable it was built from - `$p = realpath(... . $safe)` keeps
                # the path-cleaning that `$safe = basename(...)` established.
                for ref in _var_refs(rhs):
                    cleaned |= self.cleaned.get(ref, set())
                self.cleaned[var] = cleaned
                changed = True
            if not changed:
                break

        # Second pass, now that origin/cleaned have converged: record each
        # assignment in source order with whether it (re)taints the variable.
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
            if op == ".=" and history:
                # Append: taint only grows, and the prior origin is kept when the
                # appended fragment is itself clean.
                prev = history[-1]
                tainted = tainted or prev[1]
                cleaned = cleaned & prev[2] if tainted else cleaned
                origin = origin or prev[3]
            history.append((match.start(), tainted, cleaned, origin))

    def _state_at(self, var: str, pos: Optional[int]) -> Tuple[bool, Set[str], Optional[str]]:
        """Taint state of `var` as of source position `pos`: the nearest earlier
        assignment wins, so a reassignment to a constant reads as clean at a sink
        below it. With no position, or no assignment before the sink, fall back to
        the whole-file set (the original flow-insensitive behaviour)."""
        history = self.assigns.get(var)
        if pos is not None and history:
            prior = [a for a in history if a[0] < pos]
            if prior:
                _, tainted, cleaned, origin = prior[-1]
                return tainted, cleaned, origin or self.origin.get(var, "$_REQUEST")
        if var in self.origin:
            return True, self.cleaned.get(var, set()), self.origin[var]
        return False, set(), None

    def reaches(self, fragment: str, category: str, pos: Optional[int] = None) -> Optional[str]:
        """The origin of a tainted, not-yet-cleaned-for-`category` value in this
        fragment, or None. `pos` is the sink's position in the file, used to
        respect a later reassignment that clears the variable."""
        # A category escaper wrapping the sink expression itself neutralises it.
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
            # `$allow[$var]` is a lookup keyed by the tainted value, and the
            # result is whatever the allowlist holds - not the input. If every
            # occurrence of the variable is such a subscript, it does not reach
            # the sink directly.
            without_lookup = re.sub(r"\$\w+\s*\[\s*\$" + re.escape(var) + r"\s*\]", "", fragment)
            if re.search(r"\$" + re.escape(var) + r"\b", without_lookup):
                return origin
        return None


# --- sinks -------------------------------------------------------------------
# (rule_id, category, pattern that captures the sink argument fragment, meta)
SINKS: List[Tuple[str, str, re.Pattern, Dict[str, Any]]] = [
    ("php.taint-file-inclusion", "path",
     re.compile(r"\b(?:include|require)(?:_once)?\s*\(?\s*(?P<arg>[^;)]{0,200})"),
     {"title": "File included from request data",
      "severity": "critical", "cwe": ["CWE-98"], "owasp": ["A03:2021 Injection"],
      "remediation": "Map the input to a fixed allowlist of files and include only the "
                     "mapped constant. A blocklist regex is not sufficient."}),
    ("php.taint-command", "command",
     re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(?P<arg>[^;)]{0,200})"),
     {"title": "Shell command built from request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Avoid the shell. If unavoidable, escapeshellarg() every interpolated value."}),
    ("php.taint-eval", "xss",
     re.compile(r"\b(?:eval|assert|create_function)\s*\(\s*(?P<arg>[^;)]{0,200})"),
     {"title": "eval() on request data",
      "severity": "critical", "cwe": ["CWE-95"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never eval input. Parse it as data."}),
    ("php.taint-sql", "sql",
     re.compile(r"\b(?:mysqli?_query|->\s*query|->\s*exec|pg_query)\s*\(\s*(?P<arg>[^;)]{0,240})"),
     {"title": "SQL query built from request data",
      "severity": "critical", "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
      "remediation": "Use prepared statements with bound parameters."}),
    ("php.taint-unserialize", "xss",
     re.compile(r"\bunserialize\s*\(\s*(?P<arg>[^;)]{0,200})"),
     {"title": "unserialize() on request data",
      "severity": "high", "cwe": ["CWE-502"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
      "remediation": "Use json_decode(). If unavoidable, pass ['allowed_classes' => false]."}),
    ("php.taint-file-read", "path",
     re.compile(r"\b(?:file_get_contents|readfile|fopen|file|unlink|fpassthru)\s*\(\s*(?P<arg>[^;)]{0,200})"),
     {"title": "Filesystem path built from request data",
      "severity": "high", "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Resolve with realpath() and assert the result stays under the intended root."}),
    ("php.taint-header", "xss",
     re.compile(r"\bheader\s*\(\s*(?P<arg>[^;)]{0,200})"),
     {"title": "HTTP header built from request data",
      "severity": "medium", "cwe": ["CWE-113"], "owasp": ["A03:2021 Injection"],
      "remediation": "Validate the value; for a redirect, allow only relative paths or an allowlist."}),
    ("php.taint-xss", "xss",
     re.compile(r"(?:\becho\b|\bprint\b|\bprintf\b|<\?=)\s*(?P<arg>[^;?]{0,200})"),
     {"title": "Request data echoed without escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Wrap output with htmlspecialchars($v, ENT_QUOTES, 'UTF-8')."}),
    # A tainted destination path is arbitrary file write - a dropped webshell, an
    # overwritten config, or traversal out of the intended directory. Both
    # arguments of copy/rename/move_uploaded_file/link/symlink are paths, so any
    # taint in the call is a path issue; file_put_contents/fputs/fwrite take the
    # path first and the content second, so only the first argument is matched -
    # user data written to a *fixed* log file is not this bug. Category "path"
    # means a basename()/realpath()'d destination is treated as cleaned, the same
    # way the read sink treats it.
    ("php.taint-file-write", "path",
     re.compile(r"\b(?:copy|rename|move_uploaded_file|link|symlink)\s*\(\s*(?P<arg>[^;)]{0,240})"),
     {"title": "File written to a path built from request data",
      "severity": "high", "cwe": ["CWE-22", "CWE-73"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Generate the destination name server-side; never build a write path from the "
                     "client filename. basename() the value and confirm the resolved path stays "
                     "under the intended directory."}),
    ("php.taint-file-write", "path",
     re.compile(r"\b(?:file_put_contents|fputs|fwrite)\s*\(\s*(?P<arg>[^,;)]{0,200})"),
     {"title": "File written to a path built from request data",
      "severity": "high", "cwe": ["CWE-22", "CWE-73"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Generate the destination name server-side; never build a write path from the "
                     "client filename. basename() the value and confirm the resolved path stays "
                     "under the intended directory."}),
    # A tainted callable is arbitrary code execution - the function-pointer
    # analogue of eval(). Category "command" so no XSS/path/SQL escaper is
    # mistaken for neutralising it; only an allowlist can.
    ("php.taint-callable", "command",
     re.compile(r"\b(?:call_user_func|call_user_func_array)\s*\(\s*(?P<arg>[^,;)]{0,120})"),
     {"title": "Function called by a name from request data",
      "severity": "high", "cwe": ["CWE-94"], "owasp": ["A03:2021 Injection"],
      "remediation": "Map the input to an allowlist of permitted callables; never call a function "
                     "whose name comes from the request."}),
    ("php.taint-callable", "command",
     re.compile(r"(?P<arg>\$[A-Za-z_]\w*)\s*\("),
     {"title": "Variable function called with a name from request data",
      "severity": "high", "cwe": ["CWE-94"], "owasp": ["A03:2021 Injection"],
      "remediation": "Map the input to an allowlist of permitted callables; never call a function "
                     "whose name comes from the request."}),
]

_LABEL = {"$_GET": "$_GET", "$_POST": "$_POST", "$_REQUEST": "$_REQUEST",
          "$_COOKIE": "$_COOKIE", "$_FILES": "$_FILES", "$_SERVER": "$_SERVER",
          "php://input": "the request body"}


@register
class PhpTaintScanner(Scanner):
    name = "php-taint"
    description = "PHP taint tracking over a normalized view: request data through variables to sinks"
    languages = ("php",)

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        raw = source.read()
        if "$_" not in raw and "php://input" not in raw:
            return
        clean = strip_noise(raw)
        raw_lines = raw.splitlines()
        taint = Taint()
        taint.build(clean)
        if not taint.origin and not SUPERGLOBAL.search(clean) and not SERVER_TAINTED.search(clean):
            return

        from .. import suppress as suppress_mod
        counts: Dict[str, int] = {}

        for rule_id, category, pattern, meta in SINKS:
            for match in pattern.finditer(clean):
                fragment = match.group("arg")
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
                        f"A value from {_LABEL.get(origin, origin)} reaches this sink. The taint "
                        "tracker followed it from its assignment through this file, so it is a "
                        "concrete data path rather than a pattern match."
                    ),
                    remediation=meta["remediation"],
                    cwe=meta.get("cwe", []),
                    owasp=meta.get("owasp", []),
                    tags=["php", "taint"],
                    scanner=self.name,
                    salt="" if seen == 0 else str(seen),
                )
