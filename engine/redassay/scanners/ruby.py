"""Ruby taint tracking.

Ruby's line rules catch a request accessor used directly at a sink -
`system(params[:cmd])`, `redirect_to(params[:url])`. They miss the common shape
where the value lands in a variable first, and reaches the sink through string
interpolation:

    name = params[:name]
    ...
    User.where("name = '#{name}'")     # SQL injection the pattern rules never see

There is no Ruby parser in the standard library, so this scanner works the way
the PHP and JavaScript ones do: over a comment- and string-stripped view, with a
file-scoped set of locals traced back to a request source. The propagation
vector that matters in Ruby is string interpolation, so the normalizer blanks the
literal text of a `"..."`/backtick string but keeps its `#{...}` interpolations -
the only part that can carry request data.

The discriminator that keeps this quiet is the source: `puts name` is not flagged
unless `name` was assigned from `params`/`cookies`/`request.*` *in this file*. A
value coming from the database or a constant has no source assignment to find and
never enters the taint set.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# --- normalized view ---------------------------------------------------------
_LINE_COMMENT = re.compile(r"#(?!\{)[^\n]*")
_BLOCK_COMMENT = re.compile(r"^=begin\b.*?^=end\b", re.DOTALL | re.MULTILINE)
#: A quoted or backtick string. Interpolation `#{...}` is kept; only the literal
#: text around it is blanked, since that is where a sink keyword or a stray
#: `params[` in prose would otherwise be mistaken for code.
_STRING = re.compile(r"""(["'`])(?:\\.|(?!\1)[^\\])*\1""", re.DOTALL)
_INTERP = re.compile(r"#\{[^}]*\}")


def _blank_span(match: re.Match) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _string_blanker(match: re.Match) -> str:
    """Blank a string body but keep the `#{...}` interpolations verbatim.

    A single-quoted string has no interpolation, so it is blanked whole. A
    double-quoted or backtick string keeps its interpolations - they are the only
    place request data can be spliced in - while the surrounding literal text
    (which may contain SQL keywords, or the word "params") is blanked.
    """
    body = match.group(0)
    quote = match.group(1)
    inner = body[1:-1]
    if quote == "'":
        return quote + " " * len(inner) + quote

    def keep(m: re.Match) -> str:
        return m.group(0)

    out = []
    last = 0
    for interp in _INTERP.finditer(inner):
        out.append(re.sub(r"[^\n]", " ", inner[last:interp.start()]))
        out.append(interp.group(0))
        last = interp.end()
    out.append(re.sub(r"[^\n]", " ", inner[last:]))
    return quote + "".join(out) + quote


def strip_noise(text: str) -> str:
    """Blank comments and string literal bodies, preserving offsets and newlines.

    Strings are blanked first (keeping interpolations) so that a `#` inside a
    string is not seen by the comment pass, and a `#{...}` is never mistaken for
    the start of a comment.
    """
    text = _BLOCK_COMMENT.sub(_blank_span, text)
    text = _STRING.sub(_string_blanker, text)
    text = _LINE_COMMENT.sub(_blank_span, text)
    return text


# --- sources -----------------------------------------------------------------
#: Rack/Rails/Sinatra request accessors. `params` covers query, form and route
#: parameters; `request.*` and `cookies` cover the rest of the untrusted surface.
SOURCE = re.compile(
    r"\bparams\s*[\[.]"
    r"|\bcookies\s*\["
    r"|\brequest\s*\.\s*(?:params|GET|POST|query_parameters|request_parameters|"
    r"body|raw_post|query_string|referer|referrer|user_agent|fullpath|"
    r"original_url|original_fullpath|env|headers)\b"
)

#: local = <rhs>. `||=` / `+=` etc. all end in `=`; the operator tells an append
#: (`<<`, `+=`) from an overwrite. Only simple locals (lowercase/underscore lead).
ASSIGN = re.compile(
    r"(?P<var>[a-z_]\w*)\s*(?P<op>\|\|=|\+=|<<=|=)\s*(?P<rhs>[^\n]+)"
)

#: Coercions that make a value safe for every sink.
NUMERIC_CLEAN = re.compile(r"\.to_i\b|\.to_f\b|\bInteger\s*\(|\bFloat\s*\(")

#: Category-specific neutralisers. Cleaned for one category, still tainted for the
#: rest (html_escape stops XSS, not SQL injection).
ESCAPERS: Dict[str, re.Pattern] = {
    "xss": re.compile(
        r"\b(?:ERB::Util\.html_escape|CGI\.escapeHTML|CGI\.escape_html|html_escape"
        r"|escape_html|sanitize|strip_tags|h)\s*\(|\bERB::Util\.h\b"
    ),
    "sql": re.compile(
        r"\b(?:sanitize_sql\w*|quote|quote_column_name|quote_table_name)\s*\("
        r"|connection\.quote|ActiveRecord::Base\.sanitize"
    ),
    "command": re.compile(r"\bShellwords\.(?:escape|split|join)\s*\(|\bShellwords\.shellescape\b"),
    "path": re.compile(r"\bFile\.basename\s*\("),
    "redirect": re.compile(r"\bURI\.(?:parse|join)\s*\("),
}

#: Ruby keywords and common receivers that scan as lowercase identifiers but are
#: never taint-carrying locals. Membership in the taint set already filters these,
#: but excluding them keeps `_var_refs` honest for the lookup-skip heuristic.
_STOPWORDS = frozenset(
    "if elsif else end do then unless while until for in return yield begin rescue "
    "ensure raise def class module self nil true false and or not params request "
    "cookies session response".split()
)


def _var_refs(fragment: str) -> Set[str]:
    # Locals only: skip symbols (`:id`), method calls (`.foo`) and hash keys.
    return {
        m.group(1)
        for m in re.finditer(r"(?<![:.\w])([a-z_]\w*)", fragment)
        if m.group(1) not in _STOPWORDS
    }


class Taint:
    """File-scoped taint state: which locals reach back to a request source, and
    what they have been cleaned for on the way."""

    def __init__(self) -> None:
        self.origin: Dict[str, str] = {}
        self.cleaned: Dict[str, Set[str]] = {}
        self.assigns: Dict[str, List[Tuple[int, bool, Set[str], Optional[str]]]] = {}

    def _source_in(self, fragment: str) -> Optional[str]:
        match = SOURCE.search(fragment)
        if not match:
            return None
        text = match.group(0)
        if text.startswith("params"):
            return "params"
        if text.startswith("cookies"):
            return "cookies"
        return "request"

    def build(self, text: str) -> None:
        assignments = list(ASSIGN.finditer(text))

        for _ in range(3):                          # fixpoint for b = a chains
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
                    (self.origin[r] for r in _var_refs(rhs) if r in self.origin), "params"
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
            if op in ("<<=", "+=") and history:
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
                return tainted, cleaned, origin or self.origin.get(var, "params")
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
#: A SQL sink is only an injection when request data is spliced into a *string*
#: - `where("... #{x}")` or `order("..." + x)`. A hash condition `where(id: x)`
#: is parameterised and safe; after stripping it carries no quote character, so
#: requiring one in the fragment tells the two apart.
_SQL_STRINGY = re.compile(r'["\'`]')

# (rule_id, category, pattern capturing the sink argument fragment, meta)
SINKS: List[Tuple[str, str, re.Pattern, Dict[str, Any]]] = [
    ("ruby.taint-command", "command",
     re.compile(r"\b(?:system|exec|spawn)\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Shell command built from request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Pass the command and its arguments as an array so no shell is invoked, "
                     "or Shellwords.escape every interpolated value."}),
    ("ruby.taint-command", "command",
     re.compile(r"(?:Open3\.(?:capture2e?|capture3|popen3|popen2)|IO\.popen|Process\.spawn)\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Shell command built from request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Pass the command as an array of arguments; never interpolate request data "
                     "into a shell string."}),
    ("ruby.taint-command", "command",
     re.compile(r"`(?P<arg>[^`\n]{0,200})`"),
     {"title": "Command executed in backticks from request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Avoid backtick execution on request data. Use an argument array with no shell."}),
    ("ruby.taint-command", "command",
     re.compile(r"%x[\({\[](?P<arg>[^\n)}\]]{0,200})"),
     {"title": "Command executed via %x() from request data",
      "severity": "critical", "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
      "remediation": "Avoid %x execution on request data. Use an argument array with no shell."}),
    ("ruby.taint-eval", "command",
     re.compile(r"\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "eval on request data",
      "severity": "critical", "cwe": ["CWE-95"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never eval request input. Parse it as data."}),
    # ERB.new(tainted).result(binding) is server-side template injection - the
    # template body is Ruby, so request data spliced into it runs as code (RCE).
    # `render inline:` in Rails is the same hazard. Category "command" so only an
    # allowlist, never an HTML escaper, is treated as neutralising it.
    ("ruby.taint-template-injection", "command",
     re.compile(r"\b(?:ERB|Erubi::Engine|Erubis::\w+|Liquid::Template)\s*\.\s*(?:new|parse)\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Template compiled from request data (SSTI)",
      "severity": "critical", "cwe": ["CWE-94", "CWE-1336"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never build a template from request data. Treat the input as a value passed "
                     "to a fixed template, not as template source."}),
    ("ruby.taint-template-injection", "command",
     re.compile(r"\brender\s+(?:inline|body):\s*(?P<arg>[^\n]{0,160})"),
     {"title": "Inline template rendered from request data (SSTI)",
      "severity": "critical", "cwe": ["CWE-94", "CWE-1336"], "owasp": ["A03:2021 Injection"],
      "remediation": "Render a fixed template and pass the input as a local; never render request "
                     "data as inline template source."}),
    ("ruby.taint-sql", "sql",
     re.compile(r"\.(?:where|having|order|group|find_by_sql|select_all|select_values|"
                r"exists\?|update_all|delete_all|pluck|calculate|from|lock)\s*\(\s*(?P<arg>[^,\n)]{0,240})"),
     {"title": "SQL fragment built from request data", "guard": _SQL_STRINGY,
      "severity": "critical", "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
      "remediation": "Use a parameterised condition, e.g. where(\"name = ?\", value), or a hash "
                     "condition. Never interpolate request data into a SQL string."}),
    ("ruby.taint-sql", "sql",
     re.compile(r"connection\s*\.\s*(?:execute|exec_query|select_all|select_value|select_rows)\s*\(\s*(?P<arg>[^,\n)]{0,240})"),
     {"title": "Raw SQL executed with request data", "guard": _SQL_STRINGY,
      "severity": "critical", "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
      "remediation": "Use exec_query with bind parameters; never interpolate request data into SQL."}),
    ("ruby.taint-deserialize", "deser",
     re.compile(r"\b(?:Marshal\.load|Oj\.load|Psych\.load)\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Unsafe deserialization of request data",
      "severity": "high", "cwe": ["CWE-502"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
      "remediation": "Use JSON.parse for untrusted data. For YAML use YAML.safe_load with an "
                     "allowlist of permitted classes."}),
    ("ruby.taint-deserialize", "deser",
     re.compile(r"\bYAML\.load\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Unsafe YAML.load of request data",
      "severity": "high", "cwe": ["CWE-502"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
      "remediation": "Use YAML.safe_load with an allowlist of permitted classes, or JSON.parse."}),
    ("ruby.taint-code-load", "command",
     re.compile(r"\b(?:constantize|const_get|classify)\b(?P<arg>[^\n]{0,120})"),
     {"title": "Class or constant resolved from request data",
      "severity": "high", "cwe": ["CWE-470"], "owasp": ["A03:2021 Injection"],
      "remediation": "Map the input to an allowlist of permitted class names; never constantize "
                     "request data directly."}),
    ("ruby.taint-open-redirect", "redirect",
     re.compile(r"\bredirect_to\s*\(?\s*(?P<arg>[^\n)]{0,160})"),
     {"title": "Open redirect to a request-controlled URL",
      "severity": "medium", "cwe": ["CWE-601"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Redirect only to a relative path or an allowlisted host; pass allow_other_host: "
                     "false and validate the target."}),
    ("ruby.taint-file-read", "path",
     re.compile(r"\b(?:File|IO)\.(?:read|open|new|readlines|binread|foreach)\s*\(\s*(?P<arg>[^,\n)]{0,200})"),
     {"title": "Filesystem path built from request data",
      "severity": "high", "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Resolve with File.expand_path and assert the result stays under the intended "
                     "root; File.basename the value first."}),
    ("ruby.taint-file-read", "path",
     re.compile(r"\bsend_file\s*\(\s*(?P<arg>[^,\n)]{0,200})"),
     {"title": "File served from a request-controlled path",
      "severity": "high", "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
      "remediation": "Map the input to an allowlist; never build a send_file path from request data."}),
    ("ruby.taint-xss", "xss",
     re.compile(r"\braw\s*\(\s*(?P<arg>[^\n)]{0,200})"),
     {"title": "Request data rendered without escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Do not call raw() on request data; let the template auto-escape it, or "
                     "sanitize() first."}),
    ("ruby.taint-xss", "xss",
     re.compile(r"(?P<arg>[\w.\[\]:'\"]+)\.html_safe\b"),
     {"title": "Request data marked html_safe without escaping",
      "severity": "high", "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
      "remediation": "Never call html_safe on request data. Escape it, or rely on template "
                     "auto-escaping."}),
]

_LABEL = {"params": "params", "cookies": "cookies", "request": "the request object"}


@register
class RubyTaintScanner(Scanner):
    name = "ruby-taint"
    description = "Ruby taint tracking over a normalized view: request data through variables to sinks"
    languages = ("ruby",)

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        raw = source.read()
        if "params" not in raw and "request" not in raw and "cookies" not in raw:
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
                guard = meta.get("guard")
                if guard and not guard.search(fragment):
                    continue
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
                    tags=["ruby", "taint"],
                    scanner=self.name,
                    salt="" if seen == 0 else str(seen),
                )
