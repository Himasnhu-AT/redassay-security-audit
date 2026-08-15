"""The rule-pack scanner.

This is where most findings come from. It is line-oriented regex matching with
three refinements that take it from "grep with extra steps" to something whose
output a reviewer will actually read:

* **negative patterns** - `not_pattern` kills the match on the same line, which
  is how `subprocess.run(x, shell=True)` fires but `subprocess.run([...])` does not.
* **proximity requirements** - `nearby` demands a second pattern within N lines.
  A string concatenation is only an SQL injection if something SQL-shaped is in
  the neighbourhood; this is a cheap stand-in for taint tracking and it removes
  most of the noise that makes regex SAST unusable.
* **comment awareness** - a rule only fires inside a comment if it says so.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .. import languages as lang_mod
from .. import rules as rule_packs
from .. import suppress
from ..prefilter import Prefilter
from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

MAX_MATCHES_PER_RULE_PER_FILE = 25
DEFAULT_NEARBY_WINDOW = 4


class CompiledRule:
    __slots__ = (
        "raw", "id", "title", "severity", "confidence", "description", "remediation",
        "cwe", "owasp", "tags", "references", "languages", "pattern", "not_pattern",
        "nearby", "nearby_window", "nearby_absent", "path_include", "path_exclude",
        "match_comments", "pack", "max_matches", "skip_in_strings", "prefilter",
    )

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.id = raw["id"]
        self.title = raw["title"]
        self.severity = raw.get("severity", "medium")
        self.confidence = raw.get("confidence", "medium")
        self.description = raw.get("description", "")
        self.remediation = raw.get("remediation", "")
        self.cwe = raw.get("cwe") or []
        self.owasp = raw.get("owasp") or []
        self.tags = raw.get("tags") or []
        self.references = raw.get("references") or []
        self.languages = raw.get("languages") or []
        self.pack = raw.get("pack", "")
        self.match_comments = bool(raw.get("match_comments", False))
        self.skip_in_strings = bool(raw.get("skip_in_strings", False))
        self.max_matches = int(raw.get("max_matches", MAX_MATCHES_PER_RULE_PER_FILE))
        flags = re.IGNORECASE if raw.get("ignore_case") else 0
        self.pattern = re.compile(raw["pattern"], flags)
        self.not_pattern = re.compile(raw["not_pattern"], flags) if raw.get("not_pattern") else None
        self.nearby = re.compile(raw["nearby"], flags) if raw.get("nearby") else None
        self.nearby_absent = re.compile(raw["nearby_absent"], flags) if raw.get("nearby_absent") else None
        self.nearby_window = int(raw.get("nearby_window", DEFAULT_NEARBY_WINDOW))
        self.path_include = raw.get("path_include") or []
        self.prefilter = Prefilter(raw["pattern"], ignore_case=bool(raw.get("ignore_case")))
        self.path_exclude = raw.get("path_exclude") or []

    def applies_to_path(self, path: str) -> bool:
        if self.path_include and not any(fnmatch.fnmatch(path, g) for g in self.path_include):
            return False
        if any(fnmatch.fnmatch(path, g) for g in self.path_exclude):
            return False
        return True

    def applies_to_language(self, language: Optional[str]) -> bool:
        if not self.languages or "*" in self.languages:
            return True
        return language in self.languages


def compile_rules(raw_rules: Iterable[Dict[str, Any]]) -> List[CompiledRule]:
    compiled = []
    for raw in raw_rules:
        try:
            compiled.append(CompiledRule(raw))
        except re.error as exc:
            raise rule_packs.RuleError(f"rule {raw.get('id')}: bad regex - {exc}") from exc
    return compiled


_STRING_SPAN = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")


def string_spans(line: str) -> List[Tuple[int, int]]:
    """Character ranges occupied by string literals on one line.

    Used by rules that must not fire on their own example text. A rule pack that
    documents an eval call in a description, or a test asserting on a snippet, is
    not a vulnerability - and those two cases account for most of the noise a
    code-execution rule produces inside a security codebase.
    """
    return [(m.start(), m.end()) for m in _STRING_SPAN.finditer(line)]


def inside_string(spans: Sequence[Tuple[int, int]], index: int) -> bool:
    return any(start < index < end - 1 for start, end in spans)


MARKUP_LANGUAGES = {"html", "markdown", "vue", "svelte", "xml"}
_SAMPLE_OPEN = re.compile(r"<(pre|code|samp|xmp)\b", re.IGNORECASE)
_SAMPLE_CLOSE = re.compile(r"</(pre|code|samp|xmp)\s*>", re.IGNORECASE)
_FENCE = re.compile(r"^\s*(```|~~~)")


def sample_block_lines(lines: Sequence[str], language: Optional[str]) -> set:
    """Line numbers (1-indexed) inside a documentation sample.

    A tutorial page that *documents* `eval(req.body.x)` inside a <pre> block is
    not a vulnerable application - it is a description of one. Real projects hit
    this constantly (security training material, framework docs, changelogs), and
    reporting it makes every finding in the file suspect.
    """
    if language not in MARKUP_LANGUAGES:
        return set()
    inside: set = set()
    depth = 0
    fenced = False
    for index, line in enumerate(lines, start=1):
        if language == "markdown" and _FENCE.match(line):
            fenced = not fenced
            inside.add(index)
            continue
        if fenced:
            inside.add(index)
            continue
        opens = len(_SAMPLE_OPEN.findall(line))
        closes = len(_SAMPLE_CLOSE.findall(line))
        if depth > 0 or opens:
            inside.add(index)
        depth = max(0, depth + opens - closes)
    return inside


_TRIPLE = re.compile(r"(\"\"\"|''')")


def heredoc_lines(lines: Sequence[str], language: Optional[str]) -> set:
    """Line numbers inside a multi-line string literal.

    Python docstrings and test fixtures routinely quote vulnerable code as data:
    a module-level VULNERABLE = <triple-quoted block> containing an f-string SQL
    query is a fixture, not a call. `skip_in_strings` already handles the
    single-line case; this extends it across the block, which is what stops this
    tool from reporting its own test suite.
    """
    if language not in {"python", "ruby"}:
        return set()
    inside: set = set()
    delimiter: Optional[str] = None
    for index, line in enumerate(lines, start=1):
        position = 0
        opened_here = delimiter is not None
        while True:
            match = _TRIPLE.search(line, position)
            if match is None:
                break
            token = match.group(1)
            if delimiter is None:
                delimiter = token
                opened_here = True
            elif token == delimiter:
                delimiter = None
            position = match.end()
        if opened_here or delimiter is not None:
            inside.add(index)
    return inside


def is_comment_line(line: str, language: Optional[str]) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    for prefix in lang_mod.comment_prefixes(language):
        if stripped.startswith(prefix):
            return True
    return False


def _window(lines: Sequence[str], index: int, radius: int) -> str:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return "\n".join(lines[start:end])


def neighbourhood_view(lines: Sequence[str], language: Optional[str]) -> List[str]:
    """The lines a proximity check is allowed to see.

    Comment lines are blanked. Otherwise a commented-out `shell=True` two lines
    above a safe call satisfies the rule's `nearby` requirement, and the rule
    fires on code that is fine - which is how a proximity guard turns into a
    proximity false positive.
    """
    return ["" if is_comment_line(line, language) else line for line in lines]


@register
class PatternScanner(Scanner):
    name = "pattern"
    description = "Rule-pack driven source matching with negative and proximity guards"

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None, extra_rule_dirs: Optional[Sequence[str]] = None, **options: Any):
        super().__init__(**options)
        raw = rules if rules is not None else rule_packs.load_all(extra_rule_dirs)
        self.rules = compile_rules(raw)
        self._by_language: Dict[Optional[str], List[CompiledRule]] = {}

    def rules_for(self, language: Optional[str]) -> List[CompiledRule]:
        if language not in self._by_language:
            self._by_language[language] = [r for r in self.rules if r.applies_to_language(language)]
        return self._by_language[language]

    def applies_to(self, source: SourceFile) -> bool:
        return bool(self.rules_for(source.language))

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        lines = source.lines()
        if not lines:
            return
        candidates = [r for r in self.rules_for(source.language) if r.applies_to_path(source.path)]
        if not candidates:
            return

        # Cheap whole-file literal test before any per-line matching. On a large
        # repository this is the difference between a scan you wait for and one
        # you do not: most rules cannot possibly match most files, and one `in`
        # replaces a regex search per line.
        text = source.read()
        lowered: Optional[str] = None
        applicable = []
        for rule in candidates:
            if rule.prefilter.ignore_case and lowered is None:
                lowered = text.lower()
            if rule.prefilter.matches(text, lowered):
                applicable.append(rule)
        if not applicable:
            return
        counts: Dict[str, int] = {}
        samples = sample_block_lines(lines, source.language)
        heredocs = heredoc_lines(lines, source.language)
        neighbours = neighbourhood_view(lines, source.language)

        for index, line in enumerate(lines):
            if len(line) > 2000:          # minified or generated; nothing useful here
                continue
            if (index + 1) in samples:
                continue
            comment = is_comment_line(line, source.language)
            spans: Optional[List[Tuple[int, int]]] = None
            for rule in applicable:
                if comment and not rule.match_comments:
                    continue
                if counts.get(rule.id, 0) >= rule.max_matches:
                    continue
                match = rule.pattern.search(line)
                if not match:
                    continue
                if rule.not_pattern and rule.not_pattern.search(line):
                    continue
                if rule.skip_in_strings:
                    if (index + 1) in heredocs:
                        continue
                    if spans is None:
                        spans = string_spans(line)
                    if inside_string(spans, match.start()):
                        continue
                if rule.nearby or rule.nearby_absent:
                    neighbourhood = _window(neighbours, index, rule.nearby_window)
                    if rule.nearby and not rule.nearby.search(neighbourhood):
                        continue
                    if rule.nearby_absent and rule.nearby_absent.search(neighbourhood):
                        continue
                line_no = index + 1
                if suppress.suppressed_by_source(lines, line_no, rule.id):
                    continue
                seen = counts.get(rule.id, 0)
                counts[rule.id] = seen + 1
                yield self.make_finding(
                    rule_id=rule.id,
                    title=rule.title,
                    source=source,
                    line=line_no,
                    snippet=line,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    description=rule.description,
                    remediation=rule.remediation,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    tags=list(rule.tags) + ([rule.pack] if rule.pack else []),
                    references=rule.references,
                    scanner=self.name,
                    salt="" if seen == 0 else str(seen),
                )
