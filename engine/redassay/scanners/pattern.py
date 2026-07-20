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
        "match_comments", "pack", "max_matches",
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
        self.max_matches = int(raw.get("max_matches", MAX_MATCHES_PER_RULE_PER_FILE))
        flags = re.IGNORECASE if raw.get("ignore_case") else 0
        self.pattern = re.compile(raw["pattern"], flags)
        self.not_pattern = re.compile(raw["not_pattern"], flags) if raw.get("not_pattern") else None
        self.nearby = re.compile(raw["nearby"], flags) if raw.get("nearby") else None
        self.nearby_absent = re.compile(raw["nearby_absent"], flags) if raw.get("nearby_absent") else None
        self.nearby_window = int(raw.get("nearby_window", DEFAULT_NEARBY_WINDOW))
        self.path_include = raw.get("path_include") or []
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
        applicable = [r for r in self.rules_for(source.language) if r.applies_to_path(source.path)]
        if not applicable:
            return
        counts: Dict[str, int] = {}

        for index, line in enumerate(lines):
            if len(line) > 2000:          # minified or generated; nothing useful here
                continue
            comment = is_comment_line(line, source.language)
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
                if rule.nearby or rule.nearby_absent:
                    neighbourhood = _window(lines, index, rule.nearby_window)
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
