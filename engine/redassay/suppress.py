"""Suppression rules - "stop telling me about this one".

Two flavours, because they solve different problems:

* store-level suppressions (`redassay suppress <rule> --path 'tests/**'`) live in
  findings.json and apply at merge time, before a finding is ever recorded.
* inline suppressions (`# redassay: ignore py.exec-taint - runs on trusted input`)
  live in the source and apply at scan time.

Inline wins where it exists, because it carries the justification next to the
code it excuses.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import Finding

_INLINE = re.compile(
    r"(?:#|//|/\*|<!--|--)\s*redassay\s*:\s*(?:ignore|disable|suppress)"
    r"(?:\s+([\w.\-,*]+))?"
    r"(?:\s*[-:]\s*(.*?))?\s*(?:\*/|-->)?\s*$",
    re.IGNORECASE,
)


def parse_inline(line: str) -> Optional[Dict[str, Any]]:
    """Return {"rules": [...], "reason": str} for a suppression comment."""
    match = _INLINE.search(line or "")
    if not match:
        return None
    raw_rules = (match.group(1) or "*").strip()
    rules = [part for part in (r.strip() for r in raw_rules.split(",")) if part]
    return {"rules": rules or ["*"], "reason": (match.group(2) or "").strip()}


def inline_suppresses(line: str, rule_id: str) -> bool:
    parsed = parse_inline(line)
    if parsed is None:
        return False
    return any(fnmatch.fnmatch(rule_id, pattern) for pattern in parsed["rules"])


def suppressed_by_source(lines: Sequence[str], line_no: int, rule_id: str) -> bool:
    """Check the flagged line and the line above it (1-indexed line_no)."""
    if line_no <= 0 or line_no > len(lines):
        return False
    if inline_suppresses(lines[line_no - 1], rule_id):
        return True
    if line_no >= 2 and inline_suppresses(lines[line_no - 2], rule_id):
        return True
    return False


def is_suppressed(finding: Finding, rules: Iterable[Dict[str, Any]]) -> bool:
    for rule in rules or []:
        rule_pattern = str(rule.get("rule_id") or "*")
        path_pattern = str(rule.get("path") or "*")
        if not fnmatch.fnmatch(finding.rule_id, rule_pattern):
            continue
        if path_pattern in ("*", "**"):
            return True
        if fnmatch.fnmatch(finding.path, path_pattern):
            return True
    return False


def explain(rules: List[Dict[str, Any]]) -> List[str]:
    out = []
    for rule in rules:
        reason = rule.get("reason") or "no reason given"
        out.append(f"{rule.get('rule_id')} in {rule.get('path')} - {reason}")
    return out
