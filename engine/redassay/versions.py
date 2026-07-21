"""Version parsing and comparison for dependency matching.

Handles the intersection of semver, PEP 440 and Maven that actually shows up in
manifests. It is not a full implementation of any of the three - it is enough to
answer "is the pinned version below the fixed version", which is the only
question the advisory matcher asks.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_SPLIT = re.compile(r"[.\-_+]")
_NUM = re.compile(r"^(\d+)")

#: Pre-release identifiers sort below the release they precede.
_PRE_RANK = {"dev": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "rc": -2, "pre": -2, "preview": -2}


def parse(version: str) -> Tuple[List[int], int, str]:
    """Return (numeric parts, pre-release rank, original) for comparison."""
    text = str(version or "").strip().lstrip("vV=")
    text = text.split("+", 1)[0]
    pre_rank = 0
    parts: List[int] = []
    for token in _SPLIT.split(text):
        if not token:
            continue
        match = _NUM.match(token)
        if match:
            parts.append(int(match.group(1)))
            tail = token[match.end():].lower()
            if tail and tail in _PRE_RANK:
                pre_rank = _PRE_RANK[tail]
        else:
            # "rc1", "beta2": the alphabetic prefix names the stage.
            alpha = re.match(r"^([A-Za-z]+)", token)
            lowered = (alpha.group(1) if alpha else token).lower()
            if lowered in _PRE_RANK:
                pre_rank = _PRE_RANK[lowered]
    return parts or [0], pre_rank, text


def compare(left: str, right: str) -> int:
    """-1, 0 or 1 in the usual sense."""
    left_parts, left_pre, _ = parse(left)
    right_parts, right_pre, _ = parse(right)
    width = max(len(left_parts), len(right_parts))
    padded_left = left_parts + [0] * (width - len(left_parts))
    padded_right = right_parts + [0] * (width - len(right_parts))
    if padded_left != padded_right:
        return -1 if padded_left < padded_right else 1
    if left_pre != right_pre:
        return -1 if left_pre < right_pre else 1
    return 0


def lt(left: str, right: str) -> bool:
    return compare(left, right) < 0


def satisfies_vulnerable(version: str, constraint: str) -> bool:
    """Does `version` fall inside a constraint like '<4.17.21' or '>=1.0,<1.2'?"""
    if not version or not constraint:
        return False
    for clause in constraint.split(","):
        clause = clause.strip()
        if not clause:
            continue
        match = re.match(r"^(<=|>=|==|<|>|=)?\s*(.+)$", clause)
        if not match:
            return False
        operator, bound = match.group(1) or "==", match.group(2).strip()
        result = compare(version, bound)
        if operator == "<" and not result < 0:
            return False
        if operator == "<=" and not result <= 0:
            return False
        if operator == ">" and not result > 0:
            return False
        if operator == ">=" and not result >= 0:
            return False
        if operator in ("==", "=") and result != 0:
            return False
    return True


_CONCRETE = re.compile(r"\d+(\.\d+)*")


def pinned_version(spec: str) -> Optional[str]:
    """Extract the concrete version a spec resolves to, if it names one.

    '^4.17.15' -> None (a range; the lockfile decides)
    '==2.31.0' -> '2.31.0'
    '4.17.15'  -> '4.17.15'
    """
    text = str(spec or "").strip()
    if not text or text in {"*", "latest", "", "x"}:
        return None
    if text.startswith(("^", "~", ">", "<", "|")) or " - " in text or "||" in text:
        return None
    text = text.lstrip("=v ")
    match = _CONCRETE.match(text)
    return match.group(0) if match else None


def loose_version(spec: str) -> Optional[str]:
    """The lowest version a range could resolve to - used for a best-effort check."""
    text = str(spec or "").strip()
    if not text or text in {"*", "latest", "x"}:
        return None
    match = re.search(r"\d+(\.\d+)*", text)
    return match.group(0) if match else None


def is_floating(spec: str) -> bool:
    """True for specs that let the resolver pick a version you did not review."""
    text = str(spec or "").strip()
    if text in {"*", "latest", "", "x", "X"}:
        return True
    return text.startswith(("^", "~", ">=", ">")) or "||" in text or " - " in text
