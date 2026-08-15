"""Literal prefiltering for regex rules.

Running 108 compiled patterns against every line of a large repository is
quadratic in the wrong things: Django is 5,000 files and 800,000 lines, which
works out to tens of millions of regex searches, almost all of which fail.

The fix is the one every fast grep uses. Before matching a rule line by line,
ask a much cheaper question of the whole file: does it contain a substring that
the pattern *must* match? `\\bos\\.system\\s*\\(` can only match in a file
containing "os.system". One `in` test on the file text replaces a search per
line.

The extractor is deliberately conservative. Returning nothing means "run the
rule normally", which is always correct; returning a literal that is not
actually mandatory would silently drop findings. Every construct it does not
understand falls back to nothing.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence, Set, Tuple

MIN_LITERAL = 3

#: Characters that make the preceding literal optional or repeatable.
_QUANTIFIERS = "?*{"


def _split_top_level(pattern: str) -> List[str]:
    """Split on `|` that is not inside a group or a character class."""
    branches: List[str] = []
    depth = 0
    in_class = False
    escaped = False
    current: List[str] = []
    for char in pattern:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if in_class:
            current.append(char)
            if char == "]":
                in_class = False
            continue
        if char == "[":
            in_class = True
            current.append(char)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "|" and depth == 0:
            branches.append("".join(current))
            current = []
            continue
        current.append(char)
    branches.append("".join(current))
    return branches


def literal_runs(pattern: str) -> List[str]:
    """Runs of plain characters that must appear, in order, at the top level.

    Anything inside a group, a character class, or followed by an optional
    quantifier is discarded - those are not guaranteed to be present.
    """
    runs: List[str] = []
    current: List[str] = []
    depth = 0
    in_class = False
    index = 0
    length = len(pattern)

    def flush(drop_last: bool = False) -> None:
        text = "".join(current[:-1] if drop_last and current else current)
        if len(text) >= MIN_LITERAL:
            runs.append(text)
        current.clear()

    while index < length:
        char = pattern[index]

        if char == "\\":
            nxt = pattern[index + 1] if index + 1 < length else ""
            if nxt in ".+*?()[]{}|^$/-\\" and depth == 0 and not in_class:
                # An escaped literal such as \. is a real character.
                lookahead = pattern[index + 2] if index + 2 < length else ""
                # `"" in "?*{"` is True in Python, so the guard has to test for
                # a character first - without it every escaped literal at the
                # end of a pattern was silently dropped.
                if lookahead and lookahead in _QUANTIFIERS:
                    flush()
                    index += 3
                    continue
                current.append(nxt)
            else:
                flush()
            index += 2
            continue

        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue

        if char == "[":
            flush()
            in_class = True
            index += 1
            continue

        if char == "(":
            flush()
            depth += 1
            index += 1
            continue

        if char == ")":
            depth = max(0, depth - 1)
            index += 1
            continue

        if depth > 0:
            index += 1
            continue

        if char in _QUANTIFIERS or char == "+":
            # `abc?` makes only the `c` optional; `abc+` keeps everything.
            flush(drop_last=char != "+")
            if char == "{":
                closing = pattern.find("}", index)
                index = closing + 1 if closing != -1 else index + 1
                continue
            index += 1
            continue

        if char in ".^$":
            flush()
            index += 1
            continue

        current.append(char)
        index += 1

    flush()
    return runs


def _atoms(pattern: str) -> List[Tuple[str, str, bool]]:
    """Split a branch into top-level atoms: ("literal"|"group", text, optional)."""
    out: List[Tuple[str, str, bool]] = []
    index = 0
    length = len(pattern)
    current: List[str] = []
    in_class = False

    def flush_literal() -> None:
        if current:
            out.append(("literal", "".join(current), False))
            current.clear()

    while index < length:
        char = pattern[index]
        if char == "\\":
            current.append(pattern[index:index + 2])
            index += 2
            continue
        if in_class:
            current.append(char)
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            current.append(char)
            in_class = True
            index += 1
            continue
        if char == "(":
            flush_literal()
            depth = 1
            start = index + 1
            cursor = start
            escaped = False
            inner_class = False
            while cursor < length and depth:
                token = pattern[cursor]
                if escaped:
                    escaped = False
                elif token == "\\":
                    escaped = True
                elif inner_class:
                    if token == "]":
                        inner_class = False
                elif token == "[":
                    inner_class = True
                elif token == "(":
                    depth += 1
                elif token == ")":
                    depth -= 1
                cursor += 1
            body = pattern[start:cursor - 1]
            optional = cursor < length and pattern[cursor] in "?*"
            out.append(("group", body, optional))
            index = cursor + (1 if optional else 0)
            continue
        current.append(char)
        index += 1

    flush_literal()
    return out


_GROUP_PREFIX = re.compile(r"^\?(:|P<[^>]*>|=|!|<=|<!)")


def _group_alternatives(body: str) -> Optional[Set[str]]:
    """One mandatory literal per branch of a group, or None."""
    body = _GROUP_PREFIX.sub("", body, count=1)
    if body.startswith("?"):
        return None                       # inline flags or something exotic
    alternatives: Set[str] = set()
    for branch in _split_top_level(body):
        runs = literal_runs(branch)
        if runs:
            alternatives.add(max(runs, key=len))
            continue
        # The branch has no literal of its own but may wrap one, as in
        # `((?:AKIA|ASIA)[A-Z0-9]{16})`. Recurse rather than give up.
        nested = _branch_alternatives(branch)
        if not nested:
            return None
        alternatives |= nested
    return alternatives or None


def _branch_alternatives(branch: str) -> Optional[Set[str]]:
    """The most selective any-of set a single branch guarantees."""
    best: Optional[Set[str]] = None

    def consider(candidate: Optional[Set[str]]) -> None:
        nonlocal best
        if not candidate:
            return
        if min(len(text) for text in candidate) < MIN_LITERAL:
            return
        if best is None or min(map(len, candidate)) > min(map(len, best)):
            best = candidate

    for kind, text, optional in _atoms(branch):
        if optional:
            continue
        if kind == "literal":
            runs = literal_runs(text)
            if runs:
                consider({max(runs, key=len)})
        else:
            consider(_group_alternatives(text))
    return best


def required_literals(pattern: str) -> Optional[List[str]]:
    """Substrings of which at least one must appear for the pattern to match.

    Returns None when no useful guarantee can be extracted - the caller must
    then run the rule without a prefilter.
    """
    alternatives: Set[str] = set()
    for branch in _split_top_level(pattern):
        found = _branch_alternatives(branch)
        if not found:
            return None                   # this branch could match anything
        alternatives |= found
    return sorted(alternatives) or None


class Prefilter:
    """Precomputed answer to "can this rule match this file at all?"."""

    __slots__ = ("literals", "ignore_case")

    def __init__(self, pattern: str, ignore_case: bool = False):
        literals = required_literals(pattern)
        self.ignore_case = ignore_case
        self.literals: Optional[Tuple[str, ...]] = (
            tuple(literal.lower() if ignore_case else literal for literal in literals)
            if literals else None
        )

    @property
    def active(self) -> bool:
        return self.literals is not None

    def matches(self, text: str, lowered: Optional[str] = None) -> bool:
        if self.literals is None:
            return True
        haystack = (lowered if lowered is not None else text.lower()) if self.ignore_case else text
        return any(literal in haystack for literal in self.literals)


def coverage(patterns: Sequence[str]) -> float:
    """Share of patterns the extractor can prefilter. Used by the benchmark."""
    if not patterns:
        return 0.0
    usable = sum(1 for pattern in patterns if required_literals(pattern))
    return usable / len(patterns)
