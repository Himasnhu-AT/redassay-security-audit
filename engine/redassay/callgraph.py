"""Reachability, when a call graph is available.

redassay's taint tracker stops at the function boundary, and `architecture.md`
explains why: crossing it needs a call graph, and a wrong answer from a
half-built one is worse than no answer - it produces confident nonsense.

That reasoning holds for a call graph *we* would build. It does not hold for one
that already exists. If the repository has been indexed by an external graph
tool, this module borrows its edges to answer the question the scanners cannot:

    this finding sits in function F - can a request actually get to F?

The answer turns a list of dangerous-looking lines into an ordered list, because
"unreachable from any entry point" and "three hops from an unauthenticated POST"
are different findings with the same rule id.

Three properties this module must have, in order:

1. **Optional.** The tool is invoked as a subprocess and never imported. If it
   is not installed, not indexed, or too old, every function here returns empty
   and the rest of redassay behaves exactly as before. The zero-dependency
   promise is not negotiable for a convenience.
2. **Honest about absence.** "No path found" never means "unreachable" - it
   means this graph has no path. Dynamic dispatch, framework magic and
   reflection are all invisible to it. Callers get `Reachability.unknown`
   rather than a false all-clear.
3. **Cheap.** One subprocess per symbol, cached, with a hard cap. A scan that
   shells out 1,500 times is a scan nobody runs twice.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

TOOL = "graft"
TIMEOUT = 20
MAX_QUERIES = 200

#: How far to walk when looking for a path from an entry point to a finding.
DEFAULT_DEPTH = 4


@dataclass(frozen=True)
class Symbol:
    id: str
    name: str
    kind: str
    path: str
    start: int = 0
    end: int = 0

    @property
    def label(self) -> str:
        return f"{self.name} ({self.path}:{self.start})"

    def contains(self, path: str, line: int) -> bool:
        return self.path == path and self.start <= line <= (self.end or self.start)


@dataclass
class Reachability:
    """What the graph could say about one finding."""

    status: str = "unknown"        # "reachable" | "no-path" | "unknown"
    entry_point: str = ""          # the entry point the path starts from
    chain: List[Symbol] = field(default_factory=list)
    depth: int = 0
    note: str = ""

    @property
    def is_reachable(self) -> bool:
        return self.status == "reachable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "entry_point": self.entry_point,
            "depth": self.depth,
            "chain": [{"name": s.name, "path": s.path, "line": s.start} for s in self.chain],
            "note": self.note,
        }

    def describe(self) -> str:
        if self.status == "reachable":
            hops = " -> ".join(s.name for s in self.chain)
            return f"reachable from {self.entry_point} in {self.depth} hop(s): {hops}"
        if self.status == "no-path":
            return ("no call path from any known entry point - which is not proof of "
                    "unreachability, only that this graph has no edge")
        return self.note or "no call graph available"


def available(root: str = ".") -> bool:
    """Is there a usable graph for this repository?"""
    if shutil.which(TOOL) is None:
        return False
    return os.path.isdir(os.path.join(os.path.abspath(root), TOOL))


def _run(args: Sequence[str], root: str) -> Optional[Dict[str, Any]]:
    try:
        result = subprocess.run(
            [TOOL, *args, "--json", "--no-refresh"],
            cwd=root, capture_output=True, text=True, timeout=TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        # The tool prints a savings banner before the payload on some paths.
        brace = result.stdout.find("{")
        if brace == -1:
            return None
        try:
            return json.loads(result.stdout[brace:])
        except json.JSONDecodeError:
            return None


def _parse_span(span: str) -> Tuple[int, int]:
    """'L77-L112' -> (77, 112)."""
    try:
        start, _, end = span.partition("-")
        return int(start.lstrip("Ll")), int(end.lstrip("Ll") or start.lstrip("Ll"))
    except (ValueError, AttributeError):
        return 0, 0


def _symbol(raw: Dict[str, Any]) -> Symbol:
    start, end = _parse_span(raw.get("span", ""))
    return Symbol(
        id=raw.get("id", ""), name=raw.get("name", ""), kind=raw.get("kind", ""),
        path=raw.get("path", ""), start=start, end=end,
    )


class CallGraph:
    """A thin, cached view over the external graph."""

    def __init__(self, root: str = "."):
        self.root = os.path.abspath(root)
        self.enabled = available(self.root)
        self._callers: Dict[str, List[Symbol]] = {}
        self._symbols_by_file: Dict[str, List[Symbol]] = {}
        self.queries = 0
        self.reason = "" if self.enabled else self._why_not()

    def _why_not(self) -> str:
        if shutil.which(TOOL) is None:
            return f"{TOOL} is not installed - reachability is unavailable"
        return f"no {TOOL}/ index in {self.root} - run `{TOOL} build` to enable reachability"

    # -- lookups -------------------------------------------------------------
    def symbols_in(self, path: str) -> List[Symbol]:
        """Every symbol the graph knows about in one file."""
        if not self.enabled or self.queries >= MAX_QUERIES:
            return []
        if path in self._symbols_by_file:
            return self._symbols_by_file[path]
        self.queries += 1
        payload = _run(["skeleton", path], self.root)
        symbols: List[Symbol] = []
        if payload:
            # A skeleton lists entries without repeating the file on each one.
            for raw in payload.get("entries") or payload.get("symbols") or []:
                raw = dict(raw)
                raw.setdefault("path", payload.get("file", path))
                symbol = _symbol(raw)
                if symbol.name:
                    symbols.append(symbol)
        self._symbols_by_file[path] = symbols
        return symbols

    def enclosing(self, path: str, line: int) -> Optional[Symbol]:
        """The smallest symbol containing this line."""
        candidates = [s for s in self.symbols_in(path) if s.contains(path, line)]
        if not candidates:
            return None
        return min(candidates, key=lambda s: (s.end or s.start) - s.start)

    def callers(self, name: str, depth: int = 1) -> List[Symbol]:
        key = f"{name}@{depth}"
        if key in self._callers:
            return self._callers[key]
        if not self.enabled or self.queries >= MAX_QUERIES:
            return []
        self.queries += 1
        payload = _run(["callers", name, "--depth", str(depth)], self.root)
        found: List[Symbol] = []
        if payload:
            for match in payload.get("matches") or []:
                for hit in match.get("hits") or []:
                    found.append(_symbol(hit))
        self._callers[key] = found
        return found

    # -- the question worth asking -------------------------------------------
    def reaches(
        self,
        path: str,
        line: int,
        entry_points: Sequence[Any],
        depth: int = DEFAULT_DEPTH,
    ) -> Reachability:
        """Can any of these entry points call the code at path:line?

        `entry_points` are redassay `EntryPoint` records. The match is by file
        and span: an entry point is "in" a symbol when its registration line
        falls inside that symbol, or when its handler shares the file.
        """
        if not self.enabled:
            return Reachability(status="unknown", note=self.reason)

        target = self.enclosing(path, line)
        if target is None:
            return Reachability(status="unknown",
                                note=f"no symbol covering {path}:{line} in the graph")

        # An entry point registered inside the same symbol needs no call edge.
        for entry in entry_points:
            if getattr(entry, "path", None) == path and target.contains(path, getattr(entry, "line", 0)):
                return Reachability(
                    status="reachable", entry_point=_entry_label(entry),
                    chain=[target], depth=0,
                    note="the entry point is declared inside this symbol",
                )

        entry_files = {getattr(e, "path", "") for e in entry_points}
        reaching = self.callers(target.name, depth=depth)
        if not reaching:
            # The graph knows this symbol and found nothing pointing at it. That
            # is weaker than proof - a dynamic dispatch or a framework hook is
            # invisible here - but it is a real observation, and different from
            # "the graph has never heard of this code".
            return Reachability(
                status="no-path",
                note=f"the graph knows {target.name} and records no callers of it",
            )

        for caller in reaching:
            if caller.path not in entry_files:
                continue
            for entry in entry_points:
                if getattr(entry, "path", "") != caller.path:
                    continue
                return Reachability(
                    status="reachable", entry_point=_entry_label(entry),
                    chain=[caller, target], depth=1,
                    note="",
                )

        return Reachability(
            status="no-path",
            note=f"{len(reaching)} caller(s) of {target.name}, none in a file that declares an entry point",
        )

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "reason": self.reason,
            "queries": self.queries,
            "symbols_cached": sum(len(v) for v in self._symbols_by_file.values()),
        }


def _entry_label(entry: Any) -> str:
    label = getattr(entry, "label", None)
    if label:
        return str(label)
    return f"{getattr(entry, 'name', '?')} ({getattr(entry, 'path', '?')})"
