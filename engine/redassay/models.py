"""The records that live in .redassay/findings.json.

Everything is a plain dataclass with explicit to_dict/from_dict. No pydantic, no
schema library - the file on disk is the contract and it has to stay readable by
a human with `less`.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from . import severity as sev
from .ids import finding_id

# --- status vocabulary -------------------------------------------------------
# open       scanner found it, nobody has looked
# confirmed  a human (or Claude's verifier) agrees it is real
# queued     approved for fixing; the next `fix` run picks it up
# fixing     a fix is in flight
# fixed      a patch was applied
# verified   re-scan no longer reproduces it
# dismissed  human said no - false positive, accepted risk, out of scope
OPEN = "open"
CONFIRMED = "confirmed"
QUEUED = "queued"
FIXING = "fixing"
FIXED = "fixed"
VERIFIED = "verified"
DISMISSED = "dismissed"

STATUSES = [OPEN, CONFIRMED, QUEUED, FIXING, FIXED, VERIFIED, DISMISSED]

#: Statuses that mean "a human has made a decision, do not resurrect on rescan".
STICKY = {DISMISSED, FIXED, VERIFIED}

#: Statuses that still need work.
ACTIONABLE = {OPEN, CONFIRMED, QUEUED, FIXING}

_LEGAL_TRANSITIONS = {
    OPEN: {CONFIRMED, QUEUED, DISMISSED, FIXING},
    CONFIRMED: {QUEUED, DISMISSED, FIXING, OPEN},
    QUEUED: {FIXING, DISMISSED, CONFIRMED, OPEN},
    FIXING: {FIXED, QUEUED, DISMISSED, OPEN},
    FIXED: {VERIFIED, OPEN, DISMISSED, FIXING},
    VERIFIED: {OPEN},
    DISMISSED: {OPEN, CONFIRMED},
}


def can_transition(current: str, target: str) -> bool:
    if current == target:
        return True
    return target in _LEGAL_TRANSITIONS.get(current, set())


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Comment:
    author: str
    body: str
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Comment":
        return cls(
            author=str(raw.get("author") or "anonymous"),
            body=str(raw.get("body") or ""),
            created_at=str(raw.get("created_at") or utcnow()),
        )


@dataclass
class Location:
    """Where a finding lives. One finding can have several."""

    path: str
    line: int = 0
    end_line: int = 0
    snippet: str = ""

    def __post_init__(self) -> None:
        self.path = self.path.replace("\\", "/")
        self.line = max(int(self.line or 0), 0)
        self.end_line = max(int(self.end_line or 0), self.line)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Location":
        return cls(
            path=str(raw.get("path") or ""),
            line=int(raw.get("line") or 0),
            end_line=int(raw.get("end_line") or 0),
            snippet=str(raw.get("snippet") or ""),
        )

    @property
    def label(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass
class Fix:
    """What we did about a finding."""

    summary: str = ""
    diff: str = ""
    applied_at: str = ""
    applied_by: str = ""
    files_touched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Fix":
        return cls(
            summary=str(raw.get("summary") or ""),
            diff=str(raw.get("diff") or ""),
            applied_at=str(raw.get("applied_at") or ""),
            applied_by=str(raw.get("applied_by") or ""),
            files_touched=list(raw.get("files_touched") or []),
        )

    @property
    def is_empty(self) -> bool:
        return not (self.summary or self.diff)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str = sev.MEDIUM
    confidence: str = "medium"
    description: str = ""
    remediation: str = ""
    location: Location = field(default_factory=lambda: Location(path=""))
    extra_locations: List[Location] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source: str = "scanner"
    status: str = OPEN
    comments: List[Comment] = field(default_factory=list)
    fix: Fix = field(default_factory=Fix)
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = sev.normalize(self.severity)
        self.confidence = _normalize_confidence(self.confidence)
        if self.status not in STATUSES:
            self.status = OPEN
        if not self.id:
            self.id = finding_id(self.rule_id, self.location.path, self.location.snippet)

    # -- convenience ---------------------------------------------------------
    @property
    def path(self) -> str:
        return self.location.path

    @property
    def line(self) -> int:
        return self.location.line

    @property
    def is_open(self) -> bool:
        return self.status in ACTIONABLE

    @property
    def all_locations(self) -> List[Location]:
        return [self.location] + list(self.extra_locations)

    def add_comment(self, author: str, body: str) -> Comment:
        comment = Comment(author=author, body=body)
        self.comments.append(comment)
        return comment

    def set_status(self, target: str, strict: bool = False) -> bool:
        if target not in STATUSES:
            raise ValueError(f"unknown status: {target}")
        if not can_transition(self.status, target):
            if strict:
                raise ValueError(f"illegal transition {self.status} -> {target}")
            return False
        self.status = target
        return True

    # -- serialization -------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "remediation": self.remediation,
            "location": self.location.to_dict(),
            "extra_locations": [loc.to_dict() for loc in self.extra_locations],
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "references": list(self.references),
            "tags": list(self.tags),
            "source": self.source,
            "status": self.status,
            "comments": [c.to_dict() for c in self.comments],
            "fix": self.fix.to_dict(),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Finding":
        return cls(
            rule_id=str(raw.get("rule_id") or "unknown"),
            title=str(raw.get("title") or raw.get("rule_id") or "untitled"),
            severity=raw.get("severity"),
            confidence=raw.get("confidence"),
            description=str(raw.get("description") or ""),
            remediation=str(raw.get("remediation") or ""),
            location=Location.from_dict(raw.get("location") or {}),
            extra_locations=[Location.from_dict(x) for x in raw.get("extra_locations") or []],
            cwe=list(raw.get("cwe") or []),
            owasp=list(raw.get("owasp") or []),
            references=list(raw.get("references") or []),
            tags=list(raw.get("tags") or []),
            source=str(raw.get("source") or "scanner"),
            status=str(raw.get("status") or OPEN),
            comments=[Comment.from_dict(c) for c in raw.get("comments") or []],
            fix=Fix.from_dict(raw.get("fix") or {}),
            first_seen=str(raw.get("first_seen") or utcnow()),
            last_seen=str(raw.get("last_seen") or utcnow()),
            id=str(raw.get("id") or ""),
        )


_CONFIDENCE = {"high", "medium", "low"}
_CONFIDENCE_ALIASES = {"certain": "high", "definite": "high", "maybe": "low", "possible": "low"}


def _normalize_confidence(value: object) -> str:
    text = str(value or "medium").strip().lower()
    text = _CONFIDENCE_ALIASES.get(text, text)
    return text if text in _CONFIDENCE else "medium"
