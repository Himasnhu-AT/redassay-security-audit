"""The action queue - the board's half of the conversation.

When a reviewer clicks something on the board, the server appends a line to
`.redassay/actions.jsonl` and applies whatever part of it is pure bookkeeping
(a comment, a dismissal). Actions that need judgement - "fix this" - stay
pending until an agent claims them.

Append-only JSONL rather than a table in findings.json, for two reasons: the
server can append without taking the store lock, and the file doubles as an
audit trail of who asked for what.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, Iterator, List, Optional

from . import models

# Action kinds
COMMENT = "comment"
STATUS = "status"
FIX = "fix"
FIX_ALL = "fix_all"
DISMISS = "dismiss"
REOPEN = "reopen"
SUPPRESS = "suppress"
RESCAN = "rescan"
NOTE = "note"

PENDING = "pending"
CLAIMED = "claimed"
DONE = "done"
FAILED = "failed"

#: Kinds that require an agent to do something; everything else the server settles itself.
AGENT_KINDS = {FIX, FIX_ALL, RESCAN}


@dataclass
class Action:
    kind: str
    finding_id: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    author: str = "you"
    state: str = PENDING
    created_at: str = field(default_factory=models.utcnow)
    claimed_at: str = ""
    completed_at: str = ""
    result: str = ""
    seq: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Action":
        known = {f for f in cls().to_dict()} if False else {
            "kind", "finding_id", "payload", "author", "state",
            "created_at", "claimed_at", "completed_at", "result", "seq",
        }
        return cls(**{k: v for k, v in raw.items() if k in known})

    @property
    def needs_agent(self) -> bool:
        return self.kind in AGENT_KINDS

    def describe(self) -> str:
        if self.kind == FIX:
            return f"fix {self.finding_id}"
        if self.kind == FIX_ALL:
            ids = self.payload.get("finding_ids") or []
            return f"fix {len(ids)} findings"
        if self.kind == COMMENT:
            return f"comment on {self.finding_id}"
        if self.kind == STATUS:
            return f"set {self.finding_id} -> {self.payload.get('status')}"
        if self.kind == RESCAN:
            return "rescan the repository"
        return f"{self.kind} {self.finding_id}".strip()


class ActionQueue:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.dir = os.path.join(self.root, ".redassay")
        self.path = os.path.join(self.dir, "actions.jsonl")

    # -- writes --------------------------------------------------------------
    def append(self, action: Action) -> Action:
        os.makedirs(self.dir, exist_ok=True)
        action.seq = self._next_seq()
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(action.to_dict(), sort_keys=True) + "\n")
        return action

    def push(self, kind: str, finding_id: str = "", author: str = "you", **payload: Any) -> Action:
        return self.append(Action(kind=kind, finding_id=finding_id, author=author, payload=payload))

    def _next_seq(self) -> int:
        actions = self.all()
        return (max((a.seq for a in actions), default=0)) + 1

    def _rewrite(self, actions: Iterable[Action]) -> None:
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.path + f".tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as handle:
            for action in actions:
                handle.write(json.dumps(action.to_dict(), sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    # -- reads ---------------------------------------------------------------
    def all(self) -> List[Action]:
        if not os.path.isfile(self.path):
            return []
        out: List[Action] = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Action.from_dict(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
        return out

    def pending(self, agent_only: bool = True) -> List[Action]:
        return [
            action for action in self.all()
            if action.state == PENDING and (action.needs_agent or not agent_only)
        ]

    def by_finding(self, finding_id: str) -> List[Action]:
        return [a for a in self.all() if a.finding_id == finding_id]

    def get(self, seq: int) -> Optional[Action]:
        return next((a for a in self.all() if a.seq == seq), None)

    # -- state transitions ---------------------------------------------------
    def claim(self, limit: Optional[int] = None) -> List[Action]:
        """Mark pending agent actions as claimed and hand them back."""
        actions = self.all()
        claimed: List[Action] = []
        for action in actions:
            if action.state != PENDING or not action.needs_agent:
                continue
            action.state = CLAIMED
            action.claimed_at = models.utcnow()
            claimed.append(action)
            if limit and len(claimed) >= limit:
                break
        if claimed:
            self._rewrite(actions)
        return claimed

    def complete(self, seq: int, result: str = "", state: str = DONE) -> Optional[Action]:
        actions = self.all()
        target = None
        for action in actions:
            if action.seq == seq:
                action.state = state
                action.result = result
                action.completed_at = models.utcnow()
                target = action
                break
        if target:
            self._rewrite(actions)
        return target

    def release(self, seq: int) -> Optional[Action]:
        """Put a claimed action back in the queue - used when an agent gives up."""
        actions = self.all()
        target = None
        for action in actions:
            if action.seq == seq and action.state == CLAIMED:
                action.state = PENDING
                action.claimed_at = ""
                target = action
                break
        if target:
            self._rewrite(actions)
        return target

    def clear(self) -> int:
        count = len(self.all())
        if os.path.isfile(self.path):
            os.unlink(self.path)
        return count

    def stats(self) -> Dict[str, int]:
        out = {PENDING: 0, CLAIMED: 0, DONE: 0, FAILED: 0}
        for action in self.all():
            out[action.state] = out.get(action.state, 0) + 1
        return out
