"""JSON API behind the review board.

Every handler reloads the store before reading. The board and an agent write to
the same files from different processes, so anything cached in memory is stale
by the time it reaches the browser.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from .. import models, severity as sev, triage as triage_mod
from ..config import Config
from ..models import Finding
from ..queue import ActionQueue, COMMENT, DISMISS, FIX, FIX_ALL, RESCAN, STATUS
from ..store import Store
from .router import Router

router = Router()

MAX_COMMENT = 8000
CONTEXT_RADIUS = 8


class Api:
    """Holds the per-server state the handlers need."""

    def __init__(self, config: Config):
        self.config = config
        self.root = config.root
        self.store = Store(config.root)
        self.queue = ActionQueue(config.root)

    def fresh(self) -> Store:
        self.store.reload()
        return self.store


# --- serialization -----------------------------------------------------------
def _finding_json(finding: Finding) -> Dict[str, Any]:
    data = finding.to_dict()
    data["priority"] = triage_mod.priority(finding)
    data["label"] = finding.location.label
    data["is_open"] = finding.is_open
    return data


def _state(api: Api) -> Dict[str, Any]:
    store = api.fresh()
    findings = triage_mod.rank(store.all())
    actions = api.queue.all()
    last_scan = store.last_scan()
    return {
        "repo": os.path.basename(store.root),
        "root": store.root,
        "stats": store.stats(),
        "findings": [_finding_json(f) for f in findings],
        "hotspots": [
            {"path": path, "count": count, "risk": score}
            for path, count, score in triage_mod.hotspots(findings, limit=8)
        ],
        "queue": {
            "pending": [a.to_dict() for a in actions if a.state == "pending"],
            "claimed": [a.to_dict() for a in actions if a.state == "claimed"],
            "recent": [a.to_dict() for a in actions[-15:]],
            "stats": api.queue.stats(),
        },
        "last_scan": last_scan,
        "severities": sev.ORDER,
        "statuses": models.STATUSES,
    }


# --- routes ------------------------------------------------------------------
@router.get(r"/api/state")
def get_state(request) -> Tuple[int, Any]:
    return 200, _state(request.api)


@router.get(r"/api/findings")
def list_findings(request) -> Tuple[int, Any]:
    store = request.api.fresh()
    params = request.query
    statuses = params.get("status")
    findings = store.query(
        status=[s for s in statuses.split(",") if s] if statuses else None,
        severity_floor=params.get("min_severity"),
        path_prefix=params.get("path"),
        source=params.get("source"),
        rule_id=params.get("rule"),
    )
    findings = triage_mod.rank(findings)
    return 200, {"findings": [_finding_json(f) for f in findings], "count": len(findings)}


@router.get(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)")
def get_finding(request, finding_id: str) -> Tuple[int, Any]:
    store = request.api.fresh()
    finding = store.get(finding_id)
    if finding is None:
        return 404, {"error": "not found"}
    data = _finding_json(finding)
    data["context"] = _context(store.root, finding)
    data["actions"] = [a.to_dict() for a in request.api.queue.by_finding(finding.id)]
    return 200, data


@router.post(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)/comment")
def post_comment(request, finding_id: str) -> Tuple[int, Any]:
    body = (request.json.get("body") or "").strip()[:MAX_COMMENT]
    if not body:
        return 400, {"error": "comment body is required"}
    author = (request.json.get("author") or request.api.config.author)[:64]
    store = request.api.fresh()
    finding = store.add_comment(finding_id, author, body)
    if finding is None:
        return 404, {"error": "not found"}
    store.save()
    request.api.queue.push(COMMENT, finding.id, author=author, body=body)
    return 200, _finding_json(finding)


@router.post(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)/status")
def post_status(request, finding_id: str) -> Tuple[int, Any]:
    target = request.json.get("status")
    if target not in models.STATUSES:
        return 400, {"error": f"status must be one of {models.STATUSES}"}
    store = request.api.fresh()
    finding = store.get(finding_id)
    if finding is None:
        return 404, {"error": "not found"}
    if not finding.set_status(target):
        return 409, {"error": f"cannot move {finding.status} -> {target}"}
    store.put(finding)
    store.save()
    request.api.queue.push(STATUS, finding.id, author=request.api.config.author, status=target)
    return 200, _finding_json(finding)


@router.post(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)/dismiss")
def post_dismiss(request, finding_id: str) -> Tuple[int, Any]:
    reason = (request.json.get("reason") or "").strip()[:MAX_COMMENT]
    store = request.api.fresh()
    finding = store.get(finding_id)
    if finding is None:
        return 404, {"error": "not found"}
    finding.set_status(models.DISMISSED)
    finding.add_comment(request.api.config.author, reason or "Dismissed from the board.")
    store.put(finding)
    if request.json.get("suppress_rule"):
        store.suppress(finding.rule_id, request.json.get("path_glob") or finding.path, reason)
    store.save()
    request.api.queue.push(DISMISS, finding.id, author=request.api.config.author, reason=reason)
    return 200, _finding_json(finding)


@router.post(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)/reopen")
def post_reopen(request, finding_id: str) -> Tuple[int, Any]:
    store = request.api.fresh()
    finding = store.get(finding_id)
    if finding is None:
        return 404, {"error": "not found"}
    finding.set_status(models.OPEN)
    store.put(finding)
    store.save()
    return 200, _finding_json(finding)


@router.post(r"/api/findings/(?P<finding_id>[A-Za-z0-9_-]+)/fix")
def post_fix(request, finding_id: str) -> Tuple[int, Any]:
    """Queue a fix. The board never edits code itself - it asks."""
    store = request.api.fresh()
    finding = store.get(finding_id)
    if finding is None:
        return 404, {"error": "not found"}
    finding.set_status(models.QUEUED)
    note = (request.json.get("note") or "").strip()[:MAX_COMMENT]
    if note:
        finding.add_comment(request.api.config.author, f"Fix requested: {note}")
    store.put(finding)
    store.save()
    action = request.api.queue.push(
        FIX, finding.id, author=request.api.config.author, note=note,
        title=finding.title, path=finding.path, line=finding.line,
    )
    return 200, {"finding": _finding_json(finding), "action": action.to_dict()}


@router.post(r"/api/fix")
def post_fix_batch(request) -> Tuple[int, Any]:
    ids = request.json.get("finding_ids") or []
    if not isinstance(ids, list) or not ids:
        return 400, {"error": "finding_ids must be a non-empty list"}
    store = request.api.fresh()
    queued: List[str] = []
    for finding_id in ids[:200]:
        finding = store.get(str(finding_id))
        if finding is None:
            continue
        finding.set_status(models.QUEUED)
        store.put(finding)
        queued.append(finding.id)
    store.save()
    action = request.api.queue.push(
        FIX_ALL, author=request.api.config.author, finding_ids=queued,
        note=(request.json.get("note") or "")[:MAX_COMMENT],
    )
    return 200, {"queued": queued, "action": action.to_dict()}


@router.post(r"/api/rescan")
def post_rescan(request) -> Tuple[int, Any]:
    action = request.api.queue.push(RESCAN, author=request.api.config.author)
    return 200, {"action": action.to_dict()}


@router.get(r"/api/queue")
def get_queue(request) -> Tuple[int, Any]:
    queue = request.api.queue
    return 200, {"actions": [a.to_dict() for a in queue.all()], "stats": queue.stats()}


@router.get(r"/api/source")
def get_source(request) -> Tuple[int, Any]:
    path = request.query.get("path") or ""
    try:
        line = int(request.query.get("line") or 0)
        radius = min(int(request.query.get("radius") or CONTEXT_RADIUS), 60)
    except ValueError:
        return 400, {"error": "line and radius must be integers"}
    payload = _read_source(request.api.root, path, line, radius)
    if payload is None:
        return 404, {"error": "file not readable"}
    return 200, payload


@router.get(r"/api/health")
def get_health(request) -> Tuple[int, Any]:
    return 200, {"ok": True, "root": request.api.root}


# --- helpers -----------------------------------------------------------------
def _safe_path(root: str, relative: str) -> Optional[str]:
    """Resolve inside the repo or refuse. The board reads arbitrary paths on
    request, so this is the one place traversal actually matters."""
    if not relative:
        return None
    root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, relative))
    if candidate != root and not candidate.startswith(root + os.sep):
        return None
    return candidate if os.path.isfile(candidate) else None


def _read_source(root: str, relative: str, line: int, radius: int) -> Optional[Dict[str, Any]]:
    path = _safe_path(root, relative)
    if path is None:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    if line <= 0:
        start, end = 0, min(len(lines), radius * 2)
    else:
        start = max(0, line - 1 - radius)
        end = min(len(lines), line + radius)
    return {
        "path": relative,
        "start_line": start + 1,
        "focus_line": line,
        "total_lines": len(lines),
        "lines": lines[start:end],
    }


def _context(root: str, finding: Finding) -> Optional[Dict[str, Any]]:
    return _read_source(root, finding.path, finding.line, CONTEXT_RADIUS)
