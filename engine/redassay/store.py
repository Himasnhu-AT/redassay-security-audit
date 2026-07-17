"""The findings repo: `.redassay/` on disk.

Design constraints that shaped this file:

* The CLI and the board server both write to it, from different processes, so
  writes take a lock and land atomically via os.replace.
* Re-scanning must never lose a human decision. A dismissal is expensive to
  make and cheap to lose, so merge() is conservative: it refreshes where the
  code is, never what the human said about it.
* The JSON has to stay diffable. Findings are stored sorted by id with indent=2
  so a commit of `.redassay/findings.json` reads like a changelog.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional

from . import models, severity as sev
from .models import Finding, Fix, Location

SCHEMA_VERSION = 2
STORE_DIRNAME = ".redassay"
FINDINGS_FILE = "findings.json"
ACTIONS_FILE = "actions.jsonl"
LOCK_FILE = ".lock"


class StoreError(RuntimeError):
    pass


class LockTimeout(StoreError):
    pass


class _FileLock:
    """Cooperative lock. Good enough: both writers are ours and short-lived."""

    def __init__(self, path: str, timeout: float = 10.0, poll: float = 0.02):
        self.path = path
        self.timeout = timeout
        self.poll = poll
        self._fd: Optional[int] = None

    def __enter__(self) -> "_FileLock":
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, str(os.getpid()).encode())
                return self
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                if self._is_stale():
                    self._break()
                    continue
                if time.time() > deadline:
                    raise LockTimeout(f"could not acquire {self.path}")
                time.sleep(self.poll)

    def __exit__(self, *_exc: Any) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def _is_stale(self, max_age: float = 60.0) -> bool:
        try:
            return (time.time() - os.path.getmtime(self.path)) > max_age
        except OSError:
            return False

    def _break(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


@dataclass
class MergeResult:
    """What a scan did to the store."""

    added: List[str] = field(default_factory=list)
    updated: List[str] = field(default_factory=list)
    regressed: List[str] = field(default_factory=list)
    verified: List[str] = field(default_factory=list)
    absent: List[str] = field(default_factory=list)
    suppressed: List[str] = field(default_factory=list)

    @property
    def total_seen(self) -> int:
        return len(self.added) + len(self.updated) + len(self.regressed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added": list(self.added),
            "updated": list(self.updated),
            "regressed": list(self.regressed),
            "verified": list(self.verified),
            "absent": list(self.absent),
            "suppressed": list(self.suppressed),
        }

    def summary(self) -> str:
        bits = [
            f"{len(self.added)} new",
            f"{len(self.updated)} still present",
        ]
        if self.regressed:
            bits.append(f"{len(self.regressed)} regressed")
        if self.verified:
            bits.append(f"{len(self.verified)} verified fixed")
        if self.suppressed:
            bits.append(f"{len(self.suppressed)} suppressed")
        return ", ".join(bits)


class Store:
    """Read/write access to one repo's `.redassay/` directory."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.dir = os.path.join(self.root, STORE_DIRNAME)
        self.path = os.path.join(self.dir, FINDINGS_FILE)
        self.actions_path = os.path.join(self.dir, ACTIONS_FILE)
        self._data: Optional[Dict[str, Any]] = None

    # -- lifecycle -----------------------------------------------------------
    @classmethod
    def open(cls, root: str) -> "Store":
        store = cls(root)
        store.load()
        return store

    @property
    def exists(self) -> bool:
        return os.path.isfile(self.path)

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def _blank(self) -> Dict[str, Any]:
        now = models.utcnow()
        return {
            "schema_version": SCHEMA_VERSION,
            "repo": os.path.basename(self.root),
            "root": self.root,
            "created_at": now,
            "updated_at": now,
            "scans": [],
            "findings": {},
            "suppressions": [],
        }

    def load(self, force: bool = False) -> Dict[str, Any]:
        if self._data is not None and not force:
            return self._data
        if not self.exists:
            self._data = self._blank()
            return self._data
        with open(self.path, "r", encoding="utf-8") as handle:
            try:
                raw = json.load(handle)
            except json.JSONDecodeError as exc:
                raise StoreError(f"{self.path} is not valid JSON: {exc}") from exc
        self._data = migrate(raw)
        return self._data

    def save(self) -> None:
        data = self.load()
        data["updated_at"] = models.utcnow()
        data["schema_version"] = SCHEMA_VERSION
        self.ensure_dir()
        with _FileLock(os.path.join(self.dir, LOCK_FILE)):
            tmp = self.path + f".tmp.{os.getpid()}"
            payload = json.dumps(_ordered(data), indent=2, sort_keys=False)
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)

    def reload(self) -> Dict[str, Any]:
        return self.load(force=True)

    # -- reads ---------------------------------------------------------------
    def __len__(self) -> int:
        return len(self.load()["findings"])

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.all())

    def all(self) -> List[Finding]:
        raw = self.load()["findings"]
        return [Finding.from_dict(value) for value in raw.values()]

    def get(self, finding_id: str) -> Optional[Finding]:
        raw = self.load()["findings"].get(finding_id)
        if raw is None:
            match = self._resolve_prefix(finding_id)
            if match is None:
                return None
            raw = self.load()["findings"][match]
        return Finding.from_dict(raw)

    def _resolve_prefix(self, prefix: str) -> Optional[str]:
        if len(prefix) < 4:
            return None
        hits = [key for key in self.load()["findings"] if key.startswith(prefix)]
        return hits[0] if len(hits) == 1 else None

    def put(self, finding: Finding) -> None:
        self.load()["findings"][finding.id] = finding.to_dict()

    def delete(self, finding_id: str) -> bool:
        findings = self.load()["findings"]
        key = finding_id if finding_id in findings else self._resolve_prefix(finding_id)
        if key is None:
            return False
        findings.pop(key)
        return True

    def query(
        self,
        status: Optional[Iterable[str]] = None,
        severity_floor: Optional[str] = None,
        path_prefix: Optional[str] = None,
        source: Optional[str] = None,
        rule_id: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Finding]:
        wanted = set(status) if status else None
        results = []
        for finding in self.all():
            if wanted and finding.status not in wanted:
                continue
            if severity_floor and not sev.at_least(finding.severity, severity_floor):
                continue
            if path_prefix and not finding.path.startswith(path_prefix):
                continue
            if source and finding.source != source:
                continue
            if rule_id and finding.rule_id != rule_id:
                continue
            if tag and tag not in finding.tags:
                continue
            results.append(finding)
        return sort_findings(results)

    def stats(self) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {name: 0 for name in sev.ORDER}
        by_status: Dict[str, int] = {name: 0 for name in models.STATUSES}
        by_source: Dict[str, int] = {}
        for finding in self.all():
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_status[finding.status] = by_status.get(finding.status, 0) + 1
            by_source[finding.source] = by_source.get(finding.source, 0) + 1
        data = self.load()
        return {
            "total": len(data["findings"]),
            "open": sum(by_status.get(s, 0) for s in models.ACTIONABLE),
            "by_severity": by_severity,
            "by_status": by_status,
            "by_source": by_source,
            "scans": len(data.get("scans") or []),
            "updated_at": data.get("updated_at"),
        }

    # -- mutations -----------------------------------------------------------
    def set_status(self, finding_id: str, status: str, strict: bool = False) -> Optional[Finding]:
        finding = self.get(finding_id)
        if finding is None:
            return None
        finding.set_status(status, strict=strict)
        self.put(finding)
        return finding

    def add_comment(self, finding_id: str, author: str, body: str) -> Optional[Finding]:
        finding = self.get(finding_id)
        if finding is None:
            return None
        finding.add_comment(author, body)
        self.put(finding)
        return finding

    def record_fix(self, finding_id: str, fix: Fix, status: str = models.FIXED) -> Optional[Finding]:
        finding = self.get(finding_id)
        if finding is None:
            return None
        if not fix.applied_at:
            fix.applied_at = models.utcnow()
        finding.fix = fix
        finding.set_status(status)
        self.put(finding)
        return finding

    def suppress(self, rule_id: str, path_glob: str = "*", reason: str = "") -> Dict[str, Any]:
        entry = {
            "rule_id": rule_id,
            "path": path_glob,
            "reason": reason,
            "created_at": models.utcnow(),
        }
        self.load().setdefault("suppressions", []).append(entry)
        return entry

    def suppressions(self) -> List[Dict[str, Any]]:
        return list(self.load().get("suppressions") or [])

    # -- merge ---------------------------------------------------------------
    def merge(self, incoming: Iterable[Finding], scanned_paths: Optional[Iterable[str]] = None) -> MergeResult:
        """Fold a scan's output into the store without trampling human decisions."""
        from .suppress import is_suppressed  # local import: avoids a cycle

        data = self.load()
        findings = data["findings"]
        result = MergeResult()
        rules = self.suppressions()
        seen: set = set()

        for finding in incoming:
            if is_suppressed(finding, rules):
                result.suppressed.append(finding.id)
                continue
            seen.add(finding.id)
            existing_raw = findings.get(finding.id)
            if existing_raw is None:
                findings[finding.id] = finding.to_dict()
                result.added.append(finding.id)
                continue

            existing = Finding.from_dict(existing_raw)
            # Refresh where it is and what the scanner currently says about it.
            existing.location = finding.location
            existing.extra_locations = finding.extra_locations
            existing.last_seen = finding.last_seen
            existing.severity = finding.severity
            existing.confidence = finding.confidence
            if finding.description:
                existing.description = finding.description
            if finding.remediation and not existing.remediation:
                existing.remediation = finding.remediation
            existing.tags = sorted(set(existing.tags) | set(finding.tags))

            if existing.status in (models.FIXED, models.VERIFIED):
                existing.status = models.OPEN
                existing.add_comment("redassay", "Reappeared in a later scan - reopening.")
                result.regressed.append(existing.id)
            else:
                result.updated.append(existing.id)
            findings[existing.id] = existing.to_dict()

        scoped = _path_scope(scanned_paths)
        for key, raw in list(findings.items()):
            if key in seen:
                continue
            stored = Finding.from_dict(raw)
            if scoped is not None and not _in_scope(stored.path, scoped):
                continue
            result.absent.append(key)
            if stored.status in (models.FIXED, models.FIXING):
                stored.set_status(models.VERIFIED)
                stored.add_comment("redassay", "No longer reproduced by the scanner.")
                findings[key] = stored.to_dict()
                result.verified.append(key)
        return result

    def record_scan(self, entry: Dict[str, Any], keep: int = 50) -> None:
        scans = self.load().setdefault("scans", [])
        scans.append(entry)
        del scans[:-keep]

    def last_scan(self) -> Optional[Dict[str, Any]]:
        scans = self.load().get("scans") or []
        return scans[-1] if scans else None

    def destroy(self) -> None:
        if os.path.isdir(self.dir):
            shutil.rmtree(self.dir)
        self._data = None


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Worst first, then by location, so the board has a stable order."""
    return sorted(
        findings,
        key=lambda f: (sev.rank(f.severity), _confidence_rank(f.confidence), f.path, f.line, f.id),
    )


_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _confidence_rank(value: str) -> int:
    return _CONF_RANK.get(value, 1)


def _ordered(data: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(data)
    out["findings"] = {key: data["findings"][key] for key in sorted(data["findings"])}
    return out


def _path_scope(paths: Optional[Iterable[str]]) -> Optional[List[str]]:
    if paths is None:
        return None
    scope = [p.replace("\\", "/").rstrip("/") for p in paths]
    return scope or None


def _in_scope(path: str, scope: List[str]) -> bool:
    for prefix in scope:
        if prefix in ("", "."):
            return True
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def migrate(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Bring an older store forward. Cheap now, valuable the first time it matters."""
    version = int(raw.get("schema_version") or 1)
    if version < 2:
        # v1 stored findings as a list and had no suppression table.
        if isinstance(raw.get("findings"), list):
            raw["findings"] = {item.get("id", ""): item for item in raw["findings"] if item.get("id")}
        raw.setdefault("suppressions", [])
        raw["schema_version"] = 2
    raw.setdefault("findings", {})
    raw.setdefault("scans", [])
    raw.setdefault("suppressions", [])
    return raw
