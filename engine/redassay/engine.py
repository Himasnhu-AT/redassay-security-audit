"""Scan orchestration: walk, run scanners, triage, merge."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from . import gitinfo, models, severity as sev, triage as triage_mod
from .config import Config
from .models import Finding
from .scanners import ScanContext, build_all
from .store import MergeResult, Store
from .walker import SourceFile, WalkOptions, collect, summarize

ProgressFn = Callable[[str, Dict[str, Any]], None]


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    by_language: Dict[str, int] = field(default_factory=dict)
    duration: float = 0.0
    scanners_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    merge: Optional[MergeResult] = None
    git: Dict[str, Any] = field(default_factory=dict)
    scoped_to: List[str] = field(default_factory=list)

    def counts_by_severity(self) -> Dict[str, int]:
        out = {name: 0 for name in sev.ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": models.utcnow(),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "by_language": self.by_language,
            "duration_seconds": round(self.duration, 3),
            "scanners": list(self.scanners_run),
            "counts": self.counts_by_severity(),
            "total": len(self.findings),
            "errors": list(self.errors),
            "merge": self.merge.to_dict() if self.merge else None,
            "git": dict(self.git),
            "scoped_to": list(self.scoped_to),
        }


def scan(
    config: Config,
    progress: Optional[ProgressFn] = None,
    extra_rule_dirs: Optional[Sequence[str]] = None,
    since: Optional[str] = None,
    blame: bool = False,
) -> ScanResult:
    """Run every enabled scanner over the configured root.

    `since` restricts the walk to files that differ from a git ref, which is what
    makes this usable as a pull-request gate rather than a one-off inventory.
    """
    started = time.time()
    emit = progress or (lambda event, data: None)

    include = list(config.include)
    scoped_to: List[str] = []
    if since:
        changed = gitinfo.changed_files(config.root, since)
        if changed is None:
            raise ValueError(
                f"cannot diff against '{since}' - not a git repository, or the ref does not exist"
            )
        if not changed:
            emit("walk:done", {"files": 0, "bytes": 0, "languages": {}})
            return ScanResult(
                duration=time.time() - started,
                git=gitinfo.context(config.root),
                scoped_to=[],
            )
        # An explicit --include intersects with the diff rather than replacing it.
        include = [p for p in changed if not config.include or any(
            p == g.rstrip("/") or p.startswith(g.rstrip("/") + "/") for g in config.include
        )]
        scoped_to = list(include)

    options = WalkOptions(
        include=include,
        exclude=list(config.exclude),
        max_bytes=config.max_file_bytes,
        respect_gitignore=config.respect_gitignore,
    )
    emit("walk:start", {"root": config.root})
    files = collect(config.root, options)
    total_bytes, by_language = summarize(files)
    emit("walk:done", {"files": len(files), "bytes": total_bytes, "languages": by_language})

    rule_dirs = list(extra_rule_dirs or [])
    local_rules = os.path.join(config.root, ".redassay", "rules")
    if os.path.isdir(local_rules):
        rule_dirs.append(local_rules)

    scanners = build_all(
        include=config.scanners or None,
        exclude=config.disabled_scanners or None,
        extra_rule_dirs=rule_dirs,
    )
    context = ScanContext(root=config.root, files=files, disabled_rules=list(config.disabled_rules))

    findings: List[Finding] = []
    errors: List[str] = []
    for scanner in scanners:
        emit("scanner:start", {"name": scanner.name})
        produced = 0
        try:
            for finding in scanner.scan(context):
                findings.append(finding)
                produced += 1
        except Exception as exc:                                  # a broken scanner must not kill the scan
            errors.append(f"{scanner.name}: {type(exc).__name__}: {exc}")
        emit("scanner:done", {"name": scanner.name, "findings": produced})

    findings = triage_mod.triage(findings, min_severity=config.min_severity)
    emit("triage:done", {"findings": len(findings)})

    if blame:
        annotated = gitinfo.annotate(config.root, findings)
        emit("blame:done", {"annotated": annotated})

    return ScanResult(
        findings=findings,
        files_scanned=len(files),
        bytes_scanned=total_bytes,
        by_language=by_language,
        duration=time.time() - started,
        scanners_run=[s.name for s in scanners],
        errors=errors,
        git=gitinfo.context(config.root),
        scoped_to=scoped_to,
    )


def scan_and_merge(
    config: Config,
    progress: Optional[ProgressFn] = None,
    store: Optional[Store] = None,
    since: Optional[str] = None,
    blame: bool = False,
) -> ScanResult:
    """Scan, fold the result into the store, and record the run."""
    result = scan(config, progress=progress, since=since, blame=blame)
    store = store or Store.open(config.root)
    # A scoped scan must not retire findings in files it never opened.
    scope = result.scoped_to or list(config.include) or ["."]
    result.merge = store.merge(result.findings, scanned_paths=scope)
    entry = result.to_dict()
    store.record_scan(entry)
    store.save()
    return result


def exit_code(result: ScanResult, fail_on: Optional[str]) -> int:
    """0 unless something at or above `fail_on` is open. For CI."""
    if not fail_on:
        return 0
    for finding in result.findings:
        if sev.at_least(finding.severity, fail_on):
            return 1
    return 0
