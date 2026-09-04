"""redassay command line.

Two audiences share this interface. A human types `scan`, `list`, `serve`. An
agent types `queue pull`, `add`, `resolve` and reads the JSON. Every command
therefore takes `--json`, and the JSON shape is part of the contract.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__, config as config_mod, engine, models, queue as queue_mod
from . import report as report_mod, sarif as sarif_mod, severity as sev, triage as triage_mod
from .models import Finding, Fix, Location
from .store import Store

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _out(message: str = "") -> None:
    print(message, file=sys.stdout)


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _emit_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2))


def _color_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    return report_mod.supports_color(sys.stdout)


# --- commands ----------------------------------------------------------------
IGNORE_TEMPLATE = """\
# Paths redassay should not scan. gitignore syntax; read alongside .gitignore.
#
# Test suites are the usual first entry. They construct malicious input on
# purpose, so they produce findings that are technically correct and never
# actionable - on Django, 59% of all findings come from its own tests.
# Uncomment what applies to this repository.

# tests/
# **/tests/
# spec/
# **/__tests__/
# **/*.test.js
# **/*.spec.ts

# Vendored or generated code you do not own:
# vendor/
# third_party/
# **/generated/
# **/*_pb2.py
"""


def cmd_init(args: argparse.Namespace) -> int:
    config = config_mod.load(args.root)
    store = Store(config.root)
    store.ensure_dir()
    store.save()
    path = config_mod.save(config)
    created = []

    gitignore = os.path.join(config.root, ".gitignore")
    if os.path.isfile(gitignore):
        body = open(gitignore, "r", encoding="utf-8").read()
        if ".redassay" not in body:
            with open(gitignore, "a", encoding="utf-8") as handle:
                handle.write("\n# redassay findings store\n.redassay/\n")
            created.append(".gitignore entry")

    # A starter ignore file, commented out. Writing it empty-but-explained is
    # better than leaving people to discover the feature after their first scan
    # comes back 60% test code.
    ignore_path = os.path.join(config.root, ".redassayignore")
    if not os.path.exists(ignore_path):
        with open(ignore_path, "w", encoding="utf-8") as handle:
            handle.write(IGNORE_TEMPLATE)
        created.append(".redassayignore")

    if args.json:
        _emit_json({"store": store.path, "config": path, "created": created})
    else:
        _out(f"Initialized {store.dir}")
        _out(f"  findings  {store.path}")
        _out(f"  config    {path}")
        if ".redassayignore" in created:
            _out(f"  ignore    {ignore_path}  (starter template, all commented out)")
        _out("")
        _out("Next:  redassay scan")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    config = config_mod.load(
        args.root,
        min_severity=args.min_severity,
        include=args.include or [],
        exclude=args.exclude or [],
        scanners=args.scanner or [],
        disabled_scanners=args.skip_scanner or [],
        exclude_tests=args.exclude_tests or None,
        fail_on=args.fail_on,
    )
    quiet = args.json or args.quiet

    def progress(event: str, data: Dict[str, Any]) -> None:
        if quiet:
            return
        if event == "walk:done":
            _out(f"  {data['files']} files, {data['bytes'] // 1024} KiB")
        elif event == "scanner:done" and data["findings"]:
            _out(f"  {data['name']:<14} {data['findings']}")

    if not quiet:
        _out(f"Scanning {config.root}")

    store = Store.open(config.root)
    try:
        result = engine.scan_and_merge(
            config, progress=progress, store=store, since=args.since, blame=args.blame
        )
    except ValueError as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR

    if args.new_only:
        known = baseline_ids(config.root)
        result.findings = [f for f in result.findings if f.id not in known]

    if args.json:
        _emit_json({
            "scan": result.to_dict(),
            "findings": [f.to_dict() for f in result.findings],
        })
    else:
        _out("")
        _out(report_mod.terminal(result.findings, color=_color_enabled(args), limit=args.limit,
                                 show_remediation=args.verbose))
        _out("")
        _out(f"{len(result.findings)} findings   {report_mod.summary_line(result.findings, _color_enabled(args))}")
        if args.since:
            _out(f"scope: {len(result.scoped_to)} files changed since {args.since}")
        if result.merge:
            _out(f"store: {result.merge.summary()}")
        if result.errors:
            for error in result.errors:
                _err(f"scanner error: {error}")
        _out(f"\nReview them:  redassay serve --root {config.root}")

    if args.fail_on:
        return engine.exit_code(result, args.fail_on)
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    statuses = args.status or ([] if args.all else list(models.ACTIONABLE))
    findings = store.query(
        status=statuses or None,
        severity_floor=args.min_severity,
        path_prefix=args.path,
        source=args.source,
        rule_id=args.rule,
        tag=args.tag,
    )
    findings = triage_mod.rank(findings)
    if args.json:
        _emit_json({"findings": [f.to_dict() for f in findings], "count": len(findings)})
        return EXIT_OK
    if not findings:
        _out("Nothing matches.")
        return EXIT_OK
    _out(report_mod.terminal(findings, color=_color_enabled(args), limit=args.limit,
                             show_remediation=args.verbose))
    _out(f"\n{len(findings)} findings   {report_mod.summary_line(findings, _color_enabled(args))}")
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    finding = store.get(args.id)
    if finding is None:
        _err(f"no finding matching '{args.id}'")
        return EXIT_ERROR
    if args.json:
        _emit_json(finding.to_dict())
        return EXIT_OK
    color = _color_enabled(args)
    _out(report_mod.terminal([finding], color=color, show_remediation=True))
    _out(f"status: {finding.status}   source: {finding.source}   first seen: {finding.first_seen}")
    if finding.description:
        _out("")
        _out(finding.description)
    if finding.comments:
        _out("\nComments:")
        for comment in finding.comments:
            _out(f"  [{comment.created_at}] {comment.author}: {comment.body}")
    if not finding.fix.is_empty:
        _out(f"\nFix applied {finding.fix.applied_at} by {finding.fix.applied_by}")
        _out(f"  {finding.fix.summary}")
    context = _source_context(args.root, finding)
    if context:
        _out("\nContext:")
        _out(context)
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    finding = store.set_status(args.id, args.status, strict=args.strict)
    if finding is None:
        _err(f"no finding matching '{args.id}'")
        return EXIT_ERROR
    store.save()
    if args.json:
        _emit_json(finding.to_dict())
    else:
        _out(f"{finding.id} -> {finding.status}")
    return EXIT_OK


def cmd_comment(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    body = args.body if args.body else sys.stdin.read().strip()
    finding = store.add_comment(args.id, args.author, body)
    if finding is None:
        _err(f"no finding matching '{args.id}'")
        return EXIT_ERROR
    store.save()
    if args.json:
        _emit_json(finding.to_dict())
    else:
        _out(f"comment added to {finding.id}")
    return EXIT_OK


def cmd_dismiss(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    finding = store.get(args.id)
    if finding is None:
        _err(f"no finding matching '{args.id}'")
        return EXIT_ERROR
    finding.set_status(models.DISMISSED)
    finding.add_comment(args.author, args.reason or "Dismissed without a reason.")
    store.put(finding)
    if args.suppress_rule:
        store.suppress(finding.rule_id, args.path_glob or finding.path, args.reason or "")
    store.save()
    if args.json:
        _emit_json(finding.to_dict())
    else:
        _out(f"dismissed {finding.id}")
        if args.suppress_rule:
            _out(f"suppressed rule {finding.rule_id} for {args.path_glob or finding.path}")
    return EXIT_OK


def cmd_resolve(args: argparse.Namespace) -> int:
    """Record that a fix was applied. This is how an agent closes the loop."""
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    diff = args.diff or ""
    if args.diff_file == "-":
        # `git diff -- app/views.py | redassay resolve <id> --diff-file -`
        # is the shortest honest way for an agent to record what it changed.
        diff = sys.stdin.read()
    elif args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8") as handle:
            diff = handle.read()
    if args.auto_files and diff and not args.file:
        args.file = _files_from_diff(diff)
    fix = Fix(
        summary=args.summary,
        diff=diff,
        applied_by=args.author,
        files_touched=args.file or [],
    )
    finding = store.record_fix(args.id, fix, status=models.FIXED)
    if finding is None:
        _err(f"no finding matching '{args.id}'")
        return EXIT_ERROR
    store.save()
    if args.json:
        _emit_json(finding.to_dict())
    else:
        _out(f"{finding.id} marked fixed: {args.summary}")
    return EXIT_OK


def cmd_add(args: argparse.Namespace) -> int:
    """Ingest findings from JSON on stdin - the model-driven half of the pipeline."""
    store = _require_store(args.root, create=True)
    if store is None:
        return EXIT_ERROR
    raw = sys.stdin.read() if args.stdin else open(args.file, "r", encoding="utf-8").read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        _err(f"invalid JSON: {exc}")
        return EXIT_ERROR
    items = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        _err("expected a list of findings, or an object with a 'findings' key")
        return EXIT_ERROR

    incoming: List[Finding] = []
    for item in items:
        item.setdefault("source", args.source)
        finding = Finding.from_dict(item)
        if not finding.location.path:
            _err(f"skipping finding without a path: {finding.title}")
            continue
        incoming.append(finding)

    result = store.merge(incoming, scanned_paths=None)
    store.save()
    if args.json:
        _emit_json({"merged": result.to_dict(), "ids": [f.id for f in incoming]})
    else:
        _out(f"added {len(result.added)}, updated {len(result.updated)}")
        for finding in incoming:
            _out(f"  {finding.id}  {finding.severity:8} {finding.title}")
    return EXIT_OK


def cmd_queue(args: argparse.Namespace) -> int:
    queue = queue_mod.ActionQueue(args.root)
    store = Store.open(args.root)

    if args.queue_command == "list":
        actions = queue.all() if args.all else queue.pending(agent_only=not args.include_settled)
        payload = [a.to_dict() for a in actions]
        if args.json:
            _emit_json({"actions": payload, "stats": queue.stats()})
        else:
            if not actions:
                _out("queue is empty")
            for action in actions:
                _out(f"  #{action.seq}  {action.state:8} {action.describe()}")
        return EXIT_OK

    if args.queue_command == "pull":
        claimed = queue.claim(limit=args.limit)
        enriched = []
        for action in claimed:
            entry = action.to_dict()
            targets = action.payload.get("finding_ids") or ([action.finding_id] if action.finding_id else [])
            entry["findings"] = [
                store.get(fid).to_dict() for fid in targets if store.get(fid) is not None
            ]
            enriched.append(entry)
        if args.json or True:          # pull is machine-facing; always JSON
            _emit_json({"claimed": enriched, "count": len(enriched)})
        return EXIT_OK

    if args.queue_command == "complete":
        action = queue.complete(args.seq, result=args.result or "", state=args.state)
        if action is None:
            _err(f"no action #{args.seq}")
            return EXIT_ERROR
        if args.json:
            _emit_json(action.to_dict())
        else:
            _out(f"#{action.seq} -> {action.state}")
        return EXIT_OK

    if args.queue_command == "push":
        payload = json.loads(args.payload) if args.payload else {}
        action = queue.push(args.kind, args.id or "", author=args.author, **payload)
        if args.json:
            _emit_json(action.to_dict())
        else:
            _out(f"queued #{action.seq} {action.describe()}")
        return EXIT_OK

    if args.queue_command == "clear":
        count = queue.clear()
        _out(f"cleared {count} actions")
        return EXIT_OK

    _err("unknown queue command")
    return EXIT_ERROR


def cmd_report(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    statuses = args.status or ([] if args.all else list(models.ACTIONABLE))
    findings = triage_mod.rank(store.query(status=statuses or None, severity_floor=args.min_severity))

    if args.format == "markdown":
        body = report_mod.markdown(findings, title=args.title, repo=os.path.basename(store.root))
    elif args.format == "sarif":
        body = sarif_mod.dumps(findings, tool_version=__version__)
    elif args.format == "quickfix":
        body = report_mod.quickfix(findings)
    elif args.format == "json":
        body = report_mod.as_json(findings, extra={"stats": store.stats()})
    else:
        body = report_mod.terminal(findings, color=False, show_remediation=True)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.write("\n")
        _out(f"wrote {args.output} ({len(findings)} findings)")
    else:
        print(body)
    return EXIT_OK


def cmd_stats(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    stats = store.stats()
    if args.json:
        _emit_json(stats)
        return EXIT_OK
    _out(f"total     {stats['total']}")
    _out(f"open      {stats['open']}")
    _out("")
    _out("by severity")
    for name in sev.ORDER:
        if stats["by_severity"].get(name):
            _out(f"  {name:<10} {stats['by_severity'][name]}")
    _out("")
    _out("by status")
    for name, count in stats["by_status"].items():
        if count:
            _out(f"  {name:<10} {count}")
    hot = triage_mod.hotspots(store.all(), limit=5)
    if hot:
        _out("")
        _out("hotspots")
        for path, count, score in hot:
            _out(f"  {score:>7.1f}  {count:>3}  {path}")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .server.app import serve
    config = config_mod.load(args.root, host=args.host, port=args.port)
    return serve(config, open_browser=not args.no_browser, once=args.once)


def cmd_scanners(args: argparse.Namespace) -> int:
    from .scanners.registry import describe
    entries = describe()
    if args.json:
        _emit_json({"scanners": entries})
        return EXIT_OK
    for entry in entries:
        _out(f"  {entry['name']:<14} {entry['description']}")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from . import rules as rule_packs
    local = os.path.join(os.path.abspath(args.root), ".redassay", "rules")
    entries = rule_packs.load_all([local] if os.path.isdir(local) else None)
    if args.pack:
        entries = [r for r in entries if r.get("pack") == args.pack]
    if args.json:
        _emit_json({"rules": entries, "count": len(entries)})
        return EXIT_OK
    by_pack: Dict[str, List[Dict[str, Any]]] = {}
    for rule in entries:
        by_pack.setdefault(rule.get("pack", "?"), []).append(rule)
    for pack, items in sorted(by_pack.items()):
        _out(f"\n{pack} ({len(items)})")
        for rule in sorted(items, key=lambda r: r["id"]):
            _out(f"  {rule.get('severity', 'medium'):<9} {rule['id']:<34} {rule['title']}")
    _out(f"\n{len(entries)} rules")
    return EXIT_OK


def cmd_surface(args: argparse.Namespace) -> int:
    """Inventory the ways in.

    This is the artifact an audit should start from. A scanner tells you which
    lines look dangerous; this tells you what a stranger can reach and what
    stands in front of it - which is the question that decides whether any of
    those lines matter.
    """
    from . import surface as surface_mod, tech as tech_mod
    from .walker import WalkOptions, collect

    config = config_mod.load(args.root, include=args.include or [], exclude=args.exclude or [])
    files = collect(config.root, WalkOptions(
        include=list(config.include),
        exclude=list(config.exclude),
        respect_gitignore=config.respect_gitignore,
        exclude_tests=args.exclude_tests,
    ))
    detection = tech_mod.detect(files)
    entries = surface_mod.inventory(files, detection)
    if args.kind:
        entries = [e for e in entries if e.kind in args.kind]
    if args.unprotected:
        entries = surface_mod.needs_review(entries)

    stats = surface_mod.summarize(entries)
    if args.json:
        _emit_json({
            "tech": detection.to_dict(),
            "summary": stats,
            "entry_points": [e.to_dict() for e in entries],
        })
        return EXIT_OK

    _out(f"stack: {tech_mod.summarize(detection)}")
    _out("")
    if not entries:
        _out("no entry points found")
        _out("  If that is wrong, the framework may not be detected - check `redassay surface --json`")
        return EXIT_OK

    color = _color_enabled(args)
    width = min(max((len(e.label) for e in entries), default=10), 52)
    for entry in entries[: args.limit]:
        mark = _AUTH_MARK.get(entry.auth, "?")
        painted = report_mod._paint(mark, _AUTH_COLOR.get(entry.auth, ""), color)
        _out(f"  {painted} {entry.label[:width]:<{width}}  {entry.location}")
    if args.limit and len(entries) > args.limit:
        _out(f"  ... and {len(entries) - args.limit} more")

    _out("")
    _out(f"{stats['total']} entry points, {stats['externally_reachable']} externally reachable")
    for state, count in sorted(stats["by_auth"].items()):
        _out(f"  {_AUTH_MARK.get(state, '?')} {state:<12} {count}")
    if stats["unprotected"]:
        _out("")
        _out(f"{stats['unprotected']} reachable and mutating with nothing auth-shaped nearby.")
        _out("Proximity is not proof - open them and check. That is the point of the list.")
    return EXIT_OK


_AUTH_MARK = {"guarded": "+", "middleware": "~", "public": "!", "none-found": "x", "unknown": "?"}
_AUTH_COLOR = {
    "guarded": "\033[38;5;35m",
    "middleware": "\033[38;5;220m",
    "public": "\033[38;5;208m",
    "none-found": "\033[38;5;197m",
}


def cmd_history(args: argparse.Namespace) -> int:
    """Scan-over-scan trend. Answers "is this getting better or worse"."""
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    scans = store.scans()[-args.limit:]
    if args.json:
        _emit_json({"scans": scans, "count": len(scans)})
        return EXIT_OK
    if not scans:
        _out("no scans recorded yet")
        return EXIT_OK

    _out(f"{'when':<21}{'files':>7}{'total':>7}{'crit':>6}{'high':>6}{'med':>6}{'new':>6}{'fixed':>7}")
    previous: Optional[int] = None
    for entry in scans:
        counts = entry.get("counts") or {}
        merge = entry.get("merge") or {}
        total = entry.get("total", 0)
        arrow = ""
        if previous is not None and total != previous:
            arrow = " +" if total > previous else " -"
            arrow += str(abs(total - previous))
        previous = total
        _out(
            f"{entry.get('started_at', '')[:19]:<21}"
            f"{entry.get('files_scanned', 0):>7}"
            f"{total:>7}"
            f"{counts.get('critical', 0):>6}"
            f"{counts.get('high', 0):>6}"
            f"{counts.get('medium', 0):>6}"
            f"{len(merge.get('added') or []):>6}"
            f"{len(merge.get('verified') or []):>7}"
            f"{arrow}"
        )
    return EXIT_OK


def cmd_prune(args: argparse.Namespace) -> int:
    """Drop settled findings that have been settled for a while."""
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    statuses = args.status or [models.VERIFIED]
    removed = store.prune(older_than_days=args.older_than, statuses=statuses)
    if not args.dry_run and removed:
        store.save()
    if args.json:
        _emit_json({"removed": removed, "count": len(removed), "dry_run": args.dry_run})
    else:
        verb = "would remove" if args.dry_run else "removed"
        _out(f"{verb} {len(removed)} findings "
             f"({', '.join(statuses)} for more than {args.older_than} days)")
        if args.dry_run and removed:
            _out("re-run without --dry-run to apply")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    """Answer "why is this not working" without a round trip.

    Every check here corresponds to something that has actually gone wrong:
    a Python too old for the engine, a store written by a newer version, a port
    already held by a board someone forgot about, a rule pack with a bad regex.
    """
    import platform
    import socket

    from . import gitinfo
    from . import rules as rule_packs
    from .scanners.pattern import compile_rules
    from .scanners.registry import available

    checks: List[Dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str, fatal: bool = False) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, "fatal": fatal})

    version = sys.version_info
    record(
        "python",
        version >= (3, 9),
        f"{platform.python_version()} ({'ok' if version >= (3, 9) else 'redassay needs 3.9 or newer'})",
        fatal=True,
    )

    try:
        raw = rule_packs.load_all()
        compile_rules(raw)
        record("rule packs", True, f"{len(raw)} rules across {len({r.get('pack') for r in raw})} packs")
    except Exception as exc:                       # noqa: BLE001
        record("rule packs", False, f"{type(exc).__name__}: {exc}", fatal=True)

    try:
        record("scanners", True, ", ".join(available()))
    except Exception as exc:                       # noqa: BLE001
        record("scanners", False, f"{type(exc).__name__}: {exc}", fatal=True)

    try:
        from .scanners.deps import load_advisories
        index = load_advisories()
        count = sum(len(v) for v in index.values())
        record("advisory data", bool(index), f"{count} advisories, {len(index)} packages")
    except Exception as exc:                       # noqa: BLE001
        record("advisory data", False, f"{type(exc).__name__}: {exc}")

    root = os.path.abspath(args.root)
    record("target", os.path.isdir(root), root, fatal=True)
    record("git", gitinfo.is_repo(root),
           gitinfo.current_branch(root) or "not a git repository (--since will not work)")

    store = Store(root)
    if store.exists:
        try:
            data = store.load()
            record("store", data.get("schema_version", 1) <= 2,
                   f"{len(store)} findings, schema v{data.get('schema_version')}")
        except Exception as exc:                   # noqa: BLE001
            record("store", False, f"{type(exc).__name__}: {exc}")
    else:
        record("store", True, "not created yet - run `redassay scan`")

    try:
        # A store that failed to load above must not make this raise - the whole
        # point of doctor is to report a broken store, not to die on one.
        last = store.last_scan() if store.exists else None
    except Exception:                              # noqa: BLE001
        last = None
    if last:
        scanned_with = last.get("engine_version") or "unknown"
        record(
            "store version",
            scanned_with in (__version__, "unknown"),
            f"last scanned with redassay {scanned_with}"
            + ("" if scanned_with in (__version__, "unknown")
               else f" - this is {__version__}; rescan to pick up rule changes"),
        )

    config = config_mod.load(root)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        taken = probe.connect_ex((config.host, config.port)) == 0
    finally:
        probe.close()
    record("board port", not taken,
           f"{config.host}:{config.port} " + ("is already in use - pass --port" if taken else "is free"))

    writable = os.access(root, os.W_OK)
    record("writable", writable, root if writable else f"{root} is not writable")

    if args.json:
        _emit_json({"checks": checks, "ok": all(c["ok"] or not c["fatal"] for c in checks)})
    else:
        for check in checks:
            mark = "ok  " if check["ok"] else ("FAIL" if check["fatal"] else "warn")
            _out(f"  [{mark}] {check['check']:<14} {check['detail']}")
        broken = [c for c in checks if not c["ok"] and c["fatal"]]
        _out("")
        _out("everything looks fine" if not broken else f"{len(broken)} blocking problem(s)")
    return EXIT_ERROR if any(not c["ok"] and c["fatal"] for c in checks) else EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    """Poll the queue and print claimed work as JSON, one batch per line.

    The agent loop lives in the plugin, not here - this exists so the same loop
    can be driven from a terminal, and so `watch` is testable without a model.
    """
    import time

    queue = queue_mod.ActionQueue(args.root)
    store = Store(args.root)
    deadline = time.time() + args.timeout if args.timeout else None
    seen_any = False

    while True:
        claimed = queue.claim(limit=args.limit)
        if claimed:
            seen_any = True
            store.reload()
            for action in claimed:
                entry = action.to_dict()
                targets = action.payload.get("finding_ids") or ([action.finding_id] if action.finding_id else [])
                entry["findings"] = [
                    store.get(fid).to_dict() for fid in targets if store.get(fid) is not None
                ]
                print(json.dumps(entry), flush=True)
            if args.once:
                return EXIT_OK
        elif args.once:
            return EXIT_OK

        if deadline and time.time() > deadline:
            if not seen_any and not args.json:
                _err("watch timed out with nothing queued")
            return EXIT_OK
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 130


BASELINE_FILE = "baseline.json"


def baseline_path(root: str) -> str:
    return os.path.join(os.path.abspath(root), ".redassay", BASELINE_FILE)


def baseline_ids(root: str) -> set:
    try:
        with open(baseline_path(root), "r", encoding="utf-8") as handle:
            return set(json.load(handle).get("ids") or [])
    except (OSError, json.JSONDecodeError):
        return set()


def cmd_baseline(args: argparse.Namespace) -> int:
    """Freeze what exists today so a gate only fails on what gets added.

    The alternative - demanding a team fix four hundred pre-existing findings
    before the check goes green - is how security tooling gets switched off.
    """
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR

    if args.show:
        known = baseline_ids(args.root)
        if args.json:
            _emit_json({"ids": sorted(known), "count": len(known)})
        else:
            _out(f"{len(known)} findings in the baseline")
        return EXIT_OK

    if args.clear:
        try:
            os.unlink(baseline_path(args.root))
            _out("baseline cleared")
        except FileNotFoundError:
            _out("no baseline to clear")
        return EXIT_OK

    findings = store.query(status=list(models.ACTIONABLE))
    payload = {
        "created_at": models.utcnow(),
        "count": len(findings),
        "ids": sorted(f.id for f in findings),
    }
    os.makedirs(os.path.dirname(baseline_path(args.root)), exist_ok=True)
    with open(baseline_path(args.root), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    if args.json:
        _emit_json(payload)
    else:
        _out(f"baselined {len(findings)} open findings")
        _out("future scans with --new-only will report only what is added after this point")
    return EXIT_OK


def cmd_suppress(args: argparse.Namespace) -> int:
    store = _require_store(args.root)
    if store is None:
        return EXIT_ERROR
    entry = store.suppress(args.rule, args.path, args.reason or "")
    store.save()
    if args.json:
        _emit_json(entry)
    else:
        _out(f"suppressed {args.rule} for {args.path}")
    return EXIT_OK


# --- helpers -----------------------------------------------------------------
# `git diff` writes `+++ b/path`; plain `diff -u` writes `+++ path\t<timestamp>`.
# Both have to parse, and the timestamp is not part of the filename.
_DIFF_TARGET = re.compile(r"^\+\+\+ (?:b/)?([^\t\n]+)", re.MULTILINE)


def _files_from_diff(diff: str) -> List[str]:
    """Pull the touched paths out of a unified diff so `--file` is optional."""
    files: List[str] = []
    for match in _DIFF_TARGET.finditer(diff):
        path = match.group(1).strip()
        if not path or path == "/dev/null" or path in files:
            continue
        files.append(path)
    return files


def _require_store(root: str, create: bool = False) -> Optional[Store]:
    store = Store(root)
    if not store.exists and not create:
        _err(f"no findings store in {os.path.abspath(root)} - run `redassay scan` first")
        return None
    store.load()
    return store


def _source_context(root: str, finding: Finding, radius: int = 3) -> str:
    path = os.path.join(os.path.abspath(root), finding.path)
    if not os.path.isfile(path) or not finding.line:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return ""
    start = max(0, finding.line - 1 - radius)
    end = min(len(lines), finding.line + radius)
    out = []
    for index in range(start, end):
        marker = ">" if index + 1 == finding.line else " "
        out.append(f"  {marker} {index + 1:>5} | {lines[index]}")
    return "\n".join(out)


# --- parser ------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redassay",
        description="Scan a codebase for vulnerabilities, triage them, apply the fixes you approve.",
    )
    parser.add_argument("--version", action="version", version=f"redassay {__version__}")
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-color", action="store_true")

    # The same three flags accepted after the subcommand too, because
    # `redassay scan --json` is what everyone types first. SUPPRESS keeps the
    # child from overwriting a value the parent already set.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=argparse.SUPPRESS)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create the findings store", parents=[common])
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", help="run the scanners and merge into the store", parents=[common])
    p.add_argument("--min-severity", default=None, choices=sev.ORDER)
    p.add_argument("--include", action="append", help="limit to these paths/globs (repeatable)")
    p.add_argument("--exclude", action="append", help="skip these globs (repeatable)")
    p.add_argument("--exclude-tests", action="store_true",
                   help="skip test directories and test files - on a framework they can be "
                        "the majority of all findings")
    p.add_argument("--scanner", action="append", help="run only this scanner (repeatable)")
    p.add_argument("--skip-scanner", action="append", help="disable a scanner (repeatable)")
    p.add_argument("--fail-on", default=None, choices=sev.ORDER, help="exit 1 if anything at this level is open")
    p.add_argument("--since", default=None, metavar="REF",
                   help="only scan files that differ from this git ref (e.g. origin/main)")
    p.add_argument("--blame", action="store_true", help="tag findings with the commit and author that last touched the line")
    p.add_argument("--new-only", action="store_true",
                   help="report only findings absent from the baseline")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true", help="include remediation text")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("list", help="list stored findings", parents=[common])
    p.add_argument("--status", action="append", choices=models.STATUSES)
    p.add_argument("--all", action="store_true", help="include dismissed and fixed")
    p.add_argument("--min-severity", default=None, choices=sev.ORDER)
    p.add_argument("--path", default=None, help="restrict to a path prefix")
    p.add_argument("--source", default=None)
    p.add_argument("--rule", default=None)
    p.add_argument("--tag", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="show one finding in full", parents=[common])
    p.add_argument("id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("status", help="move a finding to a new status", parents=[common])
    p.add_argument("id")
    p.add_argument("status", choices=models.STATUSES)
    p.add_argument("--strict", action="store_true", help="fail on an illegal transition")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("comment", help="attach a note to a finding", parents=[common])
    p.add_argument("id")
    p.add_argument("body", nargs="?", default=None, help="omit to read from stdin")
    p.add_argument("--author", default="you")
    p.set_defaults(func=cmd_comment)

    p = sub.add_parser("dismiss", help="mark a finding as not worth fixing", parents=[common])
    p.add_argument("id")
    p.add_argument("--reason", default=None)
    p.add_argument("--author", default="you")
    p.add_argument("--suppress-rule", action="store_true", help="also stop reporting this rule here")
    p.add_argument("--path-glob", default=None)
    p.set_defaults(func=cmd_dismiss)

    p = sub.add_parser("resolve", help="record that a fix was applied", parents=[common])
    p.add_argument("id")
    p.add_argument("--summary", required=True)
    p.add_argument("--diff", default=None)
    p.add_argument("--diff-file", default=None, metavar="PATH",
                   help="read the diff from a file, or - for stdin")
    p.add_argument("--auto-files", action="store_true", default=True,
                   help="derive --file from the diff when not given")
    p.add_argument("--file", action="append", help="file touched by the fix (repeatable)")
    p.add_argument("--author", default="claude")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("add", help="ingest findings from JSON", parents=[common])
    p.add_argument("--file", default=None)
    p.add_argument("--stdin", action="store_true", default=True)
    p.add_argument("--source", default="claude")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("queue", help="the review board's action queue", parents=[common])
    qsub = p.add_subparsers(dest="queue_command", required=True)
    q = qsub.add_parser("list", parents=[common])
    q.add_argument("--all", action="store_true")
    q.add_argument("--include-settled", action="store_true")
    q = qsub.add_parser("pull", help="claim pending actions (JSON)", parents=[common])
    q.add_argument("--limit", type=int, default=None)
    q = qsub.add_parser("complete", parents=[common])
    q.add_argument("seq", type=int)
    q.add_argument("--result", default=None)
    q.add_argument("--state", default=queue_mod.DONE, choices=[queue_mod.DONE, queue_mod.FAILED])
    q = qsub.add_parser("push", parents=[common])
    q.add_argument("kind")
    q.add_argument("--id", default=None)
    q.add_argument("--payload", default=None, help="JSON object")
    q.add_argument("--author", default="you")
    qsub.add_parser("clear", parents=[common])
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("report", help="write a report", parents=[common])
    p.add_argument("--format", default="markdown",
                   choices=["markdown", "json", "sarif", "terminal", "quickfix"])
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--title", default="Security audit")
    p.add_argument("--status", action="append", choices=models.STATUSES)
    p.add_argument("--all", action="store_true")
    p.add_argument("--min-severity", default=None, choices=sev.ORDER)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("stats", help="counts and hotspots", parents=[common])
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("serve", help="start the review board", parents=[common])
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--once", action="store_true", help="handle a single request and exit (for tests)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("scanners", help="list available scanners", parents=[common])
    p.set_defaults(func=cmd_scanners)

    p = sub.add_parser("rules", help="list loaded rules", parents=[common])
    p.add_argument("--pack", default=None)
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("surface", help="inventory the entry points an attacker can reach",
                       parents=[common])
    p.add_argument("--kind", action="append",
                   choices=["http", "server-action", "queue", "socket", "graphql", "cli",
                            "webhook", "scheduled"],
                   help="restrict to one kind of entry point (repeatable)")
    p.add_argument("--unprotected", action="store_true",
                   help="only those with nothing auth-shaped in front of them")
    p.add_argument("--include", action="append")
    p.add_argument("--exclude", action="append")
    p.add_argument("--exclude-tests", action="store_true")
    p.add_argument("--limit", type=int, default=60)
    p.set_defaults(func=cmd_surface)

    p = sub.add_parser("history", help="scan-over-scan trend", parents=[common])
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("prune", help="drop long-settled findings from the store", parents=[common])
    p.add_argument("--older-than", type=int, default=90, metavar="DAYS")
    p.add_argument("--status", action="append", choices=models.STATUSES,
                   help="which statuses to prune (default: verified)")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser("doctor", help="check the environment and the store", parents=[common])
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("watch", help="poll the queue and emit claimed work as JSON", parents=[common])
    p.add_argument("--interval", type=float, default=3.0, help="seconds between polls")
    p.add_argument("--limit", type=int, default=None, help="max actions per batch")
    p.add_argument("--once", action="store_true", help="drain once and exit")
    p.add_argument("--timeout", type=float, default=None, help="give up after this many seconds")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("baseline", help="freeze today's findings so gates only fail on new ones", parents=[common])
    p.add_argument("--show", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("suppress", help="stop reporting a rule for a path", parents=[common])
    p.add_argument("rule")
    p.add_argument("--path", default="*")
    p.add_argument("--reason", default=None)
    p.set_defaults(func=cmd_suppress)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or EXIT_OK)
    except KeyboardInterrupt:
        _err("\ninterrupted")
        return 130
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:                       # noqa: BLE001 - the CLI is the last line of defence
        if os.environ.get("REDASSAY_TRACEBACK"):
            raise
        _err(f"error: {type(exc).__name__}: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
