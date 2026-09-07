#!/usr/bin/env python3
"""Run redassay against real repositories and summarise what it found.

Fixtures prove a rule still fires. They cannot tell you whether the output is
*usable*, because a fixture contains nothing but vulnerabilities. That question
only has an answer on real code, so this script scans whatever repositories you
point it at and prints the shape of the result: counts, rule frequency, and the
files that carry the most risk.

    python3 tools/evaluate.py ~/src/my-app ~/src/other-app
    python3 tools/evaluate.py --json ~/src/*/

Reading the output is the actual work. A rule near the top of the frequency
table on a repository you know well is either genuinely important or a false
positive generator, and only someone who reads the hits can say which.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "engine"))

from redassay import config as config_mod, severity as sev, triage as triage_mod  # noqa: E402
from redassay.engine import scan  # noqa: E402


def evaluate(path: str, min_severity: str = "info") -> Dict[str, Any]:
    result = scan(config_mod.load(path, min_severity=min_severity))
    findings = result.findings
    return {
        "repo": os.path.basename(os.path.abspath(path.rstrip("/"))),
        "path": os.path.abspath(path),
        "files": result.files_scanned,
        "megabytes": round(result.bytes_scanned / 1e6, 1),
        "seconds": round(result.duration, 2),
        "total": len(findings),
        "per_kloc": _per_kloc(findings, result.bytes_scanned),
        "counts": result.counts_by_severity(),
        "confidence": dict(Counter(f.confidence for f in findings)),
        "sources": dict(Counter(f.source for f in findings)),
        "top_rules": Counter(f.rule_id for f in findings).most_common(12),
        "hotspots": [
            {"path": p, "count": c, "risk": r}
            for p, c, r in triage_mod.hotspots(findings, limit=6)
        ],
        "errors": result.errors,
    }


def _per_kloc(findings, total_bytes: int) -> float:
    """Findings per thousand lines, assuming ~35 bytes per line.

    A crude denominator, but the point is comparability between repositories,
    not precision: 2 per kLOC is a usable report, 40 is a wall of noise.
    """
    approx_lines = max(total_bytes / 35.0, 1.0)
    return round(len(findings) / (approx_lines / 1000.0), 2)


def render(report: Dict[str, Any]) -> str:
    out: List[str] = []
    out.append(f"{report['repo']}")
    out.append(f"  {report['files']} files, {report['megabytes']} MB, {report['seconds']}s")
    counts = " ".join(
        f"{report['counts'][name]} {name}" for name in sev.ORDER if report["counts"].get(name)
    )
    out.append(f"  {report['total']} findings ({counts or 'none'})")
    out.append(f"  ~{report['per_kloc']} per kLOC")
    confidence = report["confidence"]
    out.append(
        "  confidence: "
        + ", ".join(f"{confidence.get(level, 0)} {level}" for level in ("high", "medium", "low"))
    )
    if report["errors"]:
        out.append(f"  errors: {report['errors']}")
    out.append("  most frequent rules:")
    for rule_id, count in report["top_rules"]:
        out.append(f"    {count:5}  {rule_id}")
    out.append("  hotspots:")
    for spot in report["hotspots"]:
        out.append(f"    {spot['risk']:8.1f}  {spot['count']:4}  {spot['path']}")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repos", nargs="+")
    parser.add_argument("--min-severity", default="info", choices=sev.ORDER)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    reports = []
    for path in args.repos:
        if not os.path.isdir(path):
            print(f"skipping {path}: not a directory", file=sys.stderr)
            continue
        reports.append(evaluate(path, args.min_severity))

    if args.json:
        print(json.dumps(reports, indent=2))
        return 0

    for report in reports:
        print(render(report))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
