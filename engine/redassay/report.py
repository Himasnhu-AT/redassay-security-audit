"""Human-readable output: terminal, markdown, JSON, SARIF."""

from __future__ import annotations

import json
import os
import shutil
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import severity as sev, triage as triage_mod
from .models import Finding

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    sev.CRITICAL: "\033[38;5;197m",
    sev.HIGH: "\033[38;5;208m",
    sev.MEDIUM: "\033[38;5;220m",
    sev.LOW: "\033[38;5;110m",
    sev.INFO: "\033[38;5;245m",
}
BADGE = {
    sev.CRITICAL: "CRIT",
    sev.HIGH: "HIGH",
    sev.MEDIUM: "MED ",
    sev.LOW: "LOW ",
    sev.INFO: "INFO",
}


def supports_color(stream: Any = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream and stream.isatty())
    except Exception:
        return False


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def terminal(
    findings: Sequence[Finding],
    color: bool = True,
    limit: Optional[int] = None,
    show_remediation: bool = False,
) -> str:
    if not findings:
        return _paint("No findings.", "\033[38;5;35m", color)
    width = shutil.get_terminal_size((100, 24)).columns
    lines: List[str] = []
    shown = findings[:limit] if limit else findings
    for finding in shown:
        badge = _paint(BADGE[finding.severity], COLORS[finding.severity], color)
        location = _paint(finding.location.label, "\033[38;5;81m", color)
        lines.append(f"{badge}  {location}  {BOLD if color else ''}{finding.title}{RESET if color else ''}")
        meta = f"      {finding.id}  {finding.rule_id}  confidence={finding.confidence}"
        if finding.cwe:
            meta += f"  {', '.join(finding.cwe)}"
        lines.append(_paint(meta, DIM, color))
        snippet = finding.location.snippet.strip()
        if snippet:
            lines.append(_paint(f"      | {snippet[: max(width - 10, 40)]}", DIM, color))
        if show_remediation and finding.remediation:
            for chunk in _wrap(finding.remediation, width - 10):
                lines.append(_paint(f"      -> {chunk}", DIM, color))
        lines.append("")
    if limit and len(findings) > limit:
        lines.append(_paint(f"... and {len(findings) - limit} more", DIM, color))
    return "\n".join(lines).rstrip()


def summary_line(findings: Sequence[Finding], color: bool = True) -> str:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = []
    for name in sev.ORDER:
        if counts.get(name):
            parts.append(_paint(f"{counts[name]} {name}", COLORS[name], color))
    if not parts:
        return _paint("clean", "\033[38;5;35m", color)
    return "  ".join(parts)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    out: List[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        out.append(current)
    return out


def markdown(findings: Sequence[Finding], title: str = "Security audit", repo: str = "") -> str:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    out: List[str] = [f"# {title}", ""]
    if repo:
        out.append(f"Repository: `{repo}`")
        out.append("")
    out.append("| Severity | Count |")
    out.append("| --- | --- |")
    for name in sev.ORDER:
        if counts.get(name):
            out.append(f"| {name} | {counts[name]} |")
    out.append(f"| **total** | **{len(findings)}** |")
    out.append("")

    spots = triage_mod.hotspots(findings, limit=8)
    if spots:
        out.extend(["## Hotspots", "", "| File | Findings | Risk |", "| --- | --- | --- |"])
        for path, count, score in spots:
            out.append(f"| `{path}` | {count} | {score} |")
        out.append("")

    out.append("## Findings")
    out.append("")
    for finding in findings:
        out.append(f"### `{finding.severity.upper()}` {finding.title}")
        out.append("")
        out.append(f"- **id** `{finding.id}` · **rule** `{finding.rule_id}` · **confidence** {finding.confidence}")
        out.append(f"- **location** `{finding.location.label}`")
        if finding.cwe:
            out.append(f"- **CWE** {', '.join(finding.cwe)}")
        if finding.owasp:
            out.append(f"- **OWASP** {', '.join(finding.owasp)}")
        out.append("")
        if finding.description:
            out.append(finding.description)
            out.append("")
        if finding.location.snippet:
            out.append("```")
            out.append(finding.location.snippet)
            out.append("```")
            out.append("")
        if finding.remediation:
            out.append(f"**Fix:** {finding.remediation}")
            out.append("")
        if finding.comments:
            out.append("**Review notes:**")
            for comment in finding.comments:
                out.append(f"- _{comment.author}_: {comment.body}")
            out.append("")
    return "\n".join(out)


def quickfix(findings: Sequence[Finding]) -> str:
    """`path:line:col: severity: message [rule]` - the grep/compiler convention.

    Every editor already knows how to jump through this format: vim's :cfile,
    emacs compilation-mode, VS Code's problem matchers. Producing it is four
    lines of code and removes the need for a plugin per editor.
    """
    lines = []
    for finding in findings:
        lines.append(
            f"{finding.path}:{max(finding.line, 1)}:1: "
            f"{finding.severity}: {finding.title} [{finding.rule_id}]"
        )
    return "\n".join(lines)


def as_json(findings: Sequence[Finding], extra: Optional[Dict[str, Any]] = None) -> str:
    payload: Dict[str, Any] = {
        "findings": [finding.to_dict() for finding in findings],
        "count": len(findings),
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2)
