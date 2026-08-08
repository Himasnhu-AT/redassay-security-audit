"""Post-processing between "a scanner said something" and "a human sees it".

Three jobs:

1. **Deduplicate.** Several scanners legitimately find the same thing - the
   pattern pack and the AST scanner both see `yaml.load`. The AST one carries
   better evidence, so it wins.
2. **Filter.** Drop anything below the configured severity floor.
3. **Rank.** Order by how much a reviewer should care, which is severity
   weighted by confidence, not severity alone. A low-confidence critical sitting
   above a high-confidence high wastes the reviewer's first ten minutes.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from . import severity as sev
from .models import Finding

#: Higher wins when two scanners report the same location.
SCANNER_PRECEDENCE = {
    "python-ast": 100,
    "javascript": 90,
    "dependencies": 85,
    "cicd": 80,
    "secrets": 75,
    "configs": 60,
    "pattern": 40,
    "configs-language": 45,
    "claude": 120,          # a model-verified finding carries the most context
}

CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.65, "low": 0.35}
SEVERITY_WEIGHT = {
    sev.CRITICAL: 100.0,
    sev.HIGH: 60.0,
    sev.MEDIUM: 30.0,
    sev.LOW: 12.0,
    sev.INFO: 4.0,
}

#: Rules that describe the same underlying defect, keyed to a shared concept.
EQUIVALENT = {
    "py.yaml-unsafe-load": "unsafe-yaml",
    "deser.yaml-unsafe-load": "unsafe-yaml",
    "py.pickle-load": "unsafe-pickle",
    "deser.python-pickle": "unsafe-pickle",
    "py.eval-dynamic": "dynamic-eval",
    "code.python-eval-exec": "dynamic-eval",
    "js.eval-tainted": "dynamic-eval-js",
    "code.js-eval": "dynamic-eval-js",
    "py.sql-dynamic": "sql-injection",
    "sql.fstring-query": "sql-injection",
    "sql.string-concat-query": "sql-injection",
    "js.sql-tainted": "sql-injection-js",
    "sql.knex-sequelize-raw": "sql-injection-js",
    "py.shell-dynamic": "command-injection",
    "cmd.shell-true": "command-injection",
    "cmd.os-system": "command-injection",
    "js.exec-tainted": "command-injection-js",
    "cmd.node-exec": "command-injection-js",
    "py.tls-verify-off": "tls-verify-off",
    "crypto.tls-verify-disabled": "tls-verify-off",
    "py.flask-debug": "debug-enabled",
    "config.debug-enabled": "debug-enabled",
    "py.django-debug-true": "debug-enabled",
    "py.path-tainted": "path-traversal",
    "authz.path-traversal-join": "path-traversal",
    "js.path-tainted": "path-traversal-js",
    "py.ssrf": "ssrf",
    "ssrf.http-client-dynamic-url": "ssrf",
    "js.ssrf-tainted": "ssrf-js",
    "py.weak-random": "weak-random",
    "crypto.weak-random-security": "weak-random",
    "py.weak-hash": "weak-hash",
    "crypto.md5-sha1-usage": "weak-hash",
    "py.open-redirect": "open-redirect",
    "ssrf.open-redirect": "open-redirect",
    "config.curl-pipe-shell": "curl-pipe",
    "ci.curl-pipe-shell": "curl-pipe",
    "crypto.ecb-mode": "weak-cipher",
    "jvm.weak-cipher-getinstance": "weak-cipher",
    "crypto.des-rc4-3des": "weak-cipher",
    "config.csrf-disabled": "csrf-disabled",
    "jvm.csrf-disabled": "csrf-disabled",
    "go.insecure-skip-verify": "tls-verify-off",
    "jvm.trust-all-certs": "tls-verify-off",
    "go.sql-concat": "sql-injection",
    "jvm.jdbc-concat": "sql-injection",
    "php.sql-superglobal": "sql-injection",
    "jvm.runtime-exec": "command-injection",
    "cmd.php-exec": "command-injection",
    "go.command-exec": "command-injection",
    "cmd.ruby-backtick": "command-injection",
    "php.file-inclusion-superglobal": "file-inclusion",
    "code.php-eval-include": "file-inclusion",
    "go.math-rand-secret": "weak-random",
    "go.path-join-request": "path-traversal",
    "ruby.render-inline": "template-injection",
    "inject.ssti-render-string": "template-injection",
    "api.mass-assignment-spread": "mass-assignment",
    "ruby.mass-assignment": "mass-assignment",
}


def concept(finding: Finding) -> str:
    return EQUIVALENT.get(finding.rule_id, finding.rule_id)


def priority(finding: Finding) -> float:
    """A single number a reviewer can sort by. Higher means look sooner."""
    base = SEVERITY_WEIGHT.get(finding.severity, 10.0)
    weight = CONFIDENCE_WEIGHT.get(finding.confidence, 0.65)
    score = base * weight
    if finding.source == "claude":
        score *= 1.15                      # verified by something that read the surrounding code
    if "test" in finding.path.lower() or "spec" in finding.path.lower():
        score *= 0.5                       # real, but not reachable in production
    return round(score, 2)


def _dedupe_key(finding: Finding) -> Tuple[str, str, int]:
    return (finding.path, concept(finding), finding.line)


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Collapse reports of the same defect, keeping the best-evidenced one."""
    best: Dict[Tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = _dedupe_key(finding)
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        if _wins(finding, current):
            merged = finding
            merged.tags = sorted(set(merged.tags) | set(current.tags) | {"deduped"})
            best[key] = merged
        else:
            current.tags = sorted(set(current.tags) | set(finding.tags) | {"deduped"})
    return list(best.values())


def _wins(candidate: Finding, incumbent: Finding) -> bool:
    candidate_rank = SCANNER_PRECEDENCE.get(candidate.source, 0)
    incumbent_rank = SCANNER_PRECEDENCE.get(incumbent.source, 0)
    if candidate_rank != incumbent_rank:
        return candidate_rank > incumbent_rank
    return priority(candidate) > priority(incumbent)


def filter_severity(findings: Iterable[Finding], floor: Optional[str]) -> List[Finding]:
    if not floor or floor == sev.INFO:
        return list(findings)
    return [f for f in findings if sev.at_least(f.severity, floor)]


def rank(findings: Iterable[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-priority(f), f.path, f.line, f.rule_id))


def triage(findings: Iterable[Finding], min_severity: Optional[str] = None) -> List[Finding]:
    return rank(filter_severity(dedupe(findings), min_severity))


def group_by_file(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for finding in findings:
        out.setdefault(finding.path, []).append(finding)
    return {path: rank(items) for path, items in sorted(out.items())}


def group_by_rule(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for finding in findings:
        out.setdefault(finding.rule_id, []).append(finding)
    return dict(sorted(out.items(), key=lambda kv: -len(kv[1])))


def hotspots(findings: Iterable[Finding], limit: int = 10) -> List[Tuple[str, int, float]]:
    """Files carrying the most risk, by summed priority rather than count."""
    scores: Dict[str, Tuple[int, float]] = {}
    for finding in findings:
        count, total = scores.get(finding.path, (0, 0.0))
        scores[finding.path] = (count + 1, total + priority(finding))
    ordered = sorted(scores.items(), key=lambda kv: -kv[1][1])
    return [(path, count, round(total, 1)) for path, (count, total) in ordered[:limit]]
