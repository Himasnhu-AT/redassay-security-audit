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
    "php-taint": 88,
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
#:
#: Concepts are language-agnostic on purpose. Deduplication is keyed on
#: (path, concept, line), and two findings at the same line of the same file are
#: necessarily the same language - so there is no need for `sql-injection-js`
#: alongside `sql-injection`, and keeping them separate is how the generic
#: `authz.path-traversal-join` ended up duplicating both language-specific rules.
EQUIVALENT = {
    # injection
    "py.sql-dynamic": "sql-injection",
    "js.sql-tainted": "sql-injection",
    "sql.fstring-query": "sql-injection",
    "sql.string-concat-query": "sql-injection",
    "sql.django-raw-interpolation": "sql-injection",
    "sql.knex-sequelize-raw": "sql-injection",
    "go.sql-concat": "sql-injection",
    "jvm.jdbc-concat": "sql-injection",
    "php.sql-superglobal": "sql-injection",

    "py.shell-dynamic": "command-injection",
    "js.exec-tainted": "command-injection",
    "cmd.shell-true": "command-injection",
    "cmd.os-system": "command-injection",
    "cmd.node-exec": "command-injection",
    "cmd.php-exec": "command-injection",
    "cmd.ruby-backtick": "command-injection",
    "go.command-exec": "command-injection",
    "jvm.runtime-exec": "command-injection",

    "py.eval-dynamic": "dynamic-eval",
    "js.eval-tainted": "dynamic-eval",
    "code.python-eval-exec": "dynamic-eval",
    "code.js-eval": "dynamic-eval",

    "py.ssti": "template-injection",
    "inject.ssti-render-string": "template-injection",
    "ruby.render-inline": "template-injection",

    # deserialization
    "py.pickle-load": "unsafe-pickle",
    "deser.python-pickle": "unsafe-pickle",
    "py.yaml-unsafe-load": "unsafe-yaml",
    "deser.yaml-unsafe-load": "unsafe-yaml",

    # access control
    "py.path-tainted": "path-traversal",
    "js.path-tainted": "path-traversal",
    "authz.path-traversal-join": "path-traversal",
    "go.path-join-request": "path-traversal",

    "py.open-redirect": "open-redirect",
    "js.redirect-tainted": "open-redirect",
    "ssrf.open-redirect": "open-redirect",

    "py.ssrf": "ssrf",
    "js.ssrf-tainted": "ssrf",
    "ssrf.http-client-dynamic-url": "ssrf",

    "py.assert-security": "assert-as-authz",
    "authz.assert-for-authorization": "assert-as-authz",

    "php.file-inclusion-superglobal": "file-inclusion",
    "code.php-eval-include": "file-inclusion",
    "php.taint-file-inclusion": "file-inclusion",

    "php.taint-sql": "sql-injection",
    "php.taint-command": "command-injection",
    "php.taint-eval": "dynamic-eval",
    "php.taint-callable": "dynamic-eval",
    "php.taint-file-read": "path-traversal",
    "php.taint-header": "open-redirect",

    # A tainted move_uploaded_file destination is both "unvalidated upload"
    # (the line rule) and "write to a request-built path" (the taint scanner);
    # at a shared line they are one defect, and php-taint outranks pattern.
    "php.taint-file-write": "unrestricted-upload",
    "php.upload-no-validation": "unrestricted-upload",

    "php.taint-xss": "xss-reflected",
    "xss.php-echo-request": "xss-reflected",
    "js.xss-tainted": "xss-reflected",

    "php.taint-unserialize": "unsafe-php-deser",
    "deser.php-unserialize": "unsafe-php-deser",

    "api.mass-assignment-spread": "mass-assignment",
    "ruby.mass-assignment": "mass-assignment",

    # crypto
    "py.tls-verify-off": "tls-verify-off",
    "crypto.tls-verify-disabled": "tls-verify-off",
    "go.insecure-skip-verify": "tls-verify-off",
    "jvm.trust-all-certs": "tls-verify-off",

    "py.weak-random": "weak-random",
    "crypto.weak-random-security": "weak-random",
    "go.math-rand-secret": "weak-random",

    "py.weak-hash": "weak-hash",
    "crypto.md5-sha1-usage": "weak-hash",
    "crypto.weak-hash-password": "weak-hash",

    "crypto.ecb-mode": "weak-cipher",
    "jvm.weak-cipher-getinstance": "weak-cipher",
    "crypto.des-rc4-3des": "weak-cipher",

    # configuration
    "py.flask-debug": "debug-enabled",
    "config.debug-enabled": "debug-enabled",
    "py.django-debug-true": "debug-enabled",

    "config.csrf-disabled": "csrf-disabled",
    "jvm.csrf-disabled": "csrf-disabled",

    "config.curl-pipe-shell": "curl-pipe",
    "ci.curl-pipe-shell": "curl-pipe",

    # exposure - the dedicated scanner knows the port and what is behind it,
    # so it supersedes the generic pattern rules at the same line
    "expose.wildcard-bind": "wildcard-bind",
    "config.bind-all-interfaces": "wildcard-bind",
    "expose.open-cidr": "open-to-internet",
    "config.terraform-public-bucket": "open-to-internet",

    # secrets - one credential on one line is one finding, however it was spotted
    "secret.hardcoded-assignment": "hardcoded-secret",
    "config.django-secret-key-literal": "hardcoded-secret",
    "config.env-secret-value": "hardcoded-secret",
    "config.dockerfile-baked-secret": "hardcoded-secret",
    "config.k8s-inline-secret": "hardcoded-secret",
    "js.jwt-hardcoded-secret": "hardcoded-secret",
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
    """Which of two reports of the same defect the reviewer should see.

    Priority first, not scanner precedence. `crypto.weak-hash-password` and
    `py.weak-hash` describe the same line, but one of them knows the digest is
    hashing a password - and that is the version worth reading, even though it
    comes from the less sophisticated scanner. Scanner precedence only breaks
    genuine ties.
    """
    candidate_priority, incumbent_priority = priority(candidate), priority(incumbent)
    if candidate_priority != incumbent_priority:
        return candidate_priority > incumbent_priority

    candidate_rank = SCANNER_PRECEDENCE.get(candidate.source, 0)
    incumbent_rank = SCANNER_PRECEDENCE.get(incumbent.source, 0)
    if candidate_rank != incumbent_rank:
        return candidate_rank > incumbent_rank

    # Two pattern rules of equal weight describing one line. Which survives must
    # not depend on the order the scanners happened to yield them in, or the
    # output changes between runs for no reason.
    return candidate.rule_id < incumbent.rule_id


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
