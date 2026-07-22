"""Dependency review: known-vulnerable versions and supply-chain hygiene.

The advisory database is a bundled snapshot (`data/advisories.json`). A scan
never makes a network request - a security tool that phones home the moment you
point it at a private repo is a hard sell, and an offline snapshot that you
refresh deliberately is honest about its staleness.

Manifest parsing is intentionally forgiving. A malformed package.json in a repo
you are auditing is itself worth noting, but it must not stop the scan.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .. import versions
from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
ADVISORY_PATH = os.path.join(DATA_DIR, "advisories.json")

_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None


def load_advisories(path: str = ADVISORY_PATH) -> Dict[str, List[Dict[str, Any]]]:
    global _cache
    if _cache is not None and path == ADVISORY_PATH:
        return _cache
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    index: Dict[str, List[Dict[str, Any]]] = {}
    for entry in payload.get("advisories", []):
        key = f"{entry['ecosystem']}:{entry['package'].lower()}"
        index.setdefault(key, []).append(entry)
    if path == ADVISORY_PATH:
        _cache = index
    return index


def match_advisories(ecosystem: str, package: str, version: str) -> List[Dict[str, Any]]:
    index = load_advisories()
    hits = []
    for entry in index.get(f"{ecosystem}:{package.lower()}", []):
        if versions.satisfies_vulnerable(version, entry["vulnerable"]):
            hits.append(entry)
    return hits


# --- manifest parsers --------------------------------------------------------
def parse_package_json(text: str) -> List[Tuple[str, str, str]]:
    """Return (name, spec, section) for every declared dependency."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            out.append((name, str(spec), section))
    return out


_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]+\])?\s*"
    r"((?:[<>=!~^]=?\s*[^,;#\s]+\s*,?\s*)*)"
)


def parse_requirements(text: str) -> List[Tuple[str, str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        name, spec = match.group(1), (match.group(2) or "").strip()
        out.append((name, spec, "requirements"))
    return out


_GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?([\w.\-]+(?:/[\w.\-~]+)+)\s+v?(\d[\w.\-+]*)")


def parse_go_mod(text: str) -> List[Tuple[str, str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("//")[0].strip()
        if not line or line.startswith(("module ", "go ", ")", "replace", "exclude")):
            continue
        match = _GO_REQUIRE.match(line)
        if match:
            out.append((match.group(1), match.group(2), "require"))
    return out


_GEM_LINE = re.compile(r"^\s*gem\s+['\"]([\w\-]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?")


def parse_gemfile(text: str) -> List[Tuple[str, str, str]]:
    out = []
    for raw in text.splitlines():
        match = _GEM_LINE.match(raw)
        if match:
            out.append((match.group(1), (match.group(2) or "").strip(), "gem"))
    return out


_MAVEN_DEP = re.compile(
    r"<groupId>\s*([^<]+?)\s*</groupId>\s*<artifactId>\s*([^<]+?)\s*</artifactId>\s*"
    r"(?:<version>\s*([^<]+?)\s*</version>)?",
    re.DOTALL,
)


def parse_pom(text: str) -> List[Tuple[str, str, str]]:
    out = []
    for match in _MAVEN_DEP.finditer(text):
        group, artifact, version = match.group(1), match.group(2), (match.group(3) or "").strip()
        if version.startswith("${"):
            continue
        out.append((f"{group}:{artifact}", version, "maven"))
    return out


def parse_composer(text: str) -> List[Tuple[str, str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for section in ("require", "require-dev"):
        block = data.get(section)
        if isinstance(block, dict):
            for name, spec in block.items():
                if "/" in name:
                    out.append((name, str(spec), section))
    return out


MANIFEST_HANDLERS = {
    "package.json": ("npm", parse_package_json),
    "requirements.txt": ("pypi", parse_requirements),
    "requirements-dev.txt": ("pypi", parse_requirements),
    "go.mod": ("go", parse_go_mod),
    "gemfile": ("rubygems", parse_gemfile),
    "pom.xml": ("maven", parse_pom),
    "composer.json": ("composer", parse_composer),
}

RISKY_SCRIPTS = re.compile(r"(curl|wget)[^\n]*\|\s*(bash|sh)|\bnode\s+-e\b|\brm\s+-rf\s+/")


@register
class DependencyScanner(Scanner):
    name = "dependencies"
    description = "Known-vulnerable dependency versions and supply-chain hygiene in manifests"

    def applies_to(self, source: SourceFile) -> bool:
        return os.path.basename(source.path).lower() in MANIFEST_HANDLERS

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        name = os.path.basename(source.path).lower()
        ecosystem, parser = MANIFEST_HANDLERS[name]
        text = source.read()
        lines = text.splitlines()
        declared = parser(text)

        for package, spec, section in declared:
            version = versions.pinned_version(spec) or versions.loose_version(spec)
            line_no = _locate(lines, package)
            if version:
                for advisory in match_advisories(ecosystem, package, version):
                    exact = versions.pinned_version(spec) is not None
                    yield self.make_finding(
                        rule_id=f"dep.{advisory['id'].lower()}",
                        title=f"{package} {version} is affected by {advisory['id']}",
                        source=source,
                        line=line_no,
                        snippet=f"{package} {spec}".strip(),
                        severity=advisory["severity"],
                        confidence="high" if exact else "medium",
                        description=(
                            f"{advisory['title']}. {advisory['description']} "
                            f"Declared here as `{spec or version}` in {section}."
                            + ("" if exact else " The spec is a range, so the resolved version may differ - "
                                              "check the lockfile to confirm.")
                        ),
                        remediation=(
                            f"Upgrade {package} to a version outside {advisory['vulnerable']} and "
                            "regenerate the lockfile."
                        ),
                        cwe=["CWE-1395"],
                        owasp=["A06:2021 Vulnerable and Outdated Components"],
                        tags=["dependencies", ecosystem, advisory["id"]],
                        references=[_advisory_url(advisory["id"])],
                        scanner=self.name,
                    )
            if spec.strip() in {"*", "latest", "x"}:
                yield self.make_finding(
                    rule_id="dep.floating-version",
                    title=f"{package} has no version constraint",
                    source=source,
                    line=line_no,
                    snippet=f"{package} {spec}".strip(),
                    severity="medium",
                    confidence="high",
                    description=(
                        f"`{package}` is declared as `{spec}`, so the resolver installs whatever is "
                        "current at build time. Builds stop being reproducible and a compromised "
                        "release is picked up automatically."
                    ),
                    remediation="Pin to a specific version or a bounded range, and commit the lockfile.",
                    cwe=["CWE-1104"],
                    owasp=["A06:2021 Vulnerable and Outdated Components"],
                    tags=["dependencies", "supply-chain"],
                    scanner=self.name,
                )

        if name == "package.json":
            yield from self._package_json_extras(source, text, lines)

    def _package_json_extras(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        scripts = data.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            body = scripts.get(hook)
            if not body:
                continue
            if RISKY_SCRIPTS.search(str(body)):
                yield self.make_finding(
                    rule_id="dep.install-hook-remote-code",
                    title=f"{hook} script fetches and runs remote code",
                    source=source,
                    line=_locate(lines, hook),
                    snippet=f"\"{hook}\": \"{body}\"",
                    severity="high",
                    confidence="high",
                    description=(
                        f"The {hook} script runs at install time on every developer machine and CI "
                        "runner, and it executes code downloaded at that moment. Whatever that host "
                        "serves is what runs."
                    ),
                    remediation="Vendor the artifact, verify a checksum, or move the step into an explicit build target.",
                    cwe=["CWE-494"],
                    owasp=["A08:2021 Software and Data Integrity Failures"],
                    tags=["dependencies", "supply-chain"],
                    scanner=self.name,
                )

        for section in ("dependencies", "devDependencies"):
            block = data.get(section) or {}
            for package, spec in block.items():
                spec = str(spec)
                if spec.startswith(("git+", "http://", "https://", "file:")) and "://" in spec:
                    yield self.make_finding(
                        rule_id="dep.non-registry-source",
                        title=f"{package} installed from a URL rather than the registry",
                        source=source,
                        line=_locate(lines, package),
                        snippet=f"\"{package}\": \"{spec}\"",
                        severity="medium",
                        confidence="high",
                        description=(
                            "A dependency resolved from a git ref or URL skips registry integrity "
                            "checks, and a mutable ref means the contents can change under you."
                        ),
                        remediation="Publish to the registry, or pin the git dependency to a full commit SHA.",
                        cwe=["CWE-829"],
                        owasp=["A08:2021 Software and Data Integrity Failures"],
                        tags=["dependencies", "supply-chain"],
                        scanner=self.name,
                    )


def _locate(lines: List[str], needle: str) -> int:
    for index, line in enumerate(lines):
        if needle in line:
            return index + 1
    return 1


def _advisory_url(identifier: str) -> str:
    if identifier.startswith("GHSA"):
        return f"https://github.com/advisories/{identifier}"
    if identifier.startswith("CVE"):
        return f"https://nvd.nist.gov/vuln/detail/{identifier}"
    return identifier
