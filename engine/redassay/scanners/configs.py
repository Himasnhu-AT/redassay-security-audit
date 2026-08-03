"""Configuration files: env files, containers, orchestration.

Structured checks that a line-oriented regex rule cannot express - mostly "this
key has this value *in this context*", which needs at least a little parsing.
The YAML reader here is a deliberate toy: enough indentation tracking to know
which block a key sits in, no anchors, no multi-document merge. Anything more
would mean vendoring a parser.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

ENV_SECRET_KEY = re.compile(
    r"(?i)^(export\s+)?([A-Z0-9_]*(SECRET|PASSWORD|PASSWD|TOKEN|KEY|CREDENTIAL|DSN|URI|URL)[A-Z0-9_]*)\s*=\s*(.*)$"
)

COMPOSE_RISKS: List[Tuple[str, str, str, str, str]] = [
    ("privileged", r"privileged\s*:\s*true", "critical",
     "Container runs privileged",
     "A privileged container disables namespace and capability isolation. A process inside it can load kernel modules and access host devices - it is root on the node with extra steps."),
    ("host-network", r"network_mode\s*:\s*[\"']?host", "high",
     "Container shares the host network namespace",
     "The container can reach anything bound to localhost on the host, including admin interfaces that assume loopback means trusted."),
    ("docker-socket", r"/var/run/docker\.sock", "critical",
     "Docker socket mounted into a container",
     "Access to the Docker socket is equivalent to root on the host: the container can start a new privileged container with the host filesystem mounted."),
    ("host-root-mount", r"-\s*[\"']?/(:|\s*:\s*/)", "high",
     "Host root filesystem mounted into a container",
     "Mounting / gives the container read or write access to everything on the node."),
    ("cap-sys-admin", r"SYS_ADMIN|CAP_SYS_ADMIN", "high",
     "CAP_SYS_ADMIN granted",
     "SYS_ADMIN is broad enough that it is widely treated as equivalent to root."),
    ("pid-host", r"pid\s*:\s*[\"']?host", "high",
     "Container shares the host PID namespace",
     "The container can see and signal every process on the host, and read their memory via /proc."),
]

DOCKERFILE_SECRET = re.compile(
    r"(?i)^\s*(ENV|ARG)\s+([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)[A-Z0-9_]*)\s*[= ]\s*(\S+)"
)

PLACEHOLDER = re.compile(r"(?i)^(|\"\"|''|changeme|xxx+|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|your[_-].*|todo|none|null)$")


@register
class ConfigScanner(Scanner):
    name = "configs"
    description = "Environment files, Dockerfiles, compose and Kubernetes manifests"

    def applies_to(self, source: SourceFile) -> bool:
        name = os.path.basename(source.path).lower()
        if name.startswith(".env") or name.endswith(".env"):
            return True
        if source.language in {"dockerfile", "compose"}:
            return True
        if source.language == "yaml":
            return True
        return False

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        name = os.path.basename(source.path).lower()
        text = source.read()
        lines = text.splitlines()

        if name.startswith(".env") or name.endswith(".env"):
            yield from self._env_file(source, lines)
        if source.language == "dockerfile":
            yield from self._dockerfile(source, lines)
        if source.language in {"compose", "yaml"}:
            yield from self._compose_like(source, lines)
        if source.language == "yaml":
            yield from self._kubernetes(source, text, lines)

    # -- .env ----------------------------------------------------------------
    def _env_file(self, source: SourceFile, lines: List[str]) -> Iterator[Finding]:
        is_template = any(
            source.path.lower().endswith(suffix)
            for suffix in (".example", ".sample", ".template", ".dist")
        )
        if is_template:
            return
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = ENV_SECRET_KEY.match(stripped)
            if not match:
                continue
            key, value = match.group(2), match.group(4).strip().strip("\"'")
            if PLACEHOLDER.match(value) or len(value) < 6:
                continue
            yield self.make_finding(
                rule_id="config.env-secret-value",
                title=f"{key} has a real-looking value in a committed env file",
                source=source,
                line=index + 1,
                snippet=f"{key}={_redact(value)}",
                severity="high",
                confidence="medium",
                description=(
                    f"`{key}` is set to a {len(value)}-character value that is not a placeholder. "
                    "Env files are where production credentials live; a committed one is a leak."
                ),
                remediation=(
                    "Rotate the value, remove the file from version control, add it to .gitignore, "
                    "and keep a .env.example with empty keys for documentation."
                ),
                cwe=["CWE-798"],
                owasp=["A05:2021 Security Misconfiguration"],
                tags=["config", "secrets"],
                scanner=self.name,
            )

    # -- Dockerfile ----------------------------------------------------------
    def _dockerfile(self, source: SourceFile, lines: List[str]) -> Iterator[Finding]:
        saw_user = False
        for index, line in enumerate(lines):
            stripped = line.strip()
            upper = stripped.upper()
            if upper.startswith("USER ") and stripped.split()[1] not in {"root", "0"}:
                saw_user = True

            match = DOCKERFILE_SECRET.match(stripped)
            if match and not PLACEHOLDER.match(match.group(4).strip("\"'")):
                yield self.make_finding(
                    rule_id="config.dockerfile-baked-secret",
                    title=f"{match.group(1)} {match.group(2)} bakes a credential into the image",
                    source=source,
                    line=index + 1,
                    snippet=f"{match.group(1)} {match.group(2)}={_redact(match.group(4))}",
                    severity="high",
                    confidence="medium",
                    description=(
                        "ENV and ARG values persist in the image layer metadata. `docker history` "
                        "reads them back out of any published image, and deleting the value in a "
                        "later layer does not remove the earlier one."
                    ),
                    remediation="Inject secrets at runtime, or use BuildKit's --mount=type=secret which leaves no layer behind.",
                    cwe=["CWE-798"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    tags=["config", "docker", "secrets"],
                    scanner=self.name,
                )

            if upper.startswith("ADD ") and re.search(r"https?://", stripped):
                yield self.make_finding(
                    rule_id="config.dockerfile-add-remote",
                    title="ADD used to fetch a remote URL",
                    source=source,
                    line=index + 1,
                    snippet=stripped,
                    severity="medium",
                    confidence="high",
                    description=(
                        "ADD with a URL downloads without verification and, for archives, extracts "
                        "them - so a crafted archive can write outside the destination."
                    ),
                    remediation="Use RUN curl with a checksum verification step, or COPY a vendored file.",
                    cwe=["CWE-494"],
                    owasp=["A08:2021 Software and Data Integrity Failures"],
                    tags=["config", "docker"],
                    scanner=self.name,
                )

        if lines and not saw_user:
            yield self.make_finding(
                rule_id="config.dockerfile-no-user",
                title="Dockerfile never drops to a non-root user",
                source=source,
                line=1,
                snippet="no USER instruction",
                severity="medium",
                confidence="high",
                description=(
                    "Without a USER instruction the entrypoint runs as uid 0 inside the container. "
                    "That turns a file-write bug in the app into a write to any mounted host path, "
                    "and removes a layer of defence against container escapes."
                ),
                remediation=(
                    "Add a non-root user and switch to it last:\n"
                    "  RUN adduser --system --no-create-home app\n"
                    "  USER app"
                ),
                cwe=["CWE-250"],
                owasp=["A05:2021 Security Misconfiguration"],
                tags=["config", "docker"],
                scanner=self.name,
            )

    # -- compose -------------------------------------------------------------
    def _compose_like(self, source: SourceFile, lines: List[str]) -> Iterator[Finding]:
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for slug, pattern, severity, title, description in COMPOSE_RISKS:
                if not re.search(pattern, stripped):
                    continue
                yield self.make_finding(
                    rule_id=f"config.container-{slug}",
                    title=title,
                    source=source,
                    line=index + 1,
                    snippet=stripped[:200],
                    severity=severity,
                    confidence="medium",
                    description=description,
                    remediation=(
                        "Remove the grant. If a specific capability is genuinely required, add just "
                        "that capability rather than the blanket option."
                    ),
                    cwe=["CWE-250"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    tags=["config", "container"],
                    scanner=self.name,
                )

    # -- kubernetes ----------------------------------------------------------
    def _kubernetes(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        if not re.search(r"^\s*kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)", text, re.MULTILINE):
            return
        if "securityContext" not in text:
            kind = re.search(r"^\s*kind\s*:\s*(\w+)", text, re.MULTILINE)
            yield self.make_finding(
                rule_id="config.k8s-no-security-context",
                title=f"{kind.group(1) if kind else 'Workload'} has no securityContext",
                source=source,
                line=(kind and text.count("\n", 0, kind.start()) + 1) or 1,
                snippet=(kind.group(0).strip() if kind else "kind: Deployment"),
                severity="medium",
                confidence="medium",
                description=(
                    "With no securityContext the pod inherits permissive defaults: root user, "
                    "writable root filesystem, privilege escalation allowed, all default capabilities."
                ),
                remediation=(
                    "Set on each container:\n"
                    "  securityContext:\n"
                    "    runAsNonRoot: true\n"
                    "    allowPrivilegeEscalation: false\n"
                    "    readOnlyRootFilesystem: true\n"
                    "    capabilities: {drop: [ALL]}"
                ),
                cwe=["CWE-250"],
                owasp=["A05:2021 Security Misconfiguration"],
                tags=["config", "kubernetes"],
                scanner=self.name,
            )

        # env entries look like:
        #   - name: DB_PASSWORD
        #     value: hunter2
        # so the secret-ish word is on the *name* line and the literal is on the
        # next one. Looking for the keyword in the value line - the first version
        # of this check - never matched a real manifest.
        name_pattern = re.compile(
            r"^\s*-?\s*name\s*:\s*[\"']?([A-Za-z0-9_.-]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|CREDENTIAL)"
            r"[A-Za-z0-9_.-]*)",
            re.IGNORECASE,
        )
        for index, line in enumerate(lines):
            name_match = name_pattern.search(line)
            if not name_match:
                continue
            for offset in (1, 2):
                if index + offset >= len(lines):
                    break
                candidate = lines[index + offset]
                if not re.match(r"^\s*value\s*:", candidate):
                    continue
                # valueFrom/secretKeyRef is the correct shape and never reaches here.
                value = candidate.split(":", 1)[-1].strip().strip("\"'")
                if len(value) <= 8 or value.startswith(("$", "{", "<")):
                    break
                yield self.make_finding(
                    rule_id="config.k8s-inline-secret",
                    title=f"{name_match.group(1)} is set to a literal value in the manifest",
                    source=source,
                    line=index + offset + 1,
                    snippet=_redact_line(candidate),
                    severity="high",
                    confidence="medium",
                    description=(
                        f"`{name_match.group(1)}` carries an inline literal. Manifests are stored in "
                        "the cluster's object store and readable by anyone with get on the resource, "
                        "and they usually end up in version control as well."
                    ),
                    remediation=(
                        "Replace the literal with a reference:\n"
                        "  valueFrom:\n"
                        "    secretKeyRef:\n"
                        "      name: app-secrets\n"
                        "      key: db-password"
                    ),
                    cwe=["CWE-798"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    tags=["config", "kubernetes", "secrets"],
                    scanner=self.name,
                )
                break


def _redact(value: str) -> str:
    value = value.strip().strip("\"'")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * 8}{value[-2:]}"


def _redact_line(line: str) -> str:
    key, _, value = line.partition(":")
    return f"{key}: {_redact(value)}"
