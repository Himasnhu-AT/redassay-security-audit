"""Git integration.

Two things are worth knowing about a finding that only git can tell you:

* **Is it new?** A repository with 400 pre-existing findings is not something
  anyone will fix. A pull request that adds one is. `changed_files` makes the
  difference between an unusable report and a gate that a team will keep.
* **Who last touched this line?** Not to assign blame - to find the person who
  can answer "is this reachable?" in thirty seconds instead of an hour.

Every call is best-effort. Not being in a git repository is normal (a tarball,
a vendored copy, a container build context) and must never fail a scan.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

TIMEOUT = 15


def _run(args: Sequence[str], cwd: str) -> Optional[str]:
    try:
        result = subprocess.run(
            list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def is_repo(root: str) -> bool:
    output = _run(["git", "rev-parse", "--is-inside-work-tree"], root)
    return bool(output) and output.strip() == "true"


def repo_root(root: str) -> Optional[str]:
    output = _run(["git", "rev-parse", "--show-toplevel"], root)
    return output.strip() if output else None


def current_branch(root: str) -> Optional[str]:
    output = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], root)
    return output.strip() if output else None


def head_sha(root: str) -> Optional[str]:
    output = _run(["git", "rev-parse", "HEAD"], root)
    return output.strip() if output else None


def remote_url(root: str) -> Optional[str]:
    output = _run(["git", "remote", "get-url", "origin"], root)
    if not output:
        return None
    url = output.strip()
    # Normalize scp-style syntax so it is usable as a SARIF repositoryUri.
    if url.startswith("git@") and ":" in url:
        host, _, path = url[4:].partition(":")
        url = f"https://{host}/{path}"
    return url.removesuffix(".git")


def resolve(root: str, ref: str) -> Optional[str]:
    output = _run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], root)
    return output.strip() if output else None


def changed_files(root: str, since: str = "HEAD", include_untracked: bool = True) -> Optional[List[str]]:
    """Repo-relative paths that differ from `since`.

    Returns None when the question cannot be answered (not a repo, bad ref) so
    callers can distinguish "nothing changed" from "I do not know", which are
    very different answers for a CI gate.
    """
    if not is_repo(root):
        return None
    if resolve(root, since) is None:
        return None

    paths: List[str] = []
    diff = _run(["git", "diff", "--name-only", "--diff-filter=ACMR", since], root)
    if diff is None:
        return None
    paths.extend(line.strip() for line in diff.splitlines() if line.strip())

    staged = _run(["git", "diff", "--name-only", "--cached", "--diff-filter=ACMR"], root)
    if staged:
        paths.extend(line.strip() for line in staged.splitlines() if line.strip())

    if include_untracked:
        untracked = _run(["git", "ls-files", "--others", "--exclude-standard"], root)
        if untracked:
            paths.extend(line.strip() for line in untracked.splitlines() if line.strip())

    top = repo_root(root)
    absolute_root = os.path.realpath(root)
    if top and os.path.realpath(top) != absolute_root:
        # Scanning a subdirectory of a larger repo: re-base and drop the rest.
        prefix = os.path.relpath(absolute_root, os.path.realpath(top)).replace("\\", "/") + "/"
        paths = [p[len(prefix):] for p in paths if p.startswith(prefix)]

    return sorted(set(paths))


def merge_base(root: str, ref: str = "origin/main") -> Optional[str]:
    output = _run(["git", "merge-base", "HEAD", ref], root)
    return output.strip() if output else None


@dataclass
class BlameLine:
    sha: str = ""
    author: str = ""
    email: str = ""
    timestamp: str = ""
    summary: str = ""

    @property
    def short_sha(self) -> str:
        return self.sha[:8]


def blame_line(root: str, path: str, line: int) -> Optional[BlameLine]:
    """Who last changed this line. None when git cannot say."""
    if line <= 0:
        return None
    output = _run(
        ["git", "blame", "--porcelain", "-L", f"{line},{line}", "--", path],
        root,
    )
    if not output:
        return None
    result = BlameLine()
    lines = output.splitlines()
    if lines:
        result.sha = lines[0].split()[0]
    for entry in lines[1:]:
        if entry.startswith("author "):
            result.author = entry[len("author "):].strip()
        elif entry.startswith("author-mail "):
            result.email = entry[len("author-mail "):].strip().strip("<>")
        elif entry.startswith("author-time "):
            result.timestamp = entry[len("author-time "):].strip()
        elif entry.startswith("summary "):
            result.summary = entry[len("summary "):].strip()
        elif entry.startswith("\t"):
            break
    return result if result.sha else None


def annotate(root: str, findings, limit: int = 200) -> int:
    """Attach blame metadata to findings, in place. Returns how many were annotated.

    Capped, because one subprocess per finding is the slowest thing this tool
    does and the value drops off sharply after the first screenful.
    """
    if not is_repo(root):
        return 0
    annotated = 0
    cache: Dict[str, Optional[BlameLine]] = {}
    for finding in list(findings)[:limit]:
        if not finding.path or not finding.line:
            continue
        key = f"{finding.path}:{finding.line}"
        if key not in cache:
            cache[key] = blame_line(root, finding.path, finding.line)
        blame = cache[key]
        if blame is None:
            continue
        finding.tags = sorted(set(finding.tags) | {f"commit:{blame.short_sha}"})
        if blame.author:
            finding.tags = sorted(set(finding.tags) | {f"author:{blame.author}"})
        annotated += 1
    return annotated


def context(root: str) -> Dict[str, Optional[str]]:
    """Repository metadata to stamp on a scan record."""
    if not is_repo(root):
        return {}
    return {
        "branch": current_branch(root),
        "head": head_sha(root),
        "remote": remote_url(root),
    }
