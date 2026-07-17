"""Walk a repo the way a reviewer would: skip the noise, read the code.

Honours .gitignore well enough for the common cases (literal names, directory
entries, `*.ext` globs, leading-slash anchors, negations). A full gitignore
implementation is a rabbit hole; what matters is that node_modules and venv do
not end up in a security report.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence, Tuple

from . import languages

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env.d", "dist", "build", "out", "target", ".next", ".nuxt",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    "htmlcov", ".gradle", ".idea", ".vscode", "vendor", "bower_components",
    ".terraform", ".serverless", "site-packages", ".redassay", ".cache",
    "Pods", "DerivedData", ".dart_tool", "elm-stuff", ".parcel-cache",
}

DEFAULT_EXCLUDE_GLOBS = [
    "*.min.js", "*.min.css", "*.map", "*.bundle.js", "*.chunk.js",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.bz2", "*.xz", "*.7z", "*.rar",
    "*.mp3", "*.mp4", "*.mov", "*.avi", "*.wav", "*.woff", "*.woff2",
    "*.ttf", "*.eot", "*.otf", "*.pyc", "*.pyo", "*.class", "*.jar",
    "*.so", "*.dylib", "*.dll", "*.exe", "*.bin", "*.wasm", "*.db",
    "*.sqlite", "*.sqlite3", "*.pack", "*.idx",
]

MAX_FILE_BYTES = 1_500_000
BINARY_SNIFF_BYTES = 4096


@dataclass
class WalkOptions:
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    exclude_dirs: set = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    max_bytes: int = MAX_FILE_BYTES
    follow_symlinks: bool = False
    respect_gitignore: bool = True
    languages: Optional[set] = None


@dataclass
class SourceFile:
    path: str          # repo-relative, forward slashes
    abspath: str
    language: Optional[str]
    size: int

    _text: Optional[str] = None

    def read(self) -> str:
        if self._text is None:
            with open(self.abspath, "r", encoding="utf-8", errors="replace") as handle:
                self._text = handle.read()
        return self._text

    def lines(self) -> List[str]:
        return self.read().splitlines()


def load_gitignore(root: str) -> List[str]:
    patterns: List[str] = []
    for name in (".gitignore", ".redassayignore"):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    return patterns


def _match_one(pattern: str, rel_path: str, name: str, is_dir: bool) -> bool:
    pattern = pattern.rstrip()
    if pattern.endswith("/"):
        if not is_dir:
            return False
        pattern = pattern[:-1]
    if pattern.startswith("/"):
        return fnmatch.fnmatch(rel_path, pattern[1:]) or rel_path.startswith(pattern[1:] + "/")
    if "/" in pattern:
        return fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path, pattern + "/*")
    return fnmatch.fnmatch(name, pattern)


def ignored(patterns: Sequence[str], rel_path: str, is_dir: bool = False) -> bool:
    """Last matching pattern wins, negations included."""
    name = os.path.basename(rel_path)
    verdict = False
    for pattern in patterns:
        negate = pattern.startswith("!")
        candidate = pattern[1:] if negate else pattern
        if _match_one(candidate, rel_path, name, is_dir):
            verdict = not negate
    return verdict


def looks_binary(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(BINARY_SNIFF_BYTES)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    # Heuristic: mostly-unprintable bytes means we cannot usefully grep it.
    printable = sum(1 for byte in chunk if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(chunk) < 0.75


def walk(root: str, options: Optional[WalkOptions] = None) -> Iterator[SourceFile]:
    options = options or WalkOptions()
    root = os.path.abspath(root)
    gitignore = load_gitignore(root) if options.respect_gitignore else []
    excludes = list(DEFAULT_EXCLUDE_GLOBS) + list(options.exclude)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=options.follow_symlinks):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [
            d for d in sorted(dirnames)
            if d not in options.exclude_dirs
            and not ignored(gitignore, f"{rel_dir}/{d}".lstrip("/"), is_dir=True)
        ]
        for filename in sorted(filenames):
            rel_path = f"{rel_dir}/{filename}".lstrip("/")
            abspath = os.path.join(dirpath, filename)
            if any(fnmatch.fnmatch(filename, glob) for glob in excludes):
                continue
            if ignored(gitignore, rel_path):
                continue
            if options.include and not any(
                fnmatch.fnmatch(rel_path, glob) or rel_path.startswith(glob.rstrip("/") + "/")
                for glob in options.include
            ):
                continue
            try:
                stat = os.stat(abspath)
            except OSError:
                continue
            if not os.path.isfile(abspath) or stat.st_size > options.max_bytes:
                continue
            language = languages.detect(rel_path)
            if options.languages and language not in options.languages:
                continue
            if language is None and looks_binary(abspath):
                continue
            if looks_binary(abspath):
                continue
            yield SourceFile(path=rel_path, abspath=abspath, language=language, size=stat.st_size)


def collect(root: str, options: Optional[WalkOptions] = None) -> List[SourceFile]:
    return list(walk(root, options))


def summarize(files: Sequence[SourceFile]) -> Tuple[int, dict]:
    by_language: dict = {}
    total = 0
    for item in files:
        total += item.size
        key = item.language or "unknown"
        by_language[key] = by_language.get(key, 0) + 1
    return total, dict(sorted(by_language.items(), key=lambda kv: -kv[1]))
