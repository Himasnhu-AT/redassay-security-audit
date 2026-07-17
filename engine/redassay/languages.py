"""Extension -> language mapping, plus the "is this worth reading" question."""

from __future__ import annotations

import os
from typing import Dict, Optional, Set

EXTENSIONS: Dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".rb": "ruby", ".erb": "ruby",
    ".php": "php", ".phtml": "php",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html", ".htm": "html",
    ".vue": "vue",
    ".svelte": "svelte",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini", ".cfg": "ini",
    ".xml": "xml",
    ".tf": "terraform", ".tfvars": "terraform",
    ".env": "dotenv",
    ".dockerfile": "dockerfile",
    ".md": "markdown",
    ".txt": "text",
    ".lock": "lockfile",
}

FILENAMES: Dict[str, str] = {
    "dockerfile": "dockerfile",
    "docker-compose.yml": "compose",
    "docker-compose.yaml": "compose",
    "makefile": "make",
    "package.json": "npm-manifest",
    "package-lock.json": "npm-lock",
    "yarn.lock": "yarn-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "requirements.txt": "pip-manifest",
    "pipfile": "pip-manifest",
    "pipfile.lock": "pip-lock",
    "poetry.lock": "poetry-lock",
    "pyproject.toml": "python-manifest",
    "gemfile": "gem-manifest",
    "gemfile.lock": "gem-lock",
    "go.mod": "go-manifest",
    "go.sum": "go-lock",
    "cargo.toml": "cargo-manifest",
    "cargo.lock": "cargo-lock",
    "composer.json": "composer-manifest",
    "composer.lock": "composer-lock",
    "pom.xml": "maven-manifest",
    "build.gradle": "gradle-manifest",
    ".env": "dotenv",
    ".npmrc": "config",
    ".htaccess": "apache",
    "nginx.conf": "nginx",
}

#: Languages whose files we run source scanners over.
SOURCE_LANGUAGES: Set[str] = {
    "python", "javascript", "typescript", "ruby", "php", "go", "java", "kotlin",
    "csharp", "rust", "c", "cpp", "swift", "scala", "shell", "powershell", "sql",
    "html", "vue", "svelte",
}

#: Files that describe dependencies rather than behaviour.
MANIFESTS: Set[str] = {
    "npm-manifest", "npm-lock", "yarn-lock", "pnpm-lock", "pip-manifest",
    "pip-lock", "poetry-lock", "python-manifest", "gem-manifest", "gem-lock",
    "go-manifest", "go-lock", "cargo-manifest", "cargo-lock",
    "composer-manifest", "composer-lock", "maven-manifest", "gradle-manifest",
}

#: Configuration we scan for misconfiguration rather than code smells.
CONFIG_LANGUAGES: Set[str] = {
    "yaml", "json", "toml", "ini", "xml", "terraform", "dotenv", "dockerfile",
    "compose", "apache", "nginx", "config",
}


def detect(path: str) -> Optional[str]:
    """Best-effort language for a path. None means "we have no scanner for it"."""
    name = os.path.basename(path).lower()
    if name in FILENAMES:
        return FILENAMES[name]
    if name.startswith("dockerfile"):
        return "dockerfile"
    if name.startswith(".env"):
        return "dotenv"
    _, ext = os.path.splitext(name)
    return EXTENSIONS.get(ext)


def is_source(path: str) -> bool:
    return detect(path) in SOURCE_LANGUAGES


def is_manifest(path: str) -> bool:
    return detect(path) in MANIFESTS


def is_config(path: str) -> bool:
    return detect(path) in CONFIG_LANGUAGES


def comment_prefixes(language: Optional[str]) -> tuple:
    if language in {"python", "ruby", "shell", "yaml", "toml", "ini", "dockerfile", "compose", "terraform", "powershell"}:
        return ("#",)
    if language in {"sql"}:
        return ("--",)
    if language in {"html", "xml", "vue", "svelte", "markdown"}:
        return ("<!--",)
    return ("//", "/*", "*")
