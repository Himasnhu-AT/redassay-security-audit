"""Shared test scaffolding."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from typing import Dict, List, Optional

from . import _bootstrap  # noqa: F401
from redassay import config as config_mod
from redassay.engine import scan
from redassay.models import Finding, Location
from redassay.scanners.base import ScanContext
from redassay.walker import SourceFile

ROOT = _bootstrap.ROOT
FIXTURES = _bootstrap.FIXTURES


class TempRepo(unittest.TestCase):
    """A throwaway directory that behaves like a repository."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="redassay-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def scan(self, **overrides) -> List[Finding]:
        config = config_mod.load(self.root, **overrides)
        return scan(config).findings

    def rule_ids(self, **overrides) -> List[str]:
        return [f.rule_id for f in self.scan(**overrides)]


def source_from(path: str, content: str, language: str) -> SourceFile:
    """An in-memory SourceFile backed by a real temp file."""
    directory = tempfile.mkdtemp(prefix="redassay-src-")
    full = os.path.join(directory, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(content)
    return SourceFile(path=path, abspath=full, language=language, size=len(content))


def run_scanner(scanner, path: str, content: str, language: str) -> List[Finding]:
    source = source_from(path, content, language)
    context = ScanContext(root=os.path.dirname(source.abspath), files=[source])
    return list(scanner.scan(context))


def make_finding(**overrides) -> Finding:
    data = {
        "rule_id": "test.rule",
        "title": "A test finding",
        "severity": "high",
        "location": Location(path="app.py", line=1, snippet="x = 1"),
    }
    data.update(overrides)
    if isinstance(data.get("location"), str):
        data["location"] = Location(path=data["location"], line=1, snippet="x = 1")
    return Finding(**data)


def by_rule(findings: List[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for finding in findings:
        out.setdefault(finding.rule_id, []).append(finding)
    return out
