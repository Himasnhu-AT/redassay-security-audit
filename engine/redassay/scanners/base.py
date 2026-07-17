"""Scanner protocol and the per-run context handed to each one."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

from ..models import Finding, Location
from ..walker import SourceFile


@dataclass
class ScanContext:
    """Shared state for one scan. Scanners may read it, never mutate it."""

    root: str
    files: Sequence[SourceFile] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)

    def by_language(self, *languages: str) -> List[SourceFile]:
        wanted = set(languages)
        return [f for f in self.files if f.language in wanted]

    def has_language(self, language: str) -> bool:
        return any(f.language == language for f in self.files)

    def find(self, *names: str) -> List[SourceFile]:
        import os
        wanted = {n.lower() for n in names}
        return [f for f in self.files if os.path.basename(f.path).lower() in wanted]


class Scanner:
    """Base class. Subclasses implement `applies_to` and `scan_file` (or `scan`)."""

    name: str = "scanner"
    description: str = ""
    #: Languages this scanner understands. Empty means "decide per file".
    languages: Sequence[str] = ()

    def __init__(self, **options: Any):
        self.options = options

    # -- overridable ---------------------------------------------------------
    def applies_to(self, source: SourceFile) -> bool:
        if not self.languages:
            return True
        return source.language in set(self.languages)

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterable[Finding]:
        return ()

    def finalize(self, context: ScanContext) -> Iterable[Finding]:
        """Emit findings that need the whole repo in view (cross-file rules)."""
        return ()

    # -- driver --------------------------------------------------------------
    def scan(self, context: ScanContext) -> Iterator[Finding]:
        for source in context.files:
            if not self.applies_to(source):
                continue
            try:
                for finding in self.scan_file(source, context):
                    if finding.rule_id in context.disabled_rules:
                        continue
                    finding.source = finding.source or self.name
                    yield finding
            except (OSError, UnicodeDecodeError):
                continue
        for finding in self.finalize(context):
            if finding.rule_id not in context.disabled_rules:
                yield finding

    # -- helpers for subclasses ---------------------------------------------
    @staticmethod
    def make_finding(
        rule_id: str,
        title: str,
        source: SourceFile,
        line: int,
        snippet: str,
        severity: str = "medium",
        confidence: str = "medium",
        description: str = "",
        remediation: str = "",
        cwe: Optional[Sequence[str]] = None,
        owasp: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        references: Optional[Sequence[str]] = None,
        scanner: str = "scanner",
        end_line: int = 0,
        salt: str = "",
    ) -> Finding:
        from ..ids import finding_id

        location = Location(path=source.path, line=line, end_line=end_line or line, snippet=snippet.strip()[:400])
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            remediation=remediation,
            location=location,
            cwe=list(cwe or []),
            owasp=list(owasp or []),
            tags=list(tags or []),
            references=list(references or []),
            source=scanner,
            id=finding_id(rule_id, source.path, snippet, salt=salt),
        )
