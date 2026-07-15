"""Stable finding identity.

A finding id must survive a reformat, a rename of a local variable, and code
moving up or down a file. It must *not* survive the vulnerability actually
changing. That trade-off is the whole reason this module exists.
"""

from __future__ import annotations

import hashlib
import re

_WS = re.compile(r"\s+")
_STRING = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")


def normalize_snippet(snippet: str) -> str:
    """Reduce a source line to something that survives cosmetic edits.

    String *contents* are collapsed to a placeholder: a hardcoded password
    rotating from "hunter2" to "hunter3" is the same finding, and we do not want
    the secret itself feeding the id (ids end up in logs).
    """
    if not snippet:
        return ""
    text = _STRING.sub(lambda m: m.group(1) + "\x00" + m.group(1), snippet)
    text = _WS.sub(" ", text)
    return text.strip()


def finding_id(rule_id: str, path: str, snippet: str, salt: str = "") -> str:
    """Content-addressed id. Deliberately excludes the line number."""
    material = "|".join([rule_id, path.replace("\\", "/"), normalize_snippet(snippet), salt])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def short(value: str, width: int = 8) -> str:
    return value[:width]
