"""Rule packs.

Each pack is a JSON file in this directory. They are data, not code, so a user
can drop a pack into `.redassay/rules/` and have it picked up without touching
the engine.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Optional

PACK_DIR = os.path.dirname(os.path.abspath(__file__))

REQUIRED_FIELDS = ("id", "title", "pattern")

#: Optional self-test fields. `examples` are lines the rule must match;
#: `counterexamples` are lines it must not. Keeping them next to the rule beats
#: a fixture file per rule: the sample and the pattern are edited together, so
#: they cannot drift, and 115 rules do not need 115 files.
EXAMPLE_FIELDS = ("examples", "counterexamples")


class RuleError(ValueError):
    pass


def _validate(rule: Dict[str, Any], origin: str) -> None:
    missing = [f for f in REQUIRED_FIELDS if not rule.get(f)]
    if missing:
        raise RuleError(f"{origin}: rule {rule.get('id', '?')} missing {', '.join(missing)}")
    for field in EXAMPLE_FIELDS:
        value = rule.get(field)
        if value is not None and not isinstance(value, list):
            raise RuleError(f"{origin}: rule {rule['id']}: {field} must be a list of strings")


def load_pack(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        raise RuleError(f"{path}: expected a list of rules")
    pack_name = (data.get("pack") if isinstance(data, dict) else None) or os.path.basename(path)
    defaults = (data.get("defaults") if isinstance(data, dict) else None) or {}
    out = []
    for rule in rules:
        merged = dict(defaults)
        merged.update(rule)
        merged.setdefault("pack", pack_name)
        _validate(merged, path)
        out.append(merged)
    return out


def builtin_packs() -> List[str]:
    return sorted(
        os.path.join(PACK_DIR, name)
        for name in os.listdir(PACK_DIR)
        if name.endswith(".json")
    )


def load_all(extra_dirs: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    paths = list(builtin_packs())
    for directory in extra_dirs or ():
        if not os.path.isdir(directory):
            continue
        paths.extend(
            os.path.join(directory, name)
            for name in sorted(os.listdir(directory))
            if name.endswith(".json")
        )
    for path in paths:
        for rule in load_pack(path):
            rule_id = rule["id"]
            if rule_id in seen:
                # A user pack overriding a builtin is intentional; last wins.
                rules = [r for r in rules if r["id"] != rule_id]
            seen[rule_id] = path
            rules.append(rule)
    return rules


def by_language(rules: Iterable[Dict[str, Any]], language: Optional[str]) -> List[Dict[str, Any]]:
    out = []
    for rule in rules:
        langs = rule.get("languages")
        if not langs or "*" in langs or language in langs:
            out.append(rule)
    return out
