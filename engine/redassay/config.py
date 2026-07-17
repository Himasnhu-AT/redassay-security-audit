"""Runtime configuration.

Resolution order, most specific first:
  1. explicit CLI flags
  2. .redassay/config.json in the target repo
  3. [tool.redassay] in pyproject.toml (read with a tiny parser, no toml dep)
  4. REDASSAY_* environment variables
  5. the defaults below
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from . import severity as sev

DEFAULT_PORT = 7717
DEFAULT_HOST = "127.0.0.1"


@dataclass
class Config:
    root: str = "."
    min_severity: str = sev.INFO
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)     # empty means "all"
    disabled_scanners: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    author: str = "you"
    max_file_bytes: int = 1_500_000
    respect_gitignore: bool = True
    fail_on: Optional[str] = None                          # severity floor for exit code 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def merged(self, **overrides: Any) -> "Config":
        data = self.to_dict()
        for key, value in overrides.items():
            if value is None or key not in data:
                continue
            if isinstance(data[key], list) and not value:
                continue
            data[key] = value
        return Config(**data)


def _from_env() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    mapping = {
        "REDASSAY_PORT": ("port", int),
        "REDASSAY_HOST": ("host", str),
        "REDASSAY_MIN_SEVERITY": ("min_severity", sev.normalize),
        "REDASSAY_AUTHOR": ("author", str),
    }
    for env_key, (field_name, cast) in mapping.items():
        value = os.environ.get(env_key)
        if value:
            try:
                out[field_name] = cast(value)
            except (TypeError, ValueError):
                continue
    return out


_TOML_SECTION = re.compile(r"^\s*\[tool\.redassay\]\s*$")
_TOML_OTHER_SECTION = re.compile(r"^\s*\[")
_TOML_PAIR = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.+?)\s*$")


def _parse_toml_section(path: str) -> Dict[str, Any]:
    """Read [tool.redassay] without pulling in a toml parser.

    Handles strings, ints, bools and flat arrays of strings - which is all this
    section is ever going to contain.
    """
    if not os.path.isfile(path):
        return {}
    out: Dict[str, Any] = {}
    inside = False
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if _TOML_SECTION.match(line):
                inside = True
                continue
            if inside and _TOML_OTHER_SECTION.match(line):
                break
            if not inside:
                continue
            match = _TOML_PAIR.match(line.split("#")[0])
            if not match:
                continue
            key, raw = match.group(1).replace("-", "_"), match.group(2).strip()
            out[key] = _coerce_toml_value(raw)
    return out


def _coerce_toml_value(raw: str) -> Any:
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:-1].strip()
        if not body:
            return []
        return [part.strip().strip("'\"") for part in body.split(",") if part.strip()]
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    if raw.startswith(("'", '"')) and raw.endswith(("'", '"')):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        return raw.strip("'\"")


def load(root: str = ".", **overrides: Any) -> Config:
    root = os.path.abspath(root)
    data: Dict[str, Any] = {"root": root}
    data.update(_from_env())
    data.update(_parse_toml_section(os.path.join(root, "pyproject.toml")))

    config_path = os.path.join(root, ".redassay", "config.json")
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                data.update(json.load(handle) or {})
        except (OSError, json.JSONDecodeError):
            pass

    known = {f for f in Config().to_dict()}
    clean = {k: v for k, v in data.items() if k in known}
    config = Config(**clean)
    config.min_severity = sev.normalize(config.min_severity)
    config.root = root
    return config.merged(**overrides)


def save(config: Config) -> str:
    target_dir = os.path.join(config.root, ".redassay")
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "config.json")
    payload = config.to_dict()
    payload.pop("root", None)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path
