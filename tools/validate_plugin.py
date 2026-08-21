#!/usr/bin/env python3
"""Check the plugin is well-formed before anyone tries to install it.

A plugin that fails to load gives a terse error and no clue which file is wrong.
Everything checked here is something Claude Code requires, or something that has
silently not worked: frontmatter that is not valid YAML-ish, a skill directory
without a SKILL.md, a command referencing a path that does not exist.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FRONTMATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)


def parse_frontmatter(text: str) -> Tuple[Dict[str, str], str]:
    """Read the leading `---` block. Flat key: value pairs only, which is all
    a command or skill header ever contains."""
    match = FRONTMATTER.match(text)
    if not match:
        return {}, text
    fields: Dict[str, str] = {}
    key = None
    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and key:
            fields[key] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        fields[key] = value.strip().strip('"\'')
    return fields, text[match.end():]


def check() -> List[str]:
    problems: List[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    # --- manifests ---------------------------------------------------------
    for name in ("plugin.json", "marketplace.json"):
        path = os.path.join(ROOT, ".claude-plugin", name)
        require(os.path.isfile(path), f"missing .claude-plugin/{name}")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            problems.append(f".claude-plugin/{name}: invalid JSON - {exc}")
            continue
        for field in ("name", "description" if name == "plugin.json" else "metadata"):
            require(field in data or field in data.get("metadata", {}),
                    f".claude-plugin/{name}: missing '{field}'")

    # --- commands ----------------------------------------------------------
    commands_dir = os.path.join(ROOT, "commands")
    require(os.path.isdir(commands_dir), "missing commands/")
    for filename in sorted(os.listdir(commands_dir)) if os.path.isdir(commands_dir) else []:
        if not filename.endswith(".md"):
            continue
        path = os.path.join(commands_dir, filename)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        fields, body = parse_frontmatter(text)
        require(bool(fields), f"commands/{filename}: no frontmatter block")
        require("description" in fields, f"commands/{filename}: frontmatter needs 'description'")
        require(len(body.strip()) > 200, f"commands/{filename}: body is suspiciously short")
        for referenced in re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([\w./-]+)", text):
            require(os.path.exists(os.path.join(ROOT, referenced)),
                    f"commands/{filename}: references missing path {referenced}")

    # --- skills ------------------------------------------------------------
    skills_dir = os.path.join(ROOT, "skills")
    for entry in sorted(os.listdir(skills_dir)) if os.path.isdir(skills_dir) else []:
        skill_path = os.path.join(skills_dir, entry, "SKILL.md")
        require(os.path.isfile(skill_path), f"skills/{entry}: no SKILL.md")
        if not os.path.isfile(skill_path):
            continue
        with open(skill_path, encoding="utf-8") as handle:
            fields, body = parse_frontmatter(handle.read())
        require(fields.get("name") == entry,
                f"skills/{entry}: frontmatter name is {fields.get('name')!r}, expected {entry!r}")
        require(len(fields.get("description", "")) > 40,
                f"skills/{entry}: description is too short to trigger reliably")
        require(len(body.strip()) > 400, f"skills/{entry}: body is suspiciously short")

    # --- agents ------------------------------------------------------------
    agents_dir = os.path.join(ROOT, "agents")
    for filename in sorted(os.listdir(agents_dir)) if os.path.isdir(agents_dir) else []:
        if not filename.endswith(".md"):
            continue
        with open(os.path.join(agents_dir, filename), encoding="utf-8") as handle:
            fields, body = parse_frontmatter(handle.read())
        stem = filename[:-3]
        require(fields.get("name") == stem,
                f"agents/{filename}: frontmatter name is {fields.get('name')!r}, expected {stem!r}")
        require(len(fields.get("description", "")) > 40,
                f"agents/{filename}: description is too short")
        require("tools" in fields, f"agents/{filename}: frontmatter needs 'tools'")

    # --- the engine the command invokes ------------------------------------
    entry_point = os.path.join(ROOT, "engine", "redassay_cli.py")
    require(os.path.isfile(entry_point), "missing engine/redassay_cli.py")
    return problems


def main() -> int:
    problems = check()
    if not problems:
        print("plugin structure is valid")
        return 0
    for problem in problems:
        print(f"  {problem}")
    print(f"\n{len(problems)} problem(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
