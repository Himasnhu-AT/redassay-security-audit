#!/usr/bin/env python3
"""Confine every published Docker Compose port to loopback.

The problem this solves: a compose file that says

    ports:
      - 80

does not mean "this container listens on 80". It means "publish 80 on a host
port bound to 0.0.0.0". Bring up a stack of deliberately vulnerable
applications with that in it and you have served them to every machine on the
network - which is a different thing from running them locally.

The fix keeps them reachable where you want them and nowhere else:

    - 80                  ->  - "127.0.0.1::80"      (random host port, loopback)
    - "8080:80"           ->  - "127.0.0.1:8080:80"  (fixed host port, loopback)
    - "127.0.0.1:8080:80" ->  unchanged, already confined
    - "0.0.0.0:8080:80"   ->  - "127.0.0.1:8080:80"

Entries under `expose:` are left alone: that keyword opens a port to the compose
network only and never to the host.

    python3 tools/bind_loopback.py <path> --dry-run
    python3 tools/bind_loopback.py <path>
    python3 tools/bind_loopback.py <path> --address 192.168.1.10
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

#: `- 80`, `- "80"`, `- 80/tcp`
SHORT_ONLY = re.compile(r"""^(?P<indent>\s*-\s*)(?P<q>["']?)(?P<container>\d{1,5})(?P<proto>/(?:tcp|udp))?(?P=q)\s*$""")

#: `- 8080:80`, `- "0.0.0.0:8080:80"`, `- "127.0.0.1:8080:80"`
MAPPING = re.compile(
    r"""^(?P<indent>\s*-\s*)(?P<q>["']?)"""
    r"""(?:(?P<host_ip>\[?[0-9a-fA-F:.]+\]?):)?"""
    r"""(?P<host>\d{1,5})(?P<host_range>-\d{1,5})?"""
    r""":(?P<container>\d{1,5})(?P<container_range>-\d{1,5})?"""
    r"""(?P<proto>/(?:tcp|udp))?(?P=q)\s*$"""
)

BLOCK_KEY = re.compile(r"^(?P<indent>\s*)(?P<key>ports|expose)\s*:\s*$")
LIST_ITEM = re.compile(r"^\s*-\s")


def _is_loopback(address: Optional[str]) -> bool:
    if not address:
        return False
    address = address.strip("[]")
    return address.startswith("127.") or address in {"::1", "localhost"}


@dataclass
class Change:
    path: str
    line: int
    before: str
    after: str


@dataclass
class Result:
    changed: List[Change] = field(default_factory=list)
    already_confined: int = 0
    files_touched: List[str] = field(default_factory=list)
    skipped_expose: int = 0


def rewrite(text: str, address: str = "127.0.0.1", path: str = "") -> Tuple[str, Result]:
    """Return the rewritten file and what changed."""
    result = Result()
    lines = text.splitlines(keepends=True)
    out: List[str] = []

    in_ports = False
    block_indent = -1

    for index, raw in enumerate(lines):
        line = raw.rstrip("\n\r")
        newline = raw[len(line):]
        stripped = line.strip()

        block = BLOCK_KEY.match(line)
        if block:
            in_ports = block.group("key") == "ports"
            block_indent = len(block.group("indent"))
            out.append(raw)
            continue

        # A non-list line at or above the block's indentation ends the block.
        if stripped and not LIST_ITEM.match(line):
            indent = len(line) - len(line.lstrip())
            if indent <= block_indent:
                in_ports = False

        if not in_ports or stripped.startswith("#"):
            if not in_ports and stripped.startswith("-") and block_indent >= 0:
                result.skipped_expose += 1 if not in_ports else 0
            out.append(raw)
            continue

        short = SHORT_ONLY.match(line)
        if short:
            container = short.group("container")
            proto = short.group("proto") or ""
            replacement = f'{short.group("indent")}"{address}::{container}{proto}"'
            out.append(replacement + newline)
            result.changed.append(Change(path, index + 1, line.strip(), replacement.strip()))
            continue

        mapping = MAPPING.match(line)
        if mapping:
            if _is_loopback(mapping.group("host_ip")):
                result.already_confined += 1
                out.append(raw)
                continue
            host = mapping.group("host") + (mapping.group("host_range") or "")
            container = mapping.group("container") + (mapping.group("container_range") or "")
            proto = mapping.group("proto") or ""
            replacement = f'{mapping.group("indent")}"{address}:{host}:{container}{proto}"'
            out.append(replacement + newline)
            result.changed.append(Change(path, index + 1, line.strip(), replacement.strip()))
            continue

        out.append(raw)

    return "".join(out), result


def compose_files(root: str) -> List[str]:
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".redassay"}]
        for filename in sorted(filenames):
            lowered = filename.lower()
            if lowered in COMPOSE_NAMES or lowered.startswith("docker-compose."):
                if lowered.endswith((".yml", ".yaml")):
                    found.append(os.path.join(dirpath, filename))
    return sorted(found)


def apply(root: str, address: str = "127.0.0.1", dry_run: bool = False) -> Result:
    total = Result()
    for path in compose_files(root):
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read()
        relative = os.path.relpath(path, root)
        rewritten, result = rewrite(original, address=address, path=relative)
        total.already_confined += result.already_confined
        if not result.changed:
            continue
        total.changed.extend(result.changed)
        total.files_touched.append(relative)
        if not dry_run:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(rewritten)
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--address", default="127.0.0.1",
                        help="host address to bind to (default: 127.0.0.1)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        print(f"not a directory: {args.root}", file=sys.stderr)
        return 2

    result = apply(args.root, address=args.address, dry_run=args.dry_run)
    verb = "would bind" if args.dry_run else "bound"

    if not args.quiet:
        for change in result.changed[:40]:
            print(f"  {change.path}:{change.line}")
            print(f"    - {change.before}")
            print(f"    + {change.after}")
        if len(result.changed) > 40:
            print(f"  ... and {len(result.changed) - 40} more")
        print()

    print(f"{verb} {len(result.changed)} published ports to {args.address} "
          f"across {len(result.files_touched)} files")
    if result.already_confined:
        print(f"{result.already_confined} were already confined and were left alone")
    if args.dry_run and result.changed:
        print("re-run without --dry-run to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
