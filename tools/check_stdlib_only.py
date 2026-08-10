#!/usr/bin/env python3
"""Fail if the engine imports anything outside the standard library.

The zero-dependency promise is the reason this tool can be pointed at a
repository you do not trust yet: no pip step, no transitive supply chain, no
"install these 40 packages to find out if you have a vulnerability". It is easy
to break by accident and invisible until someone runs it on a clean machine, so
CI checks it on every push.
"""

from __future__ import annotations

import ast
import os
import sys
from typing import List, Set, Tuple

ENGINE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine")

# Python 3.10+ has sys.stdlib_module_names; 3.9 does not, so carry a list for it.
FALLBACK_STDLIB = {
    "abc", "argparse", "ast", "base64", "binascii", "bisect", "builtins", "calendar",
    "cgi", "cmd", "codecs", "collections", "configparser", "contextlib", "copy",
    "csv", "ctypes", "dataclasses", "datetime", "decimal", "difflib", "dis",
    "email", "enum", "errno", "fnmatch", "functools", "getpass", "glob", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "importlib", "inspect", "io",
    "ipaddress", "itertools", "json", "logging", "math", "mimetypes", "multiprocessing",
    "numbers", "operator", "os", "pathlib", "pickle", "platform", "pprint", "queue",
    "random", "re", "secrets", "select", "shlex", "shutil", "signal", "socket",
    "socketserver", "sqlite3", "ssl", "stat", "string", "struct", "subprocess",
    "sys", "tarfile", "tempfile", "textwrap", "threading", "time", "timeit",
    "token", "tokenize", "traceback", "types", "typing", "unicodedata", "unittest",
    "urllib", "uuid", "warnings", "weakref", "webbrowser", "xml", "zipfile", "zlib",
    "concurrent", "dbm", "getopt", "gettext", "keyword", "linecache", "locale",
    "marshal", "posixpath", "reprlib", "sched", "shelve", "site", "stringprep",
    "symtable", "sysconfig", "tty", "unicodedata", "uu", "wave", "zoneinfo",
}


def stdlib_names() -> Set[str]:
    names = set(getattr(sys, "stdlib_module_names", ()))
    return names | FALLBACK_STDLIB


def top_level_imports(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:                 # relative import, always ours
                continue
            if node.module:
                found.add(node.module.split(".")[0])
    return found


def check(root: str = ENGINE) -> List[Tuple[str, str]]:
    allowed = stdlib_names() | {"redassay"}
    offenders: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = os.path.join(dirpath, filename)
            for module in sorted(top_level_imports(path)):
                if module not in allowed:
                    offenders.append((os.path.relpath(path, os.path.dirname(root)), module))
    return offenders


def main() -> int:
    offenders = check()
    if not offenders:
        print("engine imports stdlib only")
        return 0
    print("engine imports modules outside the standard library:")
    for path, module in offenders:
        print(f"  {path}: {module}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
