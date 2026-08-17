#!/usr/bin/env python3
"""Measure scan throughput, and the effect of the prefilters.

Wall-clock numbers taken minutes apart are not comparable - background load
moves them by a factor of two. Everything here runs back to back in one process
so the A and B halves see the same machine.

    python3 tools/benchmark.py <repo> [--repeat 3]
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Callable, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "engine"))

from redassay import config as config_mod          # noqa: E402
from redassay.prefilter import Prefilter           # noqa: E402
from redassay.scanners import ScanContext, build_all  # noqa: E402
from redassay.walker import WalkOptions, collect, summarize  # noqa: E402


def best_of(fn: Callable[[], int], repeat: int) -> Tuple[float, int]:
    """Fastest run wins - the slow ones are measuring the rest of the machine."""
    best = float("inf")
    count = 0
    for _ in range(repeat):
        start = time.perf_counter()
        count = fn()
        best = min(best, time.perf_counter() - start)
    return best, count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()

    config = config_mod.load(args.repo)
    files = collect(config.root, WalkOptions())
    total_bytes, languages = summarize(files)
    context = ScanContext(root=config.root, files=files)

    print(f"{os.path.basename(config.root)}: {len(files)} files, {total_bytes / 1e6:.1f} MB")
    print(f"  {', '.join(f'{k} {v}' for k, v in list(languages.items())[:5])}")
    print()

    rows: List[Tuple[str, float, int]] = []
    for scanner in build_all():
        elapsed, count = best_of(lambda s=scanner: sum(1 for _ in s.scan(context)), args.repeat)
        rows.append((scanner.name, elapsed, count))

    width = max(len(name) for name, _, _ in rows)
    total = 0.0
    for name, elapsed, count in sorted(rows, key=lambda r: -r[1]):
        total += elapsed
        print(f"  {name:<{width}}  {elapsed:7.3f}s  {count:5} findings")
    print(f"  {'total':<{width}}  {total:7.3f}s")
    print(f"  {'throughput':<{width}}  {total_bytes / 1e6 / total:7.2f} MB/s")
    print()

    # --- A/B: what each prefilter is worth ---------------------------------
    print("prefilter contribution (fastest of each, same process):")

    pattern_scanner = next(s for s in build_all(include=["pattern"]))
    with_pf, _ = best_of(lambda: sum(1 for _ in pattern_scanner.scan(context)), args.repeat)
    original = Prefilter.matches
    Prefilter.matches = lambda self, text, lowered=None: True
    try:
        without_pf, _ = best_of(lambda: sum(1 for _ in pattern_scanner.scan(context)), args.repeat)
    finally:
        Prefilter.matches = original
    print(f"  pattern literal prefilter   {without_pf:7.3f}s -> {with_pf:7.3f}s"
          f"  ({without_pf / with_pf:.2f}x)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
