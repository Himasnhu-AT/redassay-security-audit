# Performance

Numbers from `tools/benchmark.py`, which runs every measurement back to back in
one process. Wall-clock times taken minutes apart are not comparable - machine
load moves them by a factor of two, which is enough to make an optimization look
like a regression or vice versa.

```bash
python3 tools/benchmark.py /path/to/repo --repeat 3
```

## Where the time goes

Django, 5,375 files, 34 MB:

| Scanner | Time | Findings |
| --- | --- | --- |
| secrets | ~7-10s | 10 |
| pattern | ~3-6s | 542 |
| python-ast | ~2-5s | 279 |
| javascript | 0.03s | 0 |
| everything else | <0.01s | 1 |

Roughly 1.5-3 MB/s end to end, depending on the machine. A 250-file project
scans in well under a second; `--since` on a pull request is effectively
instant, because it only looks at the changed files.

## The optimization that worked

**A literal prefilter in front of every pattern rule.** Before matching a rule
line by line, ask a much cheaper question of the whole file: does it contain a
substring the pattern *must* match? `\bos\.system\s*\(` can only match in a file
containing "os.system". One `in` test replaces a regex search per line.

`prefilter.py` extracts those mandatory literals from the regex source,
conservatively: it understands top-level literals, escaped characters, and
alternation groups (including nested ones), and returns nothing for anything
else. Returning nothing means "run the rule normally", which is always correct.

It covers 96% of the rule packs and measures **2.3-3x** on the pattern scanner,
with output verified byte-identical on Django, PyGoat, NodeGoat and all four
fixtures.

## Two optimizations that did not work

Recorded because they look obviously correct and are not.

**A combined alternation for the 27 secret provider patterns.** One regex
instead of 27 per line. Measured 1.03-1.10x - a 27-branch alternation
backtracks, and the engine ends up doing similar work. Running the same
alternation once over the whole file instead of per line was *worse* than the
baseline: the patterns containing `[^/\s:@]+:` backtrack badly over a 30 KB
string.

**A per-provider literal gate.** The same idea as the pattern prefilter, applied
per line. Measured **0.62x** - slower. Each gate is itself a regex, and the
candidate list allocates once per line across 800,000 lines. The gate cost more
than the work it skipped.

The difference between the win and the losses is granularity. The prefilter runs
once per *file* and eliminates a rule entirely. The gates ran once per *line*
and only reordered work.

## If you need it faster

- **Scope the scan.** `--since origin/main` is the single biggest lever, and it
  is what you want in CI anyway.
- **Drop a scanner.** `--skip-scanner secrets` roughly halves a full scan if you
  already run a dedicated secret scanner in your pipeline.
- **Raise the floor.** `--min-severity high` does not speed up matching - the
  filter runs after - but it makes the output usable, which is usually the real
  complaint.

## What was deliberately not done

**Parallelism.** `multiprocessing` over files would help, but it means pickling
findings across process boundaries, a worker pool that has to be torn down
cleanly on Ctrl-C, and platform differences in how workers start. For the repo
sizes this tool is pointed at, the prefilter got the scan under 20 seconds; the
complexity was not worth the remaining factor.

**A real parser for JavaScript.** tree-sitter would be faster *and* more
accurate. It is also a native dependency, and the zero-dependency property is
worth more than the speed here. See `docs/architecture.md`.
