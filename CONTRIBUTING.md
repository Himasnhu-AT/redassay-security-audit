# Contributing

## Running it

```bash
git clone <this repo> && cd redassay
bash scripts/check.sh          # everything CI runs
bash scripts/check.sh --quick  # just the tests and the linters
```

No install step. If any of that needs one, that is a bug.

`python3 engine/redassay_cli.py doctor` answers most "why is this not working"
questions directly.

## The rules this project holds itself to

**The engine imports nothing outside the standard library.** Enforced by
`tools/check_stdlib_only.py` in CI. This is the property that lets someone point
redassay at a repository they do not trust yet, on a machine with no network. It
costs real capability - no YAML parser, no tree-sitter - and those costs are
documented in `docs/architecture.md` rather than worked around.

**Every rule earns its noise.** `fixtures/clean-app/` is idiomatic, safe code:
the correct form of everything the rules flag elsewhere. The test suite asserts
it produces zero high-confidence findings. A rule that lights it up is not
finished.

**Confidence is honest.** `high` means the pattern is specific enough that a
match is almost always the defect. If reachability is unknown, it is `medium`.
If the rule is a heuristic, it is `low`. Inflating confidence is how a security
tool teaches people to skim past its output.

**Findings explain themselves.** A `description` that names a category is not
enough. Say what the data path is and what an attacker gets. A `remediation`
should be close enough to the actual change that someone can apply it.

## Adding a rule

See [`docs/writing-rules.md`](docs/writing-rules.md) for the full guide. The
short version:

1. Add it to a pack in `engine/redassay/rules/`.
2. Add a labelled sample to `fixtures/vuln-polyglot/`:
   `# VULN: your.rule-id`
3. Add the *safe* form to `fixtures/clean-app/`.
4. `python3 tools/generate_rule_docs.py`
5. `bash scripts/run-tests.sh`
6. Run it against a real repository and read every hit.

`tests/python/test_rules.py` lints every rule: unique namespaced id, canonical
severity, a description of at least 40 characters, a remediation, at least one
CWE, no inline `(?i)`, a bounded proximity window. Each of those checks exists
because that bug shipped once.

## Adding a scanner

Subclass `Scanner`, implement `scan_file`, decorate with `@register`, and add it
to the import list in `scanners/registry.py`.

If your scanner needs to make a judgement call - is this reachable, is this guard
correct, is this value attacker-controlled - it does not belong in a scanner. It
belongs in the model-driven half of the audit (`skills/redassay-audit`). The
line between the two halves is the thing that keeps both honest.

## Changing the store format

`store.py` has a `migrate()` function and a `SCHEMA_VERSION`. Bump the version,
add the migration, add a test that loads the old shape. The store holds
dismissals a human spent time making; losing them is the worst thing this tool
can do.

## Tests

- Python: `unittest`, no pytest. 699 tests, no dependencies.
- JavaScript: `node:test`. 75 tests over the board's modules.
- Both: `bash scripts/run-tests.sh`

If you fix a false positive, add it to `tests/python/test_false_positives.py`
with a note about the repository it came from. That file is the most valuable
one in the suite - it is the only record of what the tool got wrong.

## Performance

Measure with `tools/benchmark.py`, never with `time`. Wall-clock numbers taken
minutes apart differ by a factor of two on the same machine, which is enough to
make a regression look like a win. `docs/performance.md` records two
optimizations that looked obviously correct and measured slower; if you find a
third, write it down there rather than leaving the next person to rediscover it.

## Style

Match the surrounding code. Comments explain *why*, and only where the reason is
not obvious from reading - a comment that restates the line is worse than none.
