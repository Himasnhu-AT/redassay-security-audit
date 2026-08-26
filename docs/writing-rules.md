# Writing rules

A rule pack is a JSON file. Drop one in `.redassay/rules/` and it is picked up on
the next scan — no code change, no restart, no plugin reload.

```json
{
  "pack": "house-style",
  "defaults": { "owasp": ["A03:2021 Injection"], "tags": ["internal"] },
  "rules": [
    {
      "id": "house.legacy-db-helper",
      "title": "Deprecated query helper that does not bind parameters",
      "severity": "high",
      "confidence": "medium",
      "languages": ["python"],
      "pattern": "\\blegacy_query\\s*\\(",
      "not_pattern": "legacy_query\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\)",
      "description": "legacy_query() interpolates its argument into the SQL text. It predates the parameterized helper and is kept only for the reporting module.",
      "remediation": "Use db.query(sql, params). If the call genuinely needs a dynamic table name, pass it through TABLE_ALLOWLIST first.",
      "cwe": ["CWE-89"]
    }
  ]
}
```

A rule whose `id` matches a built-in replaces it. That is the supported way to
retune a rule you disagree with, and it survives upgrades.

## Fields

**Required:** `id`, `title`, `pattern`.

| Field | Purpose |
| --- | --- |
| `id` | `namespace.kebab-name`. Stable — it appears in suppressions. |
| `title` | One line, shown in every list. |
| `severity` | `critical` `high` `medium` `low` `info`. Default `medium`. |
| `confidence` | `high` `medium` `low`. Default `medium`. |
| `description` | What the defect is and why it matters. |
| `remediation` | The change to make, ideally the corrected line. |
| `languages` | Restrict by detected language. Omit or `["*"]` for all. |
| `pattern` | Python regex, matched per line. |
| `not_pattern` | Kills the match on the same line. |
| `nearby` | A second pattern that must appear within the window. |
| `nearby_absent` | A pattern that must **not** appear within the window. |
| `nearby_window` | Lines either side. Default 4, capped at 6 by the linter. |
| `ignore_case` | Compile case-insensitively. |
| `match_comments` | Fire inside comments too. Off by default. |
| `skip_in_strings` | Do not fire inside string literals or docstrings. |
| `path_include` / `path_exclude` | Glob restrictions. |
| `max_matches` | Cap per file. Default 25. |
| `cwe` / `owasp` / `references` / `tags` | Classification. |

Inline `(?i)` is rejected — Python 3.11 made mid-pattern global flags a hard
error. Use `ignore_case` instead. The rule linter enforces this.

## The three guards, and when to reach for each

Regex SAST is unusable without them. Most of the work in a good rule is in the
guards, not the pattern.

**`not_pattern` — same line, kills the match.**

Use it when the safe and unsafe forms are distinguishable on one line:

```json
"pattern": "yaml\\.load\\s*\\(",
"not_pattern": "Loader\\s*=\\s*(yaml\\.)?SafeLoader"
```

**`nearby` — requires corroboration.**

Use it when the pattern alone is too generic. A string concatenation is not SQL
injection unless something SQL-shaped is close by:

```json
"pattern": "[\"'`]\\s*(\\+|%)\\s*",
"nearby": "(?i)\\b(select|insert|update|delete)\\b",
"nearby_window": 3
```

Keep the window small. A window of 6 reaches the *previous function*, which is
how `crypto.weak-random-security` once flagged a date helper because an
unrelated login function two lines below took a `password` argument. That bug is
pinned by a test.

**`nearby_absent` — requires the absence of a mitigation.**

Use it when the fix is visible nearby:

```json
"pattern": "\\.innerHTML\\s*=",
"nearby_absent": "DOMPurify|sanitiz|escapeHtml|textContent",
"nearby_window": 6
```

Comment lines are blanked before the window is built, so commented-out code
cannot satisfy or defeat a proximity guard.

## Severity and confidence are different axes

Severity is impact if real. Confidence is how sure the rule is that it *is*
real. The board ranks by severity weighted by confidence, so getting confidence
right matters as much as severity:

- `high` — the pattern is specific enough that a match is almost always the
  defect. `AKIA[A-Z0-9]{16}` is an AWS key. Nothing else looks like that.
- `medium` — the pattern is right but reachability is unknown.
- `low` — the pattern is a heuristic. `authz.missing-authorization-check` is
  low because "no decorator nearby" is not "no authorization".

A `low` confidence rule that is honest about it is useful. One that claims
`high` teaches people to skim the board, and then the `critical` findings go
unread too.

## Testing a rule

**Put the samples in the rule.** Every rule carries `examples` (lines it must
match) and `counterexamples` (lines it must not):

```json
{
  "id": "house.legacy-db-helper",
  "pattern": "\\blegacy_query\\s*\\(",
  "not_pattern": "legacy_query\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\)",
  "examples": ["rows = legacy_query(\"SELECT * FROM t WHERE n = '\" + name)"],
  "counterexamples": ["rows = legacy_query(\"SELECT * FROM t\")"]
}
```

`tests/python/test_rule_examples.py` runs each one through the scanner. This is
the cheapest and highest-yield test in the project: introducing it found seven
rules that were silently broken, including five whose literal matcher used
`[^"']*` and therefore could never match the quote *inside* a SQL or XPath
string - `"WHERE name = '"` never matched, in the most-used rule in the pack.

The counterexample matters as much as the example. A rule with a `not_pattern`
or a `nearby_absent` exists *because* of a false positive; the line that caused
it belongs in the pack, so the next person tightening the regex cannot
reintroduce it.

Two rules failed on their own counterexamples immediately: a credential-logging
rule that flagged `log.info("token present=%s", bool(token))` - its own
recommended fix - and a debug-endpoint rule whose guard list was snake_case only
and so missed every Express `requiresAuth` middleware.

### Fixtures, for anything the samples cannot express

A one-line sample cannot exercise a proximity guard across functions, or the
interaction between several rules. For those, add a labelled sample to
`fixtures/vuln-polyglot/` and the safe form to `fixtures/clean-app/`:

```python
# VULN: house.legacy-db-helper
rows = legacy_query("SELECT * FROM t WHERE n = '" + name + "'")
```

`tests/python/test_rule_packs_fire.py` reads those `VULN:` labels and asserts
each one still fires. `tests/python/test_engine.py` asserts the clean fixture
produces no high-confidence findings. Between them, a rule cannot rot silently
in either direction.

Then check it against something real:

```bash
redassay --root ../some-open-source-project scan --rule house.legacy-db-helper
```

Read every hit. If any is wrong, the rule is not finished.

## The rule linter

`tests/python/test_rules.py` enforces, for every rule in every pack:

- unique ids matching `^[a-z0-9]+\.[a-z0-9-]+$`
- a canonical severity string
- a non-empty `description` of at least 40 characters, and a `remediation`
- at least one CWE, formatted `CWE-\d+`
- OWASP entries formatted `A\d{2}:2021 `
- every regex compiles, with no inline `(?i)`
- `languages` naming languages the detector knows
- a bounded `nearby_window`

These are not style preferences. Each one is a bug that shipped once.

## When a rule does not belong in a pack

If the decision needs to look at more than a window of lines — reachability,
whether a guard is correct, whether the value is attacker-controlled — it is not
a pattern rule. It belongs in a scanner (see `scanners/python_ast.py` for the
taint-tracking approach) or in the model-driven half of the audit
(`skills/redassay-audit`).
