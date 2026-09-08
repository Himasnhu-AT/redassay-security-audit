# Command reference

Everything the plugin does, it does through this CLI. There is no hidden API.

```bash
redassay [--root PATH] [--json] [--no-color] <command> [options]
```

`--root`, `--json` and `--no-color` work before or after the subcommand.

Exit codes: `0` success, `1` a gate tripped (`--fail-on`), `2` an error.

---

## Getting started

### `init`

```bash
redassay init
```

Creates `.redassay/`, writes a config, adds the store to `.gitignore`, and
scaffolds a commented `.redassayignore`. Not required - `scan` creates what it
needs - but running it first gives you the ignore template, which is the thing
most repositories want before their first scan.

---

## Scanning

### `scan`

Run every enabled scanner, merge the result into the store, print a summary.

| Option | Effect |
| --- | --- |
| `--min-severity LEVEL` | Drop anything below this level |
| `--include GLOB` | Restrict to these paths (repeatable) |
| `--exclude GLOB` | Skip these filenames (repeatable) |
| `--exclude-tests` | Skip test directories and test files |
| `--scanner NAME` | Run only this scanner (repeatable) |
| `--skip-scanner NAME` | Disable a scanner (repeatable) |
| `--since REF` | Only scan files that differ from a git ref |
| `--blame` | Tag findings with the commit and author of the line |
| `--new-only` | Report only findings absent from the baseline |
| `--fail-on LEVEL` | Exit 1 if anything at this level is open |
| `--limit N` | Show at most N findings (default 40) |
| `-v` | Include remediation text |
| `--quiet` | Summary only |

```bash
redassay scan
redassay scan --min-severity high -v
redassay scan --since origin/main --fail-on high
redassay scan --scanner secrets --json
```

`--exclude-tests` is worth reaching for on an unfamiliar repository. Test suites
construct malicious input on purpose; on one large framework, 59% of all findings came from its own tests. The flag is not the default because a vulnerability in a test
helper is still a vulnerability - it is a decision, not a cleanup.

`--since` is what makes this usable as a pull-request gate. It asks git which
files differ, and scans only those. If the ref does not exist, the command fails
rather than silently scanning everything — a gate that cannot answer the
question must not report success.

A scoped scan never retires findings in files it did not open.

### `baseline`

Freeze the current open findings so a gate only fails on what gets added after.

```bash
redassay baseline            # snapshot
redassay baseline --show     # how many are frozen
redassay baseline --clear    # unfreeze
```

The alternative — demanding a team clear four hundred pre-existing findings
before the check goes green — is how security tooling gets switched off.

---

## Reading

### `list`

```bash
redassay list
redassay list --min-severity high --path app/
redassay list --all                     # include dismissed and fixed
redassay list --rule py.sql-dynamic
redassay list --json
```

Defaults to open findings only, worst first.

### `show <id>`

Full detail for one finding: description, remediation, classification, comments,
fix record, and the surrounding source. Accepts an id prefix.

### `stats`

Counts by severity and status, plus hotspots — files ranked by summed risk
rather than finding count.

### `surface`

```bash
redassay surface
redassay surface --unprotected
redassay surface --kind queue --kind socket
redassay surface --json
```

Inventories the ways in: HTTP routes, server actions, queue consumers, socket
handlers, webhooks, scheduled jobs. For each one it records what it is, where it
is, and what stands in front of it.

```
  + GET  /dashboard            app/routes/index.js:44
  x POST /admin/wipe           app/routes/admin.js:12
```

| Mark | Meaning |
| --- | --- |
| `+` | something recognisably auth-shaped is in front of it |
| `~` | an unidentified middleware argument sits between the path and the handler |
| `!` | an explicit opt-out - `@csrf_exempt`, `AllowAny`, `@Public` |
| `x` | nothing found |

**`x` is a hint, not a verdict.** Proximity is not proof: a guard three files
away in a router chain is invisible here, and an `isAdmin` that returns true for
everyone reads as a guard. The value is the *list* - a complete enumeration of
what a stranger can reach, which is what an audit should start from and what
grepping never quite produces.

Routes whose job is to be unauthenticated - `/login`, `/health`, `/webhooks/*` -
are recognised and sorted last rather than counted as problems.

Framework detection drives the whole thing, so `redassay surface --json`
includes the detected stack and, for known frameworks, the specific mistakes
that framework invites.

### `history`

```bash
redassay history
redassay history --limit 5 --json
```

One row per scan: files walked, totals by severity, how many were new, how many
were verified fixed, and the delta against the previous run. This is the answer
to "is this getting better or worse", which no single scan can give you.

### `prune`

```bash
redassay prune --dry-run
redassay prune --older-than 180
redassay prune --status dismissed --older-than 365
```

Drops long-settled findings. Defaults to `verified` only, and only those older
than 90 days - a store that only grows becomes a store nobody reads, but a
dismissal someone spent time on is expensive to lose and cheap to keep, so
pruning anything else takes an explicit `--status`.

### `scanners` / `rules`

```bash
redassay scanners
redassay rules
redassay rules --pack crypto
redassay rules --json | jq '.count'
```

---

## Triage

### `status <id> <status>`

`open` · `confirmed` · `queued` · `fixing` · `fixed` · `verified` · `dismissed`

Illegal transitions are refused. `--strict` makes that an error instead of a
silent no-op.

### `comment <id> [body]`

Omit the body to read from stdin.

### `dismiss <id> --reason "..."`

Marks it dismissed and records why. Add `--suppress-rule` to stop the rule
firing on that path at all, and `--path-glob` to widen the suppression:

```bash
redassay dismiss a584 --reason "Generated stubs" --suppress-rule --path-glob "gen/**"
```

### `suppress <rule> --path GLOB --reason "..."`

Suppress without having a finding in hand.

---

## Fixing

### `resolve <id> --summary "..."`

Record that a fix was applied. This is how an agent closes the loop.

```bash
redassay resolve a584 \
  --summary "Bound the host as a subprocess argument" \
  --file app/net.py

# Or pipe the actual change in - the touched files are read out of the diff,
# so --file becomes optional and the board shows what was done.
git diff -- app/net.py | redassay resolve a584 \
  --summary "Bound the host as a subprocess argument" --diff-file -
```

The next scan that no longer reproduces the finding moves it to `verified`. One
that reproduces it again reopens it and says so.

### `add`

Ingest findings from JSON on stdin. This is how Claude's review gets merged with
the scanners' output.

```bash
cat findings.json | redassay add --source claude
```

Accepts either `{"findings": [...]}` or a bare list. A finding without a path is
skipped with a warning rather than failing the batch.

---

## The queue

### `queue`

The board never edits code. It appends actions, and an agent drains them.

```bash
redassay queue list                       # what is pending
redassay queue pull                       # claim pending work (JSON)
redassay queue pull --limit 5
redassay queue complete 7 --result "fixed"
redassay queue complete 7 --state failed --result "needs a decision"
redassay queue push fix --id a584
redassay queue clear
```

`pull` returns each claimed action with the full finding attached, so an agent
has everything it needs in one call.

---

## Output

### `report`

```bash
redassay report --format markdown -o SECURITY-AUDIT.md
redassay report --format sarif -o redassay.sarif
redassay report --format json
redassay report --format quickfix
redassay report --format exposure
```

`exposure` answers one question - what does this repository publish? - grouped
by what is behind the port rather than by file, because the decision is per
service and the same wherever the mapping happens to be written. Data stores
come first, since most ship with authentication disabled for local development
and the port *is* the access control.

`quickfix` emits `path:line:col: severity: message [rule]` - the convention every
editor already knows how to jump through:

```vim
:cexpr system('redassay report --format quickfix')
:copen
```

```bash
# emacs compilation-mode, VS Code problem matchers, and anything else that
# parses compiler output will take it as-is.
redassay report --format quickfix > findings.txt
```

SARIF output carries `security-severity` and stable `partialFingerprints`, so
GitHub code scanning deduplicates correctly across runs.

### `serve`

```bash
redassay serve
redassay serve --port 7718 --no-browser
```

Binds `127.0.0.1` by default. It serves file contents from the repository it is
pointed at, so think before passing `--host`.

---

## Diagnostics

### `doctor`

```bash
redassay doctor
redassay doctor --json
```

Checks the Python version, that every rule pack compiles, that the scanners
load, that the advisory database reads, whether the target is a git repository,
whether the store is readable and at a schema this build understands, whether
the board port is free, and whether the directory is writable.

Every check corresponds to something that has actually gone wrong. Run it first
when something does not work; it answers most of the questions without a round
trip.

Exits 2 if a blocking problem is found.

### `watch`

```bash
redassay watch                      # poll until interrupted
redassay watch --once               # drain what is queued and exit
redassay watch --interval 1 --limit 5
redassay watch --timeout 60
```

Polls the action queue and writes each claimed action to stdout as one JSON
object per line, with the full finding attached. The agent loop lives in the
plugin; this exists so the same loop can be driven from a terminal, and so the
behaviour is testable without a model.

---

## Configuration

Resolution order, most specific first:

1. CLI flags
2. `.redassay/config.json` (written by `init`, not committed)
3. `[tool.redassay]` in `pyproject.toml` (committed — this is where team
   settings belong)
4. `REDASSAY_PORT`, `REDASSAY_HOST`, `REDASSAY_MIN_SEVERITY`, `REDASSAY_AUTHOR`
5. defaults

```toml
[tool.redassay]
min_severity = "low"
disabled_rules = [
  # A comment here is the whole point: say why.
  "authz.missing-authorization-check",
]
```

Path exclusions go in `.redassayignore`, which uses gitignore syntax and is read
alongside `.gitignore`.

---

## Debugging

`REDASSAY_TRACEBACK=1` makes the CLI re-raise instead of printing a one-line
error.
