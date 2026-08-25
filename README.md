# redassay

A security audit loop for Claude Code: scan a codebase, review what was found on
a local board, and let Claude apply only the fixes you approve.

```
/redassay-security audit
```

That runs the whole loop — deterministic scan, model-driven review of what the
rules cannot see, triage, then a board at `http://127.0.0.1:7717` where you
decide what actually gets fixed.

---

## Why it works this way

Pointing a language model at a repository and asking for the security bugs
produces a wall of markdown. You cannot dismiss anything permanently, you cannot
re-run it and get the same answer, and you cannot say "fix these four, leave the
rest". The output is unreviewable, so it does not get reviewed.

redassay splits the problem into three pieces that talk through files on disk:

| | What it does | Why it is separate |
| --- | --- | --- |
| **Engine** | Pattern, AST and dependency scanners walk the tree | Deterministic. Same input, same output, no model involved, no network. |
| **Findings repo** | `.redassay/findings.json` | Durable. Your dismissals and comments survive re-scans, refactors and code motion. |
| **Board** | A local HTTP server and a review UI | A human decides. Nothing is fixed until somebody approves it. |

Claude sits on top: it runs the scan, adds the findings the rules structurally
cannot find (authorization gaps, logic flaws, unsafe data flow), drains the
approval queue, writes the patches, and marks findings resolved.

## Install

```
/plugin marketplace add <this repo>
/plugin install redassay-security
```

No `pip install`, no `npm install`. The engine is Python standard library only —
deliberately, because a security tool that needs you to install forty packages
before it can tell you whether you have a problem is a hard sell.

Requires Python 3.9+. Node is only needed to run the board's own test suite.

## See it work

```bash
bash scripts/demo.sh
```

Copies the vulnerable fixture to a temp directory and walks the whole loop -
scan, approve two fixes, dismiss one with a reason, drain the queue, patch,
rescan. The two fixed findings come back `verified`; the dismissal and the
review note survive the rescan. Nothing touches the repository you are in. Add
`--serve` to leave the board running at the end.

## Using it

```
/redassay-security audit      # the whole loop, then open the board
/redassay-security scan       # deterministic pass only
/redassay-security review     # model-driven review only
/redassay-security board      # just start the board
/redassay-security fix        # drain the approval queue once
/redassay-security watch      # keep draining as you approve things
/redassay-security status     # counts, hotspots, pending work
/redassay-security report     # SECURITY-AUDIT.md and redassay.sarif
```

### The board

The full walkthrough is in [`docs/loop.md`](docs/loop.md).

Three panes: filters on the left, findings in the middle, detail on the right.
Each finding shows the vulnerability, the source around it, the fix, and a place
to argue with it.

For each one you can:

- **Request a fix** — queues it, with an optional note about what the fix must
  preserve. Claude picks it up on the next `watch` tick.
- **Dismiss it** — with a reason, which is stored. It will not come back.
- **Comment** — anything you want the person reading this next to know.
- **Select several and fix them together** — shift-click for a range.

Keyboard: `j`/`k` to move, `x` to select, `f` to request a fix, `d` to dismiss,
`c` to comment, `/` to search.

Nothing on the board edits your code. It writes to an approval queue; an agent
does the work and records what it did.

## The engine on its own

The board and the plugin are optional. The scanner is a normal CLI:

```bash
python3 engine/redassay_cli.py scan
python3 engine/redassay_cli.py list --min-severity high
python3 engine/redassay_cli.py show a5843742b96a
python3 engine/redassay_cli.py serve
```

Useful in CI:

```bash
# Fail a pull request only on what it adds.
redassay scan --since origin/main --fail-on high

# Or freeze today's findings and ratchet from there.
redassay baseline
redassay scan --new-only --fail-on medium
```

Full command reference: [`docs/cli.md`](docs/cli.md).

## What it detects

115 rules across 12 packs, plus four scanners that do more than match text.

**Injection** — SQL, command, code, template, LDAP, XPath, NoSQL operator
injection, across Python, JS/TS, Ruby, PHP, Java, Go, C#.

**The Python AST scanner** parses the file and tracks taint within a function.
It knows the difference between `cursor.execute(sql, params)` and an f-string
whose interpolated name was assigned from `request.args` three lines up — and it
raises severity only for the second. It also notices when the function validates
the value first, and downgrades instead of shouting.

**The JS/TS scanner** works over a comment- and string-stripped view of the
source and tracks values bound out of `req.query` / `req.body` / `req.params`
into shell, SQL, filesystem and HTTP sinks.

**Secrets** — provider tokens (AWS, GitHub, Stripe, OpenAI, Slack, and twenty
more) at high confidence, plus entropy-gated generic assignments with a
placeholder filter that keeps `password = "changeme"` out of your report.

**Dependencies** — an offline advisory snapshot across npm, PyPI, Maven, Go,
RubyGems and Composer, with manifest parsers for each. Plus supply-chain
hygiene: floating versions, install hooks that fetch and run remote code,
dependencies resolved from a git ref.

**CI/CD** — `pull_request_target` combined with a checkout of the PR head,
`${{ github.event.* }}` interpolated into a `run:` block, third-party actions
pinned to a mutable tag, secrets echoed into the log.

**Configuration** — Dockerfiles, compose files, Kubernetes manifests, `.env`
files, Terraform, cloud IAM.

**Crypto and access control** — weak hashes on passwords, ECB, static IVs,
disabled TLS verification, JWT signature bypass, non-constant-time comparison,
path traversal, IDOR shapes, CORS misconfiguration, CSRF.

**Exposure** — credentials and personal data written to logs, diagnostic
endpoints with no auth guard, tracebacks rendered into responses, privileged
actions with no audit trail.

Rule details: [`docs/rules.md`](docs/rules.md). Writing your own:
[`docs/writing-rules.md`](docs/writing-rules.md).

## About the false positives

A scanner is only as useful as its noise floor. The measures taken here:

- **The control fixture.** `fixtures/clean-app/` is idiomatic, safe code — the
  correct form of everything the rules flag elsewhere. The test suite asserts it
  produces zero high-confidence findings. Every rule that lights it up is a bug.
- **Proximity guards.** A rule can require a second pattern within N lines, so a
  string concatenation is only SQL injection if something SQL-shaped is nearby.
  Commented-out code is excluded from that window.
- **Context awareness.** Code inside `<pre>` blocks, markdown fences, Python
  docstrings and string literals is data, not code. Credentials quoted in a
  README are downgraded, not silenced.
- **Confidence, separately from severity.** The board ranks by severity weighted
  by confidence, so a confident `high` sits above a speculative `critical`.
- **Suppression that sticks.** `# redassay: ignore <rule> - <reason>` in the
  source, or a dismissal on the board. Neither comes back on the next scan.

`tests/python/test_false_positives.py` is a regression suite built from findings
that real repositories produced and a human rejected.

[`docs/evaluation.md`](docs/evaluation.md) has the measured results on PyGoat,
NodeGoat and Django - including the four false positives NodeGoat produced and
the honest finding that Django's own internals light up the rules because a
framework *implements* the primitives the rules look for.

## Layout

```
.claude-plugin/    plugin and marketplace manifests
commands/          the /redassay-security slash command
skills/            audit method, remediation method, triage loop
agents/            redassay-analyst, redassay-fixer
engine/redassay/   the scanner - stdlib only
  scanners/        pattern, secrets, python-ast, javascript, deps, cicd, configs
  rules/           nine JSON rule packs
  server/          the board: HTTP server, JSON API, static UI
tests/python/      670 unittest tests
tests/js/          59 node:test tests for the board's modules
fixtures/          vulnerable apps, and one clean control app
```

## Performance

Roughly 1.5-3 MB/s: a 250-file project in under a second, Django's 5,375 files in
around 20. A literal prefilter in front of every pattern rule does most of the
work - and two optimizations that looked obvious and measured *slower* are
written up alongside it in [`docs/performance.md`](docs/performance.md).

## Running the tests

```bash
bash scripts/run-tests.sh
```

Both suites, no installation. Python via `unittest`, JavaScript via `node:test`.

## License

MIT.
