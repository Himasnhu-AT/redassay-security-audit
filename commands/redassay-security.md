---
description: Audit this codebase for vulnerabilities, review them on a local board, and apply the fixes you approve.
argument-hint: "[audit|scan|review|board|fix|watch|status|report|reset] [path]"
allowed-tools: Bash, Read, Edit, Write, Grep, Glob, Task, TodoWrite
---

# redassay

Run the security audit loop over this repository.

**Requested operation:** `$ARGUMENTS`
(empty means `audit` — the full loop)

---

## The engine

`redassay` ships with this plugin. Every invocation below assumes:

```bash
REDASSAY="python3 ${CLAUDE_PLUGIN_ROOT}/engine/redassay_cli.py"
```

Define that once at the start and reuse it. Check it runs (`$REDASSAY --version`)
before anything else; if it fails, report the error and stop rather than
improvising a scan by hand.

The target repository is the current working directory unless a second argument
gives a path. Pass it as `--root <path>` to every command.

---

## Operations

### `audit` (default)

The whole loop, in order. Do not skip steps — each one feeds the next.

**1. Deterministic scan.**

```bash
$REDASSAY scan --json > /tmp/redassay-scan.json
```

Read the summary counts. Do not paste the whole file into the conversation.

**2. Model-driven review** — the half the scanners cannot do.

Regex and AST rules find *shapes*. They cannot find a missing authorization
check, a broken invariant, a business-logic flaw, or a race. That is your job.

Use the `redassay-audit` skill for the method. In short: identify the trust
boundaries (HTTP handlers, queue consumers, CLI entry points, webhooks,
deserialization points), follow untrusted data inward, and ask what the code
assumes that an attacker controls.

Prioritise by what the scan already told you — the hotspot list names the files
worth reading first. Launch parallel `redassay-analyst` subagents, one per
subsystem, when the repository is large enough that reading it serially would
lose the thread.

Write what you find as JSON and merge it in:

```bash
cat <<'JSON' | $REDASSAY add --source claude
{"findings": [
  {
    "rule_id": "claude.broken-object-authz",
    "title": "Order lookup is not scoped to the authenticated user",
    "severity": "high",
    "confidence": "high",
    "description": "GET /orders/<id> loads by primary key with no ownership filter, so any authenticated user can read any order by incrementing the id.",
    "remediation": "Filter the query by the session user: Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()",
    "location": {"path": "app/orders.py", "line": 84, "snippet": "order = Order.query.get(order_id)"},
    "cwe": ["CWE-639"],
    "owasp": ["A01:2021 Broken Access Control"],
    "tags": ["authz", "reviewed"]
  }
]}
JSON
```

Rules for what you write:
- **One finding per defect**, with the exact file and line.
- **`description` states the data path**, not the category. "request.args['id']
  reaches the query unfiltered" beats "possible IDOR".
- **`remediation` is the actual change**, ideally the corrected line.
- **`confidence: high` only when you read the code and are sure.** Everything
  else is `medium` or `low`. Inflating confidence is how a tool gets ignored.
- Do not restate what the scanner already found. Check `/tmp/redassay-scan.json`
  first — if the rule id is there for that line, it is already recorded.

**3. Confirm or drop the scanner's uncertain findings.**

```bash
$REDASSAY list --json --min-severity medium
```

For each finding with `confidence` of `low` or `medium`, open the file and
decide. Then either:

```bash
$REDASSAY status <id> confirmed
$REDASSAY comment <id> "Reachable from the public /search endpoint."
```

or:

```bash
$REDASSAY dismiss <id> --reason "Argument is a module-level constant, never request data."
```

This step is what makes the board worth opening. A board full of unreviewed
regex hits is a worse experience than no board.

**4. Start the board.**

```bash
$REDASSAY serve --no-browser &
```

Tell the user the URL, the finding count by severity, and the three things you
most want them to look at. Then **stop and wait** — do not start fixing.

**5. Then run `watch`** (below) so their decisions get acted on.

---

### `scan`
Just the deterministic pass. Print the summary. No model review, no board.

### `review`
Step 2 only — model-driven review against an existing store.

### `board`
```bash
$REDASSAY serve --no-browser &
```
Report the URL and the current counts.

### `fix`
Drain the queue once:

```bash
$REDASSAY queue pull
```

Returns claimed actions, each with the full finding attached. For each one,
follow the `redassay-remediate` skill. The short version:

1. Read the file and enough of its surroundings to understand the call.
2. Make the **smallest** change that removes the vulnerability class. Do not
   refactor, rename, reformat, or "improve" anything else.
3. Honour the note the reviewer attached to the fix request.
4. If tests exist, run the ones covering the file you touched.
5. Record it:

```bash
$REDASSAY resolve <finding-id> \
  --summary "Bound the host as a subprocess argument instead of a shell string" \
  --file app/net.py
$REDASSAY queue complete <seq> --result "fixed"
```

If a finding cannot be fixed safely — the correct fix needs a design decision,
or the code is a false positive you can now prove — say so and mark it:

```bash
$REDASSAY queue complete <seq> --state failed --result "Needs a decision: the endpoint is documented as accepting arbitrary URLs. Suggest an allowlist, but that changes behaviour."
$REDASSAY comment <finding-id> "Not fixed - see queue action <seq>."
```

Never fake a fix. A finding marked fixed that is not fixed is worse than an
open one.

After the batch, rescan to confirm:

```bash
$REDASSAY scan --quiet
```

Findings that no longer reproduce move to `verified` automatically. Report which
ones did and which did not — a fix that did not clear the finding is the most
important thing on the screen.

### `watch`
The interactive loop. Repeat until the user says stop:

1. `$REDASSAY queue pull`
2. If nothing is claimed, wait about 20 seconds and poll again. Stay quiet while
   polling — no output per tick.
3. If actions came back, handle them as in `fix`.
4. On a `rescan` action, run `$REDASSAY scan --quiet` and report the delta.
5. Summarise after each batch: what was fixed, what was refused, what is left.

### `status`
```bash
$REDASSAY stats
$REDASSAY queue list
```
Report counts, hotspots and anything pending.

### `report`
```bash
$REDASSAY report --format markdown -o SECURITY-AUDIT.md
$REDASSAY report --format sarif -o redassay.sarif
```

### `reset`
Ask for confirmation, then delete `.redassay/`. This discards every dismissal
and comment, so never do it without being asked explicitly.

---

## Ground rules

- **Read before you write.** Every fix starts with reading the file.
- **The store is the source of truth**, not the conversation. Anything worth
  remembering goes in via `add`, `comment` or `resolve`.
- **Severity is about impact, not how interesting the bug is.** Remote code
  execution on an unauthenticated endpoint is critical. A weak hash on a cache
  key is informational.
- **Never write a credential, token or key into the conversation or a commit**,
  even one you found in the repository. Reference it by finding id.
- **Do not commit anything** unless the user asks.
