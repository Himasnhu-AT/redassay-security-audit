---
name: redassay-audit
description: Method for the model-driven half of a security audit - finding the vulnerability classes that pattern and AST scanners structurally cannot find. Use when auditing a codebase for security issues, reviewing a diff for vulnerabilities, or after a redassay scan to add what the rules missed.
---

# Auditing what the scanners cannot see

A scanner answers "does this code contain a dangerous shape?". It cannot answer
"is this check in the right place?", "does this invariant hold?", or "what
happens when two of these run at once?". Those need someone who understands what
the code is *for*. That is the work described here.

## Start from the entry points, not the file tree

Reading a repository top to bottom finds nothing. Start from the list of places
untrusted data enters - and do not build that list by grepping, because the
review is then only as complete as the greps you thought of.

```bash
$REDASSAY surface --json
```

That returns every HTTP route, server action, queue consumer, socket handler,
webhook and scheduled job the engine can find, each with what stands in front of
it, plus the detected frameworks and the specific mistakes each one invites.

Read the `auth` field as a hint, never a verdict:

- `none-found` - nothing auth-shaped nearby. **Start here.**
- `middleware` - something unidentified sits in front. Open it and find out what.
- `public` - an explicit opt-out. Someone decided; check they were right.
- `guarded` - something auth-shaped is adjacent. This is the weakest signal in
  the set: an `isAdmin` that returns true for everyone reads as a guard.

The list will also miss things - a router mounted through a variable, a handler
registered by a factory. Treat it as a floor, not a ceiling, and add what you
find. These are the boundaries it is looking for:

| Boundary | Where to look |
| --- | --- |
| HTTP handlers | route decorators, controller classes, API gateway configs |
| Background jobs | queue consumers, cron entry points, webhook receivers |
| Deserialization | anything reading a blob it did not write |
| File upload | multipart handlers, anything writing to disk from a request |
| CLI / env | `argv`, environment variables read at startup in privileged tools |
| Inter-service | internal RPC that assumes the caller is trusted |

For each entry point, answer three questions:

1. **Who can reach this?** Anonymous, authenticated, or admin? Look at the
   middleware chain, not the docstring. If authentication is applied by a
   decorator, confirm it is actually on this route.
2. **What does it trust?** Every value from the request is attacker-controlled -
   including headers, the Host header, content types, filenames, and the order
   of repeated parameters.
3. **What does it assume?** "This id belongs to the caller." "This file is a
   PNG." "This user already passed the earlier check." Each assumption is a
   candidate finding.

## The classes worth hunting

These are the ones that pay for the reading time, roughly in order.

**Broken object-level authorization.** The single most common serious bug in
real applications and completely invisible to a scanner. Look for any lookup by
an id that came from the request. Ask: is the query scoped to the caller? A
`get(id)` without a `user_id`/`tenant_id`/`owner` filter is a finding unless
authorization happens somewhere you can point to.

**Authorization applied in the wrong layer.** A check in the UI, or in a service
method that another caller bypasses. Find every call site of the sensitive
operation, not just the one with the check.

**Missing authorization entirely.** Compare sibling routes. If nine handlers in
a file carry `@requires_role("admin")` and the tenth does not, that tenth one is
the finding — and it is usually an oversight, not a decision.

**State machine violations.** Can an order be refunded twice? Can a password
reset token be used after the password changed? Can a subscription be
downgraded to negative? Look for state transitions that read, decide, then
write without a lock or a conditional update.

**Time-of-check to time-of-use.** A permission checked, then acted on after an
await, a database round trip, or a filesystem call. The gap is exploitable if
anything can change the answer in between.

**Business-logic abuse.** Negative quantities, integer overflow in a price
calculation, a coupon applied repeatedly, a rate limit keyed on something the
client controls. These never look like vulnerabilities in a diff.

**Insecure defaults in shared code.** A helper that disables verification "for
local dev" and is used in production. A base class whose default permission is
allow. These have a large blast radius.

**Secrets in the wrong scope.** A key correctly loaded from the environment and
then logged, put in an error response, rendered into a template, or passed to a
third-party SDK that reports telemetry.

**Reachability of the scanner's findings.** A `subprocess` call with shell=True
in a script nobody runs is not a critical. Downgrading it is as valuable as
finding a new bug, because it is what makes the rest of the list credible.

## Writing a finding someone will act on

A finding is a claim that needs three things: the defect, the path to it, and
the change that fixes it.

> **Bad:** "Possible SQL injection in `views.py`."
>
> **Good:** "`GET /search` passes `request.args['q']` into an f-string query at
> `app/views.py:88`. There is no allowlist or escaping on the path from the
> handler to `cursor.execute`, so a value of `' OR 1=1--` returns every row.
> Fix: `cursor.execute("SELECT ... WHERE name LIKE %s", (f"%{q}%",))`."

Be specific about what you did not verify. "I could not confirm whether the
middleware in `auth.py:40` runs for this blueprint" is useful; quietly assuming
either answer is not.

## Calibrating severity

Severity is impact multiplied by reachability, not how clever the bug is.

- **critical** - unauthenticated remote code execution, authentication bypass,
  mass data exposure. Someone gets paged.
- **high** - authenticated RCE, injection reaching production data, broken
  authorization on sensitive records, a live credential in the repository.
- **medium** - needs unusual preconditions, or the impact is bounded: a
  same-origin XSS, a weak hash on non-credential data, a missing security header.
- **low** - defence in depth. Real, worth fixing, nobody is exploiting it alone.
- **info** - hygiene and hardening.

A finding you cannot describe the impact of is not a finding yet. Keep reading
until you can, or file it as `low` with an honest description of the uncertainty.

## Recording the work

```bash
cat <<'JSON' | python3 "$CLAUDE_PLUGIN_ROOT/engine/redassay_cli.py" add --source claude
{"findings": [ ... ]}
JSON
```

Set `confidence: "high"` only for defects you traced in the source. The board
sorts by severity weighted by confidence, so an inflated confidence pushes a
guess above someone else's verified finding.
