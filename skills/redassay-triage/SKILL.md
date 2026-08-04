---
name: redassay-triage
description: Deciding which scanner findings are real before a human sees them, and running the board's review loop. Use when triaging security scan results, reducing false positives, or handling review actions from the redassay board.
---

# Triage

A scan produces claims. Triage turns them into a list somebody will read.

The measure of good triage is not how many findings survive. It is whether the
person opening the board can trust that everything on it deserves their
attention. One confident false positive costs more than ten missed lows, because
it teaches the reader to skim.

## Work in confidence order, not severity order

Start with the `low` and `medium` confidence findings. The `high` confidence ones
are usually right; the uncertain ones are where your reading changes the answer.

```bash
redassay list --json --min-severity medium
```

For each, open the file and answer one question: **can attacker-controlled data
actually reach this line?**

- Trace the argument back to its origin. A constant, a config value read at
  startup, or a value from another internal service is not the same as
  `request.args`.
- Check reachability. Is this function called? From where? A dangerous pattern
  in dead code, a migration script, or a developer-only tool is real but not
  urgent — downgrade it and say why.
- Check the guards. Is there a validator, an allowlist, a cast, or a type
  constraint between the source and the sink? If so, is it strict? A prefix
  match (`url.startswith("https://api.example")`) is defeated by
  `https://api.example.attacker.com`.

## The three outcomes

**Confirm.** You traced the path and it is real.

```bash
redassay status <id> confirmed
redassay comment <id> "Reachable from POST /import, which is unauthenticated. Traced request.data -> payload -> yaml.load."
```

**Dismiss.** It cannot happen. Record the proof, not the verdict — the next
person to see this file needs to know *why*.

```bash
redassay dismiss <id> --reason "The argument is TEMPLATE_DIR, a module constant set at import. No request data reaches this call."
```

If the rule will keep firing on the same structurally-safe pattern, suppress it
for that path rather than dismissing it repeatedly:

```bash
redassay dismiss <id> --reason "Generated protobuf stubs" --suppress-rule --path-glob "gen/**"
```

**Downgrade.** It is real but the severity is wrong. Comment with the reason and
let the board reflect it.

## Common false positives, and how to tell

| Pattern | Usually fine when |
| --- | --- |
| `subprocess` with `shell=True` | the command is a literal with no interpolation |
| MD5 / SHA-1 | used as a cache key, ETag, or content fingerprint - not a password or signature |
| Hardcoded secret | the file is a fixture, an example, or the value is a documented public key |
| `verify=False` | in a test that talks to a local self-signed server - and nowhere else |
| SQL concatenation | the interpolated part is a table name from a module-level allowlist |
| `eval` | the argument is a literal, or it is `ast.literal_eval` |
| Path join with input | the result is resolved and checked against a root afterwards |

In every one of those rows, the deciding factor is something a scanner cannot
see. That is why this step exists.

## Handling board actions

The board appends actions to a queue. Drain it:

```bash
redassay queue pull
```

Each claimed action arrives with the full finding attached.

- **`fix`** — one finding. Follow `redassay-remediate`.
- **`fix_all`** — a batch. Work through them one at a time. Do not try to write
  one patch covering several files; fix, verify, record, then move on. If one
  fails, keep going with the rest and report the failure at the end.
- **`rescan`** — `redassay scan --quiet`, then report the delta: what is new,
  what got verified, what regressed.

Always close the action, even when the answer is no:

```bash
redassay queue complete <seq> --result "fixed"
redassay queue complete <seq> --state failed --result "<why not>"
```

An action left claimed forever is indistinguishable from a crash.

## Reporting back

After a batch, say three things and stop:

1. What was fixed, one line each.
2. What was refused, and what decision is needed to unblock it.
3. What is still open at high or critical.

Not a wall of restated findings — the board already has those.
