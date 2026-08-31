---
name: redassay-remediate
description: How to fix a security finding without breaking the code around it - minimal, class-eliminating changes with verification. Use when applying an approved security fix, remediating a vulnerability, or draining the redassay fix queue.
---

# Fixing a finding

A security fix has a narrower brief than an ordinary change: remove the
vulnerability, change nothing else, and prove it is gone.

## Before editing

**Read the whole function, not the flagged line.** The fix often belongs
somewhere other than where the scanner pointed. A path traversal reported at the
`open()` call is usually fixed where the filename is parsed.

**Find the other call sites.** If the defect is in a helper, fixing one caller
leaves the bug. If the defect is in a caller, check whether its siblings have it
too — and say so in the fix summary rather than silently fixing them all.

**Read the reviewer's note.** The fix request carries one. "Keep the CLI flag
working" or "this runs on Python 3.8" changes what the correct fix is.

## What a good fix looks like

**Eliminate the class, do not filter the symptom.**

```python
# Filters the symptom - a blocklist is always incomplete.
if ";" in host or "|" in host:
    abort(400)
subprocess.run(f"ping {host}", shell=True)

# Eliminates the class - no shell exists to inject into.
subprocess.run(["ping", "-c", "1", host], timeout=5, check=False)
```

The same distinction across the common classes:

| Class | Symptom filter | Class elimination |
| --- | --- | --- |
| SQL injection | escaping quotes | bound parameters |
| Command injection | stripping metacharacters | argument list, no shell |
| Path traversal | rejecting `..` | resolve, then assert inside the root |
| XSS | blocklisting `<script>` | contextual encoding / `textContent` |
| SSRF | blocking `localhost` | allowlist hosts, re-check after DNS, no redirects |
| Deserialization | validating after loading | a format that cannot construct objects |

**Keep the diff small.** Do not reformat the file, reorder imports, rename
variables, or add unrelated type annotations. A security fix that touches forty
lines is hard to review, and review is the point.

**Preserve behaviour for legitimate input.** The endpoint should still work. If
the only correct fix changes behaviour — rejecting inputs that used to be
accepted — that is a decision for the user, not for you. Say so and mark the
action failed.

**Fix it once.** If the same defect appears in six handlers, consider whether
the right change is a shared helper. Propose that rather than making six copies
of the same patch, unless the user asked for exactly the listed findings.

## Verifying

In order of preference:

1. **Run the tests that cover the file.** If they pass, say which ones ran.
2. **Re-run the scan.** `redassay scan --quiet` — the finding should stop
   reproducing and move to `verified` on the next merge.
3. **Re-read the changed code** as though it were someone else's patch.

If tests fail after your change, the fix is wrong until proven otherwise. Do not
adjust the test to match the new behaviour without saying so explicitly.

## Recording it

```bash
git diff -- app/net.py | python3 "$CLAUDE_PLUGIN_ROOT/engine/redassay_cli.py" \
  resolve <finding-id> \
  --summary "Replaced the shell string with an argument list" \
  --diff-file -
```

Piping the diff in is worth the extra pipe: the board shows the reviewer exactly
what changed, and the touched files are read out of the diff so `--file` is not
needed. A finding marked fixed with no visible record of the change is hard to
tell apart from one somebody quietly marked done.

The summary is read by someone who was not watching. One sentence, what changed
and why, no restating the vulnerability.

## When not to fix

Say so and mark the queue action failed, rather than doing something you are not
confident in:

- The correct fix needs a product decision (changing what input is accepted).
- The finding is a false positive and you can now prove it — dismiss it with the
  proof instead.
- The fix requires a dependency upgrade that would need testing you cannot do.
- You do not understand the surrounding code well enough to be sure the change
  is safe.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/engine/redassay_cli.py" queue complete <seq> \
  --state failed \
  --result "The endpoint is documented as accepting arbitrary URLs. An allowlist fixes the SSRF but changes the contract - needs a decision."
```

An honest refusal is a better outcome than a fix that looks right and is not.
