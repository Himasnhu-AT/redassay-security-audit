# Architecture

## The shape

```
      Claude Code
           |
   /redassay-security
           |
    +------+------+
    |             |
  engine        board  <-- you
    |             |
    +------+------+
           |
      .redassay/
```

Three processes, one directory. They never call each other; they agree on files.

| File | Written by | Read by |
| --- | --- | --- |
| `findings.json` | scan, CLI, board | everyone |
| `actions.jsonl` | board, CLI | agent |
| `config.json` | `init` | scan, board |
| `baseline.json` | `baseline` | scan |

This is deliberately boring. The board can be killed and restarted, the agent
can crash mid-fix, a scan can run from another terminal, and nothing is lost —
because the durable state is a file and every write is atomic.

## The scan pipeline

```
walk -> scanners -> triage -> merge -> store
```

**walk** (`walker.py`) yields `SourceFile` objects. It honours `.gitignore` and
`.redassayignore`, skips binaries by sniffing, and caps file size. Deterministic
order, so two runs produce the same output.

**scanners** (`scanners/`) each take the file list and yield findings. Eleven of
them, and one raising an exception does not stop the others — a scan that dies
on a malformed file in a repository you are auditing for the first time is
useless.

**triage** (`triage.py`) deduplicates by *concept* rather than rule id, so
`py.yaml-unsafe-load` and `deser.yaml-unsafe-load` on the same line become one
finding — the one from the scanner with better evidence. Then it filters by
severity and ranks by severity weighted by confidence.

**merge** (`store.py`) folds the result into what is already there. This is the
part that matters most, and the rules are:

- A finding not in the store is added.
- A finding already there has its **location refreshed** and its **human state
  preserved**. Status, comments and the fix record are never touched by a scan.
- A finding marked fixed that reappears is **reopened** with a comment saying so.
- A finding marked fixed that does not reappear becomes **verified**.
- A finding the scan did not look for — outside the scanned scope — is left
  alone entirely.

## Stable identity

```
id = sha256(rule_id | path | normalized_snippet)[:12]
```

The line number is deliberately not in the hash. Code moves; the vulnerability
does not. Adding twenty lines above a finding must not resurrect a dismissal
somebody made last month.

`normalized_snippet` collapses whitespace and blanks the *contents* of string
literals. So a hardcoded password rotating from `hunter2` to `hunter3` is the
same finding — and the secret itself never feeds the hash, which matters because
ids end up in logs and CI output.

The trade-off: two structurally identical findings on different lines of the
same file collide. The scanners break that tie with a salt on repeat matches.

## Taint tracking

`scanners/python_ast.py` carries a small intra-procedural taint tracker. It is
the difference between "this file contains `cursor.execute`" and "a value from
`request.args` reaches `cursor.execute` through an f-string, inside `search()`".

Scope is one function. No cross-call, no cross-file. That bound is deliberate:
a real interprocedural analysis needs a call graph, and a wrong answer from a
half-built one is worse than no answer — it produces confident nonsense, which
is the failure mode that gets tools uninstalled.

Within that scope it tracks assignment, f-strings, concatenation, `.format()`,
subscripting, and collection literals. Confirmed taint raises both severity and
confidence.

It also looks for **guards**: a name compared against a container, or passed to
a validator, inside an `if` whose body raises or aborts. A guarded value is
downgraded rather than suppressed — the check might be wrong (a prefix match, a
partial allowlist) but it is a different risk from no check at all, and
reporting both identically trains people to ignore the tool.

The JS/TS scanner does something similar over a comment- and string-stripped
view of the source, with file scope instead of function scope. That
over-approximates, which is the right trade for Express handlers where the
binding and the sink are almost always in the same closure.

The PHP scanner extends the same idea to a template language. PHP interleaves
code and HTML, so its normalizer is region-aware: string and comment blanking
happens only inside `<?php ... ?>`, and an HTML attribute quote around a `<?= $x ?>`
is left intact so the sink inside it stays visible. It knows the request-derived
`$_SERVER` keys from the safe ones, distinguishes `$_FILES` name from tmp_name,
and recognises the framework escapers (`esc_html`, `e()`) that real PHP relies
on. File-scope taint breaks down on very large framework files, so vendored CMS
cores are excluded at the walker rather than analyzed.

Ruby and Go reuse that machinery with language-specific fronts. Ruby's propagation vector is string interpolation, so its normalizer blanks a string body but keeps the `#{...}` inside it; its sinks know that a parameterised `where("x = ?", v)` and a hash condition are safe while an interpolated query is not, and it models ERB template injection as its own sink. Go has no interpolation, so propagation is `+` concatenation and `fmt.Sprintf`; its SQL sinks read only the first argument with bracket-aware depth, so a bound parameter after a placeholder is not mistaken for the query. All four taint scanners are flow-sensitive: a variable's state at a sink is whatever was last written to it.

## The board

`http.server` on loopback. No framework, no build step, no bundler — the UI is
three ES modules the browser loads directly.

Security properties, since the irony of a vulnerable security tool would be
expensive:

- **Bound to `127.0.0.1`** unless explicitly overridden.
- **Static files are pinned** to one directory resolved at import time; the
  request path never reaches the filesystem un-normalized.
- **`/api/source` resolves through `realpath`** and refuses anything outside the
  repo root — blocking both `..` and symlinks pointing out of the tree.
- **Mutations require `Content-Type: application/json`** (which forces a CORS
  preflight) **and a matching `Origin`**, so a page in another tab cannot drive
  the board through the browser's ambient authority.
- **A strict CSP** with `default-src 'none'`, which is why there is no inline
  script anywhere in the UI.
- **Every value rendered is escaped.** The board displays snippets from the
  repository under audit. That content is attacker-controlled by definition.

The board never modifies code. It appends to the action queue. That separation
is the whole point: the thing a human clicks and the thing that edits files are
different processes, and the second one only acts on what the first one recorded.

## Why the engine has no dependencies

Enforced by `tools/check_stdlib_only.py` in CI.

A security tool is pointed at code you do not trust yet, often on a machine you
do not control, frequently inside a container with no network. Requiring
`pip install` before it can tell you whether you have a problem — and thereby
pulling in a transitive dependency tree you have not reviewed — undercuts the
thing it is for.

The cost is real: no YAML parser, no tree-sitter, no `requests`. The YAML
handling is a toy, the JS analysis is regex over a normalized view rather than a
parse tree, and the advisory database is an offline snapshot instead of a live
API. Those are acknowledged limits, documented where they bite.

## Known limits

- **JavaScript has no AST.** The stripped-source approach handles the common
  cases and will miss anything spanning unusual syntax.
- **Taint does not cross functions.** A helper that takes a tainted argument and
  reaches a sink is not connected to its caller.
- **Taint tracking is per-language.** Python, JavaScript/TypeScript, PHP, Ruby
  and Go trace request data through variables to a sink; Java/Kotlin still have
  only line-oriented pattern rules, so a JVM source assigned to a variable and
  used at a sink a line later — the shape the taint scanners were built to catch
  — is missed. The JVM is the next candidate, held back only because the
  benchmark corpus carries little Java, so its precision cannot yet be measured
  at scale; the Ruby and Go scanners were validated on dedicated fixtures and a
  real corpus SSTI the pattern rules missed.
- **The advisory database is a snapshot.** It goes stale. It is refreshed
  deliberately, and the file says when.
- **The YAML reader tracks indentation and nothing else.** No anchors, no merge
  keys, no multi-document.
- **Authorization cannot be decided by a scanner.** That is the model's half of
  the job, which is why `skills/redassay-audit` exists.
