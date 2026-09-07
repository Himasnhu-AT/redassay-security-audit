# Evaluation

Fixtures prove a rule still fires. They cannot tell you whether the output is
*usable*, because a fixture contains nothing but vulnerabilities. That question
only has an answer on real code.

Reproduce any of this against a codebase of your own with:

```bash
python3 tools/evaluate.py /path/to/repo
```

The corpora below are described by shape and size rather than by name, so the
numbers can be compared against anything similar. Nothing here depends on a
particular repository being available.

## Deliberately vulnerable applications

The honest easy case: the defects are intentional and documented by the project
itself, so "did it find them" has a checkable answer.

### A Django training application (262 files)

134 findings, 13 critical. Every critical was opened and read:

| Finding | Verified |
| --- | --- |
| SQL injection via string concatenation into a raw query | yes - `"... user='"+name+"'"` |
| Command injection through `Popen(shell=True)` | yes - `"dig {}".format(domain)` |
| `eval()` on a request parameter | yes |
| Path traversal via `os.path.join` on request data | yes |
| SSRF - an outbound request to a request-supplied URL | yes |
| Pickle deserialization of a request body | yes |
| Hardcoded Django `SECRET_KEY` | yes |
| Two dependencies with known CVEs | yes |

The taint tracker named the source in each case - "a value originating from
`request.POST` reaches this call inside `sql_lab()`" - which is the difference
between a finding a reviewer can act on and one they have to re-derive.

### An Express training application (89 files)

16 findings after triage. The flagship defects were all found: `eval()` on a
request body, a `$where` NoSQL injection, a committed private key, a dynamic
`require()` driven by an environment variable.

**Four false positives came out of this run, and all four were fixed:**

1. A tutorial page documenting an `eval()` call inside a `<pre>` block was
   reported as an `eval()` call. Fixed generally - documentation samples in
   markup and markdown fences are no longer scanned as code.
2. `Math.random()` in a date helper was flagged as a weak security RNG, because
   the 4-line proximity window reached an unrelated `validateLogin(userName,
   password)` two functions below. Fixed by tightening the window and excluding
   date/time contexts.
3. A database connection string quoted in a README was reported at the same
   severity as one in a settings module. Now downgraded in prose files - still
   reported, because sometimes the example is the real one.
4. Escaped `innerHTML` writes were flagged because the escaping call sat a few
   lines away inside the template builder rather than on the assignment line.

All four are pinned by `tests/python/test_false_positives.py`.

## A large framework (5,375 files, 34 MB)

The harder and more honest case, and where the limitations show.

| Scope | Findings | Per kLOC |
| --- | --- | --- |
| Everything | 701 | 0.72 |
| Excluding tests | 202 at high+ | 0.36 |

**59% of the findings are in the project's own test suite** - files that
construct malicious input on purpose. Excluding test directories is the first
thing to do on any repository, which is why `--exclude-tests` and the
`.redassayignore` template exist.

Of what remains, the largest groups are:

- **Dynamic SQL construction** in the ORM's schema backends. The *shape* is
  real - a SQL string assembled at runtime - and the analysis is correct that it
  is assembled. It is not a vulnerability, because the interpolated values are
  quoted identifiers from the schema, not request data.
- **`mark_safe` in the templating and admin helpers.** The framework's own
  escaping machinery, marking strings safe *because it just escaped them*.
- **Pickle loads in the cache backends**, unpickling the framework's own cache.

**The honest conclusion: redassay is tuned for application code, not framework
internals.** A library that implements SQL construction, HTML escaping and
object caching will light it up, because those are exactly the primitives the
rules look for. On an application that *uses* such a framework, the same rules
fire almost exclusively on real problems - the training applications above are
the demonstration.

If you scan a framework, expect to spend the first pass writing
`.redassayignore` entries and a `[tool.redassay] disabled_rules` block. That is
a legitimate use of an afternoon, and the dismissals persist.

## The entry-point inventory

Measured on the same corpora. `redassay surface` found:

| Corpus | Entry points | Nothing auth-shaped in front |
| --- | --- | --- |
| Express training app | 22 | 4 (the login and signup routes, correctly) |
| Django training app | 142 | 128 |

The Express result is the interesting one: the four unguarded routes are exactly
the ones that *must* be unauthenticated, and every route behind `isLoggedIn` was
identified as guarded. Getting there required two fixes that are now pinned by
tests - a symmetric window was reading an `import login_required` at the top of
a module as a guard for every route in it, and naive comma counting was reading
a plain `(req, res) =>` handler as middleware.

The Django result is accurate rather than noisy: that application genuinely has
no authorization decorators, which is what it is for.

## The control fixture

`fixtures/clean-app/` is the other half of the measurement: idiomatic, safe code
that is the correct form of everything the rules flag elsewhere - parameterized
queries, argument lists instead of shells, resolve-and-verify path handling,
scrypt for passwords, CSPRNG tokens, constant-time comparison, an allowlisted
fetch, structured logging that records a credential's presence rather than its
value.

It produces **one** finding: a low-confidence SSRF note on the allowlisted
fetch, which the taint tracker downgrades because it can see the guard but
cannot verify it is strict enough. That is the behaviour we want - the check
could be wrong, and saying so quietly is different from saying nothing and
different again from shouting.

`tests/python/test_engine.py` asserts the clean fixture never produces a
high-confidence finding. That test is the false-positive budget, written down.

## Reproducing the loop, not just the scan

`bash scripts/demo.sh` walks the whole thing against a throwaway copy of the
vulnerable fixture: scan, approve two fixes, dismiss one with a reason, drain the
queue, patch, rescan. The two fixed findings come back `verified` with the diff
recorded; the dismissal and the review note survive. It runs in CI, so the
behaviour described in this document cannot quietly stop being true.

## What is not measured here

- **Recall.** There is no ground-truth list of every vulnerability in a large
  real codebase, so "what did it miss" is unanswerable there. The fixtures
  measure recall against known defects; they cannot measure it against unknown
  ones.
- **Comparison with other tools.** Different rule sets, different severity
  vocabularies, different opinions about what counts. A head-to-head number
  would be more misleading than no number.
