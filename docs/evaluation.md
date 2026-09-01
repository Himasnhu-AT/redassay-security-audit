# Evaluation

Fixtures prove a rule still fires. They cannot tell you whether the output is
*usable*, because a fixture contains nothing but vulnerabilities. That question
only has an answer on real code.

Reproduce any of this with:

```bash
python3 tools/evaluate.py /path/to/repo
```

## Deliberately vulnerable applications

These are the honest easy case: the bugs are real, intentional, and documented
by the project itself, so "did it find them" has a checkable answer.

### PyGoat (Django, 262 files)

134 findings, 13 critical. Every critical was opened and read:

| Finding | Location | Verified |
| --- | --- | --- |
| SQL injection via string concatenation into `.raw()` | `introduction/views.py:162` | yes - `"... user='"+name+"'"` |
| Command injection through `Popen(shell=True)` | `introduction/views.py:430` | yes - `"dig {}".format(domain)` |
| `eval()` on `request.POST` | `introduction/views.py:460` | yes |
| Path traversal via `os.path.join` on `request.POST` | `introduction/views.py:927` | yes |
| SSRF - `requests.get(request.POST["url"])` | `introduction/views.py:963` | yes |
| Pickle deserialization of request data | `introduction/views.py:214` | yes |
| Hardcoded Django `SECRET_KEY` | `pygoat/settings.py:25` | yes |
| PyYAML 5.1 (CVE-2020-14343), Pillow 9.4.0 (CVE-2023-4863) | `requirements.txt` | yes |

The taint tracker named the source in each case - "a value originating from
`request.POST` reaches this call inside `sql_lab()`" - which is the difference
between a finding a reviewer can act on and one they have to re-derive.

### OWASP NodeGoat (Express, 89 files)

16 findings after triage. The flagship defects were all found: `eval()` on
`req.body` in `contributions.js:32-34`, `$where` NoSQL injection in
`allocations-dao.js:78`, a committed private key, a dynamic `require()` driven
by `NODE_ENV`.

**Four false positives came out of this run, and all four were fixed:**

1. A tutorial page documenting `eval(req.body.preTax)` inside a `<pre>` block was
   reported as an `eval()` call. Fixed generally - documentation samples in
   markup and markdown fences are no longer scanned as code.
2. `Math.random()` in a date helper was flagged as a weak security RNG, because
   the 4-line proximity window reached an unrelated `validateLogin(userName,
   password)` two functions below. Fixed by tightening the window and excluding
   date/time contexts.
3. A MongoDB connection string quoted in the README was reported at the same
   severity as one in a settings module. Now downgraded in prose files - still
   reported, because sometimes the example is the real one.
4. Escaped `innerHTML` writes were flagged because the escaping call sat a few
   lines away inside the template builder rather than on the assignment line.

All four are pinned by `tests/python/test_false_positives.py`.

## A real framework: Django

This is the harder and more honest case, and it is where the limitations show.

| Scope | Findings | Per kLOC |
| --- | --- | --- |
| Everything | 701 | 0.72 |
| Excluding `tests/` | 202 at high+ | 0.36 |

**59% of the findings are in Django's own test suite** - files that construct
malicious input on purpose. Excluding test directories is the first thing to do
on any repository, and `.redassayignore` exists for it.

Of what remains, the largest groups are:

- **`py.sql-dynamic` (66)** in `db/backends/*/schema.py`. Django's ORM building
  DDL from internal identifiers. The *shape* is real - a SQL string assembled at
  runtime - and the analysis is correct that it is assembled. It is not a
  vulnerability, because the interpolated values are quoted identifiers from the
  schema, not request data.
- **`xss.django-mark-safe` (68)** in `contrib/admin/helpers.py` and
  `utils/html.py`. Django's own escaping machinery, which marks strings safe
  *because it just escaped them*.
- **`py.pickle-load` (9)** in the cache backends, unpickling Django's own cache.

**The honest conclusion: redassay is tuned for application code, not framework
internals.** A library that implements SQL construction, HTML escaping and
object caching will light it up, because those are exactly the primitives the
rules look for. On an application that *uses* Django, the same rules fire almost
exclusively on real problems - PyGoat above is the demonstration.

If you scan a framework, expect to spend the first pass writing `.redassayignore`
entries and a `[tool.redassay] disabled_rules` block. That is a legitimate use of
an afternoon, and the dismissals persist.

## The control fixture

`fixtures/clean-app/` is the other half of the measurement: idiomatic, safe code
that is the correct form of everything the rules flag elsewhere - parameterized
queries, argument lists instead of shells, resolve-and-verify path handling,
scrypt for passwords, `secrets.token_urlsafe`, `hmac.compare_digest`, an
allowlisted fetch.

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

- **Recall.** There is no ground-truth list of every vulnerability in Django, so
  "what did it miss" is unanswerable on real code. The fixtures measure recall
  against known defects; they cannot measure it against unknown ones.
- **Comparison with other tools.** Different rule sets, different severity
  vocabularies, different opinions about what counts. A head-to-head number
  would be more misleading than no number.
