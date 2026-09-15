# Changelog

## Unreleased

### Deeper taint coverage

- A PHP taint scanner: request data (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/
  `$_FILES`, request-derived `$_SERVER` keys, `php://input`) traced through
  variables to a sink over a template-aware normalized view. Built after a
  head-to-head against a manual reviewer showed the line-oriented PHP rules
  could not see a source that reaches a sink one variable-hop later.
- An audit of that scanner for the same blind spot in other shapes added two
  sink classes it did not model: **file write to a request-built path**
  (`file_put_contents`/`move_uploaded_file`/`copy`/`rename` — a dropped
  webshell or traversal) and a **dynamic callable** (`call_user_func` / `$var()`
  — arbitrary code execution).
- PHP taint is now **flow-sensitive**: a variable's state at a sink is whatever
  was last written to it, so a reassignment to a constant clears earlier taint.
  This removed false positives on large framework files where one name is reused
  for a constant path and a request value.
- A **reflected-XSS** sink for the JavaScript scanner (`res.send`/`res.write`/
  `res.end`), the one common web bug it had no rule for. Gated on the
  interpolations rather than the surrounding markup, so a tainted name cannot
  collide with the same word appearing as HTML prose.

## 0.1.0 - 2026-09-14

First release.

### The loop

- `/redassay-security` slash command with `audit`, `scan`, `review`, `board`,
  `fix`, `watch`, `status`, `report` and `reset`.
- Skills for the audit method, remediation, and the triage loop; agents for
  per-subsystem review and single-finding remediation.
- A local review board: filters, detail pane with source context, inline fix and
  dismiss panels, batch approval, keyboard navigation.
- An append-only action queue between the board and the agent, so nothing edits
  code until a human approves a specific finding.

### Knowing what to look at

- `redassay surface` inventories the entry points an attacker can reach - HTTP
  routes, server actions, queue consumers, socket handlers, webhooks, scheduled
  jobs - and records what stands in front of each one. This is the artifact the
  audit now starts from, replacing a set of greps whose completeness nobody
  could check.
- Framework detection from sentinel files and manifests, with short, specific
  notes on the mistakes each framework invites.
- An exposure scanner answering the question that comes before "is this code
  safe": what does this repository publish to a network it does not control -
  compose port mappings, Kubernetes Services, open CIDRs, wildcard binds.
- `redassay report --format exposure` groups those by what is behind the port
  rather than by file, because the decision is per service.

### Detection

- 115 rules across 12 packs: injection, XSS, deserialization, crypto,
  access control, SSRF, misconfiguration, exposure, JVM, Go, PHP/Ruby,
  API/mobile.
- A Python AST scanner with intra-procedural taint tracking, which raises
  severity on a confirmed data path and lowers it when the function guards the
  value first.
- A JS/TS scanner over a comment- and string-stripped view, tracking values
  bound out of `req.query` / `req.body` / `req.params`.
- Secret detection: 27 provider patterns at high confidence, plus entropy-gated
  generic assignments behind a placeholder filter.
- Dependency review against an offline advisory snapshot for six ecosystems,
  with manifest parsers for each, plus supply-chain hygiene checks.
- CI/CD analysis: `pull_request_target` with a fork checkout, `${{ github.event.* }}`
  interpolated into `run:`, unpinned third-party actions, secrets in logs.
- Configuration: Dockerfiles, compose, Kubernetes, `.env`, Terraform, cloud IAM.

### The store

- Content-addressed finding ids that exclude the line number, so a dismissal
  survives code motion.
- Merge semantics that refresh where a finding is without touching what a human
  said about it; reappearing fixes reopen with a comment, disappearing ones
  verify.
- Suppression inline in the source, per path, or repo-wide in `pyproject.toml`.
- `baseline` and `--new-only` for ratcheting on an existing codebase.
- `--since <ref>` to scan only what a pull request changed.

### Output

- Terminal, markdown, JSON, SARIF 2.1.0 with stable fingerprints, and a
  `quickfix` format any editor can jump through.
- Export from the board without leaving it.
- `doctor` for environment diagnostics, `stats` with risk-weighted hotspots,
  `history` for the scan-over-scan trend, `prune` to keep the store readable.
- `resolve` accepts a diff on stdin and reads the touched files out of it, so
  the board shows what a fix actually changed.

### Performance

- A literal prefilter in front of every pattern rule: 2.3-3x, output verified
  identical on every corpus it was measured on.
- Two optimizations that measured slower are documented in
  `docs/performance.md` rather than left for someone to rediscover.

### Testing

- Every rule carries its own `examples` and `counterexamples`, run against the
  scanner by the test suite. Introducing this found seven silently broken rules,
  including five whose literal matcher could never match a quote inside a
  differently-quoted string - so the most-used SQL rule missed `WHERE name = '"`.
- 885 Python tests and 75 JavaScript tests, neither needing an install.
- A control fixture of safe code that must produce zero high-confidence
  findings, and a regression suite built from false positives that real
  repositories produced.
