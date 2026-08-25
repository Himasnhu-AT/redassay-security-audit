# Changelog

## 0.1.0

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

- Terminal, markdown, JSON and SARIF 2.1.0 with stable fingerprints.
- `doctor` for environment diagnostics; `stats` with risk-weighted hotspots.

### Performance

- A literal prefilter in front of every pattern rule: 2.3-3x, output verified
  identical on Django, PyGoat, NodeGoat and the fixtures.
- Two optimizations that measured slower are documented in
  `docs/performance.md` rather than left for someone to rediscover.

### Testing

- 670 Python tests and 59 JavaScript tests, neither needing an install.
- A control fixture of safe code that must produce zero high-confidence
  findings, and a regression suite built from false positives that real
  repositories produced.
