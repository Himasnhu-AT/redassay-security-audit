# Running redassay in CI

The engine is a normal CLI with no dependencies, so CI setup is checkout, a
Python, and one command.

## The problem with scanning everything

Point any scanner at an existing codebase and it produces a backlog. Gating on
that backlog means the check is red on day one and stays red, and a check that
is always red gets marked non-blocking within a week.

Two ways out, and you want one of them before you turn on `--fail-on`.

### Scope to the diff

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # --since needs history to diff against

- name: Scan the changed files
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    python3 engine/redassay_cli.py scan \
      --since "origin/${BASE_REF}" \
      --fail-on high
```

This fails only on what the pull request introduces. The backlog stays visible
in a full scan but does not block anyone.

Note the `env:` block. Putting `${{ github.base_ref }}` directly in the `run:`
script would interpolate it into the shell before bash parses it — the exact
pattern redassay's own `ci.script-injection` rule flags. The workflows in this
repository pass their own scan.

If the ref does not resolve, the command fails rather than silently scanning
everything. A gate that cannot answer the question must not report success.

### Ratchet from a baseline

```bash
redassay scan --quiet          # populate the store
redassay baseline              # freeze what exists today
git add .redassay/baseline.json && git commit -m "chore: baseline security findings"
```

Then in CI:

```bash
redassay scan --new-only --fail-on medium
```

Everything frozen is ignored; anything added after is not. Commit the baseline
so the whole team shares one.

Shrink it deliberately over time — `redassay list --json` and work through the
list. Re-baseline when you have made a dent.

## GitHub code scanning

```yaml
- name: Write SARIF
  if: always()
  run: python3 engine/redassay_cli.py report --format sarif -o redassay.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: redassay.sarif
    category: redassay
```

Findings appear in the Security tab with severity, CWE and remediation. The
SARIF carries `partialFingerprints` built from redassay's stable ids, so GitHub
deduplicates correctly across runs — a finding does not reappear as new because
the file was reformatted.

`if: always()` matters: without it the upload is skipped exactly when the scan
found something, which is when you want it most.

## GitLab

```yaml
security:
  image: python:3.13-slim
  script:
    - python3 engine/redassay_cli.py scan --since "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --fail-on high
    - python3 engine/redassay_cli.py report --format sarif -o redassay.sarif
  artifacts:
    reports:
      sast: redassay.sarif
```

## Pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: redassay
        name: redassay
        entry: python3 engine/redassay_cli.py scan --since HEAD --fail-on critical --quiet
        language: system
        pass_filenames: false
```

Keep the local gate at `critical` only. A pre-commit hook that blocks on
`medium` gets bypassed with `--no-verify`, and then it blocks on nothing.

## Choosing a threshold

| Threshold | Suitable for |
| --- | --- |
| `critical` | Pre-commit, and any repository adopting this today |
| `high` | Pull requests, once the diff is clean |
| `medium` | Mature repositories with a shrinking baseline |
| `low` | Only with a baseline, and only if you mean it |

## Keeping the advisory data honest

The dependency database is an offline snapshot — the scan makes no network
requests, by design. That means it goes stale.

The scheduled job in `.github/workflows/security.yml` runs weekly so a full scan
happens even without a push, but it cannot refresh data it does not fetch. Treat
`engine/redassay/data/advisories.json` as something you update deliberately, and
pair redassay with a tool that does query a live feed (Dependabot, `pip-audit`,
`npm audit`) for dependency coverage specifically.

redassay's dependency scanner is there to catch the obvious and to check
supply-chain hygiene — floating versions, install hooks running remote code,
dependencies resolved from a mutable git ref — not to replace a live feed.
