# Security

## Reporting

Open a private security advisory on the repository, or email the maintainer.
Please do not open a public issue for an unpatched vulnerability.

## The board's threat model

`redassay serve` runs an HTTP server that reads files out of the repository it is
pointed at, and that repository may contain hostile content - that is the entire
point of the tool. The board is designed accordingly:

- **Loopback only** by default. `--host` exists but is not the default, and the
  documentation says why.
- **No authentication, by design.** The board treats the OS user as the
  principal. It has no accounts, no cookies, and no session to steal. This is
  why `authz.missing-authorization-check` is disabled for this repository in
  `pyproject.toml` rather than suppressed silently.
- **Path confinement.** `/api/source` resolves through `realpath` and refuses
  anything outside the repository root, which blocks `..` and symlinks pointing
  out of the tree. Static assets are served from one directory resolved at
  import time; the request path never reaches the filesystem un-normalized.
- **CSRF.** State-changing endpoints require `Content-Type: application/json`
  (which forces a CORS preflight) and an `Origin` matching where the board is
  listening. A page in another tab cannot drive the board through the browser's
  ambient authority.
- **CSP.** `default-src 'none'` with `script-src 'self'`. There is no inline
  script anywhere in the UI, which is what makes that policy possible.
- **Output encoding.** Every value the board renders is escaped, including
  source snippets copied verbatim out of the audited repository.
  `tests/js/render.test.js` asserts this for each rendered field.

## The engine's threat model

The scanner reads files and never executes them. It makes no network requests -
the dependency advisory database is an offline snapshot, which is also why it
goes stale and why the documentation says to pair redassay with a live feed.

Optional, opt-in telemetry is the one exception, and it lives in the CLI, not
the engine: after `redassay telemetry on`, each scan sends a random local id,
the event name and the version, and nothing that identifies you or your code.
It is off by default and documented in [docs/telemetry.md](docs/telemetry.md).

Findings are written to `.redassay/` inside the repository. Secret values are
redacted before they reach a snippet, an id, or a log line, because ids end up
in CI output.

## The agent's scope

Fixes are applied by Claude, not by the engine and not by the board. The board
only appends to an action queue; nothing edits code until a human approves a
specific finding. That separation is deliberate and should not be collapsed.

## Known limits

These are design decisions, not oversights. They are listed so you can judge
whether the tool fits your situation:

- The JavaScript analysis is regex over a normalized view, not a parse tree.
- Taint tracking does not cross function boundaries.
- The YAML reader tracks indentation and nothing else.
- The advisory snapshot is only as current as the last deliberate refresh.
- Authorization correctness cannot be decided by a scanner at all.

`docs/architecture.md` explains the reasoning behind each.
