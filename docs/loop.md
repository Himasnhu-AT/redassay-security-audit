# The review loop

What actually happens when you type `/redassay-security audit`, and where you fit
into it.

```
  you                    Claude                     engine                board
   |                       |                          |                     |
   |  /redassay-security   |                          |                     |
   |---------------------->|                          |                     |
   |                       |  scan --json             |                     |
   |                       |------------------------->|                     |
   |                       |   137 findings           |                     |
   |                       |<-------------------------|                     |
   |                       |                          |                     |
   |                       | reads the hotspot files  |                     |
   |                       | traces the entry points  |                     |
   |                       |                          |                     |
   |                       |  add  (authz gaps,       |                     |
   |                       |        logic flaws)      |                     |
   |                       |------------------------->|                     |
   |                       |                          |                     |
   |                       |  confirm / dismiss the   |                     |
   |                       |  uncertain ones          |                     |
   |                       |------------------------->|                     |
   |                       |                          |                     |
   |                       |  serve                   |                     |
   |                       |--------------------------------------------->  |
   |   "board is at :7717" |                          |                     |
   |<----------------------|                          |                     |
   |                                                                        |
   |  read, dismiss, comment, approve                                       |
   |----------------------------------------------------------------------> |
   |                                                  |    actions.jsonl    |
   |                       |                          |<--------------------|
   |                       |  queue pull              |                     |
   |                       |------------------------->|                     |
   |                       |  edits the code          |                     |
   |                       |  resolve / queue complete|                     |
   |                       |------------------------->|                     |
   |                       |  scan  -> verified       |                     |
   |                       |------------------------->|                     |
   |   "fixed 4, 1 needs   |                          |                     |
   |    a decision"        |                          |                     |
   |<----------------------|                          |                     |
```

## Step by step

### 1. The deterministic pass

Eleven scanners walk the tree. No model, no network, no judgement — the same
repository produces the same findings every time. On a 250-file project this
takes under half a second.

What comes out is *shapes*: `eval` on a non-literal, a query built with an
f-string, a dependency with a known CVE, a workflow that checks out a fork's
code with a write-scoped token.

### 2. The model-driven pass

This is the half a scanner cannot do. Claude reads the files the scan flagged as
hotspots, maps the trust boundaries, and follows untrusted data inward looking
for the classes that need understanding rather than matching:

- an order fetched by id with no ownership filter
- an authorization check in a service method that another caller bypasses
- a state transition that reads, decides and writes without a lock
- a permission checked before an `await` and acted on after it

Those go into the same store, tagged `source: claude`, in the same format. The
board does not distinguish them — a finding is a finding.

### 3. Triage before you see it

Claude opens the files behind the low-confidence findings and decides. Each one
is confirmed with a note saying why it is reachable, or dismissed with a note
saying why it is not.

This step is what makes the board worth opening. A board full of unreviewed
regex hits is a worse experience than no board, because it teaches you to skim.

### 4. Your turn

The board opens. Findings are ranked by severity weighted by confidence, so the
first screen is the part that matters.

For each one you can request a fix, dismiss it with a reason, comment, or select
several and approve them together.

**Nothing on the board edits your code.** It writes to an append-only queue. The
thing you click and the thing that edits files are separate processes, and the
second only acts on what the first recorded.

### 5. Fixing

Claude drains the queue. Each claimed action arrives with the full finding and
whatever note you attached. For each one it reads the file, makes the smallest
change that eliminates the vulnerability class, runs the tests covering that
file, and records what it did.

When it cannot fix something safely it says so and marks the action failed —
with the reason and, where relevant, the decision it needs from you. A finding
marked fixed that is not fixed is worse than an open one.

### 6. Verification

A rescan follows. Findings that no longer reproduce move to `verified`
automatically. Ones that still reproduce stay open, and that is the most
important line in the report — a fix that did not clear the finding needs
looking at before anything else.

## What persists

Everything, in `.redassay/`.

Dismiss something today; scan again next month after a refactor that moved the
code two hundred lines; it stays dismissed. Finding identity is content-addressed
and deliberately excludes the line number, so a dismissal survives code motion
but not the vulnerability actually changing.

Revert a fix and the finding reopens with a comment saying it reappeared.

## Running it as a gate

The same engine, without the board:

```bash
# Only what this pull request adds.
redassay scan --since origin/main --fail-on high

# Or freeze the backlog and ratchet.
redassay baseline
redassay scan --new-only --fail-on medium
```

See [ci.md](ci.md).
