# Reachability

## The question severity does not answer

Two findings, same rule, same severity, same file:

```
high  py.shell-dynamic  app/db.py:7     run_report()
high  py.shell-dynamic  app/db.py:12    rotate_backups()
```

The first is called by `POST /report`, an unauthenticated route. The second is
called by nothing. One is an incident; the other is a cleanup ticket. Nothing in
the scanners can tell them apart, because the difference is a call edge in
another file.

`redassay trace` answers it:

```
! high  py.shell-dynamic  app/db.py:7
    reachable from POST /report in 1 hop(s): report -> run_report
. high  py.shell-dynamic  app/db.py:12
    no call path from any known entry point
```

## Why redassay does not build the graph

`architecture.md` explains the taint tracker's scope: one function, no
cross-call propagation, because a real interprocedural analysis needs a call
graph and a wrong answer from a half-built one is worse than no answer - it
produces confident nonsense, which is the failure mode that gets tools
uninstalled.

That reasoning is about a graph *we* would build. It says nothing against using
one that already exists. So `callgraph.py` is a bridge, not an implementation:
it shells out to an external indexer, reads its edges, and degrades to silence
when there is none.

Three properties, in order of importance:

1. **Optional.** Invoked as a subprocess, never imported. No indexer, no index,
   or an incompatible version - every function returns empty and the rest of
   redassay behaves exactly as before. The zero-dependency promise does not bend
   for a convenience.
2. **Honest about absence.** "No path found" never renders as "unreachable". A
   static call graph cannot see dynamic dispatch, reflection, framework
   registration, or anything wired at runtime. The status is `no-path` - a
   statement about the graph - and the output says so every time it appears.
3. **Cheap.** One subprocess per symbol, cached, hard-capped at 200 queries. A
   scan that shells out 1,500 times is a scan nobody runs twice.

## Setting it up

```bash
npm install -g @nanonets/graft     # or: pnpm add -g @nanonets/graft
cd your-repo
graft build                        # wiring graph only - no API key, no cost
```

`graft build` parses the repository into symbols, spans and call edges. The
`--deep` flag adds an LLM-generated concept layer; redassay does not use it, so
the free pass is enough.

Then:

```bash
redassay trace --min-severity high
redassay trace --annotate          # writes reach:* tags onto the findings
```

The index lives in `graft/` and is git-ignored - it is a local cache, rebuilt
with one command. `graft check` fails if it has drifted from the code, which is
what you want in CI if you gate on reachability.

## What it is used for

**Ordering a backlog.** On a real repository most findings sit in code no
request touches: helpers, migrations, dead branches, vendored copies. Sorting by
reachability puts the afternoon where it belongs. This is the primary use.

**Not** extending taint across function boundaries to find *new* findings. That
would mean deciding, at each call site, whether an argument is attacker
controlled - which is the confident-nonsense problem again, one layer up. The
bridge reports what the graph knows; it does not infer.

## How the pieces fit

Reachability needs two things redassay already produces:

- **entry points** from `redassay surface` - the set of places a request can
  start
- **findings** from `redassay scan` - the set of places something dangerous
  happens

The call graph supplies the edges between them. Any of the three can be missing
and the other two still work; together they answer a question none of them can
answer alone.
