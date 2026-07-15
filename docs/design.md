# redassay design notes

## The problem

Running an LLM over a repo and asking "find the security bugs" produces a wall of
markdown. It is unreviewable, unrepeatable, and there is no way to say "this one
is a false positive, never show it to me again" or "fix these four, leave the
rest".

## The shape of the fix

Split the loop into three pieces that talk through a file on disk:

1. **Engine** (`engine/redassay`, Python, stdlib only). Deterministic scanners
   walk the tree and emit findings. Same input, same output, no model involved.
2. **Findings repo** (`.redassay/`, JSON). The durable state. Every finding has a
   stable id derived from its content, so re-scanning a repo merges instead of
   duplicating. Dismissals, comments and fix status survive re-scans.
3. **Review board** (local HTTP server + static UI). A human triages. Actions the
   human takes are appended to an action queue.

Claude sits on top: it runs the scan, adds findings the regex scanners cannot
see (logic flaws, authz gaps, unsafe data flow), drains the action queue, writes
the patches, and marks findings resolved.

## Why stable ids matter

A finding id is `sha256(rule_id | path | normalized_snippet)[:12]`. Line numbers
are deliberately *not* in the hash - code moves, the vulnerability does not. This
is what lets a dismissal stick across a refactor.

## Why the engine is stdlib only

The plugin has to run on whatever Python the user already has. Adding a
requirements.txt to a security tool is how you get people running `pip install`
inside a repo they do not trust yet.
