# Benchmarks

`validation-benchmarks` is a submodule: 104 deliberately vulnerable web
applications, each a self-contained Docker Compose stack. It is here as a large,
realistic corpus to scan - not as something to fix.

That distinction matters, because the two things in it are different:

- **The vulnerabilities are the point.** Each benchmark hides a flag behind a
  specific defect. Repairing them would destroy the corpus.
- **The network exposure was not the point.** Publishing those applications
  beyond the host is an accident of packaging, and fixing it costs nothing.

## What was changed

Every compose file published its application to `0.0.0.0`:

| Form | Count | What it actually did |
| --- | --- | --- |
| `- 80` | 92 | Asked Docker for an ephemeral host port on **every interface**. Reads like a declaration that the container listens on 80. |
| `- "8000:80"` | 15 | Fixed host port on every interface. |

Bringing the suite up therefore served 104 known-vulnerable applications to the
whole local network. Every published port is now confined to loopback:

```yaml
ports:
  - "127.0.0.1::80"        # was: - 80
  - "127.0.0.1:8000:80"    # was: - "8000:80"
```

Applied by `tools/bind_loopback.py`, which is idempotent, has a `--dry-run`, and
is covered by `tests/python/test_bind_loopback.py` - including the cases it must
*not* touch.

`expose:` entries were deliberately left alone. That keyword opens a port to the
compose network only and never reaches the host, so rewriting it would change
what a stack does for no security benefit.

**The challenges are unaffected.** They are reachable at `127.0.0.1` on the same
ports and solvable exactly as before.

### Verified

```
docker compose config   ->  104 parsed, 0 failed, 0 unbound publications
redassay scan --scanner exposure  ->  0 published-port findings
```

Docker's own parser reports `host_ip: 127.0.0.1` on every published port, so the
result does not depend on the rewriting tool's own regexes being right.

## What redassay still reports, and why it is fine

| Finding | Count | Why it stays |
| --- | --- | --- |
| `expose.wildcard-bind` | 42 | Application code binding `0.0.0.0` *inside* a container. The container network is the boundary, and the host mapping is now loopback. Correct as written; reported at `low`. |
| `expose.dockerfile-datastore-port` | 15 | `EXPOSE 3306` in the database images. `EXPOSE` publishes nothing - it is documentation and a hint to `docker run -P`. |

Neither reaches the host. The goal - no service of this suite reachable from
outside the machine running it - is met.

## Scanning it

```bash
redassay --root benchmarks/validation-benchmarks scan --quiet
redassay --root benchmarks/validation-benchmarks report --format exposure
redassay --root benchmarks/validation-benchmarks surface --unprotected
```

A full scan takes about 30 seconds over 3,953 files and returns roughly 1,500
findings. That number is not a bug: this is a corpus of intentional
vulnerabilities, and it is the closest thing available to a recall test.

## Working with the submodule

```bash
git submodule update --init --depth 1 benchmarks/validation-benchmarks
```

The clone is large (~1.4 GB with history) and the checkout is slow. The
submodule records only a URL and a commit, so the parent repository stays small.

**The loopback commit exists only in your local clone until it is pushed.** Until
then, anyone else running `git submodule update` gets the upstream commit with
the ports still published.
