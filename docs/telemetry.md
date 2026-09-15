# Telemetry

redassay can report anonymous usage, and it is off by default. This is the only
part of the tool that can reach the network. It exists so the project can tell
whether anyone runs it, without asking anyone to trust a black box.

## What it is not

The scan engine makes no network requests, ever. That guarantee is unchanged:
`engine.py` and everything under `scanners/` do not import the telemetry module.
A ping can only come from the CLI, only after you opt in, and it carries nothing
that identifies you or your code.

## What a ping contains

One event, five fields:

```json
{
  "anon_id": "6c5b0b093e0f40cfb80f073329218d6f",
  "event":   "scan",
  "version": "0.1.0",
  "os":      "darwin",
  "ci":      false
}
```

- `anon_id` is a random UUID generated once on your machine and stored locally.
  It is not derived from your username, your hardware, your repository, or
  anything else. It cannot be traced back to you.
- `event` is the command name, currently only `scan`.
- `os` is `platform.system()` lowercased, no version.

No path, no repository name, no file, no snippet, no finding, no code is ever
sent. `redassay telemetry status` prints the exact payload before you enable
anything, so you can see it for yourself.

## Turning it on and off

```bash
redassay telemetry status     # state, config location, endpoint, sample payload
redassay telemetry on
redassay telemetry off
```

The state lives in `${XDG_CONFIG_HOME:-~/.config}/redassay/config.json`.

Environment overrides, highest priority first:

- `DO_NOT_TRACK=1` forces it off, matching the [consoledonottrack.com] convention.
- `REDASSAY_TELEMETRY=0` forces it off; `REDASSAY_TELEMETRY=1` forces it on.
- CI environments (`CI` set) are off unless forced on.
- `REDASSAY_TELEMETRY_ENDPOINT` sends events somewhere else, which is how you
  point it at a local collector during development.

## How the send behaves

The ping runs on a daemon thread with a two-second timeout and swallows every
error. It cannot slow a scan down, and it cannot make one fail. If you are
offline, or the endpoint is down, the scan is unaffected and nothing is retried.

[consoledonottrack.com]: https://consoledonottrack.com
