"""Optional, anonymous, opt-in usage telemetry.

This is the one part of redassay that can touch the network, and it is off by
default. The scan engine (`engine.py`, `scanners/`) never imports this module, so
the guarantee that *scanning* makes no network request holds unconditionally. A
ping happens only from the CLI, only after you run `redassay telemetry on`, and
carries nothing that identifies you or your code:

    { "anon_id": <random uuid, generated once and stored locally>,
      "event":   "scan",
      "version": "0.1.0",
      "os":      "darwin",          # platform.system(), coarse
      "ci":      false }            # whether it ran in CI

No repository name, no path, no finding, no snippet, no code ever leaves the
machine. The id is random and local; it cannot be traced back to a person. The
send is fire-and-forget with a short timeout and swallows every error, so it can
neither slow a scan down nor make one fail.

Kill switches, in priority order: `DO_NOT_TRACK=1` and `REDASSAY_TELEMETRY=0`
force it off; `REDASSAY_TELEMETRY=1` forces it on; otherwise the stored config
decides, defaulting to off. CI environments are treated as off unless explicitly
turned on.
"""

from __future__ import annotations

import json
import os
import platform
import threading
import uuid
from typing import Any, Dict, Optional

from . import __version__

#: Where the ping goes. Overridable for local testing against a dev server.
DEFAULT_ENDPOINT = "https://redassay.com/api/telemetry"

_TRUE = {"1", "true", "on", "yes"}
_FALSE = {"0", "false", "off", "no"}


# --- config on disk ----------------------------------------------------------
def _config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "redassay")


def _config_path() -> str:
    return os.path.join(_config_dir(), "config.json")


def _read_config() -> Dict[str, Any]:
    try:
        with open(_config_path(), encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_config(data: Dict[str, Any]) -> None:
    try:
        os.makedirs(_config_dir(), exist_ok=True)
        with open(_config_path(), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except OSError:
        pass                                # never let config I/O break a scan


def config_exists() -> bool:
    return os.path.exists(_config_path())


def anon_id() -> str:
    """A random, local, per-install id. Created once and reused; never derived
    from anything identifying."""
    config = _read_config()
    ident = config.get("anon_id")
    if not isinstance(ident, str) or not ident:
        ident = uuid.uuid4().hex
        config["anon_id"] = ident
        _write_config(config)
    return ident


# --- enablement --------------------------------------------------------------
def _env(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return None


def _in_ci() -> bool:
    return bool(os.environ.get("CI"))


def is_enabled() -> bool:
    # Do-Not-Track and an explicit off always win.
    if os.environ.get("DO_NOT_TRACK", "").strip() == "1":
        return False
    forced = _env("REDASSAY_TELEMETRY")
    if forced is not None:
        return forced
    if _in_ci():
        return False                        # never phone home from CI unless forced on
    return bool(_read_config().get("telemetry", False))


def set_enabled(enabled: bool) -> None:
    config = _read_config()
    config["telemetry"] = bool(enabled)
    config.setdefault("anon_id", uuid.uuid4().hex)
    _write_config(config)


def endpoint() -> str:
    return os.environ.get("REDASSAY_TELEMETRY_ENDPOINT") or DEFAULT_ENDPOINT


# --- the ping ----------------------------------------------------------------
def build_payload(event: str) -> Dict[str, Any]:
    return {
        "anon_id": anon_id(),
        "event": event,
        "version": __version__,
        "os": platform.system().lower(),
        "ci": _in_ci(),
    }


def _post(url: str, payload: Dict[str, Any]) -> None:
    """Send one event. Isolated so tests can replace it and assert on calls."""
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": f"redassay/{__version__}"})
    try:
        urllib.request.urlopen(request, timeout=2).close()
    except Exception:  # redassay: ignore py.swallowed-exception - fire-and-forget telemetry must never surface a network error
        pass


def ping(event: str = "scan") -> None:
    """Send one anonymous event if telemetry is enabled. Returns immediately;
    the network call runs on a daemon thread and cannot delay or fail the scan."""
    if not is_enabled():
        return
    payload = build_payload(event)
    thread = threading.Thread(target=_post, args=(endpoint(), payload), daemon=True)
    thread.start()


# --- CLI surface -------------------------------------------------------------
FIRST_RUN_NOTICE = (
    "redassay can send anonymous usage pings (a random id, the event name, the "
    "version, your OS, and whether it is CI) to help gauge adoption. It is OFF. "
    "No code, path, repository name, or finding is ever sent. Turn it on with "
    "`redassay telemetry on`, or silence this with `redassay telemetry off`."
)


def maybe_first_run_notice() -> Optional[str]:
    """Return a one-time notice the first time redassay runs on this machine, and
    write the config so it never shows again. Returns None afterwards."""
    if config_exists():
        return None
    _write_config({"telemetry": False, "anon_id": uuid.uuid4().hex})
    return FIRST_RUN_NOTICE


def status_text() -> str:
    enabled = is_enabled()
    reason = ""
    if os.environ.get("DO_NOT_TRACK", "").strip() == "1":
        reason = " (forced off by DO_NOT_TRACK)"
    elif _env("REDASSAY_TELEMETRY") is not None:
        reason = " (set by REDASSAY_TELEMETRY)"
    elif _in_ci() and not _env("REDASSAY_TELEMETRY"):
        reason = " (off in CI)"
    lines = [
        f"telemetry: {'on' if enabled else 'off'}{reason}",
        f"config:    {_config_path()}",
        f"endpoint:  {endpoint()}",
        "",
        "If enabled, each `scan` sends exactly this and nothing else:",
        json.dumps(build_payload("scan"), indent=2),
    ]
    return "\n".join(lines)
