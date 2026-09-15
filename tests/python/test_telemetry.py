"""The opt-in telemetry client.

The whole point of this module is that it does nothing unless asked, and that
what it sends carries no identifying data. The tests weight those two properties:
default-silence and payload-minimalism are the ones that protect the user.
"""

import os
import shutil
import tempfile
import threading
import unittest

from . import _bootstrap  # noqa: F401
from redassay import telemetry


class TelemetryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="redassay-tele-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # Isolate config from the real home and clear every env influence.
        self._saved = {k: os.environ.get(k) for k in
                       ("XDG_CONFIG_HOME", "REDASSAY_TELEMETRY", "DO_NOT_TRACK", "CI",
                        "REDASSAY_TELEMETRY_ENDPOINT")}
        for k in self._saved:
            os.environ.pop(k, None)
        os.environ["XDG_CONFIG_HOME"] = self.tmp
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # -- default silence -----------------------------------------------------
    def test_off_by_default(self):
        self.assertFalse(telemetry.is_enabled())

    def test_first_run_notice_appears_once_then_never(self):
        self.assertIn("anonymous", telemetry.maybe_first_run_notice())
        self.assertIsNone(telemetry.maybe_first_run_notice())
        self.assertFalse(telemetry.is_enabled())          # notice does not enable it

    def test_ping_sends_nothing_when_disabled(self):
        sent = []
        telemetry._post = lambda url, payload: sent.append(payload)  # type: ignore
        telemetry.ping("scan")
        self.assertEqual(sent, [])

    # -- opt-in --------------------------------------------------------------
    def test_enable_then_ping_sends(self):
        telemetry.set_enabled(True)
        self.assertTrue(telemetry.is_enabled())
        done = threading.Event()
        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            done.set()

        telemetry._post = fake_post  # type: ignore
        telemetry.ping("scan")
        self.assertTrue(done.wait(2), "ping did not fire when enabled")
        self.assertEqual(captured["payload"]["event"], "scan")

    def test_toggle_off_again(self):
        telemetry.set_enabled(True)
        telemetry.set_enabled(False)
        self.assertFalse(telemetry.is_enabled())

    # -- payload carries nothing identifying ---------------------------------
    def test_payload_shape_is_minimal(self):
        payload = telemetry.build_payload("scan")
        self.assertEqual(set(payload), {"anon_id", "event", "version", "os", "ci"})
        blob = " ".join(str(v) for v in payload.values()).lower()
        for leak in ("/", "\\", self.tmp.lower(), "redassay-tele"):
            self.assertNotIn(leak, blob, f"payload leaked {leak!r}")

    def test_anon_id_is_stable_and_random(self):
        first = telemetry.anon_id()
        self.assertEqual(first, telemetry.anon_id())       # stable across calls
        self.assertRegex(first, r"^[0-9a-f]{32}$")          # a uuid4 hex, not a name

    # -- kill switches -------------------------------------------------------
    def test_do_not_track_forces_off(self):
        telemetry.set_enabled(True)
        os.environ["DO_NOT_TRACK"] = "1"
        self.assertFalse(telemetry.is_enabled())

    def test_env_can_force_on_and_off(self):
        os.environ["REDASSAY_TELEMETRY"] = "0"
        telemetry.set_enabled(True)
        self.assertFalse(telemetry.is_enabled())            # explicit env off wins
        os.environ["REDASSAY_TELEMETRY"] = "1"
        self.assertTrue(telemetry.is_enabled())

    def test_ci_is_off_unless_forced(self):
        telemetry.set_enabled(True)
        os.environ["CI"] = "true"
        self.assertFalse(telemetry.is_enabled())
        os.environ["REDASSAY_TELEMETRY"] = "1"
        self.assertTrue(telemetry.is_enabled())             # explicit on beats CI


if __name__ == "__main__":
    unittest.main()
