"""The whole loop, once, end to end.

Everything else tests a piece. This tests the thing the plugin actually does:
scan finds a bug, a reviewer dismisses one and approves another, an agent drains
the queue and fixes the code, and the next scan confirms it is gone - with the
dismissal still in place.
"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.request

from .helpers import TempRepo
from redassay import config as config_mod, models
from redassay.engine import scan_and_merge
from redassay.models import Fix
from redassay.queue import ActionQueue
from redassay.server.app import build_server
from redassay.store import Store

VULNERABLE_APP = '''
"""A small service with two real defects and one thing that only looks like one."""

import hashlib
import subprocess

from flask import Flask, request

app = Flask(__name__)
CACHE_VERSION = "v3"


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()


@app.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    cursor = connection.cursor()
    cursor.execute(f"SELECT email FROM users WHERE name = '{name}'")
    return {"rows": cursor.fetchall()}


def cache_key(path):
    # Not a credential - a content fingerprint for the CDN.
    return hashlib.md5((CACHE_VERSION + path).encode()).hexdigest()
'''

FIXED_PING = '''    host = request.args.get("host", "localhost")
    return subprocess.check_output(["ping", "-c", "1", host], timeout=5).decode()
'''


class FullLoopTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.write("service.py", VULNERABLE_APP)
        self.config = config_mod.load(self.root, host="127.0.0.1", port=0)

        self.server = build_server(self.config)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def board_get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return json.loads(response.read())

    def board_post(self, path, payload=None):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(payload or {}).encode(), method="POST"
        )
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def find(self, rule_id):
        matches = [f for f in Store.open(self.root).all() if f.rule_id == rule_id]
        self.assertEqual(len(matches), 1, f"expected exactly one {rule_id}, got {len(matches)}")
        return matches[0]

    # -- the loop ------------------------------------------------------------
    def test_scan_triage_fix_verify(self):
        # 1. The scan finds the two real defects.
        result = scan_and_merge(self.config)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("py.shell-dynamic", rule_ids)
        self.assertIn("py.sql-dynamic", rule_ids)

        command_injection = self.find("py.shell-dynamic")
        sql_injection = self.find("py.sql-dynamic")
        self.assertEqual(command_injection.severity, "critical")   # taint confirmed

        # 2. The board shows them, worst first.
        state = self.board_get("/api/state")
        self.assertEqual(state["stats"]["total"], len(result.findings))
        self.assertEqual(state["findings"][0]["severity"], "critical")

        # 3. The reviewer dismisses the md5 cache key with a reason.
        weak_hash = next((f for f in Store.open(self.root).all() if "weak-hash" in f.rule_id), None)
        if weak_hash is not None:
            self.board_post(
                f"/api/findings/{weak_hash.id}/dismiss",
                {"reason": "Cache fingerprint, not a credential. CACHE_VERSION is a constant."},
            )
            self.assertEqual(Store.open(self.root).get(weak_hash.id).status, models.DISMISSED)

        # 4. The reviewer approves the command injection, with a constraint.
        response = self.board_post(
            f"/api/findings/{command_injection.id}/fix",
            {"note": "Keep the 1-packet behaviour."},
        )
        self.assertEqual(response["finding"]["status"], models.QUEUED)

        # 5. The agent claims the work and sees the full finding plus the note.
        queue = ActionQueue(self.root)
        claimed = queue.claim()
        self.assertEqual(len(claimed), 1)
        action = claimed[0]
        self.assertEqual(action.finding_id, command_injection.id)
        self.assertEqual(action.payload["note"], "Keep the 1-packet behaviour.")

        # 6. The agent fixes the code and records it.
        source = open(f"{self.root}/service.py", encoding="utf-8").read()
        broken = ('    host = request.args.get("host", "localhost")\n'
                  '    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()\n')
        self.assertIn(broken, source)
        self.write("service.py", source.replace(broken, FIXED_PING))

        store = Store.open(self.root)
        store.record_fix(
            command_injection.id,
            Fix(summary="Passed an argument list instead of a shell string",
                applied_by="claude", files_touched=["service.py"]),
        )
        store.save()
        queue.complete(action.seq, result="fixed")

        # 7. The next scan confirms it, and leaves the human decisions alone.
        second = scan_and_merge(self.config)
        self.assertIn(command_injection.id, second.merge.verified)

        final = Store.open(self.root)
        self.assertEqual(final.get(command_injection.id).status, models.VERIFIED)
        self.assertEqual(final.get(sql_injection.id).status, models.OPEN)
        if weak_hash is not None:
            self.assertEqual(final.get(weak_hash.id).status, models.DISMISSED)

        # 8. The board reflects all of it.
        state = self.board_get("/api/state")
        statuses = {f["id"]: f["status"] for f in state["findings"]}
        self.assertEqual(statuses[command_injection.id], models.VERIFIED)
        self.assertEqual(statuses[sql_injection.id], models.OPEN)
        self.assertEqual(queue.stats()["done"], 1)

    def test_a_regression_reopens_a_verified_finding(self):
        scan_and_merge(self.config)
        command_injection = self.find("py.shell-dynamic")

        store = Store.open(self.root)
        store.record_fix(command_injection.id, Fix(summary="fixed"))
        store.save()

        source = open(f"{self.root}/service.py", encoding="utf-8").read()
        self.write("service.py", source.replace(
            '    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()',
            '    return subprocess.check_output(["ping", "-c", "1", host]).decode()'))
        self.assertIn(command_injection.id, scan_and_merge(self.config).merge.verified)

        # Someone reverts the fix.
        self.write("service.py", source)
        result = scan_and_merge(self.config)
        self.assertIn(command_injection.id, result.merge.regressed)

        reopened = Store.open(self.root).get(command_injection.id)
        self.assertEqual(reopened.status, models.OPEN)
        self.assertIn("Reappeared", reopened.comments[-1].body)

    def test_a_dismissal_outlives_the_code_moving(self):
        scan_and_merge(self.config)
        sql_injection = self.find("py.sql-dynamic")

        store = Store.open(self.root)
        store.set_status(sql_injection.id, models.DISMISSED)
        store.add_comment(sql_injection.id, "you", "Internal admin tool, not exposed.")
        store.save()

        # Add twenty lines above it. The finding keeps its identity.
        source = open(f"{self.root}/service.py", encoding="utf-8").read()
        self.write("service.py", "# padding\n" * 20 + source)

        scan_and_merge(self.config)
        after = Store.open(self.root).get(sql_injection.id)
        self.assertEqual(after.status, models.DISMISSED)
        self.assertEqual(after.line, sql_injection.line + 20)
        self.assertEqual(after.comments[-1].body, "Internal admin tool, not exposed.")

    def test_batch_approval_queues_every_selected_finding(self):
        scan_and_merge(self.config)
        ids = [f.id for f in Store.open(self.root).all()][:3]
        response = self.board_post("/api/fix", {"finding_ids": ids})
        self.assertEqual(sorted(response["queued"]), sorted(ids))

        claimed = ActionQueue(self.root).claim()
        self.assertEqual(claimed[0].kind, "fix_all")
        self.assertEqual(sorted(claimed[0].payload["finding_ids"]), sorted(ids))
        for finding_id in ids:
            self.assertEqual(Store.open(self.root).get(finding_id).status, models.QUEUED)


if __name__ == "__main__":
    unittest.main()


class DemoScriptTest(unittest.TestCase):
    """The demo is the first thing anyone runs. It must not rot."""

    def test_it_completes_and_verifies_both_fixes(self):
        import subprocess
        from .helpers import ROOT

        result = subprocess.run(
            ["bash", "scripts/demo.sh"],
            cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        self.assertIn("2 verified fixed", output)
        self.assertIn("verified  py.sql-dynamic", output)
        self.assertIn("verified  py.shell-dynamic", output)
        self.assertIn("dismissed py.request-no-timeout", output)
        self.assertIn("Confirmed reachable from the public /user endpoint.", output)

    def test_it_leaves_the_repository_untouched(self):
        import subprocess
        from .helpers import ROOT

        before = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                capture_output=True, text=True, check=False).stdout
        subprocess.run(["bash", "scripts/demo.sh"], cwd=ROOT,
                       capture_output=True, text=True, timeout=180, check=False)
        after = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                               capture_output=True, text=True, check=False).stdout
        self.assertEqual(before, after)
