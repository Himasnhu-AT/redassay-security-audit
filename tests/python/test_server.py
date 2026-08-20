"""End-to-end tests against a real HTTP server on a real socket.

Mocking the handler would test the router and nothing else. The interesting
failures - header handling, the origin check, path pinning - only show up when
something actually speaks HTTP to it.
"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from .helpers import TempRepo
from redassay import config as config_mod
from redassay.engine import scan_and_merge
from redassay.queue import ActionQueue
from redassay.server.app import build_server
from redassay.store import Store

VULNERABLE = """
from flask import request
import subprocess

def handler():
    host = request.args.get("host")
    subprocess.run("ping " + host, shell=True)
"""


class ServerTestCase(TempRepo):
    def setUp(self):
        super().setUp()
        self.write("app.py", VULNERABLE)
        self.write("config.py", 'API_KEY = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"\n')
        self.config = config_mod.load(self.root, host="127.0.0.1", port=0)
        scan_and_merge(self.config)

        self.server = build_server(self.config)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        # The default 0.5s poll interval makes shutdown() dominate the suite:
        # 36 tests x 0.5s is most of the wall clock for no benefit.
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    # -- helpers -------------------------------------------------------------
    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, json.loads(response.read())

    def post(self, path, payload=None, content_type="application/json", origin=None):
        body = json.dumps(payload or {}).encode()
        request = urllib.request.Request(self.base + path, data=body, method="POST")
        request.add_header("Content-Type", content_type)
        if origin:
            request.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def raw(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read(), dict(error.headers)

    def first_finding_id(self):
        return Store.open(self.root).all()[0].id


class StaticServingTest(ServerTestCase):
    def test_index_is_served(self):
        status, body, headers = self.raw("/")
        self.assertEqual(status, 200)
        self.assertIn(b"redassay board", body)
        self.assertIn("text/html", headers["Content-Type"])

    def test_assets_are_served(self):
        for path in ("/app.js", "/style.css", "/lib/format.js", "/lib/filters.js", "/lib/selection.js"):
            self.assertEqual(self.raw(path)[0], 200, path)

    def test_security_headers_are_set(self):
        headers = self.raw("/")[2]
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_traversal_out_of_the_static_root_is_refused(self):
        self.assertIn(self.raw("/../../../etc/passwd")[0], (403, 404))

    def test_unknown_asset_is_404(self):
        self.assertEqual(self.raw("/nope.js")[0], 404)


class StateApiTest(ServerTestCase):
    def test_state_returns_findings_and_stats(self):
        status, payload = self.get("/api/state")
        self.assertEqual(status, 200)
        self.assertTrue(payload["findings"])
        self.assertEqual(payload["stats"]["total"], len(payload["findings"]))
        self.assertIn("hotspots", payload)
        self.assertIn("queue", payload)

    def test_findings_carry_a_priority(self):
        payload = self.get("/api/state")[1]
        self.assertTrue(all("priority" in f for f in payload["findings"]))

    def test_findings_are_ranked(self):
        payload = self.get("/api/state")[1]
        priorities = [f["priority"] for f in payload["findings"]]
        self.assertEqual(priorities, sorted(priorities, reverse=True))

    def test_list_endpoint_filters_by_severity(self):
        payload = self.get("/api/findings?min_severity=critical")[1]
        self.assertTrue(all(f["severity"] == "critical" for f in payload["findings"]))

    def test_detail_includes_source_context(self):
        payload = self.get(f"/api/findings/{self.first_finding_id()}")[1]
        self.assertIn("context", payload)
        self.assertTrue(payload["context"]["lines"])

    def test_unknown_finding_is_404(self):
        try:
            self.get("/api/findings/doesnotexist")
            self.fail("expected 404")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 404)

    def test_health(self):
        self.assertTrue(self.get("/api/health")[1]["ok"])

    def test_unknown_endpoint_is_404(self):
        try:
            self.get("/api/nope")
            self.fail("expected 404")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 404)


class SourceEndpointTest(ServerTestCase):
    def test_reads_a_file_in_the_repo(self):
        payload = self.get("/api/source?path=app.py&line=7")[1]
        self.assertEqual(payload["path"], "app.py")
        self.assertTrue(payload["lines"])

    def test_refuses_to_escape_the_repo(self):
        try:
            self.get("/api/source?path=../../../../etc/passwd")
            self.fail("expected 404")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 404)

    def test_rejects_a_non_integer_line(self):
        try:
            self.get("/api/source?path=app.py&line=abc")
            self.fail("expected 400")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)


class MutationTest(ServerTestCase):
    def test_comment_is_persisted_and_queued(self):
        finding_id = self.first_finding_id()
        status, payload = self.post(f"/api/findings/{finding_id}/comment", {"body": "real, seen in prod"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["comments"][-1]["body"], "real, seen in prod")
        self.assertEqual(Store.open(self.root).get(finding_id).comments[-1].body, "real, seen in prod")

    def test_empty_comment_is_rejected(self):
        self.assertEqual(self.post(f"/api/findings/{self.first_finding_id()}/comment", {"body": "  "})[0], 400)

    def test_status_change(self):
        finding_id = self.first_finding_id()
        status, payload = self.post(f"/api/findings/{finding_id}/status", {"status": "confirmed"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "confirmed")

    def test_invalid_status_is_rejected(self):
        self.assertEqual(self.post(f"/api/findings/{self.first_finding_id()}/status", {"status": "nope"})[0], 400)

    def test_illegal_transition_is_a_conflict(self):
        finding_id = self.first_finding_id()
        self.post(f"/api/findings/{finding_id}/status", {"status": "dismissed"})
        self.assertEqual(self.post(f"/api/findings/{finding_id}/status", {"status": "fixed"})[0], 409)

    def test_dismiss_records_the_reason(self):
        finding_id = self.first_finding_id()
        payload = self.post(f"/api/findings/{finding_id}/dismiss", {"reason": "internal tool only"})[1]
        self.assertEqual(payload["status"], "dismissed")
        self.assertIn("internal tool only", payload["comments"][-1]["body"])

    def test_dismiss_can_suppress_the_rule(self):
        finding_id = self.first_finding_id()
        self.post(f"/api/findings/{finding_id}/dismiss", {"reason": "noisy", "suppress_rule": True})
        self.assertTrue(Store.open(self.root).suppressions())

    def test_reopen(self):
        finding_id = self.first_finding_id()
        self.post(f"/api/findings/{finding_id}/dismiss", {"reason": "no"})
        self.assertEqual(self.post(f"/api/findings/{finding_id}/reopen")[1]["status"], "open")


class FixQueueTest(ServerTestCase):
    def test_requesting_a_fix_queues_an_action(self):
        finding_id = self.first_finding_id()
        status, payload = self.post(f"/api/findings/{finding_id}/fix", {"note": "keep the CLI flag"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["finding"]["status"], "queued")

        pending = ActionQueue(self.root).pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].finding_id, finding_id)
        self.assertEqual(pending[0].payload["note"], "keep the CLI flag")

    def test_the_note_becomes_a_comment(self):
        finding_id = self.first_finding_id()
        payload = self.post(f"/api/findings/{finding_id}/fix", {"note": "keep the CLI flag"})[1]
        self.assertIn("keep the CLI flag", payload["finding"]["comments"][-1]["body"])

    def test_batch_fix(self):
        ids = [f.id for f in Store.open(self.root).all()][:2]
        status, payload = self.post("/api/fix", {"finding_ids": ids})
        self.assertEqual(status, 200)
        self.assertEqual(sorted(payload["queued"]), sorted(ids))
        for finding_id in ids:
            self.assertEqual(Store.open(self.root).get(finding_id).status, "queued")

    def test_batch_fix_needs_a_non_empty_list(self):
        self.assertEqual(self.post("/api/fix", {"finding_ids": []})[0], 400)

    def test_batch_fix_ignores_unknown_ids(self):
        payload = self.post("/api/fix", {"finding_ids": ["doesnotexist"]})[1]
        self.assertEqual(payload["queued"], [])

    def test_rescan_queues_an_action(self):
        self.post("/api/rescan")
        self.assertEqual(ActionQueue(self.root).pending()[0].kind, "rescan")

    def test_queue_endpoint_reflects_state(self):
        self.post(f"/api/findings/{self.first_finding_id()}/fix", {})
        payload = self.get("/api/queue")[1]
        self.assertEqual(payload["stats"]["pending"], 1)


class RequestGuardTest(ServerTestCase):
    def test_a_form_content_type_is_refused(self):
        status, _ = self.post("/api/rescan", content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, 403)

    def test_a_foreign_origin_is_refused(self):
        status, _ = self.post("/api/rescan", origin="http://evil.example")
        self.assertEqual(status, 403)

    def test_the_matching_origin_is_accepted(self):
        status, _ = self.post("/api/rescan", origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(status, 200)

    def test_get_on_a_post_endpoint_is_405(self):
        try:
            self.get("/api/rescan")
            self.fail("expected 405")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 405)


class ConcurrencyTest(ServerTestCase):
    def test_the_board_sees_writes_made_by_another_process(self):
        finding_id = self.first_finding_id()
        store = Store.open(self.root)
        store.add_comment(finding_id, "cli", "written outside the server")
        store.save()
        payload = self.get(f"/api/findings/{finding_id}")[1]
        self.assertIn("written outside the server", payload["comments"][-1]["body"])


if __name__ == "__main__":
    unittest.main()


class ReportEndpointTest(ServerTestCase):
    def test_markdown(self):
        status, payload = self.get("/api/report?format=markdown")
        self.assertEqual(status, 200)
        self.assertEqual(payload["filename"], "SECURITY-AUDIT.md")
        self.assertIn("# Security audit", payload["body"])
        self.assertGreater(payload["count"], 0)

    def test_sarif_is_valid_json(self):
        payload = self.get("/api/report?format=sarif")[1]
        doc = json.loads(payload["body"])
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(payload["media_type"], "application/sarif+json")

    def test_json(self):
        payload = self.get("/api/report?format=json")[1]
        self.assertIn("findings", json.loads(payload["body"]))

    def test_default_is_markdown(self):
        self.assertEqual(self.get("/api/report")[1]["format"], "markdown")

    def test_an_unknown_format_is_rejected(self):
        try:
            self.get("/api/report?format=pdf")
            self.fail("expected 400")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)

    def test_dismissed_findings_are_excluded_by_default(self):
        finding_id = self.first_finding_id()
        before = self.get("/api/report?format=json")[1]["count"]
        self.post(f"/api/findings/{finding_id}/dismiss", {"reason": "not reachable"})
        after = self.get("/api/report?format=json")[1]["count"]
        self.assertEqual(after, before - 1)

    def test_status_filter(self):
        finding_id = self.first_finding_id()
        self.post(f"/api/findings/{finding_id}/dismiss", {"reason": "no"})
        payload = self.get("/api/report?format=json&status=dismissed")[1]
        self.assertEqual(payload["count"], 1)
