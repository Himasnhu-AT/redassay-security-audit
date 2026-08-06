import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from .helpers import TempRepo
from redassay.cli import main
from redassay.queue import ActionQueue
from redassay.store import Store

VULNERABLE = """
from flask import request
import subprocess

def handler():
    host = request.args.get("host")
    subprocess.run("ping " + host, shell=True)
"""


class CliTestCase(TempRepo):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--root", self.root, *args])
        return code, out.getvalue(), err.getvalue()

    def run_json(self, *args):
        code, out, err = self.run_cli("--json", *args)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def seed(self):
        self.write("app.py", VULNERABLE)
        self.run_cli("scan", "--quiet")
        return Store.open(self.root).all()[0].id


class InitTest(CliTestCase):
    def test_creates_the_store(self):
        code, out, _ = self.run_cli("init")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(self.root, ".redassay", "findings.json")))
        self.assertIn("Initialized", out)

    def test_writes_a_config(self):
        self.run_cli("init")
        self.assertTrue(os.path.isfile(os.path.join(self.root, ".redassay", "config.json")))

    def test_adds_itself_to_an_existing_gitignore(self):
        self.write(".gitignore", "*.pyc\n")
        self.run_cli("init")
        self.assertIn(".redassay/", open(os.path.join(self.root, ".gitignore")).read())

    def test_does_not_duplicate_the_gitignore_entry(self):
        self.write(".gitignore", ".redassay/\n")
        self.run_cli("init")
        self.assertEqual(open(os.path.join(self.root, ".gitignore")).read().count(".redassay/"), 1)


class ScanTest(CliTestCase):
    def test_reports_findings(self):
        self.write("app.py", VULNERABLE)
        code, out, _ = self.run_cli("scan")
        self.assertEqual(code, 0)
        self.assertIn("findings", out)
        self.assertIn("app.py", out)

    def test_json_output_is_parseable(self):
        self.write("app.py", VULNERABLE)
        payload = self.run_json("scan")
        self.assertIn("scan", payload)
        self.assertTrue(payload["findings"])

    def test_findings_are_persisted(self):
        self.write("app.py", VULNERABLE)
        self.run_cli("scan", "--quiet")
        self.assertGreater(len(Store.open(self.root)), 0)

    def test_fail_on_gates_the_exit_code(self):
        self.write("app.py", VULNERABLE)
        self.assertEqual(self.run_cli("scan", "--quiet", "--fail-on", "critical")[0], 1)

    def test_fail_on_passes_when_nothing_qualifies(self):
        self.write("app.py", "x = 1\n")
        self.assertEqual(self.run_cli("scan", "--quiet", "--fail-on", "critical")[0], 0)

    def test_scanner_selection(self):
        self.write("app.py", VULNERABLE)
        payload = self.run_json("scan", "--scanner", "secrets")
        self.assertEqual(payload["scan"]["scanners"], ["secrets"])

    def test_include_narrows_the_scan(self):
        self.write("app/a.py", VULNERABLE)
        self.write("lib/b.py", VULNERABLE)
        payload = self.run_json("scan", "--include", "app/")
        self.assertTrue(all(f["location"]["path"].startswith("app/") for f in payload["findings"]))

    def test_no_color_suppresses_ansi(self):
        self.write("app.py", VULNERABLE)
        self.assertNotIn("\033[", self.run_cli("scan", "--no-color")[1])

    def test_flags_work_after_the_subcommand(self):
        self.write("app.py", VULNERABLE)
        code, out, _ = self.run_cli("scan", "--json", "--quiet")
        self.assertEqual(code, 0)
        json.loads(out)


class ListAndShowTest(CliTestCase):
    def test_list_without_a_store_is_an_error(self):
        code, _, err = self.run_cli("list")
        self.assertEqual(code, 2)
        self.assertIn("no findings store", err)

    def test_list_shows_open_findings(self):
        self.seed()
        self.assertIn("app.py", self.run_cli("list")[1])

    def test_list_filters_by_severity(self):
        self.seed()
        payload = self.run_json("list", "--min-severity", "critical")
        self.assertTrue(all(f["severity"] == "critical" for f in payload["findings"]))

    def test_list_hides_dismissed_by_default(self):
        finding_id = self.seed()
        self.run_cli("dismiss", finding_id, "--reason", "accepted")
        ids = [f["id"] for f in self.run_json("list")["findings"]]
        self.assertNotIn(finding_id, ids)

    def test_list_all_includes_dismissed(self):
        finding_id = self.seed()
        self.run_cli("dismiss", finding_id, "--reason", "accepted")
        ids = [f["id"] for f in self.run_json("list", "--all")["findings"]]
        self.assertIn(finding_id, ids)

    def test_show_renders_source_context(self):
        finding_id = self.seed()
        out = self.run_cli("show", finding_id)[1]
        self.assertIn("Context:", out)
        self.assertIn("subprocess", out)

    def test_show_accepts_an_id_prefix(self):
        finding_id = self.seed()
        self.assertEqual(self.run_cli("show", finding_id[:6])[0], 0)

    def test_show_on_an_unknown_id_is_an_error(self):
        self.seed()
        self.assertEqual(self.run_cli("show", "ffffffffffff")[0], 2)


class TriageTest(CliTestCase):
    def test_status_change(self):
        finding_id = self.seed()
        self.run_cli("status", finding_id, "confirmed")
        self.assertEqual(Store.open(self.root).get(finding_id).status, "confirmed")

    def test_strict_mode_reports_an_illegal_transition(self):
        finding_id = self.seed()
        self.run_cli("status", finding_id, "dismissed")
        code, _, err = self.run_cli("status", finding_id, "fixed", "--strict")
        self.assertEqual(code, 2)
        self.assertIn("illegal transition", err)

    def test_comment(self):
        finding_id = self.seed()
        self.run_cli("comment", finding_id, "seen in production")
        self.assertEqual(Store.open(self.root).get(finding_id).comments[-1].body, "seen in production")

    def test_dismiss_with_rule_suppression(self):
        finding_id = self.seed()
        self.run_cli("dismiss", finding_id, "--reason", "internal only", "--suppress-rule")
        self.assertTrue(Store.open(self.root).suppressions())

    def test_suppressed_rule_stays_out_on_rescan(self):
        finding_id = self.seed()
        rule_id = Store.open(self.root).get(finding_id).rule_id
        self.run_cli("dismiss", finding_id, "--reason", "internal only", "--suppress-rule")
        self.run_cli("scan", "--quiet")
        self.assertNotIn(rule_id, [f.rule_id for f in Store.open(self.root).all() if f.is_open])

    def test_resolve_records_a_fix(self):
        finding_id = self.seed()
        self.run_cli("resolve", finding_id, "--summary", "used an argument list", "--file", "app.py")
        stored = Store.open(self.root).get(finding_id)
        self.assertEqual(stored.status, "fixed")
        self.assertEqual(stored.fix.summary, "used an argument list")
        self.assertEqual(stored.fix.files_touched, ["app.py"])

    def test_suppress_command(self):
        self.seed()
        self.run_cli("suppress", "py.shell-dynamic", "--path", "app.py", "--reason", "wrapper is safe")
        self.assertEqual(Store.open(self.root).suppressions()[0]["rule_id"], "py.shell-dynamic")


class AddTest(CliTestCase):
    PAYLOAD = {
        "findings": [{
            "rule_id": "claude.authz-gap",
            "title": "Order lookup does not scope to the caller",
            "severity": "high",
            "confidence": "high",
            "description": "The handler fetches by id from the path with no ownership filter.",
            "remediation": "Scope the query to the authenticated user.",
            "location": {"path": "app.py", "line": 6, "snippet": "order = Order.get(order_id)"},
            "cwe": ["CWE-639"],
        }]
    }

    def _add(self, payload):
        import sys
        self.write("app.py", VULNERABLE)
        self.run_cli("scan", "--quiet")
        original = sys.stdin
        sys.stdin = io.StringIO(json.dumps(payload))
        try:
            return self.run_cli("add")
        finally:
            sys.stdin = original

    def test_model_findings_are_merged_in(self):
        code, out, err = self._add(self.PAYLOAD)
        self.assertEqual(code, 0, err)
        stored = [f for f in Store.open(self.root).all() if f.rule_id == "claude.authz-gap"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].source, "claude")

    def test_a_bare_list_is_accepted(self):
        self.assertEqual(self._add(self.PAYLOAD["findings"])[0], 0)

    def test_a_finding_without_a_path_is_skipped_with_a_warning(self):
        payload = {"findings": [{"rule_id": "x.y", "title": "no path", "location": {}}]}
        code, _, err = self._add(payload)
        self.assertEqual(code, 0)
        self.assertIn("without a path", err)

    def test_invalid_json_is_an_error(self):
        import sys
        self.write("app.py", VULNERABLE)
        self.run_cli("scan", "--quiet")
        original = sys.stdin
        sys.stdin = io.StringIO("{not json")
        try:
            code, _, err = self.run_cli("add")
        finally:
            sys.stdin = original
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)


class QueueCommandTest(CliTestCase):
    def test_push_list_pull_complete(self):
        finding_id = self.seed()
        self.run_cli("queue", "push", "fix", "--id", finding_id)

        listed = self.run_json("queue", "list")
        self.assertEqual(len(listed["actions"]), 1)

        code, out, _ = self.run_cli("queue", "pull")
        self.assertEqual(code, 0)
        claimed = json.loads(out)["claimed"]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["findings"][0]["id"], finding_id)

        self.run_cli("queue", "complete", str(claimed[0]["seq"]), "--result", "done")
        self.assertEqual(ActionQueue(self.root).get(claimed[0]["seq"]).state, "done")

    def test_pull_returns_the_full_finding_for_the_agent(self):
        finding_id = self.seed()
        self.run_cli("queue", "push", "fix", "--id", finding_id)
        claimed = json.loads(self.run_cli("queue", "pull")[1])["claimed"]
        finding = claimed[0]["findings"][0]
        for key in ("title", "description", "remediation", "location", "severity"):
            self.assertIn(key, finding)

    def test_clear(self):
        self.seed()
        self.run_cli("queue", "push", "rescan")
        self.run_cli("queue", "clear")
        self.assertEqual(ActionQueue(self.root).all(), [])


class ReportTest(CliTestCase):
    def test_markdown_to_stdout(self):
        self.seed()
        out = self.run_cli("report", "--format", "markdown")[1]
        self.assertIn("# Security audit", out)

    def test_sarif_is_valid(self):
        self.seed()
        doc = json.loads(self.run_cli("report", "--format", "sarif")[1])
        self.assertEqual(doc["version"], "2.1.0")

    def test_writes_to_a_file(self):
        self.seed()
        target = os.path.join(self.root, "report.md")
        code, out, _ = self.run_cli("report", "--format", "markdown", "-o", target)
        self.assertEqual(code, 0)
        self.assertIn("wrote", out)
        self.assertIn("# Security audit", open(target).read())


class InfoCommandTest(CliTestCase):
    def test_scanners(self):
        out = self.run_cli("scanners")[1]
        self.assertIn("python-ast", out)

    def test_rules_lists_packs(self):
        out = self.run_cli("rules")[1]
        self.assertIn("injection", out)
        self.assertIn("rules", out)

    def test_rules_can_filter_by_pack(self):
        payload = self.run_json("rules", "--pack", "crypto")
        self.assertTrue(all(r["pack"] == "crypto" for r in payload["rules"]))

    def test_stats(self):
        self.seed()
        payload = self.run_json("stats")
        self.assertGreater(payload["total"], 0)
        self.assertIn("by_severity", payload)


class ErrorHandlingTest(CliTestCase):
    def test_an_unexpected_error_becomes_exit_2(self):
        code, _, err = self.run_cli("show", "x")
        self.assertEqual(code, 2)
        self.assertTrue(err)

    def test_unknown_subcommand_exits_nonzero(self):
        with self.assertRaises(SystemExit):
            main(["--root", self.root, "nonsense"])


if __name__ == "__main__":
    unittest.main()


class GitScopedScanTest(CliTestCase):
    def _init_repo(self):
        import subprocess
        for args in (["init", "-q", "-b", "main"],
                     ["config", "user.email", "t@example.invalid"],
                     ["config", "user.name", "T"],
                     ["config", "commit.gpgsign", "false"]):
            subprocess.run(["git", *args], cwd=self.root, capture_output=True, check=False)

    def _commit(self, message):
        import subprocess
        subprocess.run(["git", "add", "-A"], cwd=self.root, capture_output=True, check=False)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.root, capture_output=True, check=False)

    def test_since_reports_the_scope(self):
        self._init_repo()
        self.write("old.py", VULNERABLE)
        self._commit("old")
        self.write("new.py", VULNERABLE)
        code, out, _ = self.run_cli("scan", "--since", "HEAD")
        self.assertEqual(code, 0)
        self.assertIn("1 files changed since HEAD", out)

    def test_a_bad_ref_is_an_error_not_a_full_scan(self):
        self._init_repo()
        self.write("app.py", VULNERABLE)
        code, _, err = self.run_cli("scan", "--quiet", "--since", "no-such-ref")
        self.assertEqual(code, 2)
        self.assertIn("cannot diff", err)

    def test_blame_adds_commit_tags(self):
        self._init_repo()
        self.write("app.py", VULNERABLE)
        self._commit("add app")
        payload = self.run_json("scan", "--blame")
        tags = [t for f in payload["findings"] for t in f["tags"]]
        self.assertTrue(any(t.startswith("commit:") for t in tags))


class BaselineTest(CliTestCase):
    def test_baseline_then_new_only_reports_nothing(self):
        self.seed()
        code, out, _ = self.run_cli("baseline")
        self.assertEqual(code, 0)
        self.assertIn("baselined", out)
        payload = self.run_json("scan", "--new-only")
        self.assertEqual(payload["findings"], [])

    def test_a_new_finding_still_reports(self):
        self.seed()
        self.run_cli("baseline")
        self.write("extra.py", "import os\nos.system(other_input)\n")
        payload = self.run_json("scan", "--new-only")
        self.assertTrue(payload["findings"])
        self.assertTrue(all(f["location"]["path"] == "extra.py" for f in payload["findings"]))

    def test_show(self):
        self.seed()
        self.run_cli("baseline")
        payload = self.run_json("baseline", "--show")
        self.assertGreater(payload["count"], 0)

    def test_clear(self):
        self.seed()
        self.run_cli("baseline")
        self.run_cli("baseline", "--clear")
        self.assertEqual(self.run_json("baseline", "--show")["count"], 0)

    def test_new_only_without_a_baseline_reports_everything(self):
        self.seed()
        self.assertTrue(self.run_json("scan", "--new-only")["findings"])

    def test_fail_on_combines_with_new_only_for_a_ratchet(self):
        self.seed()
        self.run_cli("baseline")
        self.assertEqual(self.run_cli("scan", "--quiet", "--new-only", "--fail-on", "critical")[0], 0)
