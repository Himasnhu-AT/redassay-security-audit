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


class DoctorTest(CliTestCase):
    def test_reports_every_check(self):
        payload = self.run_json("doctor")
        names = {c["check"] for c in payload["checks"]}
        for expected in ("python", "rule packs", "scanners", "advisory data",
                         "target", "git", "store", "board port", "writable"):
            self.assertIn(expected, names)

    def test_a_healthy_environment_passes(self):
        code, _, _ = self.run_cli("doctor")
        self.assertEqual(code, 0)
        self.assertTrue(self.run_json("doctor")["ok"])

    def test_it_notices_a_missing_store(self):
        detail = next(c for c in self.run_json("doctor")["checks"] if c["check"] == "store")
        self.assertIn("not created yet", detail["detail"])

    def test_it_notices_an_existing_store(self):
        self.seed()
        detail = next(c for c in self.run_json("doctor")["checks"] if c["check"] == "store")
        self.assertIn("findings", detail["detail"])

    def test_a_missing_target_is_fatal(self):
        out, err = io.StringIO(), io.StringIO()
        from contextlib import redirect_stderr, redirect_stdout
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--root", os.path.join(self.root, "nope"), "doctor"])
        self.assertEqual(code, 2)

    def test_a_corrupt_store_is_reported_not_raised(self):
        self.seed()
        with open(os.path.join(self.root, ".redassay", "findings.json"), "w") as handle:
            handle.write("{not json")
        detail = next(c for c in self.run_json("doctor")["checks"] if c["check"] == "store")
        self.assertFalse(detail["ok"])

    def test_a_port_in_use_is_reported(self):
        import socket
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        self.addCleanup(server.close)
        os.makedirs(os.path.join(self.root, ".redassay"), exist_ok=True)
        self.write(".redassay/config.json", json.dumps({"port": port}))
        detail = next(c for c in self.run_json("doctor")["checks"] if c["check"] == "board port")
        self.assertFalse(detail["ok"])
        self.assertIn("already in use", detail["detail"])


class WatchTest(CliTestCase):
    def test_once_with_an_empty_queue_exits_cleanly(self):
        self.seed()
        code, out, _ = self.run_cli("watch", "--once")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")

    def test_once_emits_claimed_work_as_jsonl(self):
        finding_id = self.seed()
        self.run_cli("queue", "push", "fix", "--id", finding_id)
        code, out, _ = self.run_cli("watch", "--once")
        self.assertEqual(code, 0)
        lines = [line for line in out.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        action = json.loads(lines[0])
        self.assertEqual(action["kind"], "fix")
        self.assertEqual(action["findings"][0]["id"], finding_id)

    def test_claimed_work_is_not_emitted_twice(self):
        finding_id = self.seed()
        self.run_cli("queue", "push", "fix", "--id", finding_id)
        self.run_cli("watch", "--once")
        self.assertEqual(self.run_cli("watch", "--once")[1].strip(), "")

    def test_limit_leaves_the_rest_queued(self):
        finding_id = self.seed()
        # Three separate requests for the same finding: what matters here is the
        # batch size, not how many distinct findings the fixture happens to have.
        for _ in range(3):
            self.run_cli("queue", "push", "fix", "--id", finding_id)
        code, out, _ = self.run_cli("watch", "--once", "--limit", "2")
        self.assertEqual(len([line for line in out.splitlines() if line.strip()]), 2)
        self.assertEqual(len(ActionQueue(self.root).pending()), 1)

    def test_timeout_returns_rather_than_hanging(self):
        self.seed()
        code, _, _ = self.run_cli("watch", "--timeout", "0.05", "--interval", "0.01")
        self.assertEqual(code, 0)


class InitTemplateTest(CliTestCase):
    def test_a_starter_ignore_file_is_written(self):
        self.run_cli("init")
        path = os.path.join(self.root, ".redassayignore")
        self.assertTrue(os.path.isfile(path))
        body = open(path).read()
        self.assertIn("tests/", body)
        self.assertIn("59%", body)

    def test_every_line_in_the_template_is_commented_out(self):
        self.run_cli("init")
        body = open(os.path.join(self.root, ".redassayignore")).read()
        for line in body.splitlines():
            if line.strip():
                self.assertTrue(line.startswith("#"), line)

    def test_the_template_does_not_change_scan_results(self):
        self.write("app.py", VULNERABLE)
        before = len(self.run_json("scan")["findings"])
        os.remove(os.path.join(self.root, ".redassay", "findings.json"))
        self.run_cli("init")
        self.assertEqual(len(self.run_json("scan")["findings"]), before)

    def test_an_existing_ignore_file_is_not_overwritten(self):
        self.write(".redassayignore", "vendor/\n")
        self.run_cli("init")
        self.assertEqual(open(os.path.join(self.root, ".redassayignore")).read(), "vendor/\n")

    def test_json_reports_what_it_created(self):
        payload = self.run_json("init")
        self.assertIn(".redassayignore", payload["created"])


class ExcludeTestsFlagTest(CliTestCase):
    def test_the_flag_narrows_the_scan(self):
        self.write("app.py", VULNERABLE)
        self.write("tests/test_app.py", VULNERABLE)
        everything = self.run_json("scan")["scan"]["files_scanned"]
        narrowed = self.run_json("scan", "--exclude-tests")["scan"]["files_scanned"]
        self.assertLess(narrowed, everything)

    def test_findings_in_test_code_disappear(self):
        self.write("tests/test_app.py", VULNERABLE)
        paths = {f["location"]["path"] for f in self.run_json("scan", "--exclude-tests")["findings"]}
        self.assertEqual(paths, set())


class QuickfixFormatTest(CliTestCase):
    def test_report_emits_quickfix_lines(self):
        self.seed()
        out = self.run_cli("report", "--format", "quickfix")[1]
        for line in out.splitlines():
            if line.strip():
                self.assertRegex(line, r"^[\w./-]+:\d+:\d+: \w+: .+ \[[\w.-]+\]$")


class HistoryTest(CliTestCase):
    def test_history_without_scans(self):
        self.write("app.py", VULNERABLE)
        self.run_cli("init")
        self.assertIn("no scans recorded", self.run_cli("history")[1])

    def test_history_shows_one_row_per_scan(self):
        self.seed()
        self.run_cli("scan", "--quiet")
        payload = self.run_json("history")
        self.assertEqual(payload["count"], 2)
        self.assertIn("counts", payload["scans"][0])

    def test_history_renders_a_table(self):
        self.seed()
        out = self.run_cli("history")[1]
        self.assertIn("when", out)
        self.assertIn("crit", out)

    def test_limit(self):
        self.seed()
        for _ in range(3):
            self.run_cli("scan", "--quiet")
        self.assertEqual(self.run_json("history", "--limit", "2")["count"], 2)


class PruneTest(CliTestCase):
    def test_dry_run_changes_nothing(self):
        self.seed()
        before = len(Store.open(self.root))
        out = self.run_cli("prune", "--older-than", "0", "--status", "open", "--dry-run")[1]
        self.assertIn("would remove", out)
        self.assertEqual(len(Store.open(self.root)), before)

    def test_prune_removes_and_persists(self):
        self.seed()
        before = len(Store.open(self.root))
        self.run_cli("prune", "--older-than", "0", "--status", "open")
        self.assertLess(len(Store.open(self.root)), before)

    def test_defaults_to_verified_only(self):
        self.seed()
        before = len(Store.open(self.root))
        self.run_cli("prune", "--older-than", "0")
        self.assertEqual(len(Store.open(self.root)), before)
