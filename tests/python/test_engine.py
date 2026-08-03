import os
import unittest

from .helpers import FIXTURES, TempRepo
from redassay import config as config_mod, severity as sev
from redassay.engine import exit_code, scan, scan_and_merge
from redassay.store import Store


class ScanResultTest(TempRepo):
    def test_scan_counts_files_and_bytes(self):
        self.write("app.py", "x = 1\n")
        self.write("lib.js", "const x = 1;\n")
        result = scan(config_mod.load(self.root))
        self.assertEqual(result.files_scanned, 2)
        self.assertGreater(result.bytes_scanned, 0)
        self.assertEqual(result.by_language["python"], 1)

    def test_every_scanner_runs(self):
        result = scan(config_mod.load(self.root))
        for name in ("pattern", "secrets", "python-ast", "javascript", "dependencies", "cicd", "configs"):
            self.assertIn(name, result.scanners_run)

    def test_scanner_selection(self):
        result = scan(config_mod.load(self.root, scanners=["secrets"]))
        self.assertEqual(result.scanners_run, ["secrets"])

    def test_scanner_exclusion(self):
        result = scan(config_mod.load(self.root, disabled_scanners=["pattern"]))
        self.assertNotIn("pattern", result.scanners_run)

    def test_severity_floor_is_applied(self):
        self.write("app.py", "import os\nos.system(cmd)\nimport requests\nrequests.get('https://x')\n")
        everything = scan(config_mod.load(self.root))
        serious = scan(config_mod.load(self.root, min_severity="high"))
        self.assertGreater(len(everything.findings), len(serious.findings))
        self.assertTrue(all(sev.at_least(f.severity, "high") for f in serious.findings))

    def test_disabled_rules_are_dropped(self):
        self.write("app.py", "eval(payload)\n")
        self.assertNotIn(
            "py.eval-dynamic",
            [f.rule_id for f in scan(config_mod.load(self.root, disabled_rules=["py.eval-dynamic"])).findings],
        )

    def test_results_are_ordered_worst_first(self):
        self.write("app.py", "import os\nos.system(cmd)\nimport requests\nrequests.get('https://x')\n")
        findings = scan(config_mod.load(self.root)).findings
        ranks = [sev.rank(f.severity) for f in findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_the_run_is_deterministic(self):
        self.write("app.py", "eval(a)\nos.system(b)\n")
        first = [f.id for f in scan(config_mod.load(self.root)).findings]
        second = [f.id for f in scan(config_mod.load(self.root)).findings]
        self.assertEqual(first, second)

    def test_progress_events_are_emitted(self):
        self.write("app.py", "x = 1\n")
        events = []
        scan(config_mod.load(self.root), progress=lambda name, data: events.append(name))
        self.assertIn("walk:start", events)
        self.assertIn("walk:done", events)
        self.assertIn("triage:done", events)

    def test_to_dict_is_serializable(self):
        import json
        self.write("app.py", "x = 1\n")
        json.dumps(scan(config_mod.load(self.root)).to_dict())


class BrokenScannerTest(TempRepo):
    def test_a_scanner_that_raises_does_not_kill_the_run(self):
        from redassay.scanners.base import Scanner
        from redassay.scanners.registry import REGISTRY

        class Exploding(Scanner):
            name = "exploding"
            description = "always fails"

            def scan_file(self, source, context):
                raise RuntimeError("boom")

        REGISTRY["exploding"] = Exploding
        self.addCleanup(REGISTRY.pop, "exploding", None)

        self.write("app.py", "eval(x)\n")
        result = scan(config_mod.load(self.root))
        self.assertTrue(any("exploding" in error for error in result.errors))
        self.assertTrue(result.findings)          # the other scanners still ran


class ScanAndMergeTest(TempRepo):
    def test_findings_land_in_the_store(self):
        self.write("app.py", "eval(payload)\n")
        result = scan_and_merge(config_mod.load(self.root))
        self.assertTrue(result.merge.added)
        self.assertEqual(len(Store.open(self.root)), len(result.findings))

    def test_the_run_is_recorded_in_history(self):
        self.write("app.py", "eval(payload)\n")
        scan_and_merge(config_mod.load(self.root))
        last = Store.open(self.root).last_scan()
        self.assertEqual(last["total"], 1)
        self.assertIn("counts", last)

    def test_rescanning_does_not_duplicate(self):
        self.write("app.py", "eval(payload)\n")
        config = config_mod.load(self.root)
        scan_and_merge(config)
        scan_and_merge(config)
        self.assertEqual(len(Store.open(self.root)), 1)

    def test_fixing_the_code_verifies_the_finding(self):
        self.write("app.py", "eval(payload)\n")
        config = config_mod.load(self.root)
        scan_and_merge(config)
        store = Store.open(self.root)
        finding_id = store.all()[0].id
        from redassay.models import Fix
        store.record_fix(finding_id, Fix(summary="replaced with literal_eval"))
        store.save()

        self.write("app.py", "import ast\nast.literal_eval(payload)\n")
        result = scan_and_merge(config)
        self.assertIn(finding_id, result.merge.verified)


class ExitCodeTest(TempRepo):
    def test_no_gate_means_success(self):
        self.write("app.py", "eval(payload)\n")
        self.assertEqual(exit_code(scan(config_mod.load(self.root)), None), 0)

    def test_gate_trips_on_a_matching_severity(self):
        self.write("app.py", "eval(payload)\n")
        self.assertEqual(exit_code(scan(config_mod.load(self.root)), "critical"), 1)

    def test_gate_passes_when_nothing_reaches_it(self):
        self.write("app.py", "import requests\nrequests.get('https://x')\n")
        self.assertEqual(exit_code(scan(config_mod.load(self.root)), "critical"), 0)


class CleanFixtureTest(unittest.TestCase):
    """The control fixture is the false-positive budget, expressed as a test."""

    @classmethod
    def setUpClass(cls):
        cls.findings = scan(config_mod.load(os.path.join(FIXTURES, "clean-app"))).findings

    def test_nothing_is_reported_with_high_confidence(self):
        loud = [f for f in self.findings if f.confidence == "high"]
        self.assertEqual([f"{f.rule_id} {f.location.label}" for f in loud], [])

    def test_nothing_is_reported_above_medium_severity(self):
        loud = [f for f in self.findings if sev.rank(f.severity) < sev.rank("medium")]
        self.assertEqual([f"{f.rule_id} {f.location.label}" for f in loud], [])

    def test_the_residue_stays_small(self):
        self.assertLessEqual(len(self.findings), 2, [f.rule_id for f in self.findings])


class LocalRulePackTest(TempRepo):
    def test_a_pack_in_dot_redassay_rules_is_picked_up(self):
        import json
        rule = {
            "id": "local.no-todo-secrets",
            "title": "TODO next to a credential",
            "pattern": "TODO.*credential",
            "severity": "low",
            "description": "A reminder to handle a credential properly, left in the code." + " " * 10,
            "remediation": "Handle it.",
            "cwe": ["CWE-1"],
        }
        os.makedirs(os.path.join(self.root, ".redassay", "rules"), exist_ok=True)
        with open(os.path.join(self.root, ".redassay", "rules", "local.json"), "w") as handle:
            json.dump({"pack": "local", "rules": [rule]}, handle)
        self.write("app.py", "x = 1  # TODO rotate this credential\n")
        self.assertIn("local.no-todo-secrets", [f.rule_id for f in scan(config_mod.load(self.root)).findings])


if __name__ == "__main__":
    unittest.main()
