import json
import unittest

from .helpers import make_finding
from redassay import report, sarif
from redassay.models import Fix, Location


def sample():
    finding = make_finding(
        rule_id="py.sql-dynamic",
        title="SQL statement assembled at runtime",
        severity="critical",
        confidence="high",
        description="A value from request.args reaches execute().",
        remediation="Use bound parameters.",
        cwe=["CWE-89"],
        owasp=["A03:2021 Injection"],
        location=Location(path="app/views.py", line=42, snippet='cursor.execute(f"...{name}")'),
    )
    finding.add_comment("you", "confirmed against staging")
    return [finding]


class TerminalTest(unittest.TestCase):
    def test_empty(self):
        self.assertIn("No findings", report.terminal([], color=False))

    def test_includes_location_and_title(self):
        text = report.terminal(sample(), color=False)
        self.assertIn("app/views.py:42", text)
        self.assertIn("SQL statement assembled", text)

    def test_no_ansi_when_color_is_off(self):
        self.assertNotIn("\033[", report.terminal(sample(), color=False))

    def test_ansi_when_color_is_on(self):
        self.assertIn("\033[", report.terminal(sample(), color=True))

    def test_remediation_is_opt_in(self):
        self.assertNotIn("bound parameters", report.terminal(sample(), color=False))
        self.assertIn("bound parameters", report.terminal(sample(), color=False, show_remediation=True))

    def test_limit_reports_what_it_hid(self):
        findings = [make_finding(rule_id=f"r{i}", location=Location(path=f"{i}.py", line=1, snippet="x"))
                    for i in range(10)]
        self.assertIn("and 7 more", report.terminal(findings, color=False, limit=3))

    def test_summary_line(self):
        self.assertIn("1 critical", report.summary_line(sample(), color=False))
        self.assertIn("clean", report.summary_line([], color=False))


class MarkdownTest(unittest.TestCase):
    def setUp(self):
        self.text = report.markdown(sample(), title="Audit", repo="demo")

    def test_has_a_title_and_repo(self):
        self.assertIn("# Audit", self.text)
        self.assertIn("`demo`", self.text)

    def test_has_a_severity_table(self):
        self.assertIn("| Severity | Count |", self.text)
        self.assertIn("| critical | 1 |", self.text)

    def test_has_a_hotspot_table(self):
        self.assertIn("## Hotspots", self.text)
        self.assertIn("app/views.py", self.text)

    def test_includes_the_snippet_in_a_fence(self):
        self.assertIn("```", self.text)
        self.assertIn("cursor.execute", self.text)

    def test_includes_classification_and_remediation(self):
        self.assertIn("CWE-89", self.text)
        self.assertIn("**Fix:**", self.text)

    def test_includes_review_notes(self):
        self.assertIn("confirmed against staging", self.text)

    def test_empty_report_still_renders(self):
        self.assertIn("# Audit", report.markdown([], title="Audit"))


class JsonTest(unittest.TestCase):
    def test_round_trips(self):
        payload = json.loads(report.as_json(sample()))
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "py.sql-dynamic")

    def test_extra_fields_are_merged(self):
        payload = json.loads(report.as_json(sample(), extra={"stats": {"total": 1}}))
        self.assertEqual(payload["stats"]["total"], 1)


class SarifTest(unittest.TestCase):
    def setUp(self):
        self.doc = sarif.build(sample())
        self.run = self.doc["runs"][0]

    def test_envelope(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("$schema", self.doc)
        self.assertEqual(self.run["tool"]["driver"]["name"], "redassay")

    def test_a_rule_is_declared_once_per_rule_id(self):
        findings = sample() + sample()
        run = sarif.build(findings)["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)

    def test_severity_maps_to_a_sarif_level(self):
        self.assertEqual(self.run["results"][0]["level"], "error")
        low = make_finding(severity="low", location=Location(path="a.py", line=1, snippet="x"))
        self.assertEqual(sarif.build([low])["runs"][0]["results"][0]["level"], "note")

    def test_security_severity_is_present_for_code_scanning(self):
        rule = self.run["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "9.5")

    def test_location_is_physical_and_one_indexed(self):
        region = self.run["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 42)

    def test_fingerprint_carries_our_stable_id(self):
        self.assertIn("redassayId", self.run["results"][0]["partialFingerprints"])

    def test_line_zero_is_clamped_to_one(self):
        finding = make_finding(location=Location(path="a.py", line=0, snippet="x"))
        region = sarif.build([finding])["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_output_is_valid_json(self):
        json.loads(sarif.dumps(sample()))

    def test_repo_uri_is_optional(self):
        doc = sarif.build(sample(), repo_uri="https://github.com/a/b")
        self.assertIn("versionControlProvenance", doc["runs"][0])
        self.assertNotIn("versionControlProvenance", self.run)


if __name__ == "__main__":
    unittest.main()
