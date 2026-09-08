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


class QuickfixTest(unittest.TestCase):
    def test_matches_the_grep_convention(self):
        line = report.quickfix(sample()).splitlines()[0]
        self.assertTrue(line.startswith("app/views.py:42:1: critical: "))
        self.assertTrue(line.endswith("[py.sql-dynamic]"))

    def test_every_finding_gets_a_line(self):
        findings = [
            make_finding(rule_id=f"r{i}", location=Location(path=f"{i}.py", line=i + 1, snippet="x"))
            for i in range(4)
        ]
        self.assertEqual(len(report.quickfix(findings).splitlines()), 4)

    def test_line_zero_is_clamped_so_editors_can_jump(self):
        finding = make_finding(location=Location(path="a.py", line=0, snippet="x"))
        self.assertIn("a.py:1:1:", report.quickfix([finding]))

    def test_empty(self):
        self.assertEqual(report.quickfix([]), "")

    def test_it_is_single_line_per_finding(self):
        finding = make_finding(description="a\nmultiline\ndescription")
        self.assertEqual(len(report.quickfix([finding]).splitlines()), 1)


class ExposureReportTest(unittest.TestCase):
    def _published(self, **overrides):
        data = {
            "rule_id": "expose.published-datastore",
            "title": "PostgreSQL published on port 5432",
            "severity": "critical",
            "tags": ["exposure", "docker", "datastore"],
            "location": Location(path="docker-compose.yml", line=18, snippet='- "5432:5432"'),
        }
        data.update(overrides)
        return make_finding(**data)

    def test_an_empty_report_says_so_plainly(self):
        text = report.exposure([])
        self.assertIn("No published services", text)

    def test_findings_without_the_exposure_tag_are_ignored(self):
        other = make_finding(rule_id="py.sql-dynamic", tags=["injection"])
        self.assertIn("No published services", report.exposure([other]))

    def test_data_stores_get_their_own_section_first(self):
        text = report.exposure([
            self._published(),
            self._published(rule_id="expose.published-port", title="Port 8080 published",
                            severity="medium", tags=["exposure", "docker"],
                            location=Location(path="docker-compose.yml", line=7, snippet='- "8080:80"')),
        ])
        self.assertLess(text.index("Data stores reachable"), text.index("Other published surfaces"))

    def test_the_snippet_is_a_code_span_not_a_nested_bullet(self):
        text = report.exposure([self._published()])
        self.assertIn('`- "5432:5432"`', text)
        self.assertNotIn('  - - "5432:5432"', text)

    def test_it_counts_by_severity(self):
        text = report.exposure([self._published(), self._published(
            rule_id="expose.published-port", severity="medium",
            location=Location(path="a.yml", line=2, snippet="x"))])
        self.assertIn("1 critical", text)
        self.assertIn("1 medium", text)

    def test_it_ends_with_the_remediation_ladder(self):
        text = report.exposure([self._published()])
        self.assertIn("How to close them", text)
        self.assertIn("127.0.0.1:5432:5432", text)

    def test_worst_first_within_a_section(self):
        text = report.exposure([
            self._published(rule_id="expose.k8s-host-port", title="hostPort", severity="medium",
                            tags=["exposure"], location=Location(path="a.yml", line=1, snippet="x")),
            self._published(rule_id="expose.open-cidr", title="Open CIDR", severity="critical",
                            tags=["exposure"], location=Location(path="b.tf", line=1, snippet="y")),
        ])
        self.assertLess(text.index("Open CIDR"), text.index("hostPort"))
