"""Control-framework mapping.

The risk here is not a wrong id - it is the report being read as an assurance
statement. "Touches PR.AA-05" and "PR.AA-05 is satisfied" are different claims,
and only one of them is something a scan can make.
"""

import json
import re
import unittest

from .helpers import make_finding
from redassay import compliance
from redassay.rules import load_all
from redassay.scanners.python_ast import RULES as AST_RULES


class TableTest(unittest.TestCase):
    def test_the_table_loads(self):
        self.assertGreater(len(compliance.mappings()), 50)

    def test_control_ids_are_well_formed(self):
        for cwe, entry in compliance.mappings().items():
            self.assertRegex(cwe, r"^CWE-\d+$")
            for control in entry["nist_csf"]:
                self.assertRegex(control, r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$", control)
            for technique in entry["mitre_attack"]:
                self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$", technique)

    def test_every_entry_has_both_frameworks_and_a_theme(self):
        for cwe, entry in compliance.mappings().items():
            self.assertTrue(entry["nist_csf"], cwe)
            self.assertTrue(entry["mitre_attack"], cwe)
            self.assertTrue(entry["theme"], cwe)

    def test_function_lookup(self):
        self.assertEqual(compliance.function_of("PR.AA-05"), "Protect")
        self.assertEqual(compliance.function_of("GV.SC-04"), "Govern")
        self.assertEqual(compliance.function_of("nonsense"), "")

    def test_an_unknown_cwe_maps_to_nothing_rather_than_guessing(self):
        self.assertEqual(compliance.for_cwe("CWE-99999"), {})


class CoverageOfOurOwnRulesTest(unittest.TestCase):
    """A rule emitting a CWE the table does not know is a gap, not an error -
    but it should stay small enough to notice."""

    def _emitted(self):
        cwes = set()
        for rule in load_all():
            cwes.update(rule.get("cwe") or [])
        for meta in AST_RULES.values():
            cwes.update(meta.get("cwe") or [])
        return cwes

    def test_most_emitted_cwes_are_mapped(self):
        emitted = self._emitted()
        mapped = set(compliance.mappings())
        missing = sorted(emitted - mapped)
        ratio = 1 - (len(missing) / max(len(emitted), 1))
        self.assertGreaterEqual(ratio, 0.95, f"unmapped: {missing}")

    def test_the_table_does_not_carry_entries_nothing_emits(self):
        """Dead rows drift out of date unnoticed."""
        unused = sorted(set(compliance.mappings()) - self._emitted())
        self.assertLessEqual(len(unused), 3, f"unused rows: {unused}")


class AnnotateTest(unittest.TestCase):
    def test_a_finding_gets_both_frameworks(self):
        marks = compliance.annotate(make_finding(cwe=["CWE-89"]))
        self.assertIn("PR.DS-01", marks["nist_csf"])
        self.assertIn("T1190", marks["mitre_attack"])
        self.assertIn("query parameterisation", marks["themes"])

    def test_several_cwes_merge_without_duplicates(self):
        marks = compliance.annotate(make_finding(cwe=["CWE-89", "CWE-943"]))
        self.assertEqual(len(marks["mitre_attack"]), len(set(marks["mitre_attack"])))

    def test_a_finding_with_no_cwe_is_empty_not_an_error(self):
        marks = compliance.annotate(make_finding(cwe=[]))
        self.assertEqual(marks["nist_csf"], [])


class ReportTest(unittest.TestCase):
    def _findings(self):
        return [
            make_finding(rule_id="a", cwe=["CWE-89"]),
            make_finding(rule_id="b", cwe=["CWE-798"]),
            make_finding(rule_id="c", cwe=["CWE-99999"]),
        ]

    def test_it_counts_by_function_and_subcategory(self):
        text = compliance.report(self._findings())
        self.assertIn("By CSF function", text)
        self.assertIn("Protect", text)
        self.assertIn("PR.DS-01", text)

    def test_it_refuses_to_claim_a_control_is_satisfied(self):
        text = compliance.report(self._findings())
        self.assertIn("touch", text)
        self.assertIn("does not say a control is satisfied", text)

    def test_unmapped_cwes_are_surfaced_not_hidden(self):
        text = compliance.report(self._findings())
        self.assertIn("Unmapped", text)
        self.assertIn("CWE-99999", text)

    def test_an_empty_run_still_renders(self):
        self.assertIn("Control coverage", compliance.report([]))

    def test_coverage_is_serializable(self):
        json.dumps(compliance.coverage(self._findings()))


if __name__ == "__main__":
    unittest.main()
