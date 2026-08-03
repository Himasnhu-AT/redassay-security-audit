import unittest

from .helpers import make_finding
from redassay import triage
from redassay.models import Location


class PriorityTest(unittest.TestCase):
    def test_severity_dominates(self):
        critical = make_finding(severity="critical", confidence="medium")
        high = make_finding(severity="high", confidence="high", rule_id="other")
        self.assertGreater(triage.priority(critical), triage.priority(high))

    def test_confidence_separates_equal_severities(self):
        confident = make_finding(severity="high", confidence="high")
        unsure = make_finding(severity="high", confidence="low", rule_id="other")
        self.assertGreater(triage.priority(confident), triage.priority(unsure))

    def test_a_low_confidence_critical_can_fall_below_a_confident_high(self):
        vague = make_finding(severity="critical", confidence="low")
        solid = make_finding(severity="high", confidence="high", rule_id="other")
        self.assertLess(triage.priority(vague), triage.priority(solid))

    def test_test_paths_are_discounted(self):
        production = make_finding(location=Location(path="app/views.py", line=1, snippet="x"))
        test = make_finding(location=Location(path="tests/test_views.py", line=1, snippet="x"))
        self.assertLess(triage.priority(test), triage.priority(production))

    def test_model_verified_findings_get_a_small_boost(self):
        plain = make_finding(source="pattern")
        verified = make_finding(source="claude", rule_id="other")
        self.assertGreater(triage.priority(verified), triage.priority(plain))


class DedupeTest(unittest.TestCase):
    def _pair(self):
        location = Location(path="app.py", line=10, snippet="yaml.load(x)")
        return (
            make_finding(rule_id="deser.yaml-unsafe-load", source="pattern", location=location),
            make_finding(rule_id="py.yaml-unsafe-load", source="python-ast", location=location),
        )

    def test_equivalent_rules_collapse_to_one(self):
        self.assertEqual(len(triage.dedupe(self._pair())), 1)

    def test_the_better_evidenced_scanner_wins(self):
        kept = triage.dedupe(self._pair())[0]
        self.assertEqual(kept.source, "python-ast")

    def test_order_does_not_change_the_winner(self):
        pattern_first, ast_first = self._pair(), tuple(reversed(self._pair()))
        self.assertEqual(triage.dedupe(pattern_first)[0].source, triage.dedupe(ast_first)[0].source)

    def test_the_survivor_inherits_both_sets_of_tags(self):
        a, b = self._pair()
        a.tags = ["pack-a"]
        b.tags = ["pack-b"]
        kept = triage.dedupe([a, b])[0]
        self.assertIn("pack-a", kept.tags)
        self.assertIn("deduped", kept.tags)

    def test_different_lines_are_different_findings(self):
        a = make_finding(rule_id="py.eval-dynamic", location=Location(path="a.py", line=1, snippet="eval(x)"))
        b = make_finding(rule_id="py.eval-dynamic", location=Location(path="a.py", line=9, snippet="eval(y)"))
        self.assertEqual(len(triage.dedupe([a, b])), 2)

    def test_different_files_are_different_findings(self):
        a = make_finding(location=Location(path="a.py", line=1, snippet="x"))
        b = make_finding(location=Location(path="b.py", line=1, snippet="x"))
        self.assertEqual(len(triage.dedupe([a, b])), 2)

    def test_unrelated_rules_are_both_kept(self):
        a = make_finding(rule_id="py.weak-hash", location=Location(path="a.py", line=1, snippet="x"))
        b = make_finding(rule_id="py.weak-random", location=Location(path="a.py", line=1, snippet="x"))
        self.assertEqual(len(triage.dedupe([a, b])), 2)


class FilterAndRankTest(unittest.TestCase):
    def _mixed(self):
        return [
            make_finding(severity="low", rule_id="a", location=Location(path="a.py", line=1, snippet="1")),
            make_finding(severity="critical", rule_id="b", location=Location(path="b.py", line=1, snippet="2")),
            make_finding(severity="medium", rule_id="c", location=Location(path="c.py", line=1, snippet="3")),
        ]

    def test_severity_floor(self):
        self.assertEqual(len(triage.filter_severity(self._mixed(), "medium")), 2)
        self.assertEqual(len(triage.filter_severity(self._mixed(), "critical")), 1)

    def test_info_floor_keeps_everything(self):
        self.assertEqual(len(triage.filter_severity(self._mixed(), "info")), 3)
        self.assertEqual(len(triage.filter_severity(self._mixed(), None)), 3)

    def test_rank_is_worst_first(self):
        self.assertEqual(triage.rank(self._mixed())[0].severity, "critical")

    def test_rank_is_stable_across_calls(self):
        findings = self._mixed()
        self.assertEqual([f.id for f in triage.rank(findings)], [f.id for f in triage.rank(findings)])

    def test_triage_composes_all_three_steps(self):
        result = triage.triage(self._mixed(), min_severity="medium")
        self.assertEqual([f.severity for f in result], ["critical", "medium"])


class GroupingTest(unittest.TestCase):
    def _spread(self):
        return [
            make_finding(rule_id="r1", severity="critical", location=Location(path="hot.py", line=1, snippet="a")),
            make_finding(rule_id="r2", severity="high", location=Location(path="hot.py", line=5, snippet="b")),
            make_finding(rule_id="r1", severity="low", location=Location(path="cold.py", line=1, snippet="c")),
        ]

    def test_group_by_file(self):
        groups = triage.group_by_file(self._spread())
        self.assertEqual(len(groups["hot.py"]), 2)

    def test_group_by_rule_is_ordered_by_frequency(self):
        groups = triage.group_by_rule(self._spread())
        self.assertEqual(list(groups)[0], "r1")

    def test_hotspots_rank_by_summed_risk_not_count(self):
        spots = triage.hotspots(self._spread())
        self.assertEqual(spots[0][0], "hot.py")
        self.assertEqual(spots[0][1], 2)

    def test_hotspots_respects_the_limit(self):
        self.assertEqual(len(triage.hotspots(self._spread(), limit=1)), 1)


class ConceptMapTest(unittest.TestCase):
    def test_known_equivalences_share_a_concept(self):
        for a, b in [
            ("py.sql-dynamic", "sql.fstring-query"),
            ("py.shell-dynamic", "cmd.os-system"),
            ("py.tls-verify-off", "crypto.tls-verify-disabled"),
        ]:
            self.assertEqual(
                triage.concept(make_finding(rule_id=a)),
                triage.concept(make_finding(rule_id=b)),
                f"{a} / {b}",
            )

    def test_an_unmapped_rule_is_its_own_concept(self):
        self.assertEqual(triage.concept(make_finding(rule_id="brand.new")), "brand.new")

    def test_every_mapped_rule_id_is_lowercase_and_dotted(self):
        for rule_id in triage.EQUIVALENT:
            self.assertEqual(rule_id, rule_id.lower())
            self.assertIn(".", rule_id)


if __name__ == "__main__":
    unittest.main()
