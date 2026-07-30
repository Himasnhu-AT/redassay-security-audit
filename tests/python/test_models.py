import unittest

from .helpers import make_finding
from redassay import models
from redassay.models import Comment, Finding, Fix, Location


class LocationTest(unittest.TestCase):
    def test_normalizes_windows_separators(self):
        self.assertEqual(Location(path="a\\b\\c.py").path, "a/b/c.py")

    def test_end_line_never_precedes_start(self):
        self.assertEqual(Location(path="a.py", line=10, end_line=3).end_line, 10)

    def test_label(self):
        self.assertEqual(Location(path="a.py", line=7).label, "a.py:7")
        self.assertEqual(Location(path="a.py").label, "a.py")


class FindingTest(unittest.TestCase):
    def test_id_is_derived_when_absent(self):
        self.assertTrue(make_finding().id)

    def test_explicit_id_is_kept(self):
        self.assertEqual(make_finding(id="deadbeef").id, "deadbeef")

    def test_severity_and_confidence_are_normalized(self):
        finding = make_finding(severity="BLOCKER", confidence="certain")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.confidence, "high")

    def test_unknown_status_falls_back_to_open(self):
        self.assertEqual(make_finding(status="banana").status, models.OPEN)

    def test_round_trips_through_dict(self):
        finding = make_finding()
        finding.add_comment("me", "looks real")
        finding.fix = Fix(summary="parameterized the query", files_touched=["app.py"])
        clone = Finding.from_dict(finding.to_dict())
        self.assertEqual(clone.to_dict(), finding.to_dict())

    def test_from_dict_tolerates_a_sparse_payload(self):
        finding = Finding.from_dict({"rule_id": "x.y", "location": {"path": "a.py"}})
        self.assertEqual(finding.title, "x.y")
        self.assertEqual(finding.severity, "medium")

    def test_all_locations_includes_extras(self):
        finding = make_finding(extra_locations=[Location(path="b.py", line=3)])
        self.assertEqual(len(finding.all_locations), 2)


class StatusMachineTest(unittest.TestCase):
    def test_legal_transition(self):
        finding = make_finding()
        self.assertTrue(finding.set_status(models.QUEUED))
        self.assertEqual(finding.status, models.QUEUED)

    def test_illegal_transition_is_refused_quietly(self):
        finding = make_finding(status=models.VERIFIED)
        self.assertFalse(finding.set_status(models.QUEUED))
        self.assertEqual(finding.status, models.VERIFIED)

    def test_strict_mode_raises(self):
        finding = make_finding(status=models.VERIFIED)
        with self.assertRaises(ValueError):
            finding.set_status(models.QUEUED, strict=True)

    def test_unknown_status_always_raises(self):
        with self.assertRaises(ValueError):
            make_finding().set_status("elsewhere")

    def test_same_status_is_a_no_op(self):
        finding = make_finding(status=models.FIXED)
        self.assertTrue(finding.set_status(models.FIXED))

    def test_fixed_is_reachable_from_every_pre_fix_state(self):
        for start in (models.OPEN, models.CONFIRMED, models.QUEUED, models.FIXING):
            finding = make_finding(status=start)
            self.assertTrue(finding.set_status(models.FIXED), start)

    def test_dismissed_can_be_reopened(self):
        finding = make_finding(status=models.DISMISSED)
        self.assertTrue(finding.set_status(models.OPEN))

    def test_actionable_and_sticky_do_not_overlap(self):
        self.assertFalse(models.ACTIONABLE & models.STICKY)


class CommentTest(unittest.TestCase):
    def test_defaults_fill_in(self):
        comment = Comment.from_dict({})
        self.assertEqual(comment.author, "anonymous")
        self.assertTrue(comment.created_at)

    def test_add_comment_appends(self):
        finding = make_finding()
        finding.add_comment("a", "one")
        finding.add_comment("b", "two")
        self.assertEqual([c.author for c in finding.comments], ["a", "b"])


class FixTest(unittest.TestCase):
    def test_is_empty(self):
        self.assertTrue(Fix().is_empty)
        self.assertFalse(Fix(summary="did a thing").is_empty)


if __name__ == "__main__":
    unittest.main()
