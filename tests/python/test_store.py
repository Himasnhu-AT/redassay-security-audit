import json
import os
import unittest

from .helpers import TempRepo, make_finding
from redassay import models
from redassay.models import Finding, Fix, Location
from redassay.store import Store, StoreError, migrate


class StoreBasicsTest(TempRepo):
    def test_blank_store_when_nothing_on_disk(self):
        store = Store.open(self.root)
        self.assertEqual(len(store), 0)
        self.assertFalse(store.exists)

    def test_save_then_reopen(self):
        store = Store.open(self.root)
        finding = make_finding()
        store.put(finding)
        store.save()

        reopened = Store.open(self.root)
        self.assertEqual(len(reopened), 1)
        self.assertEqual(reopened.get(finding.id).title, finding.title)

    def test_written_json_is_sorted_and_indented(self):
        store = Store.open(self.root)
        for index in range(3):
            store.put(make_finding(rule_id=f"r{index}", location=Location(path=f"{index}.py", line=1)))
        store.save()
        raw = open(store.path, encoding="utf-8").read()
        self.assertIn("\n  ", raw)
        keys = list(json.loads(raw)["findings"])
        self.assertEqual(keys, sorted(keys))

    def test_corrupt_json_raises_a_useful_error(self):
        store = Store(self.root)
        store.ensure_dir()
        open(store.path, "w", encoding="utf-8").write("{not json")
        with self.assertRaises(StoreError):
            store.load()

    def test_prefix_lookup(self):
        store = Store.open(self.root)
        finding = make_finding()
        store.put(finding)
        self.assertEqual(store.get(finding.id[:6]).id, finding.id)

    def test_ambiguous_prefix_returns_nothing(self):
        store = Store.open(self.root)
        store.load()["findings"]["aaaa1111"] = make_finding(id="aaaa1111").to_dict()
        store.load()["findings"]["aaaa2222"] = make_finding(id="aaaa2222").to_dict()
        self.assertIsNone(store.get("aaaa"))

    def test_delete(self):
        store = Store.open(self.root)
        finding = make_finding()
        store.put(finding)
        self.assertTrue(store.delete(finding.id))
        self.assertFalse(store.delete(finding.id))


class QueryTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.store = Store.open(self.root)
        self.store.put(make_finding(rule_id="a", severity="critical", location=Location(path="app/x.py", line=1)))
        self.store.put(make_finding(rule_id="b", severity="low", location=Location(path="app/y.py", line=1)))
        self.store.put(make_finding(rule_id="c", severity="high", status=models.DISMISSED,
                                    location=Location(path="tests/z.py", line=1), source="secrets"))

    def test_filter_by_status(self):
        self.assertEqual(len(self.store.query(status=[models.OPEN])), 2)

    def test_severity_floor_is_inclusive(self):
        self.assertEqual(len(self.store.query(severity_floor="high")), 2)

    def test_path_prefix(self):
        self.assertEqual(len(self.store.query(path_prefix="app/")), 2)

    def test_source_and_rule(self):
        self.assertEqual(len(self.store.query(source="secrets")), 1)
        self.assertEqual(len(self.store.query(rule_id="a")), 1)

    def test_results_are_worst_first(self):
        severities = [f.severity for f in self.store.query()]
        self.assertEqual(severities[0], "critical")

    def test_stats(self):
        stats = self.store.stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["open"], 2)
        self.assertEqual(stats["by_severity"]["critical"], 1)


class MergeTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.store = Store.open(self.root)
        self.finding = make_finding()

    def test_first_merge_adds(self):
        result = self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(result.added, [self.finding.id])
        self.assertEqual(result.updated, [])

    def test_second_merge_updates_rather_than_duplicating(self):
        self.store.merge([self.finding], scanned_paths=["."])
        result = self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(result.added, [])
        self.assertEqual(result.updated, [self.finding.id])
        self.assertEqual(len(self.store), 1)

    def test_dismissal_survives_a_rescan(self):
        self.store.merge([self.finding], scanned_paths=["."])
        self.store.set_status(self.finding.id, models.DISMISSED)
        self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(self.store.get(self.finding.id).status, models.DISMISSED)

    def test_comments_survive_a_rescan(self):
        self.store.merge([self.finding], scanned_paths=["."])
        self.store.add_comment(self.finding.id, "me", "known risk, accepted")
        self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(len(self.store.get(self.finding.id).comments), 1)

    def test_location_is_refreshed_when_code_moves(self):
        self.store.merge([self.finding], scanned_paths=["."])
        moved = make_finding(location=Location(path="app.py", line=99, snippet="x = 1"))
        self.assertEqual(moved.id, self.finding.id)      # the id must not track the line
        self.store.merge([moved], scanned_paths=["."])
        self.assertEqual(self.store.get(self.finding.id).line, 99)

    def test_a_fixed_finding_that_reappears_is_reopened(self):
        self.store.merge([self.finding], scanned_paths=["."])
        self.store.record_fix(self.finding.id, Fix(summary="fixed"))
        result = self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(result.regressed, [self.finding.id])
        self.assertEqual(self.store.get(self.finding.id).status, models.OPEN)

    def test_a_fixed_finding_that_stays_gone_is_verified(self):
        self.store.merge([self.finding], scanned_paths=["."])
        self.store.record_fix(self.finding.id, Fix(summary="fixed"))
        result = self.store.merge([], scanned_paths=["."])
        self.assertEqual(result.verified, [self.finding.id])
        self.assertEqual(self.store.get(self.finding.id).status, models.VERIFIED)

    def test_findings_outside_the_scanned_scope_are_left_alone(self):
        other = make_finding(location=Location(path="other/mod.py", line=1, snippet="y = 2"))
        self.store.merge([self.finding, other], scanned_paths=["."])
        result = self.store.merge([self.finding], scanned_paths=["app.py"])
        self.assertNotIn(other.id, result.absent)

    def test_suppressed_findings_never_enter_the_store(self):
        self.store.suppress("test.rule", "*", "known noisy")
        result = self.store.merge([self.finding], scanned_paths=["."])
        self.assertEqual(result.suppressed, [self.finding.id])
        self.assertEqual(len(self.store), 0)

    def test_summary_is_human_readable(self):
        result = self.store.merge([self.finding], scanned_paths=["."])
        self.assertIn("1 new", result.summary())


class ScanHistoryTest(TempRepo):
    def test_history_is_capped(self):
        store = Store.open(self.root)
        for index in range(60):
            store.record_scan({"n": index}, keep=10)
        self.assertEqual(len(store.load()["scans"]), 10)
        self.assertEqual(store.last_scan()["n"], 59)


class MigrationTest(unittest.TestCase):
    def test_v1_list_becomes_a_dict(self):
        raw = {"schema_version": 1, "findings": [{"id": "abc", "rule_id": "r"}]}
        migrated = migrate(raw)
        self.assertEqual(migrated["schema_version"], 2)
        self.assertIn("abc", migrated["findings"])
        self.assertEqual(migrated["suppressions"], [])

    def test_missing_keys_are_filled(self):
        migrated = migrate({})
        for key in ("findings", "scans", "suppressions"):
            self.assertIn(key, migrated)


if __name__ == "__main__":
    unittest.main()


class PruneTest(TempRepo):
    def _aged(self, days: int, status: str = models.VERIFIED, rule_id: str = "r"):
        import datetime as dt
        when = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
        finding = make_finding(rule_id=rule_id, status=status,
                               location=Location(path=f"{rule_id}.py", line=1, snippet="x"))
        finding.last_seen = when
        finding.fix = Fix(summary="fixed", applied_at=when)
        return finding

    def test_old_verified_findings_are_dropped(self):
        store = Store.open(self.root)
        store.put(self._aged(200, rule_id="old"))
        store.put(self._aged(5, rule_id="recent"))
        removed = store.prune(older_than_days=90)
        self.assertEqual(len(removed), 1)
        self.assertEqual(len(store), 1)

    def test_open_findings_are_never_pruned(self):
        store = Store.open(self.root)
        store.put(self._aged(500, status=models.OPEN, rule_id="open"))
        self.assertEqual(store.prune(older_than_days=1), [])

    def test_dismissals_are_only_pruned_when_asked(self):
        store = Store.open(self.root)
        store.put(self._aged(500, status=models.DISMISSED, rule_id="dismissed"))
        self.assertEqual(store.prune(older_than_days=1), [])
        self.assertEqual(len(store.prune(older_than_days=1, statuses=[models.DISMISSED])), 1)

    def test_an_unparseable_timestamp_is_left_alone(self):
        store = Store.open(self.root)
        finding = make_finding(status=models.VERIFIED)
        finding.last_seen = "not a date"
        finding.fix = Fix(summary="x", applied_at="also not a date")
        store.put(finding)
        self.assertEqual(store.prune(older_than_days=1), [])

    def test_scans_returns_the_history(self):
        store = Store.open(self.root)
        for index in range(3):
            store.record_scan({"total": index})
        self.assertEqual([entry["total"] for entry in store.scans()], [0, 1, 2])
