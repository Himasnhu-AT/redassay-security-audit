import os
import unittest

from .helpers import TempRepo
from redassay import queue as queue_mod
from redassay.queue import Action, ActionQueue


class QueueBasicsTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.queue = ActionQueue(self.root)

    def test_empty_queue_reads_as_empty(self):
        self.assertEqual(self.queue.all(), [])
        self.assertEqual(self.queue.pending(), [])

    def test_push_assigns_increasing_sequence_numbers(self):
        first = self.queue.push(queue_mod.FIX, "abc")
        second = self.queue.push(queue_mod.COMMENT, "abc", body="hi")
        self.assertEqual((first.seq, second.seq), (1, 2))

    def test_the_file_is_append_only_jsonl(self):
        self.queue.push(queue_mod.FIX, "abc")
        self.queue.push(queue_mod.FIX, "def")
        with open(self.queue.path, encoding="utf-8") as handle:
            self.assertEqual(len([line for line in handle if line.strip()]), 2)

    def test_payload_survives_the_round_trip(self):
        self.queue.push(queue_mod.FIX, "abc", note="keep the public API")
        self.assertEqual(self.queue.all()[0].payload["note"], "keep the public API")

    def test_a_corrupt_line_is_skipped_not_fatal(self):
        self.queue.push(queue_mod.FIX, "abc")
        with open(self.queue.path, "a", encoding="utf-8") as handle:
            handle.write("{this is not json\n")
        self.queue.push(queue_mod.FIX, "def")
        self.assertEqual(len(self.queue.all()), 2)


class AgentActionTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.queue = ActionQueue(self.root)

    def test_only_agent_kinds_are_pending_by_default(self):
        self.queue.push(queue_mod.COMMENT, "a", body="note")
        self.queue.push(queue_mod.FIX, "b")
        pending = self.queue.pending()
        self.assertEqual([a.kind for a in pending], [queue_mod.FIX])

    def test_including_settled_kinds_shows_everything(self):
        self.queue.push(queue_mod.COMMENT, "a", body="note")
        self.assertEqual(len(self.queue.pending(agent_only=False)), 1)

    def test_claim_marks_and_returns(self):
        self.queue.push(queue_mod.FIX, "a")
        claimed = self.queue.claim()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(self.queue.all()[0].state, queue_mod.CLAIMED)

    def test_claiming_twice_yields_nothing_the_second_time(self):
        self.queue.push(queue_mod.FIX, "a")
        self.queue.claim()
        self.assertEqual(self.queue.claim(), [])

    def test_claim_respects_a_limit(self):
        for index in range(3):
            self.queue.push(queue_mod.FIX, f"f{index}")
        self.assertEqual(len(self.queue.claim(limit=2)), 2)
        self.assertEqual(len(self.queue.pending()), 1)

    def test_complete(self):
        action = self.queue.push(queue_mod.FIX, "a")
        self.queue.claim()
        self.queue.complete(action.seq, result="parameterized the query")
        stored = self.queue.get(action.seq)
        self.assertEqual(stored.state, queue_mod.DONE)
        self.assertEqual(stored.result, "parameterized the query")
        self.assertTrue(stored.completed_at)

    def test_complete_can_record_failure(self):
        action = self.queue.push(queue_mod.FIX, "a")
        self.queue.claim()
        self.queue.complete(action.seq, result="no safe fix", state=queue_mod.FAILED)
        self.assertEqual(self.queue.get(action.seq).state, queue_mod.FAILED)

    def test_release_returns_an_action_to_the_queue(self):
        action = self.queue.push(queue_mod.FIX, "a")
        self.queue.claim()
        self.queue.release(action.seq)
        self.assertEqual(len(self.queue.pending()), 1)

    def test_release_only_affects_claimed_actions(self):
        action = self.queue.push(queue_mod.FIX, "a")
        self.assertIsNone(self.queue.release(action.seq))

    def test_completing_an_unknown_sequence_returns_none(self):
        self.assertIsNone(self.queue.complete(999))


class DescribeTest(unittest.TestCase):
    def test_fix(self):
        self.assertEqual(Action(kind=queue_mod.FIX, finding_id="abc").describe(), "fix abc")

    def test_fix_all(self):
        action = Action(kind=queue_mod.FIX_ALL, payload={"finding_ids": ["a", "b", "c"]})
        self.assertEqual(action.describe(), "fix 3 findings")

    def test_status(self):
        action = Action(kind=queue_mod.STATUS, finding_id="abc", payload={"status": "dismissed"})
        self.assertEqual(action.describe(), "set abc -> dismissed")

    def test_rescan(self):
        self.assertEqual(Action(kind=queue_mod.RESCAN).describe(), "rescan the repository")

    def test_needs_agent(self):
        self.assertTrue(Action(kind=queue_mod.FIX).needs_agent)
        self.assertFalse(Action(kind=queue_mod.COMMENT).needs_agent)


class StatsTest(TempRepo):
    def test_counts_by_state(self):
        queue = ActionQueue(self.root)
        queue.push(queue_mod.FIX, "a")
        queue.push(queue_mod.FIX, "b")
        queue.claim(limit=1)
        stats = queue.stats()
        self.assertEqual(stats[queue_mod.PENDING], 1)
        self.assertEqual(stats[queue_mod.CLAIMED], 1)

    def test_clear(self):
        queue = ActionQueue(self.root)
        queue.push(queue_mod.FIX, "a")
        self.assertEqual(queue.clear(), 1)
        self.assertEqual(queue.all(), [])


if __name__ == "__main__":
    unittest.main()
