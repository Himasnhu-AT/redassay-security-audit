"""The call-graph bridge.

Two properties matter more than the feature itself: it must be *optional* -
absent tooling changes nothing - and it must never turn "this graph found no
path" into "nothing can reach this". The second is the failure that would make
a reviewer skip a live vulnerability.
"""

from __future__ import annotations

import unittest
from unittest import mock

from .helpers import TempRepo
from redassay import callgraph
from redassay.callgraph import CallGraph, Reachability, Symbol, _parse_span, _symbol


class Entry:
    """Stands in for a surface.EntryPoint."""

    def __init__(self, path, line, label="POST /x"):
        self.path = path
        self.line = line
        self.label = label


class SpanParsingTest(unittest.TestCase):
    def test_a_range(self):
        self.assertEqual(_parse_span("L77-L112"), (77, 112))

    def test_a_single_line(self):
        self.assertEqual(_parse_span("L42-L42"), (42, 42))

    def test_junk_is_zero_not_an_exception(self):
        self.assertEqual(_parse_span("nonsense"), (0, 0))
        self.assertEqual(_parse_span(""), (0, 0))

    def test_symbol_construction(self):
        symbol = _symbol({"id": "a#b", "name": "b", "kind": "method",
                          "path": "a.py", "span": "L3-L9"})
        self.assertEqual((symbol.start, symbol.end), (3, 9))
        self.assertTrue(symbol.contains("a.py", 5))
        self.assertFalse(symbol.contains("a.py", 10))
        self.assertFalse(symbol.contains("other.py", 5))


class OptionalityTest(TempRepo):
    """The zero-dependency promise is not negotiable for a convenience."""

    def test_absent_tool_disables_cleanly(self):
        with mock.patch.object(callgraph.shutil, "which", return_value=None):
            graph = CallGraph(self.root)
        self.assertFalse(graph.enabled)
        self.assertIn("not installed", graph.reason)
        self.assertEqual(graph.callers("anything"), [])
        self.assertEqual(graph.symbols_in("a.py"), [])

    def test_absent_index_disables_cleanly(self):
        with mock.patch.object(callgraph.shutil, "which", return_value="/usr/bin/graft"):
            graph = CallGraph(self.root)
        self.assertFalse(graph.enabled)
        self.assertIn("build", graph.reason)

    def test_a_disabled_graph_reports_unknown_never_unreachable(self):
        with mock.patch.object(callgraph.shutil, "which", return_value=None):
            graph = CallGraph(self.root)
        result = graph.reaches("a.py", 1, [])
        self.assertEqual(result.status, "unknown")
        self.assertFalse(result.is_reachable)

    def test_a_crashing_tool_is_not_fatal(self):
        with mock.patch.object(callgraph.shutil, "which", return_value="/usr/bin/graft"), \
             mock.patch.object(callgraph, "_run", side_effect=OSError("boom")):
            graph = CallGraph(self.root)
            graph.enabled = True
            with self.assertRaises(OSError):
                graph.callers("x")      # the mock raises; _run itself swallows

    def test_malformed_output_yields_nothing(self):
        with mock.patch.object(callgraph.shutil, "which", return_value="/usr/bin/graft"), \
             mock.patch.object(callgraph, "_run", return_value=None):
            graph = CallGraph(self.root)
            graph.enabled = True
            self.assertEqual(graph.callers("x"), [])


class ReachabilityLanguageTest(unittest.TestCase):
    """What each status is allowed to claim."""

    def test_no_path_does_not_claim_unreachable(self):
        text = Reachability(status="no-path").describe()
        self.assertIn("not proof", text)

    def test_reachable_names_the_entry_point_and_the_chain(self):
        chain = [Symbol("a#f", "handler", "function", "a.py", 1, 5),
                 Symbol("b#g", "sink", "function", "b.py", 2, 6)]
        text = Reachability(status="reachable", entry_point="POST /x",
                            chain=chain, depth=1).describe()
        self.assertIn("POST /x", text)
        self.assertIn("handler -> sink", text)

    def test_unknown_carries_its_reason(self):
        self.assertIn("no index", Reachability(status="unknown", note="no index").describe())

    def test_only_reachable_is_reachable(self):
        for status in ("no-path", "unknown"):
            self.assertFalse(Reachability(status=status).is_reachable)
        self.assertTrue(Reachability(status="reachable").is_reachable)

    def test_it_serializes(self):
        import json
        json.dumps(Reachability(status="reachable", chain=[
            Symbol("a#f", "f", "function", "a.py", 1, 2)]).to_dict())


class ReachesTest(TempRepo):
    """The decision logic, with the graph stubbed so the test does not need one."""

    def _graph(self, symbols, callers):
        graph = CallGraph(self.root)
        graph.enabled = True
        graph.reason = ""
        graph._symbols_by_file = symbols
        graph._callers = callers
        return graph

    def test_an_entry_point_inside_the_symbol_needs_no_edge(self):
        target = Symbol("v#handler", "handler", "function", "views.py", 5, 12)
        graph = self._graph({"views.py": [target]}, {})
        result = graph.reaches("views.py", 8, [Entry("views.py", 6)])
        self.assertTrue(result.is_reachable)
        self.assertEqual(result.depth, 0)

    def test_a_caller_in_an_entry_point_file_is_a_path(self):
        target = Symbol("d#sink", "sink", "function", "db.py", 1, 9)
        caller = Symbol("v#report", "report", "function", "views.py", 4, 10)
        graph = self._graph({"db.py": [target]}, {"sink@4": [caller]})
        result = graph.reaches("db.py", 3, [Entry("views.py", 5, "POST /report")])
        self.assertTrue(result.is_reachable)
        self.assertEqual(result.entry_point, "POST /report")
        self.assertEqual([s.name for s in result.chain], ["report", "sink"])

    def test_callers_that_touch_no_entry_point_file_are_no_path(self):
        target = Symbol("d#sink", "sink", "function", "db.py", 1, 9)
        caller = Symbol("w#worker", "worker", "function", "worker.py", 1, 5)
        graph = self._graph({"db.py": [target]}, {"sink@4": [caller]})
        result = graph.reaches("db.py", 3, [Entry("views.py", 5)])
        self.assertEqual(result.status, "no-path")

    def test_zero_callers_is_no_path_not_unknown(self):
        """The graph knows the symbol and found nothing pointing at it - weaker
        than proof, but a real observation."""
        target = Symbol("d#dead", "dead", "function", "db.py", 1, 9)
        graph = self._graph({"db.py": [target]}, {"dead@4": []})
        result = graph.reaches("db.py", 3, [Entry("views.py", 5)])
        self.assertEqual(result.status, "no-path")
        self.assertIn("records no callers", result.note)

    def test_a_line_no_symbol_covers_is_unknown(self):
        graph = self._graph({"db.py": []}, {})
        result = graph.reaches("db.py", 3, [Entry("views.py", 5)])
        self.assertEqual(result.status, "unknown")

    def test_the_smallest_enclosing_symbol_wins(self):
        outer = Symbol("a#Class", "Class", "class", "a.py", 1, 50)
        inner = Symbol("a#Class.method", "method", "method", "a.py", 10, 20)
        graph = self._graph({"a.py": [outer, inner]}, {})
        self.assertEqual(graph.enclosing("a.py", 15).name, "method")

    def test_the_query_budget_is_enforced(self):
        graph = CallGraph(self.root)
        graph.enabled = True
        graph.queries = callgraph.MAX_QUERIES
        self.assertEqual(graph.callers("anything"), [])
        self.assertEqual(graph.symbols_in("a.py"), [])


if __name__ == "__main__":
    unittest.main()
