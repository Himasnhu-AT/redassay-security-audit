import unittest

from .helpers import TempRepo, make_finding
from redassay import suppress
from redassay.models import Location


class InlineParsingTest(unittest.TestCase):
    def test_hash_comment(self):
        parsed = suppress.parse_inline("x = eval(y)  # redassay: ignore code.python-eval-exec - trusted")
        self.assertEqual(parsed["rules"], ["code.python-eval-exec"])
        self.assertEqual(parsed["reason"], "trusted")

    def test_slash_comment(self):
        self.assertIsNotNone(suppress.parse_inline("// redassay: ignore js.eval-tainted"))

    def test_block_comment(self):
        self.assertIsNotNone(suppress.parse_inline("/* redassay: ignore js.eval-tainted */"))

    def test_html_comment(self):
        self.assertIsNotNone(suppress.parse_inline("<!-- redassay: disable xss.vue-v-html -->"))

    def test_multiple_rules(self):
        parsed = suppress.parse_inline("# redassay: ignore a.b,c.d")
        self.assertEqual(parsed["rules"], ["a.b", "c.d"])

    def test_bare_directive_covers_everything(self):
        self.assertEqual(suppress.parse_inline("# redassay: ignore")["rules"], ["*"])

    def test_non_directive_returns_none(self):
        self.assertIsNone(suppress.parse_inline("# just an ordinary comment"))
        self.assertIsNone(suppress.parse_inline(""))

    def test_glob_matching(self):
        self.assertTrue(suppress.inline_suppresses("# redassay: ignore secret.*", "secret.aws-access-key-id"))
        self.assertFalse(suppress.inline_suppresses("# redassay: ignore secret.*", "py.eval-dynamic"))


class SourcePositionTest(unittest.TestCase):
    LINES = [
        "value = 1",
        "# redassay: ignore py.eval-dynamic - controlled input",
        "eval(value)",
        "eval(other)",
    ]

    def test_comment_on_the_line_above_applies(self):
        self.assertTrue(suppress.suppressed_by_source(self.LINES, 3, "py.eval-dynamic"))

    def test_two_lines_below_does_not_apply(self):
        self.assertFalse(suppress.suppressed_by_source(self.LINES, 4, "py.eval-dynamic"))

    def test_trailing_comment_on_the_same_line_applies(self):
        lines = ["eval(x)  # redassay: ignore py.eval-dynamic"]
        self.assertTrue(suppress.suppressed_by_source(lines, 1, "py.eval-dynamic"))

    def test_out_of_range_is_safe(self):
        self.assertFalse(suppress.suppressed_by_source(self.LINES, 0, "x"))
        self.assertFalse(suppress.suppressed_by_source(self.LINES, 99, "x"))


class StoreSuppressionTest(unittest.TestCase):
    def test_exact_rule_and_path(self):
        finding = make_finding(rule_id="py.eval-dynamic", location=Location(path="app/x.py", line=1))
        rules = [{"rule_id": "py.eval-dynamic", "path": "app/*.py"}]
        self.assertTrue(suppress.is_suppressed(finding, rules))

    def test_wildcard_path(self):
        finding = make_finding(rule_id="py.eval-dynamic")
        self.assertTrue(suppress.is_suppressed(finding, [{"rule_id": "py.*", "path": "*"}]))

    def test_non_matching_path(self):
        finding = make_finding(rule_id="py.eval-dynamic", location=Location(path="lib/x.py", line=1))
        self.assertFalse(suppress.is_suppressed(finding, [{"rule_id": "py.eval-dynamic", "path": "app/*"}]))

    def test_empty_rule_list(self):
        self.assertFalse(suppress.is_suppressed(make_finding(), []))
        self.assertFalse(suppress.is_suppressed(make_finding(), None))

    def test_explain(self):
        lines = suppress.explain([{"rule_id": "a.b", "path": "x/*", "reason": "vendored"}])
        self.assertIn("vendored", lines[0])


class EndToEndSuppressionTest(TempRepo):
    """Both scanners see `os.system(x)`; triage keeps the AST one. Suppression
    has to work at whichever layer the surviving finding came from."""

    SOURCE = "import os\nos.system(user_input)\n"

    def test_ast_finding_is_suppressed_inline(self):
        self.write("app.py", self.SOURCE)
        self.assertIn("py.shell-dynamic", self.rule_ids())

        self.write("app.py", "import os\n# redassay: ignore py.shell-dynamic - literal command\nos.system(user_input)\n")
        self.assertNotIn("py.shell-dynamic", self.rule_ids())

    def test_pattern_finding_is_suppressed_inline(self):
        self.write("app.py", self.SOURCE)
        self.assertIn("cmd.os-system", self.rule_ids(disabled_scanners=["python-ast"]))

        self.write("app.py", "import os\n# redassay: ignore cmd.os-system - literal command\nos.system(user_input)\n")
        self.assertNotIn("cmd.os-system", self.rule_ids(disabled_scanners=["python-ast"]))

    def test_a_wildcard_directive_silences_every_rule_on_the_line(self):
        self.write("app.py", "import os\nos.system(user_input)  # redassay: ignore\n")
        self.assertEqual(self.rule_ids(), [])


if __name__ == "__main__":
    unittest.main()
