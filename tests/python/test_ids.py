import unittest

from . import _bootstrap  # noqa: F401
from redassay.ids import finding_id, normalize_snippet


class NormalizeSnippetTest(unittest.TestCase):
    def test_collapses_whitespace(self):
        self.assertEqual(normalize_snippet("  a   =  1\t"), "a = 1")

    def test_blanks_string_contents(self):
        a = normalize_snippet('password = "hunter2"')
        b = normalize_snippet('password = "hunter3"')
        self.assertEqual(a, b)

    def test_keeps_quote_style_distinct_from_code(self):
        self.assertNotEqual(normalize_snippet('x = "a"'), normalize_snippet("y = 'a'"))

    def test_empty_is_empty(self):
        self.assertEqual(normalize_snippet(""), "")


class FindingIdTest(unittest.TestCase):
    def test_is_stable(self):
        args = ("py.eval", "app/views.py", "eval(request.args['q'])")
        self.assertEqual(finding_id(*args), finding_id(*args))

    def test_ignores_indentation_changes(self):
        a = finding_id("py.eval", "app.py", "eval(x)")
        b = finding_id("py.eval", "app.py", "        eval(x)")
        self.assertEqual(a, b)

    def test_ignores_secret_rotation(self):
        a = finding_id("secret.aws", "cfg.py", 'KEY = "AKIA0000000000000000"')
        b = finding_id("secret.aws", "cfg.py", 'KEY = "AKIA1111111111111111"')
        self.assertEqual(a, b)

    def test_path_separators_are_normalized(self):
        self.assertEqual(
            finding_id("r", "a/b/c.py", "x"),
            finding_id("r", "a\\b\\c.py", "x"),
        )

    def test_different_rule_gives_different_id(self):
        self.assertNotEqual(finding_id("r1", "a.py", "x"), finding_id("r2", "a.py", "x"))

    def test_salt_separates_repeat_occurrences(self):
        self.assertNotEqual(finding_id("r", "a.py", "x"), finding_id("r", "a.py", "x", salt="2"))

    def test_is_twelve_hex_chars(self):
        value = finding_id("r", "a.py", "x")
        self.assertEqual(len(value), 12)
        int(value, 16)


if __name__ == "__main__":
    unittest.main()
