"""Regression tests for false positives found by running against real repositories.

Each case here was a finding redassay reported on an open-source project that a
human read and rejected. They are the most valuable tests in the suite: the
scanner's usefulness is bounded by its noise, not by its coverage.
"""

import unittest

from .helpers import run_scanner
from redassay.scanners.pattern import PatternScanner, sample_block_lines
from redassay.scanners.secrets import SecretScanner
from redassay.rules import load_all


def pattern_rules(path: str, content: str, language: str):
    return {f.rule_id for f in run_scanner(PatternScanner(), path, content, language)}


def secret_findings(path: str, content: str, language: str):
    return run_scanner(SecretScanner(), path, content, language)


class MarkupSampleTest(unittest.TestCase):
    """A tutorial page documenting an eval() call was reported as an eval() call."""

    TUTORIAL = """<html><body>
<p>The handler insecurely uses <code>eval()</code> to parse input.</p>
<pre>
    var preTax = eval(req.body.preTax);
    var afterTax = eval(req.body.afterTax);
</pre>
<p>Fix it with parseInt().</p>
</body></html>
"""

    def test_code_in_a_pre_block_is_documentation(self):
        self.assertNotIn("code.js-eval", pattern_rules("docs/a1.html", self.TUTORIAL, "html"))

    def test_real_inline_script_is_still_scanned(self):
        page = '<html><script>eval(location.hash.slice(1));</script></html>\n'
        self.assertIn("code.js-eval", pattern_rules("app/index.html", page, "html"))

    def test_markdown_fences_are_documentation(self):
        doc = "# Guide\n\n```js\neval(userInput);\n```\n\nDo not do that.\n"
        self.assertNotIn("code.js-eval", pattern_rules("README.md", doc, "markdown"))

    def test_sample_block_lines_tracks_nesting(self):
        lines = ["<pre>", "code", "</pre>", "outside", "<code>x</code>", "outside"]
        inside = sample_block_lines(lines, "html")
        self.assertEqual(inside & {1, 2, 3}, {1, 2, 3})
        self.assertNotIn(4, inside)
        self.assertNotIn(6, inside)

    def test_python_is_unaffected(self):
        self.assertEqual(sample_block_lines(["eval(x)"], "python"), set())


class WeakRandomProximityTest(unittest.TestCase):
    """A date helper was flagged because an unrelated function two lines below
    took a `password` argument."""

    DATE_HELPER = """
this.getRandomFutureDate = () => {
    const today = new Date();
    const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
    const year = Math.ceil(Math.random() * 30) + today.getFullYear();
    return `${year}-${day}`;
};

this.validateLogin = (userName, password, callback) => {
"""

    def test_a_date_helper_near_a_login_function_is_not_a_crypto_finding(self):
        self.assertNotIn("crypto.weak-random-security",
                         pattern_rules("app/data/user-dao.js", self.DATE_HELPER, "javascript"))

    def test_a_token_generated_from_math_random_is_still_flagged(self):
        code = "const sessionToken = Math.random().toString(36).slice(2);\n"
        self.assertIn("crypto.weak-random-security", pattern_rules("app/auth.js", code, "javascript"))

    def test_a_password_reset_code_is_still_flagged(self):
        code = "def reset_code():\n    return random.randint(100000, 999999)  # password reset\n"
        self.assertIn("crypto.weak-random-security", pattern_rules("app/auth.py", code, "python"))


class ProseDowngradeTest(unittest.TestCase):
    """A connection string in a README was reported at the same severity as one
    in a settings module."""

    LINE = 'Connect with `mongodb://admin:Passw0rd123@localhost:27017/goat`\n'

    def test_a_connection_string_in_a_readme_is_downgraded(self):
        findings = secret_findings("README.md", self.LINE, "markdown")
        self.assertTrue(findings)
        self.assertEqual(findings[0].confidence, "low")
        self.assertNotEqual(findings[0].severity, "high")

    def test_the_same_string_in_source_keeps_full_severity(self):
        source = 'DSN = "mongodb://admin:Passw0rd123@localhost:27017/goat"\n'
        findings = secret_findings("app/settings.py", source, "python")
        self.assertTrue(findings)
        self.assertEqual(findings[0].confidence, "high")

    def test_it_is_downgraded_not_silenced(self):
        self.assertTrue(secret_findings("README.md", self.LINE, "markdown"))


class KnownSafePatternTest(unittest.TestCase):
    """Shapes that look dangerous and are not. Each one was reported once."""

    def test_literal_subprocess_without_shell(self):
        code = "import subprocess\nsubprocess.run(['git', 'status'], check=True)\n"
        self.assertEqual(pattern_rules("app.py", code, "python") & {"cmd.shell-true", "cmd.os-system"}, set())

    def test_parameterized_sql_is_not_concatenation(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        self.assertNotIn("sql.string-concat-query", pattern_rules("db.py", code, "python"))

    def test_ast_literal_eval_is_not_eval(self):
        code = "import ast\nvalue = ast.literal_eval(payload)\n"
        self.assertNotIn("code.python-eval-exec", pattern_rules("app.py", code, "python"))

    def test_yaml_safe_load(self):
        code = "import yaml\nconfig = yaml.safe_load(stream)\n"
        self.assertNotIn("deser.yaml-unsafe-load", pattern_rules("app.py", code, "python"))

    def test_a_commented_out_vulnerability_is_not_live_code(self):
        code = "# subprocess.run(cmd, shell=True)\nsubprocess.run(['ls'])\n"
        self.assertNotIn("cmd.shell-true", pattern_rules("app.py", code, "python"))

    def test_a_proximity_rule_does_not_read_commented_code(self):
        code = "# nearby mentions password here\nchecksum = hashlib.md5(data).hexdigest()\n"
        self.assertNotIn("crypto.weak-hash-password", pattern_rules("app.py", code, "python"))

    def test_an_env_backed_secret_is_not_hardcoded(self):
        code = 'SECRET_KEY = os.environ["SECRET_KEY"]\n'
        self.assertEqual(secret_findings("settings.py", code, "python"), [])

    def test_a_docstring_mentioning_eval_is_not_a_call(self):
        code = 'def parse(x):\n    """Safer than eval(x) - uses literal_eval."""\n    return ast.literal_eval(x)\n'
        self.assertNotIn("code.python-eval-exec", pattern_rules("app.py", code, "python"))


class RuleCoverageTest(unittest.TestCase):
    def test_every_rule_that_uses_nearby_bounds_the_window(self):
        """An unbounded proximity window is how this class of bug happens."""
        for rule in load_all():
            if rule.get("nearby") or rule.get("nearby_absent"):
                self.assertLessEqual(rule.get("nearby_window", 4), 6, rule["id"])


if __name__ == "__main__":
    unittest.main()


class ConstantTimeCompareTest(unittest.TestCase):
    """Found by redassay scanning itself: a regex parser comparing a parse
    `token` against `"\\\\"` was reported as a non-constant-time secret check."""

    def test_a_parser_comparing_short_literals_is_not_a_signature_check(self):
        code = (
            "for token in pattern:\n"
            '    if token == "\\\\":\n'
            '        escaped = True\n'
            '    elif token == "[":\n'
            "        in_class = True\n"
        )
        self.assertNotIn("crypto.constant-time-compare",
                         pattern_rules("engine/parser.py", code, "python"))

    def test_a_real_signature_comparison_is_still_flagged(self):
        code = (
            "def verify(body, signature):\n"
            "    expected = hmac.new(KEY, body, hashlib.sha256).hexdigest()\n"
            "    return expected == signature\n"
        )
        self.assertIn("crypto.constant-time-compare",
                      pattern_rules("app/auth.py", code, "python"))

    def test_compare_digest_is_accepted(self):
        code = (
            "def verify(body, signature):\n"
            "    expected = hmac.new(KEY, body, hashlib.sha256).hexdigest()\n"
            "    return hmac.compare_digest(expected, signature)\n"
        )
        self.assertNotIn("crypto.constant-time-compare",
                         pattern_rules("app/auth.py", code, "python"))
