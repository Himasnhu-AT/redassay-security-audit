import json
import os
import re
import sys
import unittest

from . import _bootstrap  # noqa: F401
from redassay import rules as rule_packs
from redassay import severity as sev
from redassay.scanners.pattern import PatternScanner, compile_rules, inside_string, string_spans


class PackIntegrityTest(unittest.TestCase):
    """The rule packs are data, so these are the schema checks a linter would do."""

    @classmethod
    def setUpClass(cls):
        cls.rules = rule_packs.load_all()

    def test_packs_load(self):
        self.assertGreater(len(self.rules), 50)

    def test_every_regex_compiles(self):
        compile_rules(self.rules)          # raises on a bad pattern

    def test_ids_are_unique(self):
        ids = [rule["id"] for rule in self.rules]
        duplicates = {rule_id for rule_id in ids if ids.count(rule_id) > 1}
        self.assertEqual(duplicates, set())

    def test_ids_follow_the_namespace_convention(self):
        for rule in self.rules:
            self.assertRegex(rule["id"], r"^[a-z0-9]+\.[a-z0-9-]+$", rule["id"])

    def test_severities_are_canonical(self):
        for rule in self.rules:
            self.assertIn(sev.normalize(rule.get("severity")), sev.ORDER, rule["id"])
            self.assertEqual(rule.get("severity", "medium"), sev.normalize(rule.get("severity")), rule["id"])

    def test_every_rule_explains_itself(self):
        for rule in self.rules:
            self.assertTrue(rule.get("description"), f"{rule['id']} has no description")
            self.assertTrue(rule.get("remediation"), f"{rule['id']} has no remediation")

    def test_descriptions_are_written_for_a_human(self):
        for rule in self.rules:
            self.assertGreater(len(rule["description"]), 40, rule["id"])

    def test_every_rule_carries_a_cwe(self):
        for rule in self.rules:
            self.assertTrue(rule.get("cwe"), f"{rule['id']} has no CWE")
            for cwe in rule["cwe"]:
                self.assertRegex(cwe, r"^CWE-\d+$", rule["id"])

    def test_owasp_tags_look_right(self):
        for rule in self.rules:
            for entry in rule.get("owasp") or []:
                self.assertRegex(entry, r"^A\d{2}:2021 ", rule["id"])

    def test_no_inline_global_flags(self):
        """(?i) mid-pattern is a hard error in Python 3.11+; use ignore_case."""
        for rule in self.rules:
            for key in ("pattern", "not_pattern", "nearby", "nearby_absent"):
                value = rule.get(key)
                if value:
                    self.assertNotIn("(?i)", value, f"{rule['id']}.{key}")

    def test_languages_are_known(self):
        from redassay import languages
        known = (languages.SOURCE_LANGUAGES | languages.CONFIG_LANGUAGES
                 | languages.MANIFESTS | {"*", "markdown", "text", "make", "nginx", "apache"})
        for rule in self.rules:
            for language in rule.get("languages") or []:
                self.assertIn(language, known, f"{rule['id']} targets unknown language {language}")


class PackLoadingTest(unittest.TestCase):
    def test_defaults_are_merged_into_each_rule(self):
        path = os.path.join(rule_packs.PACK_DIR, "xss.json")
        for rule in rule_packs.load_pack(path):
            self.assertIn("CWE-79", rule["cwe"])

    def test_pack_name_is_attached(self):
        path = os.path.join(rule_packs.PACK_DIR, "injection.json")
        self.assertEqual(rule_packs.load_pack(path)[0]["pack"], "injection")

    def test_a_rule_missing_a_required_field_is_rejected(self):
        import tempfile
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "bad.json")
        json.dump({"rules": [{"id": "x.y", "title": "no pattern"}]}, open(path, "w"))
        with self.assertRaises(rule_packs.RuleError):
            rule_packs.load_pack(path)

    def test_a_user_pack_overrides_a_builtin_id(self):
        import tempfile
        directory = tempfile.mkdtemp()
        json.dump(
            {"rules": [{"id": "sql.fstring-query", "title": "overridden", "pattern": "zzz",
                        "description": "x" * 50, "remediation": "y", "cwe": ["CWE-89"]}]},
            open(os.path.join(directory, "custom.json"), "w"),
        )
        merged = rule_packs.load_all([directory])
        matches = [r for r in merged if r["id"] == "sql.fstring-query"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["title"], "overridden")

    def test_by_language_filters(self):
        rules = [{"id": "a", "languages": ["python"]}, {"id": "b", "languages": []},
                 {"id": "c", "languages": ["*"]}]
        self.assertEqual({r["id"] for r in rule_packs.by_language(rules, "python")}, {"a", "b", "c"})
        self.assertEqual({r["id"] for r in rule_packs.by_language(rules, "go")}, {"b", "c"})


class StringSpanTest(unittest.TestCase):
    def test_finds_double_and_single_quoted_spans(self):
        self.assertEqual(len(string_spans('a = "x" + \'y\'')), 2)

    def test_escaped_quotes_do_not_end_a_span(self):
        self.assertEqual(len(string_spans(r'a = "he said \"hi\""')), 1)

    def test_inside_string(self):
        line = 'assert snippet == "eval(x)"'
        self.assertTrue(inside_string(string_spans(line), line.index("eval")))
        self.assertFalse(inside_string(string_spans(line), line.index("assert")))


class PatternScannerBehaviourTest(unittest.TestCase):
    def _scan(self, rule, content, language="python", path="a.py"):
        from .helpers import run_scanner
        base = {"description": "x" * 50, "remediation": "fix it", "cwe": ["CWE-1"]}
        base.update(rule)
        return run_scanner(PatternScanner(rules=[base]), path, content, language)

    def test_a_plain_match(self):
        found = self._scan({"id": "t.x", "title": "t", "pattern": "danger"}, "value = danger\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].line, 1)

    def test_not_pattern_suppresses(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "not_pattern": "safe"}
        self.assertEqual(self._scan(rule, "danger # safe\n"), [])

    def test_nearby_is_required_when_set(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "nearby": "trigger", "nearby_window": 2}
        self.assertEqual(self._scan(rule, "danger\n"), [])
        self.assertEqual(len(self._scan(rule, "trigger\ndanger\n")), 1)

    def test_nearby_window_is_respected(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "nearby": "trigger", "nearby_window": 1}
        self.assertEqual(self._scan(rule, "trigger\n\n\ndanger\n"), [])

    def test_nearby_absent_blocks_the_match(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "nearby_absent": "guard", "nearby_window": 2}
        self.assertEqual(self._scan(rule, "guard\ndanger\n"), [])

    def test_comment_lines_are_skipped_by_default(self):
        self.assertEqual(self._scan({"id": "t.x", "title": "t", "pattern": "danger"}, "# danger\n"), [])

    def test_match_comments_opts_back_in(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "match_comments": True}
        self.assertEqual(len(self._scan(rule, "# danger\n")), 1)

    def test_skip_in_strings(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "skip_in_strings": True}
        self.assertEqual(self._scan(rule, 'msg = "danger"\n'), [])
        self.assertEqual(len(self._scan(rule, "danger()\n")), 1)

    def test_language_scoping(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "languages": ["go"]}
        self.assertEqual(self._scan(rule, "danger\n"), [])

    def test_path_exclusion(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "path_exclude": ["tests/*"]}
        self.assertEqual(self._scan(rule, "danger\n", path="tests/a.py"), [])

    def test_max_matches_caps_the_noise(self):
        rule = {"id": "t.x", "title": "t", "pattern": "danger", "max_matches": 3}
        self.assertEqual(len(self._scan(rule, "danger\n" * 20)), 3)

    def test_repeat_matches_get_distinct_ids(self):
        found = self._scan({"id": "t.x", "title": "t", "pattern": "danger"}, "danger\ndanger\n")
        self.assertEqual(len({f.id for f in found}), 2)

    def test_very_long_lines_are_skipped(self):
        content = "x" * 2500 + "danger\n"
        self.assertEqual(self._scan({"id": "t.x", "title": "t", "pattern": "danger"}, content), [])


if __name__ == "__main__":
    unittest.main()


class GeneratedDocsTest(unittest.TestCase):
    """The rule catalogue is generated. A stale one is a lie about what runs."""

    def test_docs_are_current(self):
        import subprocess
        script = os.path.join(_bootstrap.ROOT, "tools", "generate_rule_docs.py")
        result = subprocess.run(
            [sys.executable, script, "--check"],
            capture_output=True, text=True, cwd=_bootstrap.ROOT, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class InsideStringSpanTest(unittest.TestCase):
    """A pattern that includes the surrounding quotes starts *at* the quote, not
    inside it - so testing only the first character let it read as code."""

    def _spans(self, line):
        from redassay.scanners.pattern import string_spans
        return string_spans(line)

    def test_a_match_that_includes_the_quotes_is_still_inside(self):
        from redassay.scanners.pattern import inside_string
        line = 'sample = "0.0.0.0:8080:80"'
        spans = self._spans(line)
        start = line.index('"')
        end = line.index('"', start + 1) + 1
        self.assertTrue(inside_string(spans, start, end))

    def test_a_match_outside_every_span_is_not_inside(self):
        from redassay.scanners.pattern import inside_string
        line = 'host = "x"  # 0.0.0.0'
        spans = self._spans(line)
        index = line.rindex("0.0.0.0")
        self.assertFalse(inside_string(spans, index, index + 7))

    def test_a_match_spanning_out_of_a_string_is_not_inside(self):
        from redassay.scanners.pattern import inside_string
        line = 'a = "abc" + danger'
        spans = self._spans(line)
        self.assertFalse(inside_string(spans, 5, len(line)))

    def test_the_single_index_form_still_works(self):
        from redassay.scanners.pattern import inside_string
        line = 'msg = "eval(x)"'
        self.assertTrue(inside_string(self._spans(line), line.index("eval")))
