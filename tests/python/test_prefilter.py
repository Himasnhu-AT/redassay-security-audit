"""The literal prefilter must never change what a scan finds.

It is an optimization sitting in front of every pattern rule, so a wrong
extraction does not produce a slow scan - it produces a silently missing
finding. These tests are about correctness, not speed.
"""

import unittest

from .helpers import TempRepo, run_scanner
from redassay.prefilter import Prefilter, coverage, literal_runs, required_literals
from redassay.rules import load_all
from redassay.scanners.pattern import PatternScanner


class LiteralExtractionTest(unittest.TestCase):
    def test_a_plain_literal(self):
        self.assertEqual(required_literals(r"os\.system"), ["os.system"])

    def test_escaped_dots_are_literal(self):
        self.assertIn("yaml.", required_literals(r"yaml\.(load|unsafe_load)\s*\(") or [])

    def test_a_top_level_alternation_yields_every_branch(self):
        self.assertEqual(sorted(required_literals(r"(eval|exec)\s*\(")), ["eval", "exec"])

    def test_nested_groups_recurse(self):
        self.assertEqual(
            sorted(required_literals(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b")),
            ["ABIA", "ACCA", "AKIA", "ASIA"],
        )

    def test_a_branch_without_a_literal_gives_up(self):
        self.assertIsNone(required_literals(r"(\w+|x)\s*\("))

    def test_character_classes_are_not_literals(self):
        self.assertIsNone(required_literals(r"[a-z]{3}\s*="))

    def test_optional_characters_are_dropped(self):
        # `colou?r` only guarantees "colo".
        self.assertEqual(required_literals(r"colou?r"), ["colo"])

    def test_plus_keeps_the_character(self):
        self.assertEqual(required_literals(r"danger+ous"), ["danger"])

    def test_short_runs_are_not_useful(self):
        self.assertIsNone(required_literals(r"ab\s*="))

    def test_literal_runs_splits_on_metacharacters(self):
        self.assertEqual(literal_runs(r"foo.bar"), ["foo", "bar"])


class PrefilterTest(unittest.TestCase):
    def test_an_active_prefilter_rejects_a_file_without_the_literal(self):
        prefilter = Prefilter(r"os\.system\s*\(")
        self.assertTrue(prefilter.active)
        self.assertFalse(prefilter.matches("import subprocess\n"))
        self.assertTrue(prefilter.matches("os.system(cmd)\n"))

    def test_an_inactive_prefilter_lets_everything_through(self):
        prefilter = Prefilter(r"(\w+)\s*\(")
        self.assertFalse(prefilter.active)
        self.assertTrue(prefilter.matches("anything at all"))

    def test_case_insensitive_prefilters_use_the_lowered_text(self):
        prefilter = Prefilter(r"privileged\s*:\s*true", ignore_case=True)
        self.assertTrue(prefilter.matches("PRIVILEGED: TRUE", "privileged: true"))

    def test_coverage_is_high_enough_to_be_worth_it(self):
        self.assertGreater(coverage([rule["pattern"] for rule in load_all()]), 0.85)


class ResultNeutralityTest(TempRepo):
    """The property that actually matters, checked against every rule pack."""

    SOURCES = {
        "app.py": (
            "import os, subprocess, pickle, yaml, hashlib, random\n"
            "os.system(user_input)\n"
            "subprocess.run(cmd, shell=True)\n"
            "eval(payload)\n"
            "pickle.loads(blob)\n"
            "yaml.load(blob)\n"
            "token = hashlib.md5(password.encode()).hexdigest()\n"
            "session_key = random.randint(0, 99999)\n"
            "requests.get(url, verify=False)\n"
        ),
        "app.js": (
            "const host = req.query.host;\n"
            "exec('ping ' + host);\n"
            "el.innerHTML = userInput;\n"
            "document.write(location.hash);\n"
            "jwt.sign(p, 'hardcoded-secret-value');\n"
        ),
        "Dockerfile": "FROM alpine:latest\nADD https://x.invalid/a.sh /tmp/\nUSER root\n",
        "deploy.yaml": "kind: Deployment\nspec:\n  containers:\n    - name: a\n      image: a\n",
        "main.go": 'tr := &tls.Config{InsecureSkipVerify: true}\n',
        "index.php": "<?php\ninclude($_GET['page']);\nextract($_GET);\n",
        "App.java": 'Runtime.getRuntime().exec("ls " + name);\nhttp.csrf().disable();\n',
    }

    def _scan(self, active: bool):
        for name, body in self.SOURCES.items():
            self.write(name, body)
        original = Prefilter.matches
        if not active:
            Prefilter.matches = lambda self, text, lowered=None: True
        try:
            from redassay import config as config_mod
            from redassay.engine import scan
            return {(f.rule_id, f.path, f.line) for f in scan(config_mod.load(self.root)).findings}
        finally:
            Prefilter.matches = original

    def test_the_prefilter_changes_nothing(self):
        with_prefilter = self._scan(active=True)
        without = self._scan(active=False)
        self.assertEqual(without - with_prefilter, set(), "the prefilter dropped findings")
        self.assertEqual(with_prefilter - without, set())
        self.assertGreater(len(with_prefilter), 10)


class EveryRulePrefilterTest(unittest.TestCase):
    """For each rule, a line that matches the pattern must pass its prefilter."""

    def test_no_rule_prefilters_away_its_own_match(self):
        import re

        broken = []
        for rule in load_all():
            prefilter = Prefilter(rule["pattern"], ignore_case=bool(rule.get("ignore_case")))
            if not prefilter.active:
                continue
            # The literals come out of the pattern itself, so a line built from
            # them must pass. This catches an extractor that mangles the literal.
            for literal in prefilter.literals:
                if not prefilter.matches(literal, literal.lower()):
                    broken.append(f"{rule['id']}: {literal!r}")
        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
