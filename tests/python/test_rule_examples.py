"""Each rule carries its own samples, and this runs them.

A rule pack is data, so nothing type-checks it and nothing notices when a regex
tightened to kill a false positive stops matching the true positive it was
written for. Fixture files catch that for a few dozen rules; carrying the sample
*inside* the rule catches it for all of them, and the sample cannot drift from
the pattern because they are edited together.

    "examples":        lines the rule must match
    "counterexamples": lines it must not
"""

from __future__ import annotations

import unittest
from typing import Dict, List

from .helpers import run_scanner
from redassay.rules import load_all
from redassay.scanners.pattern import PatternScanner

#: File extension to use when a rule names a language, so the scanner's
#: language detection agrees with what the rule targets.
SUFFIX = {
    "python": "py", "javascript": "js", "typescript": "ts", "ruby": "rb",
    "php": "php", "go": "go", "java": "java", "kotlin": "kt", "scala": "scala",
    "csharp": "cs", "rust": "rs", "c": "c", "cpp": "cpp", "swift": "swift",
    "shell": "sh", "powershell": "ps1", "sql": "sql", "html": "html",
    "vue": "vue", "svelte": "svelte", "yaml": "yaml", "json": "json",
    "toml": "toml", "ini": "ini", "xml": "xml", "terraform": "tf",
    "markdown": "md", "text": "txt",
}

SPECIAL_NAME = {
    "dockerfile": "Dockerfile",
    "compose": "docker-compose.yml",
    "dotenv": ".env",
    "make": "Makefile",
    "nginx": "nginx.conf",
    "apache": ".htaccess",
    "npm-manifest": "package.json",
}


def _path_for(rule: Dict) -> str:
    languages = rule.get("languages") or []
    for language in languages:
        if language in SPECIAL_NAME:
            return "app/" + SPECIAL_NAME[language] if language != "dotenv" else ".env"
        if language in SUFFIX:
            return f"app/sample.{SUFFIX[language]}"
    return "app/sample.py"


def _language_for(rule: Dict) -> str:
    languages = [lang for lang in (rule.get("languages") or []) if lang != "*"]
    return languages[0] if languages else "python"


def _fires(rule: Dict, line: str) -> bool:
    """Run one rule over one line, in a file the rule's language would match."""
    scanner = PatternScanner(rules=[rule])
    findings = run_scanner(scanner, _path_for(rule), line + "\n", _language_for(rule))
    return any(f.rule_id == rule["id"] for f in findings)


class ExampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_all()

    def test_every_example_matches(self):
        failures: List[str] = []
        for rule in self.rules:
            for example in rule.get("examples") or []:
                if not _fires(rule, example):
                    failures.append(f"{rule['id']} does not match its own example: {example!r}")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_no_counterexample_matches(self):
        failures: List[str] = []
        for rule in self.rules:
            for counterexample in rule.get("counterexamples") or []:
                if _fires(rule, counterexample):
                    failures.append(
                        f"{rule['id']} matches a line it should not: {counterexample!r}"
                    )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_an_example_does_not_trip_unrelated_rules_of_its_own_pack(self):
        """A sample written for one rule should not be a false positive for its
        neighbours - if it is, one of the two patterns is too broad."""
        by_pack: Dict[str, List[Dict]] = {}
        for rule in self.rules:
            by_pack.setdefault(rule.get("pack", "?"), []).append(rule)

        collisions: List[str] = []
        for pack, rules in by_pack.items():
            for rule in rules:
                for example in rule.get("examples") or []:
                    for other in rules:
                        if other["id"] == rule["id"]:
                            continue
                        if other.get("languages") != rule.get("languages"):
                            continue
                        if _fires(other, example):
                            collisions.append(
                                f"{other['id']} also matches {rule['id']}'s example: {example!r}"
                            )
        # Some overlap is legitimate (two rules genuinely describing one line),
        # so this is a budget rather than a hard zero.
        self.assertLessEqual(len(collisions), 12, "\n".join(collisions))


class CoverageTest(unittest.TestCase):
    """How much of the rule set tests itself. Ratchet this upward, never down."""

    MINIMUM = 0.95

    def test_most_rules_carry_an_example(self):
        rules = load_all()
        with_examples = [rule for rule in rules if rule.get("examples")]
        ratio = len(with_examples) / len(rules)
        missing = sorted(rule["id"] for rule in rules if not rule.get("examples"))
        self.assertGreaterEqual(
            ratio, self.MINIMUM,
            f"{ratio:.0%} of rules have an example, want {self.MINIMUM:.0%}.\n"
            f"Missing: {', '.join(missing)}",
        )

    def test_counterexamples_exist_where_a_rule_has_a_negative_guard(self):
        """A rule with `not_pattern` or `nearby_absent` exists *because* of a
        false positive. The line that caused it belongs in the pack."""
        missing = [
            rule["id"] for rule in load_all()
            if (rule.get("not_pattern") or rule.get("nearby_absent"))
            and not rule.get("counterexamples")
        ]
        self.assertLessEqual(
            len(missing), 8,
            f"{len(missing)} guarded rules have no counterexample: {', '.join(sorted(missing))}",
        )


if __name__ == "__main__":
    unittest.main()
