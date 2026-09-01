"""The plugin layer: manifests, command, skills, agents.

These files are not code, so nothing else catches a typo in them. A skill whose
frontmatter name does not match its directory simply never triggers, silently.
"""

import json
import os
import re
import unittest

from . import _bootstrap  # noqa: F401

ROOT = _bootstrap.ROOT
import sys
sys.path.insert(0, os.path.join(ROOT, "tools"))
from validate_plugin import check, parse_frontmatter  # noqa: E402


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


class StructureTest(unittest.TestCase):
    def test_the_validator_passes(self):
        self.assertEqual(check(), [])


class ManifestTest(unittest.TestCase):
    def test_plugin_json(self):
        data = json.loads(read(".claude-plugin", "plugin.json"))
        self.assertEqual(data["name"], "redassay-security")
        self.assertTrue(data["description"])
        self.assertRegex(data["version"], r"^\d+\.\d+\.\d+$")

    def test_marketplace_lists_the_plugin(self):
        data = json.loads(read(".claude-plugin", "marketplace.json"))
        names = {plugin["name"] for plugin in data["plugins"]}
        self.assertIn("redassay-security", names)

    def test_versions_agree_across_manifests_and_package(self):
        plugin = json.loads(read(".claude-plugin", "plugin.json"))["version"]
        market = json.loads(read(".claude-plugin", "marketplace.json"))["plugins"][0]["version"]
        package = json.loads(read("package.json"))["version"]
        from redassay import __version__
        self.assertEqual({plugin, market, package, __version__}, {plugin})


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.text = read("commands", "redassay-security.md")
        self.fields, self.body = parse_frontmatter(self.text)

    def test_frontmatter(self):
        self.assertTrue(self.fields["description"])
        self.assertIn("argument-hint", self.fields)
        self.assertIn("Bash", self.fields["allowed-tools"])

    def test_it_documents_every_operation_it_dispatches_on(self):
        for operation in ("audit", "scan", "review", "board", "fix", "watch",
                          "status", "report", "doctor", "reset"):
            self.assertIn(f"### `{operation}`", self.body, operation)

    def test_the_argument_hint_lists_the_operations(self):
        for operation in ("audit", "scan", "board", "fix", "watch"):
            self.assertIn(operation, self.fields["argument-hint"])

    def test_it_uses_the_plugin_root_variable(self):
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", self.text)

    def test_it_tells_the_agent_not_to_fake_a_fix(self):
        self.assertIn("Never fake a fix", self.body)

    def test_it_forbids_writing_credentials_into_the_conversation(self):
        self.assertIn("Never write a credential", self.body)


class SkillTest(unittest.TestCase):
    EXPECTED = {"redassay-audit", "redassay-remediate", "redassay-triage"}

    def test_every_expected_skill_exists(self):
        present = {
            name for name in os.listdir(os.path.join(ROOT, "skills"))
            if os.path.isdir(os.path.join(ROOT, "skills", name))
        }
        self.assertEqual(present, self.EXPECTED)

    def test_frontmatter_names_match_directories(self):
        for name in self.EXPECTED:
            fields, _ = parse_frontmatter(read("skills", name, "SKILL.md"))
            self.assertEqual(fields["name"], name)

    def test_descriptions_say_when_to_use_the_skill(self):
        for name in self.EXPECTED:
            fields, _ = parse_frontmatter(read("skills", name, "SKILL.md"))
            self.assertIn("use", fields["description"].lower(), name)

    def test_the_audit_skill_covers_the_classes_scanners_cannot_find(self):
        _, body = parse_frontmatter(read("skills", "redassay-audit", "SKILL.md"))
        for topic in ("authorization", "Time-of-check", "Business-logic", "severity"):
            self.assertIn(topic, body, topic)

    def test_the_remediation_skill_says_to_eliminate_the_class(self):
        _, body = parse_frontmatter(read("skills", "redassay-remediate", "SKILL.md"))
        self.assertIn("Eliminate the class", body)
        self.assertIn("When not to fix", body)


class AgentTest(unittest.TestCase):
    EXPECTED = {"redassay-analyst", "redassay-fixer"}

    def test_every_expected_agent_exists(self):
        present = {f[:-3] for f in os.listdir(os.path.join(ROOT, "agents")) if f.endswith(".md")}
        self.assertEqual(present, self.EXPECTED)

    def test_frontmatter(self):
        for name in self.EXPECTED:
            fields, _ = parse_frontmatter(read("agents", f"{name}.md"))
            self.assertEqual(fields["name"], name)
            self.assertTrue(fields["description"])
            self.assertTrue(fields["tools"])

    def test_the_analyst_is_read_only(self):
        fields, body = parse_frontmatter(read("agents", "redassay-analyst.md"))
        self.assertNotIn("Edit", fields["tools"])
        self.assertNotIn("Write", fields["tools"])
        self.assertIn("You do not modify anything", body)

    def test_the_fixer_can_edit(self):
        fields, _ = parse_frontmatter(read("agents", "redassay-fixer.md"))
        self.assertIn("Edit", fields["tools"])

    def test_both_agents_specify_their_return_shape(self):
        for name in self.EXPECTED:
            _, body = parse_frontmatter(read("agents", f"{name}.md"))
            self.assertIn("```json", body, name)
            self.assertIn("final message is the return value", body, name)


class DocumentedJsonIsValidTest(unittest.TestCase):
    """Every JSON block in the plugin docs is an example someone will copy."""

    FENCE = re.compile(r"```json\n(.*?)```", re.DOTALL)

    def _check(self, text: str, label: str):
        for block in self.FENCE.findall(text):
            try:
                json.loads(block)
            except json.JSONDecodeError as exc:
                self.fail(f"{label}: invalid JSON example - {exc}\n{block[:200]}")

    def test_command(self):
        self._check(read("commands", "redassay-security.md"), "command")

    def test_agents(self):
        for name in ("redassay-analyst", "redassay-fixer"):
            self._check(read("agents", f"{name}.md"), name)

    def test_skills(self):
        for name in ("redassay-audit", "redassay-remediate", "redassay-triage"):
            self._check(read("skills", name, "SKILL.md"), name)


if __name__ == "__main__":
    unittest.main()


class DocumentationCoverageTest(unittest.TestCase):
    """Every command must appear in the CLI reference. An undocumented command
    is a command nobody uses."""

    def _commands(self):
        import subprocess
        import sys
        help_text = subprocess.run(
            [sys.executable, os.path.join(ROOT, "engine", "redassay_cli.py"), "--help"],
            capture_output=True, text=True, check=False,
        ).stdout
        return set(re.search(r"\{([a-z,]+)\}", help_text).group(1).split(","))

    def test_every_command_is_in_the_cli_reference(self):
        reference = read("docs", "cli.md")
        # Headings carry their arguments: "### `show <id>`".
        headings = {
            match.split()[0]
            for match in re.findall(r"^#+ `([^`]+)`", reference, re.MULTILINE)
        }
        headings |= set(re.findall(r"^#+ .*`(\w+)`", reference, re.MULTILINE))
        missing = sorted(self._commands() - headings)
        self.assertEqual(missing, [], f"undocumented commands: {missing}")

    def test_the_reference_documents_no_command_that_does_not_exist(self):
        reference = read("docs", "cli.md")
        headings = {
            match.split()[0]
            for match in re.findall(r"^### `([^`]+)`", reference, re.MULTILINE)
        }
        unknown = sorted(h for h in headings - self._commands() if h.isalpha())
        self.assertEqual(unknown, [], f"documented but not a command: {unknown}")
