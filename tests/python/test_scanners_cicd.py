import unittest

from .helpers import FIXTURES, by_rule, run_scanner
from redassay.scanners.cicd import CicdScanner


def scan(content: str, path: str = ".github/workflows/ci.yml"):
    return run_scanner(CicdScanner(), path, content, "yaml")


def rules(content: str, path: str = ".github/workflows/ci.yml"):
    return {f.rule_id for f in scan(content, path)}


class AppliesToTest(unittest.TestCase):
    def test_github_workflows(self):
        from redassay.walker import SourceFile
        scanner = CicdScanner()
        self.assertTrue(scanner.applies_to(SourceFile(".github/workflows/ci.yml", "/x", "yaml", 1)))
        self.assertTrue(scanner.applies_to(SourceFile(".gitlab-ci.yml", "/x", "yaml", 1)))
        self.assertFalse(scanner.applies_to(SourceFile("k8s/deploy.yaml", "/x", "yaml", 1)))


class PullRequestTargetTest(unittest.TestCase):
    DANGEROUS = """
on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""

    def test_the_combination_is_critical(self):
        finding = by_rule(scan(self.DANGEROUS))["ci.pull-request-target-checkout"][0]
        self.assertEqual(finding.severity, "critical")

    def test_the_description_names_the_trigger_line(self):
        finding = by_rule(scan(self.DANGEROUS))["ci.pull-request-target-checkout"][0]
        self.assertIn("line 3", finding.description)

    def test_the_trigger_alone_is_not_flagged(self):
        content = "on:\n  pull_request_target:\njobs:\n  label:\n    steps:\n      - run: gh pr edit\n"
        self.assertNotIn("ci.pull-request-target-checkout", rules(content))

    def test_plain_pull_request_with_a_checkout_is_fine(self):
        content = self.DANGEROUS.replace("pull_request_target", "pull_request")
        self.assertNotIn("ci.pull-request-target-checkout", rules(content))


class ScriptInjectionTest(unittest.TestCase):
    def test_issue_title_in_a_run_block(self):
        content = 'jobs:\n  a:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n'
        self.assertIn("ci.script-injection", rules(content))

    def test_head_ref_in_a_run_block(self):
        content = "jobs:\n  a:\n    steps:\n      - run: git checkout ${{ github.head_ref }}\n"
        self.assertIn("ci.script-injection", rules(content))

    def test_the_same_expression_in_env_is_safe(self):
        content = ('jobs:\n  a:\n    steps:\n      - env:\n'
                   '          TITLE: ${{ github.event.issue.title }}\n'
                   '        run: echo "$TITLE"\n')
        self.assertNotIn("ci.script-injection", rules(content))

    def test_a_trusted_context_is_not_flagged(self):
        content = "jobs:\n  a:\n    steps:\n      - run: echo ${{ github.sha }}\n"
        self.assertNotIn("ci.script-injection", rules(content))

    def test_the_remediation_shows_the_env_pattern(self):
        content = 'jobs:\n  a:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n'
        finding = by_rule(scan(content))["ci.script-injection"][0]
        self.assertIn("env:", finding.remediation)


class ActionPinningTest(unittest.TestCase):
    def test_third_party_tag_is_flagged(self):
        self.assertIn("ci.unpinned-action", rules("jobs:\n  a:\n    steps:\n      - uses: vendor/thing@v2\n"))

    def test_a_sha_pin_is_accepted(self):
        content = f"jobs:\n  a:\n    steps:\n      - uses: vendor/thing@{'a' * 40}\n"
        self.assertNotIn("ci.unpinned-action", rules(content))

    def test_first_party_actions_are_exempt(self):
        content = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: docker/setup-buildx-action@v3\n"
        self.assertNotIn("ci.unpinned-action", rules(content))

    def test_a_branch_ref_is_worse_than_a_tag(self):
        tag = by_rule(scan("jobs:\n  a:\n    steps:\n      - uses: vendor/thing@v2\n"))["ci.unpinned-action"][0]
        branch = by_rule(scan("jobs:\n  a:\n    steps:\n      - uses: vendor/thing@main\n"))["ci.unpinned-action"][0]
        self.assertEqual(tag.severity, "medium")
        self.assertEqual(branch.severity, "high")

    def test_local_actions_are_exempt(self):
        self.assertNotIn("ci.unpinned-action", rules("jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/x\n"))


class MiscellaneousTest(unittest.TestCase):
    def test_write_all_permissions(self):
        self.assertIn("ci.permissions-write-all", rules("permissions: write-all\njobs: {}\n"))

    def test_scoped_permissions_are_fine(self):
        self.assertNotIn("ci.permissions-write-all", rules("permissions:\n  contents: read\njobs: {}\n"))

    def test_secret_printed_to_the_log(self):
        self.assertIn("ci.secret-printed", rules('jobs:\n  a:\n    steps:\n      - run: echo "${{ secrets.TOKEN }}"\n'))

    def test_secret_used_without_printing_is_fine(self):
        content = "jobs:\n  a:\n    steps:\n      - run: deploy --token ${{ secrets.TOKEN }}\n"
        self.assertNotIn("ci.secret-printed", rules(content))

    def test_curl_pipe_shell(self):
        self.assertIn("ci.curl-pipe-shell", rules("jobs:\n  a:\n    steps:\n      - run: curl -sL https://x.invalid | bash\n"))


class FixtureCoverageTest(unittest.TestCase):
    def test_the_vulnerable_workflow_triggers_everything_it_claims(self):
        import os
        path = os.path.join(FIXTURES, "vuln-node", ".github", "workflows", "ci.yml")
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
        found = rules(content)
        for expected in ("ci.pull-request-target-checkout", "ci.script-injection",
                         "ci.unpinned-action", "ci.permissions-write-all",
                         "ci.secret-printed", "ci.curl-pipe-shell"):
            self.assertIn(expected, found)


if __name__ == "__main__":
    unittest.main()
