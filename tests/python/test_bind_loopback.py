"""The loopback-binding remediation.

This edits other people's compose files in bulk, so its failure modes are
asymmetric: rewriting an `expose:` entry changes what a stack does, and missing
a `ports:` entry leaves a service published while reporting success. Both are
silent. Hence the tests.
"""

from __future__ import annotations

import os
import sys
import unittest

from .helpers import ROOT, TempRepo

sys.path.insert(0, os.path.join(ROOT, "tools"))
from bind_loopback import apply, compose_files, rewrite  # noqa: E402


def only(text: str) -> str:
    rewritten, _ = rewrite(text)
    return rewritten


class ShortFormTest(unittest.TestCase):
    def test_bare_container_port(self):
        source = "services:\n  app:\n    ports:\n      - 80\n"
        self.assertIn('- "127.0.0.1::80"', only(source))

    def test_quoted_container_port(self):
        source = 'services:\n  app:\n    ports:\n      - "8080"\n'
        self.assertIn('- "127.0.0.1::8080"', only(source))

    def test_protocol_suffix_is_preserved(self):
        source = "services:\n  app:\n    ports:\n      - 53/udp\n"
        self.assertIn('- "127.0.0.1::53/udp"', only(source))

    def test_indentation_is_preserved(self):
        source = "services:\n  app:\n    ports:\n        - 80\n"
        self.assertIn('        - "127.0.0.1::80"', only(source))


class MappingTest(unittest.TestCase):
    def test_host_and_container(self):
        source = 'services:\n  app:\n    ports:\n      - "8080:80"\n'
        self.assertIn('- "127.0.0.1:8080:80"', only(source))

    def test_unquoted_mapping(self):
        source = "services:\n  app:\n    ports:\n      - 8000:80\n"
        self.assertIn('- "127.0.0.1:8000:80"', only(source))

    def test_an_explicit_wildcard_address_is_replaced(self):
        source = 'services:\n  app:\n    ports:\n      - "0.0.0.0:8080:80"\n'
        rewritten = only(source)
        self.assertIn('- "127.0.0.1:8080:80"', rewritten)
        self.assertNotIn("0.0.0.0", rewritten)

    def test_port_ranges_survive(self):
        source = 'services:\n  app:\n    ports:\n      - "8000-8010:8000-8010"\n'
        self.assertIn('- "127.0.0.1:8000-8010:8000-8010"', only(source))

    def test_a_loopback_mapping_is_left_alone(self):
        source = 'services:\n  app:\n    ports:\n      - "127.0.0.1:8080:80"\n'
        rewritten, result = rewrite(source)
        self.assertEqual(rewritten, source)
        self.assertEqual(result.already_confined, 1)
        self.assertEqual(result.changed, [])


class ExposeTest(unittest.TestCase):
    """`expose:` never publishes to the host. Rewriting it would change what the
    stack does for no security benefit."""

    def test_expose_entries_are_untouched(self):
        source = "services:\n  db:\n    expose:\n      - 3306\n"
        self.assertEqual(only(source), source)

    def test_the_malformed_mapping_form_under_expose_is_also_untouched(self):
        source = "services:\n  db:\n    expose:\n      - 3306:3306\n"
        self.assertEqual(only(source), source)

    def test_expose_then_ports_in_the_same_file(self):
        source = (
            "services:\n"
            "  db:\n    expose:\n      - 3306\n"
            "  app:\n    ports:\n      - 80\n"
        )
        rewritten = only(source)
        self.assertIn("      - 3306\n", rewritten)
        self.assertIn('- "127.0.0.1::80"', rewritten)

    def test_ports_then_expose_in_the_same_file(self):
        source = (
            "services:\n"
            "  app:\n    ports:\n      - 80\n"
            "  db:\n    expose:\n      - 3306\n"
        )
        rewritten = only(source)
        self.assertIn('- "127.0.0.1::80"', rewritten)
        self.assertIn("      - 3306\n", rewritten)

    def test_a_key_after_the_ports_block_ends_it(self):
        source = (
            "services:\n"
            "  app:\n"
            "    ports:\n"
            "      - 80\n"
            "    environment:\n"
            "      - DEBUG=1\n"
        )
        rewritten = only(source)
        self.assertIn("      - DEBUG=1\n", rewritten)
        self.assertNotIn("127.0.0.1::DEBUG", rewritten)

    def test_other_list_keys_are_not_ports(self):
        source = (
            "services:\n  app:\n"
            "    depends_on:\n      - db\n"
            "    networks:\n      - backend\n"
        )
        self.assertEqual(only(source), source)


class SafetyTest(unittest.TestCase):
    def test_it_is_idempotent(self):
        source = 'services:\n  app:\n    ports:\n      - 80\n      - "8080:80"\n'
        once = only(source)
        self.assertEqual(only(once), once)

    def test_comments_are_preserved(self):
        source = "services:\n  app:\n    ports:\n      # the web port\n      - 80\n"
        rewritten = only(source)
        self.assertIn("# the web port", rewritten)
        self.assertIn('- "127.0.0.1::80"', rewritten)

    def test_a_commented_entry_is_not_rewritten(self):
        source = "services:\n  app:\n    ports:\n      # - 80\n"
        self.assertEqual(only(source), source)

    def test_trailing_newline_is_preserved(self):
        with_newline = "services:\n  app:\n    ports:\n      - 80\n"
        self.assertTrue(only(with_newline).endswith("\n"))

    def test_a_file_without_a_trailing_newline_does_not_gain_one(self):
        without = "services:\n  app:\n    ports:\n      - 80"
        self.assertFalse(only(without).endswith("\n"))

    def test_a_custom_address_is_honoured(self):
        source = "services:\n  app:\n    ports:\n      - 80\n"
        rewritten, _ = rewrite(source, address="192.168.1.10")
        self.assertIn('- "192.168.1.10::80"', rewritten)

    def test_line_count_never_changes(self):
        source = 'services:\n  app:\n    ports:\n      - 80\n      - "8080:80"\n    expose:\n      - 3306\n'
        self.assertEqual(len(only(source).splitlines()), len(source.splitlines()))


class DiscoveryTest(TempRepo):
    def test_it_finds_every_compose_spelling(self):
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            self.write(f"{name.split('.')[0]}-dir/{name}", "services: {}\n")
        self.write("nested/deep/docker-compose.yml", "services: {}\n")
        self.assertEqual(len(compose_files(self.root)), 5)

    def test_it_skips_vendored_trees(self):
        self.write("node_modules/pkg/docker-compose.yml", "services: {}\n")
        self.write("docker-compose.yml", "services: {}\n")
        self.assertEqual(len(compose_files(self.root)), 1)

    def test_dry_run_changes_nothing_on_disk(self):
        path = self.write("docker-compose.yml", "services:\n  app:\n    ports:\n      - 80\n")
        before = open(path).read()
        result = apply(self.root, dry_run=True)
        self.assertEqual(len(result.changed), 1)
        self.assertEqual(open(path).read(), before)

    def test_applying_writes_the_file(self):
        path = self.write("docker-compose.yml", "services:\n  app:\n    ports:\n      - 80\n")
        apply(self.root)
        self.assertIn('127.0.0.1::80', open(path).read())

    def test_a_second_run_reports_nothing_to_do(self):
        self.write("docker-compose.yml", "services:\n  app:\n    ports:\n      - 80\n")
        apply(self.root)
        self.assertEqual(apply(self.root).changed, [])


class EndToEndTest(TempRepo):
    """The transform must actually remove the findings it claims to remove."""

    def test_the_exposure_scanner_goes_quiet_afterwards(self):
        from redassay import config as config_mod
        from redassay.engine import scan

        self.write("docker-compose.yml",
                   "services:\n"
                   "  db:\n    image: postgres:16\n    ports:\n      - 5432:5432\n"
                   "  app:\n    image: app\n    ports:\n      - 80\n")

        before = [f for f in scan(config_mod.load(self.root)).findings if "exposure" in f.tags]
        self.assertEqual(len(before), 2)

        apply(self.root)

        after = [f for f in scan(config_mod.load(self.root)).findings if "exposure" in f.tags]
        self.assertEqual([f.rule_id for f in after], [])


if __name__ == "__main__":
    unittest.main()
