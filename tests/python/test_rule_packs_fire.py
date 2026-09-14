"""Every labelled defect in the fixtures must still be detected.

Rule packs rot quietly: a regex tightened to kill a false positive can stop
matching the true positive it was written for, and nothing notices until someone
runs a scan on a real repository. These tests read the `VULN:` labels out of the
fixtures and assert each one still fires.
"""

from __future__ import annotations

import os
import re
import unittest
from typing import Dict, List, Set

from .helpers import FIXTURES
from redassay import config as config_mod
from redassay.engine import scan

LABEL = re.compile(r"VULN:\s*([\w.\-]+)")


def labelled_rules(root: str) -> Dict[str, List[str]]:
    """Rule ids named by a `VULN:` comment, keyed by file."""
    out: Dict[str, List[str]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".redassay"]
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            matches = LABEL.findall(text)
            if matches:
                out[os.path.relpath(path, root)] = matches
    return out


def detected(fixture: str) -> Set[str]:
    root = os.path.join(FIXTURES, fixture)
    return {f.rule_id for f in scan(config_mod.load(root)).findings}


class FixtureLabelTest(unittest.TestCase):
    """Assert the labels themselves are meaningful before relying on them."""

    def test_the_polyglot_fixture_is_labelled(self):
        labels = labelled_rules(os.path.join(FIXTURES, "vuln-polyglot"))
        self.assertGreaterEqual(sum(len(v) for v in labels.values()), 15)

    def test_labels_name_real_rules(self):
        from redassay.rules import load_all
        from redassay.scanners.python_ast import RULES as AST_RULES

        known = {rule["id"] for rule in load_all()} | set(AST_RULES)
        known |= {
            "js.exec-tainted", "js.path-tainted", "js.ssrf-tainted", "js.sql-tainted",
            "js.redirect-tainted", "js.eval-tainted", "js.jwt-hardcoded-secret",
            "js.express-trust-proxy-all", "js.dynamic-require", "js.cookie-no-flags",
            "js.prototype-pollution-sink", "js.helmet-missing-csp", "js.set-timeout-string",
            "ci.pull-request-target-checkout", "ci.script-injection", "ci.unpinned-action",
            "ci.permissions-write-all", "ci.secret-printed", "ci.curl-pipe-shell",
            "secret.hardcoded-assignment", "config.dockerfile-baked-secret",
            "config.dockerfile-no-user", "config.dockerfile-add-remote",
            "config.env-secret-value", "config.k8s-inline-secret",
            "config.k8s-no-security-context", "secret.env-file-committed",
            "dep.install-hook-remote-code", "dep.floating-version", "dep.non-registry-source",
            "php.taint-xss", "php.taint-file-inclusion", "php.taint-sql",
            "php.taint-command", "php.taint-file-read", "php.taint-unserialize",
            "php.taint-eval", "php.taint-header",
        }
        for fixture in ("vuln-polyglot", "vuln-flask", "vuln-node"):
            for path, rules in labelled_rules(os.path.join(FIXTURES, fixture)).items():
                for rule_id in rules:
                    if rule_id.startswith("pack:"):
                        continue
                    self.assertIn(rule_id, known, f"{fixture}/{path} names unknown rule {rule_id}")


class PolyglotCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = detected("vuln-polyglot")

    def _assert_pack(self, prefix: str, expected):
        """Match on concept: triage may keep an equivalent rule that describes
        the same defect, and which one wins is a triage decision, not a
        detection failure."""
        from redassay.triage import EQUIVALENT

        concepts = {EQUIVALENT.get(rule_id, rule_id) for rule_id in self.found}
        missing = [
            rule for rule in expected
            if rule not in self.found and EQUIVALENT.get(rule, rule) not in concepts
        ]
        self.assertEqual(missing, [], f"{prefix} pack stopped detecting: {missing}")

    def test_jvm_pack(self):
        self._assert_pack("jvm", [
            "jvm.runtime-exec", "jvm.jdbc-concat", "jvm.xxe-factory", "jvm.csrf-disabled",
        ])

    def test_go_pack(self):
        self._assert_pack("golang", [
            "go.sql-concat", "go.math-rand-secret",
        ])

    def test_php_pack(self):
        self._assert_pack("php", [
            "php.file-inclusion-superglobal", "php.sql-superglobal",
            "php.weak-comparison-hash", "php.extract-superglobal",
        ])

    def test_ruby_pack(self):
        self._assert_pack("ruby", [
            "ruby.mass-assignment", "ruby.send-dynamic",
            "ruby.constantize-input", "ruby.render-inline",
        ])

    def test_mobile_pack(self):
        self._assert_pack("mobile", [
            "mobile.cleartext-traffic", "mobile.android-exported-component",
        ])

    def test_weak_cipher_is_reported_once_not_twice(self):
        """crypto.ecb-mode and jvm.weak-cipher-getinstance describe one defect."""
        findings = scan(config_mod.load(os.path.join(FIXTURES, "vuln-polyglot"))).findings
        at_line = [f for f in findings if f.path.endswith("App.java") and f.line == 14]
        self.assertEqual(len(at_line), 1, [f.rule_id for f in at_line])

    def test_tls_verification_is_reported_once(self):
        findings = scan(config_mod.load(os.path.join(FIXTURES, "vuln-polyglot"))).findings
        at_line = [f for f in findings if f.path.endswith("main.go") and f.line == 18]
        self.assertEqual(len(at_line), 1, [f.rule_id for f in at_line])


class FlaskFixtureCoverageTest(unittest.TestCase):
    def test_every_labelled_rule_fires(self):
        found = detected("vuln-flask")
        labels = labelled_rules(os.path.join(FIXTURES, "vuln-flask"))
        expected = {rule for rules in labels.values() for rule in rules}
        # Some labels name a rule that triage dedupes away in favour of a better
        # one; accept the concept rather than the exact id in that case.
        from redassay.triage import EQUIVALENT
        found_concepts = {EQUIVALENT.get(r, r) for r in found}
        missing = [r for r in expected if r not in found and EQUIVALENT.get(r, r) not in found_concepts]
        self.assertEqual(missing, [], f"vuln-flask stopped detecting: {missing}")


class NodeFixtureCoverageTest(unittest.TestCase):
    def test_every_labelled_rule_fires(self):
        found = detected("vuln-node")
        labels = labelled_rules(os.path.join(FIXTURES, "vuln-node"))
        expected = {rule for rules in labels.values() for rule in rules}
        from redassay.triage import EQUIVALENT
        found_concepts = {EQUIVALENT.get(r, r) for r in found}
        missing = [r for r in expected if r not in found and EQUIVALENT.get(r, r) not in found_concepts]
        self.assertEqual(missing, [], f"vuln-node stopped detecting: {missing}")


if __name__ == "__main__":
    unittest.main()
