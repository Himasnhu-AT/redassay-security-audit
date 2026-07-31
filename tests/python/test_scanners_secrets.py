import unittest

from .helpers import by_rule, run_scanner
from redassay.scanners.secrets import (
    SecretScanner, is_high_entropy, looks_like_placeholder, redact, shannon_entropy,
)


def scan(code: str, path: str = "config.py", language: str = "python"):
    return run_scanner(SecretScanner(), path, code, language)


def rules(code: str, path: str = "config.py"):
    return {f.rule_id for f in scan(code, path)}


class EntropyTest(unittest.TestCase):
    def test_uniform_text_has_no_entropy(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_looking_text_scores_higher_than_prose(self):
        self.assertGreater(shannon_entropy("kR7pW2xQ9mL4zV6tN8yB"), shannon_entropy("the quick brown fox"))

    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_is_high_entropy_rejects_short_values(self):
        self.assertFalse(is_high_entropy("abc123"))

    def test_is_high_entropy_accepts_a_key_shaped_value(self):
        self.assertTrue(is_high_entropy("kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"))

    def test_is_high_entropy_rejects_a_sentence(self):
        self.assertFalse(is_high_entropy("this is a normal sentence"))


class PlaceholderTest(unittest.TestCase):
    def test_known_placeholders(self):
        for value in ("changeme", "password", "your_password", "TODO", "xxxxxxxx"):
            self.assertTrue(looks_like_placeholder(value), value)

    def test_template_markers(self):
        for value in ("${DB_PASSWORD}", "{{ secret }}", "<your-key-here>", "process.env.KEY"):
            self.assertTrue(looks_like_placeholder(value), value)

    def test_paths_and_versions(self):
        self.assertTrue(looks_like_placeholder("/etc/ssl/private"))
        self.assertTrue(looks_like_placeholder("1.2.3"))

    def test_a_real_looking_key_is_not_a_placeholder(self):
        self.assertFalse(looks_like_placeholder("kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"))


class RedactionTest(unittest.TestCase):
    def test_keeps_the_ends_only(self):
        self.assertEqual(redact("ABCD1234EFGH5678"), "ABCD********5678")

    def test_short_values_are_fully_masked(self):
        self.assertEqual(redact("abcd"), "****")

    def test_the_snippet_never_carries_the_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        finding = scan(f'AWS_KEY = "{secret}"')[0]
        self.assertNotIn(secret, finding.location.snippet)


class ProviderPatternTest(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("secret.aws-access-key-id", rules('KEY = "AKIAIOSFODNN7EXAMPLE"'))

    def test_github_token(self):
        self.assertIn("secret.github-token", rules('T = "ghp_' + "a" * 36 + '"'))

    def test_stripe_key(self):
        self.assertIn("secret.stripe-secret", rules('K = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'))

    def test_private_key_block(self):
        self.assertIn("secret.private-key-block", rules("-----BEGIN RSA PRIVATE KEY-----"))

    def test_connection_string_with_a_password(self):
        found = rules('DSN = "postgresql://svc:hunter2xyz@db.internal:5432/app"')
        self.assertTrue({"secret.db-conn-string", "secret.basic-auth-url"} & found)

    def test_severity_is_critical_for_a_live_key(self):
        finding = by_rule(scan('KEY = "AKIAIOSFODNN7EXAMPLE"'))["secret.aws-access-key-id"][0]
        self.assertEqual(finding.severity, "critical")


class GenericAssignmentTest(unittest.TestCase):
    def test_high_entropy_assignment_is_reported(self):
        self.assertIn("secret.hardcoded-assignment", rules('API_KEY = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"'))

    def test_placeholder_assignment_is_not(self):
        self.assertNotIn("secret.hardcoded-assignment", rules('API_KEY = "changeme"'))

    def test_env_lookup_is_not(self):
        self.assertNotIn("secret.hardcoded-assignment", rules('API_KEY = os.environ["API_KEY"]'))

    def test_an_unrelated_variable_name_is_not_checked(self):
        self.assertNotIn("secret.hardcoded-assignment", rules('BUILD_ID = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"'))

    def test_the_same_value_is_only_reported_once_per_file(self):
        code = ('API_KEY = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"\n'
                'BACKUP_API_KEY = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"')
        self.assertEqual(len(scan(code)), 1)

    def test_a_name_that_does_not_read_as_a_secret_is_skipped(self):
        # Deliberately conservative: bare "*_KEY" names are too often cache keys
        # and partition keys for the entropy gate alone to carry the decision.
        self.assertEqual(scan('PARTITION_KEY = "kR7pW2xQ9mL4zV6tN8yBcD3fG5hJ1"'), [])


class TestPathDowngradeTest(unittest.TestCase):
    def test_a_key_in_a_test_file_is_downgraded(self):
        finding = by_rule(scan('KEY = "AKIAIOSFODNN7EXAMPLE"', "tests/test_auth.py"))["secret.aws-access-key-id"][0]
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.confidence, "low")

    def test_the_description_explains_the_downgrade(self):
        finding = by_rule(scan('KEY = "AKIAIOSFODNN7EXAMPLE"', "tests/test_auth.py"))["secret.aws-access-key-id"][0]
        self.assertIn("test or example", finding.description)

    def test_a_key_in_production_code_is_not_downgraded(self):
        finding = by_rule(scan('KEY = "AKIAIOSFODNN7EXAMPLE"', "app/settings.py"))["secret.aws-access-key-id"][0]
        self.assertEqual(finding.severity, "critical")


class EnvFileTest(unittest.TestCase):
    ENV = "DATABASE_URL=postgres://u:realpassword@db/app\nAPI_KEY=kR7pW2xQ9mL4zV6tN8yB\n"

    def test_a_populated_env_file_is_flagged(self):
        self.assertIn("secret.env-file-committed", rules(self.ENV, ".env"))

    def test_an_example_env_file_is_not(self):
        self.assertNotIn("secret.env-file-committed", rules("API_KEY=\n", ".env.example"))

    def test_an_empty_env_file_is_not(self):
        self.assertNotIn("secret.env-file-committed", rules("# nothing here\n", ".env"))


if __name__ == "__main__":
    unittest.main()
