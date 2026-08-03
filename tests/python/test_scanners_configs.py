import unittest

from .helpers import by_rule, run_scanner
from redassay.scanners.configs import ConfigScanner


def scan(path: str, content: str, language: str):
    return run_scanner(ConfigScanner(), path, content, language)


def rules(path: str, content: str, language: str):
    return {f.rule_id for f in scan(path, content, language)}


class EnvFileTest(unittest.TestCase):
    def test_a_real_value_is_flagged(self):
        found = rules(".env", "DATABASE_PASSWORD=Qx7pR2wN9mL4zV\n", "dotenv")
        self.assertIn("config.env-secret-value", found)

    def test_placeholders_are_not(self):
        content = "DATABASE_PASSWORD=\nAPI_KEY=changeme\nSECRET=${VAULT_SECRET}\nTOKEN=<your-token>\n"
        self.assertNotIn("config.env-secret-value", rules(".env", content, "dotenv"))

    def test_template_files_are_skipped(self):
        self.assertEqual(rules(".env.example", "DATABASE_PASSWORD=Qx7pR2wN9mL4zV\n", "dotenv"), set())

    def test_comments_are_skipped(self):
        self.assertEqual(rules(".env", "# PASSWORD=Qx7pR2wN9mL4zV\n", "dotenv"), set())

    def test_the_snippet_is_redacted(self):
        finding = by_rule(scan(".env", "API_KEY=Qx7pR2wN9mL4zVsecret\n", "dotenv"))["config.env-secret-value"][0]
        self.assertNotIn("Qx7pR2wN9mL4zVsecret", finding.location.snippet)


class DockerfileTest(unittest.TestCase):
    def test_no_user_instruction(self):
        self.assertIn("config.dockerfile-no-user", rules("Dockerfile", "FROM python:3.12\nCMD [\"x\"]\n", "dockerfile"))

    def test_a_non_root_user_satisfies_the_rule(self):
        content = "FROM python:3.12\nRUN adduser app\nUSER app\nCMD [\"x\"]\n"
        self.assertNotIn("config.dockerfile-no-user", rules("Dockerfile", content, "dockerfile"))

    def test_user_root_does_not_satisfy_it(self):
        content = "FROM python:3.12\nUSER root\nCMD [\"x\"]\n"
        self.assertIn("config.dockerfile-no-user", rules("Dockerfile", content, "dockerfile"))

    def test_baked_secret(self):
        content = "FROM alpine\nENV API_TOKEN=Qx7pR2wN9mL4zV\nUSER app\n"
        self.assertIn("config.dockerfile-baked-secret", rules("Dockerfile", content, "dockerfile"))

    def test_placeholder_env_is_not_a_secret(self):
        content = "FROM alpine\nENV API_TOKEN=${API_TOKEN}\nUSER app\n"
        self.assertNotIn("config.dockerfile-baked-secret", rules("Dockerfile", content, "dockerfile"))

    def test_add_from_a_url(self):
        content = "FROM alpine\nADD https://x.invalid/a.tar.gz /tmp/\nUSER app\n"
        self.assertIn("config.dockerfile-add-remote", rules("Dockerfile", content, "dockerfile"))

    def test_copy_is_fine(self):
        content = "FROM alpine\nCOPY . /srv\nUSER app\n"
        self.assertNotIn("config.dockerfile-add-remote", rules("Dockerfile", content, "dockerfile"))


class ComposeTest(unittest.TestCase):
    def test_privileged(self):
        self.assertIn("config.container-privileged",
                      rules("docker-compose.yml", "services:\n  a:\n    privileged: true\n", "compose"))

    def test_docker_socket_mount(self):
        content = "services:\n  a:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        self.assertIn("config.container-docker-socket", rules("docker-compose.yml", content, "compose"))

    def test_host_network(self):
        content = "services:\n  a:\n    network_mode: host\n"
        self.assertIn("config.container-host-network", rules("docker-compose.yml", content, "compose"))

    def test_a_plain_service_is_clean(self):
        content = "services:\n  a:\n    image: nginx:1.25\n    ports:\n      - \"8080:80\"\n"
        self.assertEqual(rules("docker-compose.yml", content, "compose"), set())


class KubernetesTest(unittest.TestCase):
    DEPLOY = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:1.0
"""

    def test_missing_security_context(self):
        self.assertIn("config.k8s-no-security-context", rules("k8s/api.yaml", self.DEPLOY, "yaml"))

    def test_a_security_context_satisfies_it(self):
        content = self.DEPLOY + "          securityContext:\n            runAsNonRoot: true\n"
        self.assertNotIn("config.k8s-no-security-context", rules("k8s/api.yaml", content, "yaml"))

    def test_a_non_workload_manifest_is_ignored(self):
        content = "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: b\n"
        self.assertEqual(rules("k8s/cm.yaml", content, "yaml"), set())

    def test_inline_secret(self):
        content = self.DEPLOY + ("          securityContext: {}\n          env:\n"
                                 "            - name: DB_PASSWORD\n              value: Qx7pR2wN9mL4zV\n")
        self.assertIn("config.k8s-inline-secret", rules("k8s/api.yaml", content, "yaml"))


if __name__ == "__main__":
    unittest.main()
