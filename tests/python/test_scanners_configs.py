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


class ExposureTest(unittest.TestCase):
    """Published services. The question that comes before "is this code safe":
    can anyone outside reach it at all."""

    def _scan(self, path, content, language):
        from redassay.scanners.exposure import ExposureScanner
        return run_scanner(ExposureScanner(), path, content, language)

    def _rules(self, path, content, language):
        return {f.rule_id for f in self._scan(path, content, language)}

    # -- compose ---------------------------------------------------------
    COMPOSE = (
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    ports:\n"
        '      - "8080:80"\n'
        "  db:\n"
        "    image: postgres:16\n"
        "    ports:\n"
        '      - "5432:5432"\n'
        "  cache:\n"
        "    image: redis:7\n"
        "    ports:\n"
        '      - "127.0.0.1:6379:6379"\n'
    )

    def test_a_published_datastore_is_critical(self):
        findings = {f.rule_id: f for f in self._scan("docker-compose.yml", self.COMPOSE, "compose")}
        self.assertIn("expose.published-datastore", findings)
        self.assertEqual(findings["expose.published-datastore"].severity, "critical")

    def test_the_finding_names_the_service_behind_the_port(self):
        finding = next(f for f in self._scan("docker-compose.yml", self.COMPOSE, "compose")
                       if f.rule_id == "expose.published-datastore")
        self.assertIn("PostgreSQL", finding.title)

    def test_an_ordinary_web_port_is_not_critical(self):
        finding = next(f for f in self._scan("docker-compose.yml", self.COMPOSE, "compose")
                       if f.rule_id == "expose.published-port")
        self.assertEqual(finding.severity, "medium")

    def test_a_loopback_mapping_is_not_published(self):
        """This is the recommended fix - flagging it would be flagging the remedy."""
        lines = [f.location.line for f in self._scan("docker-compose.yml", self.COMPOSE, "compose")]
        self.assertNotIn(13, lines)

    def test_explicit_wildcard_host_is_published(self):
        content = 'services:\n  db:\n    image: redis:7\n    ports:\n      - "0.0.0.0:6379:6379"\n'
        self.assertIn("expose.published-datastore", self._rules("docker-compose.yml", content, "compose"))

    def test_long_form_syntax(self):
        content = (
            "services:\n  es:\n    image: elasticsearch:8\n    ports:\n"
            "      - target: 9200\n        published: 9200\n        protocol: tcp\n"
        )
        self.assertIn("expose.published-datastore", self._rules("docker-compose.yml", content, "compose"))

    def test_a_commented_mapping_is_ignored(self):
        content = 'services:\n  db:\n    image: postgres:16\n    ports:\n      # - "5432:5432"\n'
        self.assertEqual(self._rules("docker-compose.yml", content, "compose"), set())

    def test_the_remediation_offers_the_loopback_form(self):
        finding = next(f for f in self._scan("docker-compose.yml", self.COMPOSE, "compose")
                       if f.rule_id == "expose.published-datastore")
        self.assertIn("127.0.0.1:5432:5432", finding.remediation)

    # -- kubernetes ------------------------------------------------------
    def test_loadbalancer_service(self):
        content = "apiVersion: v1\nkind: Service\nspec:\n  type: LoadBalancer\n"
        self.assertIn("expose.k8s-loadbalancer", self._rules("svc.yaml", content, "yaml"))

    def test_nodeport_is_lower_severity_than_loadbalancer(self):
        node = self._scan("svc.yaml", "kind: Service\nspec:\n  type: NodePort\n", "yaml")[0]
        load = self._scan("svc.yaml", "kind: Service\nspec:\n  type: LoadBalancer\n", "yaml")[0]
        self.assertEqual(node.severity, "medium")
        self.assertEqual(load.severity, "high")

    def test_clusterip_is_not_a_finding(self):
        content = "apiVersion: v1\nkind: Service\nspec:\n  type: ClusterIP\n"
        self.assertEqual(self._rules("svc.yaml", content, "yaml"), set())

    def test_host_port_as_a_list_item(self):
        content = "kind: Pod\nspec:\n  containers:\n    - ports:\n        - hostPort: 6379\n"
        findings = self._scan("pod.yaml", content, "yaml")
        self.assertEqual(findings[0].rule_id, "expose.k8s-host-port")
        self.assertEqual(findings[0].severity, "high")

    def test_host_port_as_a_later_key(self):
        content = ("kind: Pod\nspec:\n  containers:\n    - ports:\n"
                   "        - containerPort: 6379\n          hostPort: 6379\n")
        self.assertIn("expose.k8s-host-port", self._rules("pod.yaml", content, "yaml"))

    # -- cloud -----------------------------------------------------------
    def test_open_cidr_on_a_database_port_is_critical(self):
        content = 'resource "x" {\n  from_port   = 5432\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        finding = next(f for f in self._scan("main.tf", content, "terraform")
                       if f.rule_id == "expose.open-cidr")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("PostgreSQL", finding.title)

    def test_open_cidr_on_a_web_port_is_high(self):
        content = 'resource "x" {\n  from_port   = 443\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        finding = next(f for f in self._scan("main.tf", content, "terraform")
                       if f.rule_id == "expose.open-cidr")
        self.assertEqual(finding.severity, "high")

    def test_a_scoped_cidr_is_not_a_finding(self):
        content = 'resource "x" {\n  from_port   = 5432\n  cidr_blocks = ["10.0.0.0/8"]\n}\n'
        self.assertNotIn("expose.open-cidr", self._rules("main.tf", content, "terraform"))

    def test_ipv6_open_cidr(self):
        content = 'resource "x" {\n  from_port = 22\n  cidr_blocks = ["::/0"]\n}\n'
        self.assertIn("expose.open-cidr", self._rules("main.tf", content, "terraform"))

    # -- dockerfile and binds --------------------------------------------
    def test_expose_of_a_datastore_port(self):
        self.assertIn("expose.dockerfile-datastore-port",
                      self._rules("Dockerfile", "FROM postgres:16\nEXPOSE 5432\n", "dockerfile"))

    def test_expose_of_a_web_port_is_not_a_finding(self):
        self.assertEqual(self._rules("Dockerfile", "FROM nginx\nEXPOSE 80\n", "dockerfile"), set())

    def test_wildcard_bind_on_a_datastore_port_is_high(self):
        content = 'port = 6379\napp.run(host="0.0.0.0", port=port)\n'
        finding = next(f for f in self._scan("serve.py", content, "python")
                       if f.rule_id == "expose.wildcard-bind")
        self.assertEqual(finding.severity, "high")

    def test_wildcard_bind_on_an_app_port_is_low(self):
        content = 'app.run(host="0.0.0.0", port=8000)\n'
        finding = next(f for f in self._scan("serve.py", content, "python")
                       if f.rule_id == "expose.wildcard-bind")
        self.assertEqual(finding.severity, "low")

    def test_loopback_bind_is_not_a_finding(self):
        self.assertEqual(self._rules("serve.py", 'app.run(host="127.0.0.1")\n', "python"), set())


class ExposureFixtureTest(unittest.TestCase):
    def test_every_labelled_defect_in_the_fixture_fires(self):
        import os
        from redassay import config as config_mod
        from redassay.engine import scan
        from .helpers import FIXTURES

        findings = scan(config_mod.load(os.path.join(FIXTURES, "exposed-stack"))).findings
        found = {f.rule_id for f in findings}
        for expected in ("expose.published-port", "expose.published-datastore",
                         "expose.k8s-loadbalancer", "expose.k8s-host-port",
                         "expose.open-cidr", "expose.dockerfile-datastore-port",
                         "expose.wildcard-bind"):
            self.assertIn(expected, found, expected)

    def test_the_loopback_mapping_produces_nothing(self):
        import os
        from redassay import config as config_mod
        from redassay.engine import scan
        from .helpers import FIXTURES

        findings = scan(config_mod.load(os.path.join(FIXTURES, "exposed-stack"))).findings
        compose = [f for f in findings if f.path.endswith("docker-compose.yml")]
        self.assertNotIn(11, [f.line for f in compose])
