import unittest

from .helpers import TempRepo, by_rule, run_scanner
from redassay.scanners.python_ast import PythonAstScanner


def scan_py(code: str):
    return run_scanner(PythonAstScanner(), "app.py", code, "python")


def rules(code: str):
    return {f.rule_id for f in scan_py(code)}


class DangerousCallTest(unittest.TestCase):
    def test_eval_on_a_variable_is_flagged(self):
        self.assertIn("py.eval-dynamic", rules("eval(payload)"))

    def test_eval_on_a_literal_is_not(self):
        self.assertNotIn("py.eval-dynamic", rules("eval('1 + 1')"))

    def test_method_named_eval_is_not_builtin_eval(self):
        self.assertNotIn("py.eval-dynamic", rules("engine.eval(expr)"))

    def test_os_system(self):
        self.assertIn("py.shell-dynamic", rules("import os\nos.system(cmd)"))

    def test_subprocess_with_shell_true_and_a_literal_is_only_a_warning(self):
        found = rules("import subprocess\nsubprocess.run('ls -la', shell=True)")
        self.assertIn("py.shell-true-literal", found)
        self.assertNotIn("py.shell-dynamic", found)

    def test_subprocess_with_an_argument_list_is_clean(self):
        self.assertEqual(rules("import subprocess\nsubprocess.run(['ls', target])"), set())

    def test_pickle_and_yaml(self):
        self.assertIn("py.pickle-load", rules("import pickle\npickle.loads(blob)"))
        self.assertIn("py.yaml-unsafe-load", rules("import yaml\nyaml.load(blob)"))

    def test_safe_yaml_loader_is_accepted(self):
        self.assertNotIn("py.yaml-unsafe-load", rules("import yaml\nyaml.safe_load(blob)"))
        self.assertNotIn("py.yaml-unsafe-load", rules("import yaml\nyaml.load(blob, Loader=yaml.SafeLoader)"))


class TaintTrackingTest(unittest.TestCase):
    HANDLER = """
from flask import request
def view():
    name = request.args.get("name")
    cursor.execute("SELECT * FROM t WHERE n = '%s'" % name)
"""

    def test_request_data_to_sql_is_found(self):
        findings = by_rule(scan_py(self.HANDLER))
        self.assertIn("py.sql-dynamic", findings)

    def test_confirmed_taint_raises_severity_and_confidence(self):
        finding = by_rule(scan_py(self.HANDLER))["py.sql-dynamic"][0]
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.severity, "critical")

    def test_the_description_names_the_source(self):
        finding = by_rule(scan_py(self.HANDLER))["py.sql-dynamic"][0]
        self.assertIn("request.args", finding.description)

    def test_taint_survives_a_chain_of_assignments(self):
        code = """
from flask import request
def view():
    raw = request.args.get("q")
    trimmed = raw.strip()
    query = f"SELECT * FROM t WHERE q = {trimmed}"
    cursor.execute(query)
"""
        self.assertIn("py.sql-dynamic", rules(code))

    def test_taint_travels_through_an_f_string(self):
        code = """
from flask import request
def view():
    target = request.args["host"]
    subprocess.run(f"ping {target}", shell=True)
"""
        self.assertIn("py.shell-dynamic", rules(code))

    def test_a_static_query_is_not_flagged(self):
        code = """
def view():
    cursor.execute("SELECT * FROM t WHERE n = %s", (name,))
"""
        self.assertNotIn("py.sql-dynamic", rules(code))

    def test_taint_does_not_leak_between_functions(self):
        code = """
from flask import request
def a():
    name = request.args.get("n")

def b():
    subprocess.run(name, shell=True)
"""
        findings = by_rule(scan_py(code))
        shell = findings.get("py.shell-dynamic", [])
        self.assertTrue(all(not f.description.startswith("A value originating") for f in shell))

    def test_route_parameters_count_as_tainted(self):
        code = """
@app.route("/f/<name>")
def show(name):
    return open("/data/" + name).read()
"""
        self.assertIn("py.path-tainted", rules(code))


class GuardDetectionTest(unittest.TestCase):
    GUARDED = """
from flask import request, abort
import requests
ALLOWED = {"api.example"}
def fetch():
    url = request.args.get("url")
    if urlparse(url).hostname not in ALLOWED:
        abort(400)
    return requests.get(url, timeout=5).text
"""

    def test_a_guarded_value_is_downgraded_not_dropped(self):
        findings = by_rule(scan_py(self.GUARDED))
        self.assertIn("py.ssrf", findings)
        finding = findings["py.ssrf"][0]
        self.assertEqual(finding.confidence, "low")
        self.assertNotEqual(finding.severity, "critical")

    def test_the_description_says_a_check_exists(self):
        finding = by_rule(scan_py(self.GUARDED))["py.ssrf"][0]
        self.assertIn("validates it first", finding.description)

    def test_an_unguarded_equivalent_stays_critical(self):
        code = """
from flask import request
import requests
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
"""
        finding = by_rule(scan_py(code))["py.ssrf"][0]
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.confidence, "high")

    def test_a_check_that_does_not_bail_out_is_not_a_guard(self):
        code = """
from flask import request
import requests
def fetch():
    url = request.args.get("url")
    if url in ALLOWED:
        log("known host")
    return requests.get(url, timeout=5).text
"""
        self.assertEqual(by_rule(scan_py(code))["py.ssrf"][0].severity, "critical")


class ConfigurationTest(unittest.TestCase):
    def test_flask_debug(self):
        self.assertIn("py.flask-debug", rules("app.run(debug=True)"))

    def test_django_settings(self):
        found = rules("DEBUG = True\nALLOWED_HOSTS = ['*']")
        self.assertIn("py.django-debug-true", found)
        self.assertIn("py.django-allowed-hosts-wildcard", found)

    def test_allowed_hosts_without_a_wildcard_is_fine(self):
        self.assertNotIn("py.django-allowed-hosts-wildcard", rules("ALLOWED_HOSTS = ['example.com']"))

    def test_verify_false(self):
        self.assertIn("py.tls-verify-off", rules("requests.get(url, verify=False, timeout=1)"))

    def test_missing_timeout(self):
        self.assertIn("py.request-no-timeout", rules("requests.get('https://example.com')"))
        self.assertNotIn("py.request-no-timeout", rules("requests.get('https://example.com', timeout=5)"))

    def test_world_writable_chmod(self):
        self.assertIn("py.world-writable-chmod", rules("import os\nos.chmod(path, 0o777)"))
        self.assertNotIn("py.world-writable-chmod", rules("import os\nos.chmod(path, 0o600)"))

    def test_mktemp(self):
        self.assertIn("py.mktemp-race", rules("import tempfile\ntempfile.mktemp()"))


class CodeQualityTest(unittest.TestCase):
    def test_assert_on_a_security_predicate(self):
        self.assertIn("py.assert-security", rules("assert user.is_admin"))

    def test_assert_on_something_ordinary_is_ignored(self):
        self.assertNotIn("py.assert-security", rules("assert len(items) == 3"))

    def test_swallowed_broad_exception(self):
        self.assertIn("py.swallowed-exception", rules("try:\n    check()\nexcept Exception:\n    pass"))

    def test_a_handled_exception_is_fine(self):
        self.assertNotIn("py.swallowed-exception", rules("try:\n    check()\nexcept ValueError:\n    log()"))


class RobustnessTest(unittest.TestCase):
    def test_syntax_errors_do_not_raise(self):
        self.assertEqual(scan_py("def broken(:\n"), [])

    def test_empty_file(self):
        self.assertEqual(scan_py(""), [])

    def test_repeat_occurrences_get_distinct_ids(self):
        findings = scan_py("eval(a)\neval(b)")
        self.assertEqual(len({f.id for f in findings}), len(findings))
        self.assertEqual(len(findings), 2)


class FixtureCoverageTest(TempRepo):
    """The vulnerable fixture must keep triggering what it claims to trigger."""

    EXPECTED = [
        "py.sql-dynamic", "py.shell-dynamic", "py.ssti", "py.path-tainted",
        "py.ssrf", "py.pickle-load", "py.yaml-unsafe-load", "py.open-redirect",
        "py.weak-hash", "py.tls-verify-off", "py.assert-security", "py.flask-debug",
    ]

    def test_every_labelled_defect_is_detected(self):
        from .helpers import FIXTURES
        import os
        from redassay import config as config_mod
        from redassay.engine import scan as run

        findings = run(config_mod.load(os.path.join(FIXTURES, "vuln-flask"))).findings
        found = {f.rule_id for f in findings}
        missing = [rule for rule in self.EXPECTED if rule not in found]
        self.assertEqual(missing, [], f"fixture stopped triggering: {missing}")


if __name__ == "__main__":
    unittest.main()
