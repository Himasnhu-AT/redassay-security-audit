import unittest

from .helpers import by_rule, run_scanner
from redassay.scanners.javascript import JavaScriptScanner, collect_tainted, strip_noise, taint_in


def scan_js(code: str, path: str = "server.js"):
    return run_scanner(JavaScriptScanner(), path, code, "javascript")


def rules(code: str):
    return {f.rule_id for f in scan_js(code)}


class StripNoiseTest(unittest.TestCase):
    def test_line_comments_are_blanked(self):
        cleaned = strip_noise("const a = 1; // exec(userInput)\n")
        self.assertNotIn("exec", cleaned)

    def test_block_comments_are_blanked(self):
        cleaned = strip_noise("/* exec(x) */ const a = 1;")
        self.assertNotIn("exec", cleaned)

    def test_offsets_are_preserved(self):
        source = "line one // comment\nline two\n"
        self.assertEqual(len(strip_noise(source)), len(source))
        self.assertEqual(strip_noise(source).count("\n"), source.count("\n"))

    def test_string_bodies_are_blanked_but_quotes_remain(self):
        cleaned = strip_noise('const a = "exec(evil)";')
        self.assertNotIn("evil", cleaned)
        self.assertEqual(cleaned.count('"'), 2)


class TaintCollectionTest(unittest.TestCase):
    def test_simple_binding(self):
        tainted = collect_tainted("const host = req.query.host;")
        self.assertEqual(tainted["host"], "req.query")

    def test_destructured_binding(self):
        tainted = collect_tainted("const { a, b } = req.body;")
        self.assertEqual(set(tainted), {"a", "b"})

    def test_renamed_destructure(self):
        tainted = collect_tainted("const { id: userId } = req.params;")
        self.assertIn("userId", tainted)

    def test_unrelated_binding_is_not_tainted(self):
        self.assertEqual(collect_tainted("const x = config.value;"), {})

    def test_taint_in_recognizes_a_template_variable(self):
        tainted = {"term": "req.query"}
        self.assertEqual(taint_in("db.query(`SELECT ${term}`)", tainted), "req.query")

    def test_taint_in_recognizes_a_direct_reference(self):
        self.assertEqual(taint_in("exec(req.query.cmd)", {}), "req.query")


class SinkTest(unittest.TestCase):
    def test_command_injection(self):
        code = 'const host = req.query.host;\nexec("ping " + host);'
        self.assertIn("js.exec-tainted", rules(code))

    def test_execfile_with_an_array_is_clean(self):
        code = 'const host = req.query.host;\nexecFile("ping", ["-c", "1", host]);'
        self.assertNotIn("js.exec-tainted", rules(code))

    def test_sql_injection_via_template_literal(self):
        code = 'const q = req.query.q;\ndb.query(`SELECT * FROM t WHERE n = \'${q}\'`);'
        self.assertIn("js.sql-tainted", rules(code))

    def test_path_traversal(self):
        code = 'const name = req.params.name;\nfs.readFile("/data/" + name, cb);'
        self.assertIn("js.path-tainted", rules(code))

    def test_ssrf(self):
        code = 'const url = req.query.url;\naxios.get(url).then(send);'
        self.assertIn("js.ssrf-tainted", rules(code))

    def test_open_redirect(self):
        code = 'const next = req.query.next;\nres.redirect(next);'
        self.assertIn("js.redirect-tainted", rules(code))

    def test_untainted_sinks_are_silent(self):
        code = 'exec("ls -la");\nfs.readFile("/etc/config.json", cb);'
        self.assertEqual(rules(code) & {"js.exec-tainted", "js.path-tainted"}, set())

    def test_a_sink_inside_a_comment_is_ignored(self):
        code = 'const host = req.query.host;\n// exec("ping " + host);'
        self.assertNotIn("js.exec-tainted", rules(code))


class StaticRuleTest(unittest.TestCase):
    def test_hardcoded_jwt_secret(self):
        self.assertIn("js.jwt-hardcoded-secret", rules('jwt.sign(payload, "my-super-secret");'))

    def test_jwt_secret_from_env_is_fine(self):
        self.assertNotIn("js.jwt-hardcoded-secret", rules("jwt.sign(payload, process.env.JWT_SECRET);"))

    def test_trust_proxy_true(self):
        self.assertIn("js.express-trust-proxy-all", rules('app.set("trust proxy", true);'))

    def test_dynamic_require(self):
        self.assertIn("js.dynamic-require", rules("const mod = require(pluginName);"))

    def test_literal_require_is_fine(self):
        self.assertNotIn("js.dynamic-require", rules('const fs = require("fs");'))

    def test_cookie_without_flags(self):
        self.assertIn("js.cookie-no-flags", rules('res.cookie("session", token);'))

    def test_cookie_with_httponly_is_accepted(self):
        self.assertNotIn("js.cookie-no-flags", rules('res.cookie("session", token, { httpOnly: true });'))

    def test_helmet_with_csp_disabled(self):
        self.assertIn("js.helmet-missing-csp", rules("app.use(helmet({ contentSecurityPolicy: false }));"))


class LineNumberTest(unittest.TestCase):
    def test_reported_line_matches_the_source(self):
        code = "\n\n\nconst host = req.query.host;\nexec('ping ' + host);\n"
        finding = by_rule(scan_js(code))["js.exec-tainted"][0]
        self.assertEqual(finding.line, 5)
        self.assertIn("exec", finding.location.snippet)


if __name__ == "__main__":
    unittest.main()
