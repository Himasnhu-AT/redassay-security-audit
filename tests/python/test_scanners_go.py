"""The Go taint scanner.

Motivated by the same blind spot as the PHP and Ruby scanners: line rules see a
request accessor only on the sink line and miss the value that reaches the sink
through a variable and concatenation - `id := r.URL.Query().Get("id"); q := "..."
+ id; db.Query(q)`.

Go has no string interpolation, so the propagation vectors are `+` and
`fmt.Sprintf`. Its safe query form passes the value as a bound parameter after a
placeholder, which looks like the unsafe form on the surface; the suite pins that
down as a non-finding, since SQL sinks inspect only their first argument.
"""

import unittest

from .helpers import run_scanner
from redassay.scanners.go import GoTaintScanner, strip_noise, Taint


def scan(code: str, path: str = "main.go"):
    return run_scanner(GoTaintScanner(), path, code, "go")


def rules(code: str):
    return {f.rule_id for f in scan(code)}


HDR = "package main\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n"
END = "\n}\n"


def body(*lines: str) -> str:
    return HDR + "\n".join("\t" + line for line in lines) + END


class StrippingTest(unittest.TestCase):
    def test_string_body_blanked(self):
        code = 'q := "SELECT secret FROM t"'
        stripped = strip_noise(code)
        self.assertNotIn("SELECT secret", stripped)
        self.assertIn('"', stripped)

    def test_raw_string_blanked(self):
        code = "q := `SELECT secret`"
        self.assertNotIn("SELECT secret", strip_noise(code))

    def test_comment_blanked(self):
        code = "x := 1 // r.FormValue(\"evil\")\n"
        self.assertNotIn("evil", strip_noise(code))

    def test_offsets_preserved(self):
        code = 'q := "abc"\ndb.Query(q)\n'
        self.assertEqual(len(strip_noise(code)), len(code))
        self.assertEqual(strip_noise(code).count("\n"), code.count("\n"))


class TaintPropagationTest(unittest.TestCase):
    def test_source_binding_taints(self):
        t = Taint()
        t.build(strip_noise('id := r.URL.Query().Get("id")'))
        self.assertIn("id", t.origin)

    def test_concat_propagates(self):
        t = Taint()
        t.build(strip_noise('id := r.FormValue("id")\nq := "x" + id'))
        self.assertIn("q", t.origin)

    def test_sprintf_propagates(self):
        t = Taint()
        t.build(strip_noise('id := r.FormValue("id")\nq := fmt.Sprintf("x %s", id)'))
        self.assertIn("q", t.origin)

    def test_strconv_kills_taint(self):
        t = Taint()
        t.build(strip_noise('n, _ := strconv.Atoi(r.FormValue("n"))'))
        self.assertNotIn("n", t.origin)


class SinkTest(unittest.TestCase):
    def test_sql_via_concat_variable(self):
        code = body('id := r.URL.Query().Get("id")',
                    'q := "SELECT * FROM t WHERE id = " + id',
                    'db.Query(q)')
        self.assertIn("go.taint-sql", rules(code))

    def test_sql_sprintf(self):
        code = body('id := r.FormValue("id")',
                    'db.Query(fmt.Sprintf("... %s", id))')
        self.assertIn("go.taint-sql", rules(code))

    def test_command(self):
        code = body('name := r.FormValue("host")', 'exec.Command("ping", name)')
        self.assertIn("go.taint-command", rules(code))

    def test_file_read(self):
        code = body('p := r.URL.Query().Get("f")', 'os.ReadFile("/data/" + p)')
        self.assertIn("go.taint-file-read", rules(code))

    def test_ssrf(self):
        code = body('u := r.FormValue("url")', 'http.Get(u)')
        self.assertIn("go.taint-ssrf", rules(code))

    def test_open_redirect(self):
        code = body('n := r.URL.Query().Get("next")', 'http.Redirect(w, r, n, 302)')
        self.assertIn("go.taint-open-redirect", rules(code))

    def test_xss_fprintf(self):
        code = body('name := r.FormValue("n")', 'fmt.Fprintf(w, "<h1>%s</h1>", name)')
        self.assertIn("go.taint-xss", rules(code))

    def test_gin_source(self):
        code = ("func h(c *gin.Context, db *sql.DB) {\n"
                '\tid := c.Query("id")\n'
                '\tdb.Query("SELECT * FROM t WHERE id = " + id)\n}\n')
        self.assertIn("go.taint-sql", rules(code))


class SafeFormTest(unittest.TestCase):
    def test_parameterised_query_is_safe(self):
        code = body('id := r.URL.Query().Get("id")',
                    'db.Query("SELECT * FROM t WHERE id = $1", id)')
        self.assertNotIn("go.taint-sql", rules(code))

    def test_numeric_parse_is_safe(self):
        code = body('n, _ := strconv.Atoi(r.URL.Query().Get("n"))',
                    'db.Query(fmt.Sprintf("LIMIT %d", n))')
        self.assertNotIn("go.taint-sql", rules(code))

    def test_filepath_base_confines(self):
        code = body('name := filepath.Base(r.URL.Query().Get("f"))',
                    'os.ReadFile("/data/" + name)')
        self.assertNotIn("go.taint-file-read", rules(code))

    def test_html_escape_before_write(self):
        code = body('safe := template.HTMLEscapeString(r.FormValue("q"))',
                    'fmt.Fprintf(w, "<h1>%s</h1>", safe)')
        self.assertNotIn("go.taint-xss", rules(code))

    def test_constant_command_is_safe(self):
        code = body('exec.Command("ls", "-la", "/tmp")')
        self.assertNotIn("go.taint-command", rules(code))

    def test_constant_query_is_safe(self):
        code = body('db.Query("SELECT 1")')
        self.assertNotIn("go.taint-sql", rules(code))


class FlowSensitivityTest(unittest.TestCase):
    def test_reassignment_to_constant_clears_taint(self):
        code = body('name := r.FormValue("host")',
                    'name = "fixed"',
                    'exec.Command("ping", name)')
        self.assertNotIn("go.taint-command", rules(code))


if __name__ == "__main__":
    unittest.main()
