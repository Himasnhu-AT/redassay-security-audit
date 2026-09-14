"""The PHP taint scanner.

Motivated by a concrete miss: a head-to-head against a manual reviewer showed
redassay's line-oriented PHP rules could not see request data that reaches a
sink through a variable - `$name = $_POST['x']; echo $name;`. This scanner
closes that, following the JS scanner's normalized-view approach.

The failure directions are asymmetric, so the tests weight them: a missed sink
is a vulnerability the tool cannot see, while a flagged safe line is noise that
teaches people to skim. PHP being a template language, the normalizer must also
not mistake an HTML attribute quote for a string delimiter.
"""

import unittest

from .helpers import by_rule, run_scanner
from redassay.scanners.php import PhpTaintScanner, strip_noise, Taint, _php_regions


def scan(code: str, path: str = "index.php"):
    return run_scanner(PhpTaintScanner(), path, code, "php")


def rules(code: str):
    return {f.rule_id for f in scan(code)}


class RegionStrippingTest(unittest.TestCase):
    """PHP is a template: only text inside <?php ... ?> is code."""

    def test_html_attribute_quotes_are_not_string_delimiters(self):
        code = '<input value="<?php echo $x; ?>">'
        # The echo must survive - it is the sink. If the stripper treated the
        # attribute as a PHP string it would blank $x.
        self.assertIn("echo $x", strip_noise(code))

    def test_a_real_php_string_body_is_blanked(self):
        code = '<?php $q = "SELECT secret FROM t"; ?>'
        stripped = strip_noise(code)
        self.assertNotIn("SELECT secret", stripped)
        self.assertIn('"', stripped)

    def test_a_pure_html_file_is_untouched(self):
        html = '<div class="x">no php here</div>\n'
        self.assertEqual(strip_noise(html), html)

    def test_regions_track_open_and_close(self):
        code = 'A<?php $x=1; ?>B<?= $y ?>C'
        regions = _php_regions(code)
        self.assertEqual(len(regions), 2)

    def test_offsets_are_preserved(self):
        code = '<?php $q = "abc"; echo $q; ?>\nsecond line\n'
        self.assertEqual(strip_noise(code).count("\n"), code.count("\n"))
        self.assertEqual(len(strip_noise(code)), len(code))

    def test_comments_inside_php_are_blanked(self):
        code = "<?php // system($_GET['x'])\n$safe = 1; ?>"
        self.assertNotIn("system", strip_noise(code))


class TaintPropagationTest(unittest.TestCase):
    def _taint(self, code):
        t = Taint()
        t.build(strip_noise(code))
        return t

    def test_a_direct_source_assignment_taints(self):
        t = self._taint('<?php $x = $_GET["a"]; ?>')
        self.assertIn("x", t.origin)
        self.assertEqual(t.origin["x"], "$_GET")

    def test_taint_survives_trim(self):
        t = self._taint('<?php $x = trim($_POST["a"]); ?>')
        self.assertIn("x", t.origin)

    def test_a_numeric_coercion_removes_taint(self):
        t = self._taint('<?php $x = intval($_GET["a"]); ?>')
        self.assertNotIn("x", t.origin)

    def test_a_cast_removes_taint(self):
        t = self._taint('<?php $x = (int)$_GET["a"]; ?>')
        self.assertNotIn("x", t.origin)

    def test_taint_propagates_through_a_variable(self):
        t = self._taint('<?php $a = $_GET["x"]; $b = $a; $c = "p" . $b; ?>')
        for name in ("a", "b", "c"):
            self.assertIn(name, t.origin)

    def test_htmlspecialchars_marks_cleaned_for_xss_only(self):
        t = self._taint('<?php $x = htmlspecialchars($_GET["a"]); ?>')
        self.assertIn("x", t.origin)
        self.assertIn("xss", t.cleaned.get("x", set()))
        self.assertNotIn("sql", t.cleaned.get("x", set()))

    def test_cleaning_carries_forward_through_assignment(self):
        t = self._taint('<?php $a = basename($_GET["f"]); $b = "d/" . $a; ?>')
        self.assertIn("path", t.cleaned.get("b", set()))


class SinkTest(unittest.TestCase):
    def test_reflected_xss_through_a_variable(self):
        code = '<?php $n = $_POST["name"]; ?>\n<span><?php echo $n; ?></span>'
        self.assertIn("php.taint-xss", rules(code))

    def test_reflected_xss_in_an_html_attribute(self):
        code = '<?php $n = trim($_POST["name"]); ?>\n<input value="<?php echo $n; ?>">'
        self.assertIn("php.taint-xss", rules(code))

    def test_escaped_output_is_clean(self):
        code = '<?php $n = $_POST["name"]; ?>\n<span><?php echo htmlspecialchars($n); ?></span>'
        self.assertNotIn("php.taint-xss", rules(code))

    def test_file_inclusion_through_a_variable(self):
        code = '<?php $p = $_GET["page"]; include($p . ".php"); ?>'
        self.assertIn("php.taint-file-inclusion", rules(code))

    def test_an_allowlist_lookup_is_not_inclusion(self):
        code = ('<?php $pages = ["a" => "a.php"]; $k = $_GET["p"];'
                ' if (isset($pages[$k])) include($pages[$k]); ?>')
        self.assertNotIn("php.taint-file-inclusion", rules(code))

    def test_sql_through_concatenation(self):
        code = '<?php $id = $_GET["id"]; $r = $db->query("SELECT * FROM u WHERE id = " . $id); ?>'
        self.assertIn("php.taint-sql", rules(code))

    def test_prepared_statement_is_clean(self):
        code = '<?php $s = $db->prepare("SELECT * FROM u WHERE id = ?"); $s->execute([$_GET["id"]]); ?>'
        self.assertNotIn("php.taint-sql", rules(code))

    def test_command_injection_through_a_variable(self):
        code = '<?php $h = $_GET["host"]; system("ping " . $h); ?>'
        self.assertIn("php.taint-command", rules(code))

    def test_escapeshellarg_is_clean(self):
        code = '<?php $h = $_GET["host"]; system("ping " . escapeshellarg($h)); ?>'
        self.assertNotIn("php.taint-command", rules(code))

    def test_numeric_command_argument_is_clean(self):
        code = '<?php $c = intval($_GET["n"]); system("report --count " . $c); ?>'
        self.assertNotIn("php.taint-command", rules(code))

    def test_path_traversal_through_a_variable(self):
        code = '<?php $f = $_GET["file"]; echo file_get_contents("/data/" . $f); ?>'
        self.assertIn("php.taint-file-read", rules(code))

    def test_basename_confines_the_path(self):
        code = '<?php $f = basename($_GET["file"]); readfile("/data/" . $f); ?>'
        self.assertNotIn("php.taint-file-read", rules(code))

    def test_unserialize_of_a_cookie(self):
        code = '<?php $s = $_COOKIE["state"]; $o = unserialize($s); ?>'
        self.assertIn("php.taint-unserialize", rules(code))

    def test_header_redirect_from_input(self):
        code = '<?php $u = $_GET["next"]; header("Location: " . $u); ?>'
        self.assertIn("php.taint-header", rules(code))

    def test_confirmed_taint_is_high_confidence(self):
        code = '<?php $h = $_GET["host"]; system("ping " . $h); ?>'
        finding = by_rule(scan(code))["php.taint-command"][0]
        self.assertEqual(finding.confidence, "high")


class NoiseControlTest(unittest.TestCase):
    def test_an_echo_of_a_non_request_variable_is_silent(self):
        code = '<?php $title = $post->title; echo $title; ?>'
        self.assertNotIn("php.taint-xss", rules(code))

    def test_a_file_with_no_superglobal_is_skipped(self):
        self.assertEqual(scan('<?php echo "hello"; ?>'), [])

    def test_a_server_key_that_is_not_request_derived_is_not_a_source(self):
        code = '<?php $t = $_SERVER["SERVER_ADDR"]; echo $t; ?>'
        self.assertNotIn("php.taint-xss", rules(code))

    def test_a_request_server_key_is_a_source(self):
        code = '<?php $r = $_SERVER["HTTP_REFERER"]; echo $r; ?>'
        self.assertIn("php.taint-xss", rules(code))

    def test_files_tmp_name_is_not_attacker_controlled(self):
        """$_FILES[...]['tmp_name'] is the server's temp path, not the client's."""
        code = '<?php $c = file_get_contents($_FILES["f"]["tmp_name"]); ?>'
        self.assertNotIn("php.taint-file-read", rules(code))

    def test_files_name_is_attacker_controlled(self):
        code = '<?php readfile("/d/" . $_FILES["f"]["name"]); ?>'
        self.assertIn("php.taint-file-read", rules(code))

    def test_a_wordpress_escaper_is_recognised(self):
        code = '<?php $n = $_POST["name"]; echo esc_html($n); ?>'
        self.assertNotIn("php.taint-xss", rules(code))

    def test_esc_url_and_esc_attr_are_recognised(self):
        self.assertNotIn("php.taint-xss", rules('<?php echo esc_url($_GET["u"]); ?>'))
        self.assertNotIn("php.taint-xss", rules('<?php echo esc_attr($_GET["a"]); ?>'))

    def test_the_laravel_e_helper_is_recognised(self):
        self.assertNotIn("php.taint-xss", rules('<?php echo e($_GET["x"]); ?>'))

    def test_absint_coerces_to_a_number(self):
        code = '<?php $id = absint($_GET["id"]); system("job " . $id); ?>'
        self.assertNotIn("php.taint-command", rules(code))

    def test_an_inline_suppression_is_honoured(self):
        code = ('<?php $n = $_POST["name"]; // redassay: ignore php.taint-xss - trusted admin form\n'
                'echo $n; ?>')
        self.assertNotIn("php.taint-xss", rules(code))


if __name__ == "__main__":
    unittest.main()
