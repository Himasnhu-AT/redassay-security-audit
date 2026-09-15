"""The Ruby taint scanner.

Motivated by the same blind spot that drove the PHP scanner: line-oriented rules
see a request accessor only when it sits on the sink line, and miss the common
shape where the value reaches the sink through a local variable and string
interpolation - `name = params[:name]; User.where("... #{name}")`.

The failure directions are asymmetric, so the tests weight them: a missed sink is
a vulnerability the tool cannot see, a flagged safe line is noise. Ruby's
propagation vector is interpolation, and its safe query forms (parameterised and
hash conditions) look superficially like the unsafe ones, so those are the FP
cases the suite pins down.
"""

import unittest

from .helpers import run_scanner
from redassay.scanners.ruby import RubyTaintScanner, strip_noise, Taint


def scan(code: str, path: str = "app.rb"):
    return run_scanner(RubyTaintScanner(), path, code, "ruby")


def rules(code: str):
    return {f.rule_id for f in scan(code)}


class StrippingTest(unittest.TestCase):
    def test_interpolation_is_kept(self):
        code = 'x = "name = \'#{name}\'"'
        self.assertIn("#{name}", strip_noise(code))

    def test_literal_text_is_blanked(self):
        code = 'q = "SELECT secret FROM t"'
        stripped = strip_noise(code)
        self.assertNotIn("SELECT secret", stripped)
        self.assertIn('"', stripped)

    def test_single_quotes_have_no_interpolation(self):
        code = "x = 'literal #{not_interp}'"
        # In a single-quoted string #{...} is literal text, so it is blanked.
        self.assertNotIn("not_interp", strip_noise(code))

    def test_comment_is_blanked_but_interpolation_survives(self):
        code = 'y = "a #{z}"  # params[:evil] in a comment\n'
        stripped = strip_noise(code)
        self.assertIn("#{z}", stripped)
        self.assertNotIn("evil", stripped)

    def test_offsets_and_newlines_preserved(self):
        code = 'q = "abc"\nsystem(cmd)\n'
        self.assertEqual(len(strip_noise(code)), len(code))
        self.assertEqual(strip_noise(code).count("\n"), code.count("\n"))


class TaintPropagationTest(unittest.TestCase):
    def test_direct_source_assignment_taints(self):
        t = Taint()
        t.build(strip_noise("name = params[:name]"))
        self.assertIn("name", t.origin)

    def test_chain_propagates(self):
        t = Taint()
        t.build(strip_noise("a = params[:x]\nb = a\nc = b"))
        self.assertIn("c", t.origin)

    def test_numeric_coercion_kills_taint(self):
        t = Taint()
        t.build(strip_noise("n = params[:n].to_i"))
        self.assertNotIn("n", t.origin)

    def test_constant_is_not_tainted(self):
        t = Taint()
        t.build(strip_noise('title = "Static"'))
        self.assertNotIn("title", t.origin)


class SinkTest(unittest.TestCase):
    def test_sql_interpolation(self):
        code = 'name = params[:name]\nUser.where("name = \'#{name}\'")'
        self.assertIn("ruby.taint-sql", rules(code))

    def test_sql_concatenation(self):
        code = 'q = params[:q]\nPost.order("created_at " + q)'
        self.assertIn("ruby.taint-sql", rules(code))

    def test_command_concat(self):
        code = 'h = params[:host]\nsystem("ping " + h)'
        self.assertIn("ruby.taint-command", rules(code))

    def test_command_backticks(self):
        code = 'h = params[:host]\nout = `traceroute #{h}`'
        self.assertIn("ruby.taint-command", rules(code))

    def test_template_injection(self):
        code = 's = params[:s]\nERB.new("#{s}").result(binding)'
        self.assertIn("ruby.taint-template-injection", rules(code))

    def test_render_inline_injection(self):
        code = 'render inline: "Hello #{params[:name]}"'
        self.assertIn("ruby.taint-template-injection", rules(code))

    def test_file_read_traversal(self):
        code = 'p = params[:file]\nFile.read("/data/#{p}")'
        self.assertIn("ruby.taint-file-read", rules(code))

    def test_deserialize(self):
        code = 'b = params[:data]\nMarshal.load(b)'
        self.assertIn("ruby.taint-deserialize", rules(code))

    def test_open_redirect(self):
        code = 'u = params[:next]\nredirect_to u'
        self.assertIn("ruby.taint-open-redirect", rules(code))

    def test_cookies_are_a_source(self):
        code = 'b = cookies[:state]\nMarshal.load(b)'
        self.assertIn("ruby.taint-deserialize", rules(code))


class SafeFormTest(unittest.TestCase):
    """The forms that superficially resemble injection but are safe. A hit here
    is noise that trains people to ignore the tool."""

    def test_parameterised_query_is_safe(self):
        code = 'name = params[:name]\nUser.where("name = ?", name)'
        self.assertNotIn("ruby.taint-sql", rules(code))

    def test_hash_condition_is_safe(self):
        code = 'User.where(name: params[:name])'
        self.assertNotIn("ruby.taint-sql", rules(code))

    def test_numeric_coercion_is_safe(self):
        code = 'age = params[:age].to_i\nUser.where("age = #{age}")'
        self.assertNotIn("ruby.taint-sql", rules(code))

    def test_basename_confines_path(self):
        code = 's = File.basename(params[:file])\nFile.read("/data/#{s}")'
        self.assertNotIn("ruby.taint-file-read", rules(code))

    def test_html_escape_before_html_safe(self):
        code = 'g = ERB::Util.html_escape(params[:q])\ng.html_safe'
        self.assertNotIn("ruby.taint-xss", rules(code))

    def test_untainted_local_in_command_is_safe(self):
        code = 'greeting = "hello"\nsystem("echo #{greeting}")'
        self.assertNotIn("ruby.taint-command", rules(code))

    def test_constant_template_is_safe(self):
        code = 'ERB.new("static #{1 + 1}").result(binding)'
        self.assertNotIn("ruby.taint-template-injection", rules(code))

    def test_prose_mentioning_params_is_not_a_source(self):
        code = 'puts "read params[:x] from the query string"'
        self.assertEqual(rules(code), set())


class FlowSensitivityTest(unittest.TestCase):
    def test_reassignment_to_constant_clears_taint(self):
        code = (
            'x = params[:x]\n'
            'x = "safe-constant"\n'
            'system("echo " + x)'
        )
        # x is a constant by the time it reaches the sink.
        self.assertNotIn("ruby.taint-command", rules(code))


if __name__ == "__main__":
    unittest.main()
