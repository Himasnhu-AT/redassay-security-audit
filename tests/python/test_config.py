import json
import os
import unittest

from .helpers import TempRepo
from redassay import config as config_mod
from redassay.config import Config, _coerce_toml_value, _parse_toml_section


class DefaultsTest(TempRepo):
    def test_defaults(self):
        config = config_mod.load(self.root)
        self.assertEqual(config.port, config_mod.DEFAULT_PORT)
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.min_severity, "info")
        self.assertTrue(config.respect_gitignore)

    def test_root_is_absolute(self):
        self.assertTrue(os.path.isabs(config_mod.load(".").root))


class TomlParsingTest(TempRepo):
    def test_scalars(self):
        self.write("pyproject.toml", "[tool.redassay]\nport = 9000\nauthor = \"ana\"\nrespect_gitignore = false\n")
        config = config_mod.load(self.root)
        self.assertEqual(config.port, 9000)
        self.assertEqual(config.author, "ana")
        self.assertFalse(config.respect_gitignore)

    def test_single_line_array(self):
        self.write("pyproject.toml", '[tool.redassay]\ndisabled_rules = ["a.b", "c.d"]\n')
        self.assertEqual(config_mod.load(self.root).disabled_rules, ["a.b", "c.d"])

    def test_multi_line_array_with_comments(self):
        self.write("pyproject.toml", (
            "[tool.redassay]\n"
            "disabled_rules = [\n"
            "  # this one is noisy in generated code\n"
            '  "a.b",\n'
            '  "c.d",\n'
            "]\n"
        ))
        self.assertEqual(config_mod.load(self.root).disabled_rules, ["a.b", "c.d"])

    def test_dashed_keys_become_underscored(self):
        self.write("pyproject.toml", '[tool.redassay]\nmin-severity = "high"\n')
        self.assertEqual(config_mod.load(self.root).min_severity, "high")

    def test_a_later_section_ends_ours(self):
        self.write("pyproject.toml", '[tool.redassay]\nport = 9000\n\n[tool.black]\nport = 1234\n')
        self.assertEqual(config_mod.load(self.root).port, 9000)

    def test_a_multiline_array_is_not_ended_by_a_bracketed_line(self):
        self.write("pyproject.toml", '[tool.redassay]\ndisabled_rules = [\n  "a.b",\n]\nport = 9000\n')
        config = config_mod.load(self.root)
        self.assertEqual(config.disabled_rules, ["a.b"])
        self.assertEqual(config.port, 9000)

    def test_no_pyproject_is_fine(self):
        self.assertEqual(_parse_toml_section(os.path.join(self.root, "nope.toml")), {})

    def test_no_redassay_section_is_fine(self):
        self.write("pyproject.toml", "[project]\nname = \"x\"\n")
        self.assertEqual(config_mod.load(self.root).port, config_mod.DEFAULT_PORT)

    def test_value_coercion(self):
        self.assertEqual(_coerce_toml_value("true"), True)
        self.assertEqual(_coerce_toml_value("42"), 42)
        self.assertEqual(_coerce_toml_value('"x"'), "x")
        self.assertEqual(_coerce_toml_value("[]"), [])
        self.assertEqual(_coerce_toml_value('["a", "b"]'), ["a", "b"])


class PrecedenceTest(TempRepo):
    def test_config_json_beats_pyproject(self):
        self.write("pyproject.toml", "[tool.redassay]\nport = 9000\n")
        os.makedirs(os.path.join(self.root, ".redassay"), exist_ok=True)
        self.write(".redassay/config.json", json.dumps({"port": 9100}))
        self.assertEqual(config_mod.load(self.root).port, 9100)

    def test_explicit_overrides_beat_everything(self):
        self.write("pyproject.toml", "[tool.redassay]\nport = 9000\n")
        self.assertEqual(config_mod.load(self.root, port=9200).port, 9200)

    def test_none_overrides_are_ignored(self):
        self.write("pyproject.toml", "[tool.redassay]\nport = 9000\n")
        self.assertEqual(config_mod.load(self.root, port=None).port, 9000)

    def test_empty_list_overrides_are_ignored(self):
        self.write("pyproject.toml", '[tool.redassay]\ndisabled_rules = ["a.b"]\n')
        self.assertEqual(config_mod.load(self.root, disabled_rules=[]).disabled_rules, ["a.b"])

    def test_environment_variables(self):
        os.environ["REDASSAY_PORT"] = "9300"
        os.environ["REDASSAY_MIN_SEVERITY"] = "blocker"
        self.addCleanup(os.environ.pop, "REDASSAY_PORT", None)
        self.addCleanup(os.environ.pop, "REDASSAY_MIN_SEVERITY", None)
        config = config_mod.load(self.root)
        self.assertEqual(config.port, 9300)
        self.assertEqual(config.min_severity, "critical")

    def test_a_junk_environment_value_is_ignored(self):
        os.environ["REDASSAY_PORT"] = "not-a-port"
        self.addCleanup(os.environ.pop, "REDASSAY_PORT", None)
        self.assertEqual(config_mod.load(self.root).port, config_mod.DEFAULT_PORT)

    def test_unknown_keys_are_dropped(self):
        self.write("pyproject.toml", '[tool.redassay]\nnonsense = "x"\nport = 9000\n')
        self.assertEqual(config_mod.load(self.root).port, 9000)


class RoundTripTest(TempRepo):
    def test_save_then_load(self):
        original = config_mod.load(self.root, port=9400, author="ana")
        config_mod.save(original)
        self.assertEqual(config_mod.load(self.root).port, 9400)

    def test_save_does_not_persist_the_root(self):
        config_mod.save(config_mod.load(self.root, port=9400))
        with open(os.path.join(self.root, ".redassay", "config.json")) as handle:
            self.assertNotIn("root", json.load(handle))


if __name__ == "__main__":
    unittest.main()
