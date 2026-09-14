import os
import unittest

from .helpers import TempRepo
from redassay import languages
from redassay.walker import WalkOptions, collect, ignored, looks_binary, load_gitignore, summarize


class LanguageDetectionTest(unittest.TestCase):
    def test_by_extension(self):
        self.assertEqual(languages.detect("a/b.py"), "python")
        self.assertEqual(languages.detect("a/b.tsx"), "typescript")
        self.assertEqual(languages.detect("a/b.tf"), "terraform")

    def test_by_filename(self):
        self.assertEqual(languages.detect("Dockerfile"), "dockerfile")
        self.assertEqual(languages.detect("svc/Dockerfile.prod"), "dockerfile")
        self.assertEqual(languages.detect("package.json"), "npm-manifest")
        self.assertEqual(languages.detect(".env.production"), "dotenv")

    def test_unknown(self):
        self.assertIsNone(languages.detect("a/b.qqq"))

    def test_classification_helpers(self):
        self.assertTrue(languages.is_source("a.py"))
        self.assertTrue(languages.is_manifest("go.mod"))
        self.assertTrue(languages.is_config("deploy.yaml"))
        self.assertFalse(languages.is_source("README.md"))

    def test_comment_prefixes(self):
        self.assertIn("#", languages.comment_prefixes("python"))
        self.assertIn("//", languages.comment_prefixes("javascript"))
        self.assertIn("--", languages.comment_prefixes("sql"))


class IgnoreMatchingTest(unittest.TestCase):
    def test_literal_name(self):
        self.assertTrue(ignored(["secrets.txt"], "a/b/secrets.txt"))

    def test_extension_glob(self):
        self.assertTrue(ignored(["*.log"], "var/app.log"))
        self.assertFalse(ignored(["*.log"], "var/app.txt"))

    def test_directory_entry_only_matches_directories(self):
        self.assertTrue(ignored(["build/"], "build", is_dir=True))
        self.assertFalse(ignored(["build/"], "build", is_dir=False))

    def test_anchored_pattern(self):
        self.assertTrue(ignored(["/dist"], "dist/app.js"))
        self.assertFalse(ignored(["/dist"], "src/dist/app.js"))

    def test_negation_wins_when_it_comes_last(self):
        patterns = ["*.env", "!.env.example"]
        self.assertTrue(ignored(patterns, ".env"))
        self.assertFalse(ignored(patterns, ".env.example"))


class WalkTest(TempRepo):
    def test_finds_source_and_skips_noise(self):
        self.write("app/main.py", "print('hi')\n")
        self.write("node_modules/pkg/index.js", "module.exports = 1\n")
        self.write("app/bundle.min.js", "var a=1\n")
        self.write("logo.png", "\x89PNG\x00\x00binary")
        paths = {f.path for f in collect(self.root)}
        self.assertIn("app/main.py", paths)
        self.assertNotIn("node_modules/pkg/index.js", paths)
        self.assertNotIn("app/bundle.min.js", paths)
        self.assertNotIn("logo.png", paths)

    def test_honours_gitignore(self):
        self.write(".gitignore", "secret/\n*.bak\n")
        self.write("secret/keys.py", "KEY = 1\n")
        self.write("app/old.bak", "stale\n")
        self.write("app/live.py", "x = 1\n")
        paths = {f.path for f in collect(self.root)}
        self.assertEqual(paths & {"secret/keys.py", "app/old.bak"}, set())
        self.assertIn("app/live.py", paths)

    def test_redassayignore_is_honoured_too(self):
        self.write(".redassayignore", "vendor/\n")
        self.write("vendor/lib.py", "x = 1\n")
        self.write("app.py", "x = 1\n")
        self.assertEqual({f.path for f in collect(self.root)}, {"app.py", ".redassayignore"})

    def test_include_narrows_the_walk(self):
        self.write("app/a.py", "x = 1\n")
        self.write("lib/b.py", "x = 1\n")
        files = collect(self.root, WalkOptions(include=["app/"]))
        self.assertEqual([f.path for f in files], ["app/a.py"])

    def test_size_limit(self):
        self.write("big.py", "x = 1\n" * 5000)
        files = collect(self.root, WalkOptions(max_bytes=100))
        self.assertEqual(files, [])

    def test_language_filter(self):
        self.write("a.py", "x = 1\n")
        self.write("b.js", "var x = 1\n")
        files = collect(self.root, WalkOptions(languages={"python"}))
        self.assertEqual([f.path for f in files], ["a.py"])

    def test_results_are_deterministic(self):
        for name in ("c.py", "a.py", "b.py"):
            self.write(name, "x = 1\n")
        first = [f.path for f in collect(self.root)]
        self.assertEqual(first, sorted(first))
        self.assertEqual(first, [f.path for f in collect(self.root)])

    def test_source_file_reads_lazily_and_caches(self):
        self.write("a.py", "line one\nline two\n")
        source = collect(self.root)[0]
        self.assertEqual(source.lines(), ["line one", "line two"])
        self.assertEqual(source.read(), source.read())

    def test_summarize(self):
        self.write("a.py", "x = 1\n")
        self.write("b.py", "x = 1\n")
        self.write("c.js", "var x = 1\n")
        total, by_language = summarize(collect(self.root))
        self.assertGreater(total, 0)
        self.assertEqual(by_language["python"], 2)


class VendoredCoreTest(TempRepo):
    """WordPress core is third-party code the user did not write - the same
    category as vendor/ and node_modules/."""

    def test_wp_admin_and_wp_includes_are_skipped(self):
        self.write("wp-admin/includes/ajax.php", "<?php echo 1;\n")
        self.write("wp-includes/functions.php", "<?php echo 1;\n")
        self.write("wp-content/themes/mine/index.php", "<?php echo 1;\n")
        self.write("index.php", "<?php echo 1;\n")
        paths = {f.path for f in collect(self.root)}
        self.assertNotIn("wp-admin/includes/ajax.php", paths)
        self.assertNotIn("wp-includes/functions.php", paths)

    def test_wp_content_is_kept_because_it_is_the_users_code(self):
        self.write("wp-content/plugins/mine/plugin.php", "<?php echo 1;\n")
        self.assertIn("wp-content/plugins/mine/plugin.php", {f.path for f in collect(self.root)})


class BinaryDetectionTest(TempRepo):
    def test_null_bytes_mean_binary(self):
        path = self.write("a.bin", "abc")
        with open(path, "wb") as handle:
            handle.write(b"abc\x00def")
        self.assertTrue(looks_binary(path))

    def test_plain_text_is_not_binary(self):
        self.assertFalse(looks_binary(self.write("a.txt", "hello world\n")))

    def test_empty_file_is_not_binary(self):
        self.assertFalse(looks_binary(self.write("empty.txt", "")))

    def test_missing_file_is_treated_as_binary(self):
        self.assertTrue(looks_binary(os.path.join(self.root, "nope")))


if __name__ == "__main__":
    unittest.main()


class ExcludeTestsTest(TempRepo):
    """Driven by the Django evaluation: 59% of findings came from its test suite."""

    def setUp(self):
        super().setUp()
        self.write("app/main.py", "x = 1\n")
        self.write("tests/test_main.py", "x = 1\n")
        self.write("app/main_test.go", "x = 1\n")
        self.write("src/component.test.js", "x = 1\n")
        self.write("spec/thing_spec.rb", "x = 1\n")
        self.write("app/contest.py", "x = 1\n")          # not a test directory

    def test_off_by_default(self):
        paths = {f.path for f in collect(self.root)}
        self.assertIn("tests/test_main.py", paths)
        self.assertIn("src/component.test.js", paths)

    def test_test_directories_are_skipped(self):
        paths = {f.path for f in collect(self.root, WalkOptions(exclude_tests=True))}
        self.assertNotIn("tests/test_main.py", paths)
        self.assertNotIn("spec/thing_spec.rb", paths)

    def test_test_files_outside_test_directories_are_skipped(self):
        paths = {f.path for f in collect(self.root, WalkOptions(exclude_tests=True))}
        self.assertNotIn("app/main_test.go", paths)
        self.assertNotIn("src/component.test.js", paths)

    def test_production_code_is_kept(self):
        paths = {f.path for f in collect(self.root, WalkOptions(exclude_tests=True))}
        self.assertIn("app/main.py", paths)

    def test_a_name_that_merely_contains_test_is_kept(self):
        paths = {f.path for f in collect(self.root, WalkOptions(exclude_tests=True))}
        self.assertIn("app/contest.py", paths)
