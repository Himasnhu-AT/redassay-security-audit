import os
import subprocess
import unittest

from .helpers import TempRepo
from redassay import config as config_mod, gitinfo
from redassay.engine import scan


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)


class NotARepoTest(TempRepo):
    def test_every_query_degrades_quietly(self):
        self.assertFalse(gitinfo.is_repo(self.root))
        self.assertIsNone(gitinfo.current_branch(self.root))
        self.assertIsNone(gitinfo.head_sha(self.root))
        self.assertIsNone(gitinfo.changed_files(self.root))
        self.assertEqual(gitinfo.context(self.root), {})

    def test_blame_on_a_missing_file_is_none(self):
        self.assertIsNone(gitinfo.blame_line(self.root, "nope.py", 1))

    def test_annotate_is_a_no_op(self):
        from .helpers import make_finding
        self.assertEqual(gitinfo.annotate(self.root, [make_finding()]), 0)


class RepoTest(TempRepo):
    def setUp(self):
        super().setUp()
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "commit.gpgsign", "false")
        self.write("base.py", "x = 1\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "initial")

    def test_detects_the_repository(self):
        self.assertTrue(gitinfo.is_repo(self.root))
        self.assertEqual(gitinfo.current_branch(self.root), "main")
        self.assertEqual(len(gitinfo.head_sha(self.root)), 40)

    def test_context_carries_branch_and_head(self):
        context = gitinfo.context(self.root)
        self.assertEqual(context["branch"], "main")
        self.assertTrue(context["head"])

    def test_resolve_known_and_unknown_refs(self):
        self.assertTrue(gitinfo.resolve(self.root, "HEAD"))
        self.assertIsNone(gitinfo.resolve(self.root, "no-such-ref"))

    def test_changed_files_sees_modifications(self):
        self.write("base.py", "x = 2\n")
        self.assertEqual(gitinfo.changed_files(self.root, "HEAD"), ["base.py"])

    def test_changed_files_sees_untracked(self):
        self.write("added.py", "y = 1\n")
        self.assertIn("added.py", gitinfo.changed_files(self.root, "HEAD"))

    def test_untracked_can_be_excluded(self):
        self.write("added.py", "y = 1\n")
        self.assertNotIn("added.py", gitinfo.changed_files(self.root, "HEAD", include_untracked=False))

    def test_nothing_changed_is_an_empty_list_not_none(self):
        self.assertEqual(gitinfo.changed_files(self.root, "HEAD"), [])

    def test_an_unknown_ref_is_none_not_empty(self):
        """The distinction matters: a CI gate must not pass because it could not ask."""
        self.assertIsNone(gitinfo.changed_files(self.root, "no-such-ref"))

    def test_blame_identifies_the_commit(self):
        blame = gitinfo.blame_line(self.root, "base.py", 1)
        self.assertIsNotNone(blame)
        self.assertEqual(blame.author, "Test")
        self.assertEqual(len(blame.short_sha), 8)

    def test_blame_on_line_zero_is_none(self):
        self.assertIsNone(gitinfo.blame_line(self.root, "base.py", 0))

    def test_remote_url_normalizes_scp_syntax(self):
        git(self.root, "remote", "add", "origin", "git@github.com:acme/thing.git")
        self.assertEqual(gitinfo.remote_url(self.root), "https://github.com/acme/thing")


class ScopedScanTest(RepoTest):
    VULNERABLE = "import os\nos.system(user_input)\n"

    def test_since_limits_the_walk_to_changed_files(self):
        self.write("old.py", self.VULNERABLE)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "pre-existing")

        self.write("new.py", self.VULNERABLE)
        result = scan(config_mod.load(self.root), since="HEAD")
        self.assertEqual(result.scoped_to, ["new.py"])
        self.assertTrue(all(f.path == "new.py" for f in result.findings))

    def test_an_unchanged_tree_scans_nothing(self):
        result = scan(config_mod.load(self.root), since="HEAD")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 0)

    def test_a_bad_ref_raises_rather_than_scanning_everything(self):
        with self.assertRaises(ValueError):
            scan(config_mod.load(self.root), since="no-such-ref")

    def test_include_intersects_with_the_diff(self):
        self.write("app/a.py", self.VULNERABLE)
        self.write("lib/b.py", self.VULNERABLE)
        result = scan(config_mod.load(self.root, include=["app/"]), since="HEAD")
        self.assertEqual(result.scoped_to, ["app/a.py"])

    def test_a_scoped_scan_does_not_retire_findings_elsewhere(self):
        from redassay.engine import scan_and_merge
        from redassay.store import Store

        self.write("old.py", self.VULNERABLE)
        config = config_mod.load(self.root)
        scan_and_merge(config)
        old_id = Store.open(self.root).all()[0].id
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "add old")

        self.write("new.py", self.VULNERABLE)
        result = scan_and_merge(config, since="HEAD")
        self.assertNotIn(old_id, result.merge.absent)
        self.assertIsNotNone(Store.open(self.root).get(old_id))

    def test_blame_tags_the_findings(self):
        self.write("old.py", self.VULNERABLE)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "add old")
        result = scan(config_mod.load(self.root), blame=True)
        tags = [t for f in result.findings for t in f.tags]
        self.assertTrue(any(t.startswith("commit:") for t in tags))
        self.assertTrue(any(t.startswith("author:") for t in tags))


if __name__ == "__main__":
    unittest.main()
