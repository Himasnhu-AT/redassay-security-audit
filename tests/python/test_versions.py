import unittest

from . import _bootstrap  # noqa: F401
from redassay.versions import (
    compare, is_floating, loose_version, lt, parse, pinned_version, satisfies_vulnerable,
)


class ParseTest(unittest.TestCase):
    def test_strips_a_leading_v(self):
        self.assertEqual(parse("v1.2.3")[0], [1, 2, 3])

    def test_drops_build_metadata(self):
        self.assertEqual(parse("1.2.3+build99")[0], [1, 2, 3])

    def test_prerelease_rank_is_negative(self):
        self.assertLess(parse("1.0.0-rc1")[1], 0)
        self.assertEqual(parse("1.0.0")[1], 0)


class CompareTest(unittest.TestCase):
    def test_numeric_not_lexical(self):
        self.assertLess(compare("1.2.3", "1.10.0"), 0)
        self.assertLess(compare("2.9.0", "2.10.0"), 0)

    def test_equal(self):
        self.assertEqual(compare("1.0.0", "1.0.0"), 0)

    def test_different_lengths_are_zero_padded(self):
        self.assertEqual(compare("1.0", "1.0.0"), 0)
        self.assertLess(compare("1.0", "1.0.1"), 0)

    def test_prereleases_sort_below_the_release(self):
        self.assertLess(compare("1.0.0-rc1", "1.0.0"), 0)
        self.assertLess(compare("1.0.0-alpha", "1.0.0-rc1"), 0)
        self.assertLess(compare("2.0.0-beta", "2.0.0"), 0)

    def test_pep440_style(self):
        self.assertLess(compare("1.0.0a1", "1.0.0"), 0)

    def test_lt_helper(self):
        self.assertTrue(lt("1.0.0", "1.0.1"))
        self.assertFalse(lt("1.0.1", "1.0.0"))


class ConstraintTest(unittest.TestCase):
    def test_less_than(self):
        self.assertTrue(satisfies_vulnerable("4.17.15", "<4.17.21"))
        self.assertFalse(satisfies_vulnerable("4.17.21", "<4.17.21"))
        self.assertFalse(satisfies_vulnerable("5.0.0", "<4.17.21"))

    def test_less_than_or_equal(self):
        self.assertTrue(satisfies_vulnerable("1.0.0", "<=1.0.0"))

    def test_compound_range(self):
        self.assertTrue(satisfies_vulnerable("1.1.0", ">=1.0.0,<1.2.0"))
        self.assertFalse(satisfies_vulnerable("1.2.0", ">=1.0.0,<1.2.0"))
        self.assertFalse(satisfies_vulnerable("0.9.0", ">=1.0.0,<1.2.0"))

    def test_missing_input_is_never_vulnerable(self):
        self.assertFalse(satisfies_vulnerable("", "<1.0.0"))
        self.assertFalse(satisfies_vulnerable("1.0.0", ""))


class SpecTest(unittest.TestCase):
    def test_pinned_versions(self):
        self.assertEqual(pinned_version("==2.31.0"), "2.31.0")
        self.assertEqual(pinned_version("4.17.15"), "4.17.15")
        self.assertEqual(pinned_version("v1.2.3"), "1.2.3")

    def test_ranges_are_not_pinned(self):
        for spec in ("^4.17.15", "~1.2.0", ">=2.0.0", "*", "latest", "1.0.0 - 2.0.0", "1.x || 2.x"):
            self.assertIsNone(pinned_version(spec), spec)

    def test_loose_version_extracts_the_lower_bound(self):
        self.assertEqual(loose_version("^4.17.15"), "4.17.15")
        self.assertEqual(loose_version(">=2.0.0"), "2.0.0")
        self.assertIsNone(loose_version("*"))

    def test_is_floating(self):
        for spec in ("*", "latest", "^1.0.0", "~1.0.0", ">=1.0.0", "1.x || 2.x"):
            self.assertTrue(is_floating(spec), spec)
        for spec in ("1.0.0", "==1.0.0"):
            self.assertFalse(is_floating(spec), spec)


if __name__ == "__main__":
    unittest.main()
