import unittest

from . import _bootstrap  # noqa: F401
from redassay import severity as sev


class NormalizeTest(unittest.TestCase):
    def test_canonical_names_pass_through(self):
        for name in sev.ORDER:
            self.assertEqual(sev.normalize(name), name)

    def test_case_and_whitespace_are_ignored(self):
        self.assertEqual(sev.normalize("  HIGH "), sev.HIGH)

    def test_aliases_are_folded(self):
        self.assertEqual(sev.normalize("blocker"), sev.CRITICAL)
        self.assertEqual(sev.normalize("warning"), sev.MEDIUM)
        self.assertEqual(sev.normalize("informational"), sev.INFO)

    def test_unknown_defaults_to_medium(self):
        self.assertEqual(sev.normalize("spicy"), sev.MEDIUM)
        self.assertEqual(sev.normalize(None), sev.MEDIUM)


class OrderingTest(unittest.TestCase):
    def test_critical_outranks_everything(self):
        self.assertTrue(all(sev.rank(sev.CRITICAL) < sev.rank(x) for x in sev.ORDER[1:]))

    def test_at_least_is_inclusive(self):
        self.assertTrue(sev.at_least(sev.HIGH, sev.HIGH))
        self.assertTrue(sev.at_least(sev.CRITICAL, sev.HIGH))
        self.assertFalse(sev.at_least(sev.LOW, sev.HIGH))

    def test_sorting_by_rank_puts_worst_first(self):
        shuffled = [sev.LOW, sev.CRITICAL, sev.MEDIUM, sev.INFO, sev.HIGH]
        self.assertEqual(sorted(shuffled, key=sev.rank), sev.ORDER)


class CvssBandTest(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(sev.cvss_band(9.8), sev.CRITICAL)
        self.assertEqual(sev.cvss_band(7.5), sev.HIGH)
        self.assertEqual(sev.cvss_band(5.3), sev.MEDIUM)
        self.assertEqual(sev.cvss_band(2.1), sev.LOW)
        self.assertEqual(sev.cvss_band(0.0), sev.INFO)


if __name__ == "__main__":
    unittest.main()
