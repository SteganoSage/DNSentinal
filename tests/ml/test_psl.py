"""The Public Suffix List rules (https://publicsuffix.org/list/), on a small
hand-made list and on the pinned snapshot in config/."""

import unittest

from ml.dga.psl import PublicSuffixList, default_list


class SpecRules(unittest.TestCase):
    """The algorithm's corner cases, on a list small enough to read."""

    psl = PublicSuffixList(["com", "uk", "co.uk", "*.ck", "!www.ck", "jp", "*.kawasaki.jp", "!city.kawasaki.jp"])

    def test_longest_rule_wins(self):
        self.assertEqual(self.psl.public_suffix("www.example.co.uk"), "co.uk")
        self.assertEqual(self.psl.registrable_domain("www.example.co.uk"), "example.co.uk")

    def test_a_public_suffix_has_no_registrable_domain(self):
        self.assertIsNone(self.psl.registrable_domain("co.uk"))
        self.assertIsNone(self.psl.registrable_domain("com"))

    def test_unlisted_tld_is_its_own_suffix(self):
        self.assertEqual(self.psl.registrable_domain("a.b.example.zz"), "example.zz")

    def test_wildcard_matches_one_label(self):
        self.assertEqual(self.psl.public_suffix("foo.bar.ck"), "bar.ck")
        self.assertEqual(self.psl.registrable_domain("x.foo.bar.ck"), "foo.bar.ck")
        self.assertIsNone(self.psl.registrable_domain("bar.ck"))

    def test_exception_beats_its_wildcard(self):
        self.assertEqual(self.psl.registrable_domain("www.ck"), "www.ck")
        self.assertEqual(self.psl.registrable_domain("a.b.www.ck"), "www.ck")
        self.assertEqual(self.psl.registrable_domain("city.kawasaki.jp"), "city.kawasaki.jp")
        self.assertEqual(self.psl.registrable_domain("a.b.c.kawasaki.jp"), "b.c.kawasaki.jp")


class PinnedSnapshot(unittest.TestCase):
    """config/public_suffix_list.dat, the file the resolver reads too."""

    psl = default_list()

    def test_it_is_the_pinned_version(self):
        self.assertEqual(self.psl.version, "2026-10-16_09-29-46_UTC")
        self.assertEqual(self.psl.skipped, 0)

    def test_private_section_is_used(self):
        # A DGA name under a dynamic-DNS provider is its own registrable domain.
        self.assertEqual(self.psl.registrable_domain("cvyh1po636.ddns.net"), "cvyh1po636.ddns.net")
        self.assertEqual(self.psl.registrable_domain("x.foo.blogspot.com"), "foo.blogspot.com")

    def test_idn_rules_match_punycode_names(self):
        # 公司.cn is a public suffix, listed in Unicode; DNS carries it as punycode.
        self.assertEqual(self.psl.public_suffix("xn--85x722f.xn--55qx5d.cn"), "xn--55qx5d.cn")


if __name__ == "__main__":
    unittest.main()
