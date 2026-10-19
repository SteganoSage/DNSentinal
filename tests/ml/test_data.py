"""The dataset builder, without the network: smoke data, blocklists, generation."""

import csv
import tempfile
import textwrap
import unittest
from pathlib import Path

from ml.dga import data


class SmokeDataset(unittest.TestCase):
    def test_same_files_and_columns_as_the_real_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            data.build_smoke(out, per_family=20, benign=100)
            rows = data.read_csv(out / "dga_dataset.csv")
            self.assertEqual(list(rows[0]), data.COLUMNS)
            self.assertEqual(len(rows), 100 + 4 * 20)
            self.assertEqual(len({r["domain"] for r in rows}), len(rows))
            self.assertEqual({r["kind"] for r in rows}, {"benign", "dga", "dictionary"})
            self.assertTrue(any(r["stable"] for r in rows) and not all(r["stable"] for r in rows if r["label"] == 0))
            external = data.read_csv(out / "external_netlab.csv")
            self.assertTrue(external and all(r["source"] == "netlab" for r in external))
            self.assertTrue((out / "blocklist_snapshot.txt").read_text().strip())


class Blocklist(unittest.TestCase):
    def test_host_files_are_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            for name in data.BLOCKLISTS:  # already "downloaded": fetch() reuses them
                (cache / f"blocklist_{name}.txt").write_text(
                    f"# comment\n127.0.0.1\tBad-{name}.example.\n\n127.0.0.1 not..valid\n")
            names, sources = data.blocklist(cache)
            self.assertEqual(names, {f"bad-{name}.example" for name in data.BLOCKLISTS})
            self.assertTrue(all(len(s["sha256"]) == 64 for s in sources.values()))


class Generation(unittest.TestCase):
    def test_names_spread_over_dates_and_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "fake").mkdir()
            (repo / "fake" / "dga.py").write_text(textwrap.dedent("""
                import sys
                day = sys.argv[sys.argv.index("-d") + 1].replace("-", "")
                for i in range(5):
                    print(f"n{day}x{i}.com")
                print("not a domain")
            """))
            family = data._family("fake", "fake/dga.py")
            names, failed = data.generate(repo, family, per_family=200, seed=1)
            self.assertEqual(failed, 0)
            self.assertEqual(len(names), 200)
            self.assertEqual(len({n for n, _ in names}), 200)
            self.assertGreater(len({d for _, d in names}), 100)  # many dates, not the first few

    def test_seeded_families_run_with_many_seeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "fake").mkdir()
            (repo / "fake" / "dga.py").write_text("import sys\nprint(f'n{sys.argv[1].lower()}.com')\n")
            family = data._family("fake", "fake/dga.py", date_flag=None, variants=(("{seed}",),), seed="hex",
                                  seed_runs=40)
            names, failed = data.generate(repo, family, per_family=1000, seed=1)
            self.assertEqual((failed, len(names)), (0, 40))
            self.assertTrue(all(date == "" for _, date in names))


if __name__ == "__main__":
    unittest.main()
