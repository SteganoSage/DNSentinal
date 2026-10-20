"""The files the resolver reads (ml/dga/export.py) say exactly what the Python model holds."""

import json
import tempfile
import unittest
from pathlib import Path

from ml.dga import export
from ml.dga.features import NgramModel, TldPrior

REPO = Path(__file__).resolve().parents[2]


class Exported(unittest.TestCase):
    def test_tables_read_back_exactly(self):
        model = REPO / "models" / "dga"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for name in ("model.json", "features.json"):
                (out / name).write_text((model / name).read_text())
            export.export(out)
            tables = json.loads((model / "features.json").read_text())
            lines = (out / "features.txt").read_text().splitlines()
            seen, i = set(), 0
            while i < len(lines):
                fields = lines[i].split()
                if fields[0] in ("ngram", "tld"):
                    entries = int(fields[-1])
                    counts = {g: int(c) for g, c in (line.split() for line in lines[i + 1 : i + 1 + entries])}
                    key = fields[1] if fields[0] == "ngram" else "tld_prior"
                    self.assertEqual(counts, tables[key]["counts"], key)
                    seen.add(key)
                    i += 1 + entries
                else:
                    i += 1
            self.assertEqual(seen, set(tables))
            # "end" is a real 3-gram: counts, not an end marker, delimit tables
            self.assertIn("end", tables["ngram"]["counts"])
            rules = (out / "public_suffixes.txt").read_text().splitlines()
            self.assertIn("co.uk", rules)
            self.assertTrue(rules[0].startswith("# VERSION: "))
            self.assertTrue(all(rule.isascii() for rule in rules))

    def test_committed_files_are_current(self):
        """models/dga/features.txt matches its features.json (rerun ml.dga.export if not)."""
        model = REPO / "models" / "dga"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for name in ("model.json", "features.json"):
                (out / name).write_text((model / name).read_text())
            export.export(out)
            self.assertEqual((out / "features.txt").read_text(), (model / "features.txt").read_text())
            self.assertEqual((out / "public_suffixes.txt").read_text(), (model / "public_suffixes.txt").read_text())

    def test_loaded_tables_score_like_the_originals(self):
        tables = json.loads((REPO / "models" / "dga" / "features.json").read_text())
        ngram, prior = NgramModel.from_state(tables["ngram"]), TldPrior.from_state(tables["tld_prior"])
        self.assertLess(ngram.score("xkqzvtrwpl"), ngram.score("example"))
        self.assertLess(prior.score("kz"), prior.score("com"))


if __name__ == "__main__":
    unittest.main()
