"""The deployed model in files the resolver reads without a JSON or IDNA library (core/ml/).

    python -m ml.dga.export models/dga                                    # features.txt, public_suffixes.txt
    python -m ml.dga.export models/dga --parity tests/unit/ml/dga_parity.tsv --data ml/data

The pipeline's final mode writes both files too. The resolver reads:

dga_lgbm.txt         LightGBM's own text model (core/ml/gbdt.cpp reads it)
features.txt         everything the features need, one item per line:
                       dnsentinel-dga 1                      format version
                       threshold <x>                         flag scores above this
                       feature <name>                        the model's inputs, in order
                       words_sha256 <hex>                    config/english_words.txt it was trained with
                       ngram <table> <n> <alpha> <total> <alphabet> <entries>   then that many "<gram> <count>" lines
                       tld <alpha> <total> <entries>         then that many "<tld> <count>" lines
                     (counts, not an end marker: "end" is itself a 3-gram)
public_suffixes.txt  the Public Suffix List's rules in ASCII (IDNs in punycode), converted
                     exactly as psl.py converts them, so C++ needs no IDNA code: "rule",
                     "*.rule" or "!rule", one per line, after a "# VERSION:" line

The parity fixture holds names with the features and score scorer.py gives
them; tests/unit/ml checks that the C++ classifier reproduces them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

from .features import WORDS_PATH, DomainFeatures
from .psl import default_list

FORMAT = 1
TABLES = ("ngram", "bigram", "dga_ngram", "rhythm")  # features.json keys holding n-gram models


def _number(value: float) -> str:
    return repr(float(value))  # shortest text that reads back as exactly the same double


def write_features(folder: Path) -> Path:
    card = json.loads((folder / "model.json").read_text())
    tables = json.loads((folder / "features.json").read_text())
    unknown = [n for n in card["features"] if n not in DomainFeatures.names()]
    if unknown:
        raise SystemExit(f"model.json names features this code doesn't have: {unknown}")
    lines = [f"dnsentinel-dga {FORMAT}", f"threshold {_number(card['threshold'])}"]
    lines += [f"feature {name}" for name in card["features"]]
    lines.append(f"words_sha256 {card.get('words_sha256') or hashlib.sha256(WORDS_PATH.read_bytes()).hexdigest()}")
    for key in TABLES:
        if key not in tables:
            continue
        t = tables[key]
        lines.append(f"ngram {key} {t['n']} {_number(t['alpha'])} {t['total']} {t['alphabet']} {len(t['counts'])}")
        lines += [f"{gram} {count}" for gram, count in t["counts"].items()]
    prior = tables["tld_prior"]
    lines.append(f"tld {_number(prior['alpha'])} {prior['total']} {len(prior['counts'])}")
    lines += [f"{tld} {count}" for tld, count in prior["counts"].items()]
    path = folder / "features.txt"
    path.write_text("\n".join(lines) + "\n")
    return path


def write_public_suffixes(folder: Path) -> Path:
    psl = default_list()
    rules = sorted(psl._rules) + sorted(f"*.{w}" for w in psl._wildcards) + sorted(f"!{e}" for e in psl._exceptions)
    path = folder / "public_suffixes.txt"
    path.write_text(f"# VERSION: {psl.version}\n# ASCII rules from config/public_suffix_list.dat (ml/dga/export.py)\n"
                    + "\n".join(rules) + "\n")
    return path


EDGE_CASES = [
    "example.com", "WWW.Example.COM.", "x7kq2.example.co.uk", "cvyh1po636avyrsxebwbkn7.ddns.net", "blogspot.com.br",
    "co.uk", "a.b.c.d.example.org", "xn--o3cdo0fyd3b.net", "xn--fiqs8s.xn--fiqz9s", "_dmarc.example.com",
    "a-b-c-d.info", "123456789.com", "a.com", "abc.xyz", "z" * 63 + ".com", "q" * 20 + "1" * 20 + ".biz",
    "test.www.ck", "anything.kawasaki.jp", "city.kawasaki.jp", "localhost", "nafojeivo.kz", "gatyfus.com",
    "plasticbags.com", "travelinsurance.co.uk", "mdexmtiwmjia.info", "github.io", "user.github.io",
]


def write_parity(folder: Path, data: Path, out: Path, per_kind: int, seed: int) -> Path:
    """Names, their features and their scores from the Python scorer: what C++ must reproduce."""
    import csv

    from .scorer import Scorer

    scorer = Scorer(folder)
    rng = random.Random(seed)
    names = list(EDGE_CASES)
    for path in (data / "dga_dataset.csv", data / "external_netlab.csv"):
        rows = list(csv.DictReader(open(path, newline="")))
        for kind in ("benign", "dga", "dictionary"):
            pool = [r["domain"] for r in rows if r["kind"] == kind]
            names += rng.sample(pool, min(per_kind if path.name.startswith("dga") else per_kind // 4, len(pool)))
    with open(out, "w") as stream:
        stream.write(f"# from ml/dga/export.py: name, score, verdict, then the {len(scorer.features)} features "
                     f"({', '.join(scorer.features)})\n")
        for name in dict.fromkeys(names):
            vector = scorer.vector(name)
            score = scorer.score(name)
            stream.write("\t".join([name, _number(score), "1" if score > scorer.threshold else "0",
                                    *[_number(v) for v in vector]]) + "\n")
    return out


def export(folder: Path) -> list[Path]:
    return [write_features(folder), write_public_suffixes(folder)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("folder", type=Path, help="a final/ folder: dga_lgbm.txt, features.json, model.json")
    parser.add_argument("--parity", type=Path, help="also write the C++ parity fixture here")
    parser.add_argument("--data", type=Path, default=Path("ml/data"), help="where to sample the fixture's names")
    parser.add_argument("--per-kind", type=int, default=150, help="fixture names per kind (benign, dga, dictionary)")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    for path in export(args.folder):
        print(f"wrote {path}")
    if args.parity:
        print(f"wrote {write_parity(args.folder, args.data, args.parity, args.per_kind, args.seed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
