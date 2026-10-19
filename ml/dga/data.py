"""Building the DGA dataset reproducibly (EVALUATION.md E7; sources in ml/DATA.md).

Every source is pinned, so anyone (or a Kaggle/Colab notebook) gets the
same data:

benign     The Tranco list TRANCO_LIST. Ranks 1-100k become the resolver's
           allowlist and are never scored in deployment, so the benign data is
           ranks beyond 100k: where the classifier actually runs. A name is
           marked stable if the lists of 6 and 12 months earlier
           (TRANCO_HISTORY) have it too: DGA and throwaway names don't last
           that long. Names on the malware blocklists are dropped.
generated  DGA domains from Johannes Bader's reimplementations of real malware
           DGAs, at BADER_COMMIT. They are GPL-2.0, so they are run as separate
           programs and never copied into this repository; only their output
           is kept. Families seeded by date run over six years (a later
           stretch can be held out); families seeded by a number run with many
           random seeds. Dictionary families are marked, for E7's separate set.
netlab     chrmor/DGA_domains_dataset at CHRMOR_COMMIT: real DGA domains
           observed by Netlab 360. Families we can't generate are trained on
           (dga_dataset.csv); families we generate are the external test set
           (external_netlab.csv): trained on generated names, tested on real.
blocklist  abuse.ch's ThreatFox and URLhaus host files, for E7's
           blocklist-only baseline. Live feeds can't be pinned, so the
           download time and SHA-256 go into dataset_info.json.

    python -m ml.dga.data --out ml/data            # downloads and generates
    python -m ml.dga.data --out /tmp/x --smoke     # tiny offline dataset for tests
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import random
import re
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .features import normalise

TRANCO_LIST = "64VVX"  # 2026-10-16, 30 days of CrUX, Farsight, Majestic, Radar, Umbrella
TRANCO_HISTORY = {"VQYYN": "2026-04-16", "8LZGV": "2025-10-16"}  # the same configuration, 6 and 12 months earlier
ALLOWLIST_TOP = 100_000

BADER_REPO = "https://github.com/baderj/domain_generation_algorithms"
BADER_COMMIT = "0faef452d267a62a94124ef2806bc4a72e0913bd"

CHRMOR_COMMIT = "9dcc29e5cc644fdfd99d82a3abec993c15bbc7bc"
CHRMOR_URL = f"https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/{CHRMOR_COMMIT}/dga_domains_full.csv"
CHRMOR_DICTIONARY = frozenset({"gozi", "matsnu", "suppobox"})  # word-based families in that set

SCOWL_URL = "https://github.com/en-wl/wordlist/releases/download/rel-2026.02.25/hunspell-en_US-2026.02.25.zip"
SCOWL_SHA256 = "ac8e73310e951d88c52c2cf2ba54ceaca34f8486a81630ac8a75dc5f931179f9"

BLOCKLISTS = {  # both CC0
    "threatfox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
}

FIRST_DATE = dt.date(2019, 1, 1)  # generated families cover these six years, so
LAST_DATE = dt.date(2024, 12, 31)  # any later stretch can be held out (future split)

COLUMNS = ["domain", "label", "family", "kind", "date", "rank", "source", "stable"]
_NAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@dataclass(frozen=True)
class Family:
    """How to run one family's reimplementation.

    Each script runs with each variant's arguments, either once per date
    (date_flag), or once per random seed (seed: "{seed}" in a variant is
    replaced), or just once.
    """

    name: str
    scripts: tuple[str, ...]  # inside the repository; several for families with versions
    date_flag: str | None = "-d"
    date_format: str = "%Y-%m-%d"
    step_days: int = 7  # one run every this many days
    variants: tuple[tuple[str, ...], ...] = ((),)
    seed: str | None = None  # "hex", "int" or "domain": run seed_runs times with random seeds
    seed_runs: int = 0
    dictionary: bool = False


def _family(name, script, **options) -> Family:
    return Family(name, (script,) if isinstance(script, str) else tuple(script), **options)


FAMILIES = [
    # Seeded by date: these make the future-date split possible.
    _family("bazarbackdoor", "bazarbackdoor/dga.py"),
    _family("bumblebee", "bumblebee/dga.py", date_flag="-t", date_format="%Y-%m-%d 12:00:00"),
    _family("chinad", "chinad/dga.py"),
    _family("corebot", "corebot/dga.py"),
    _family("darkcracks", "darkcracks/dga.py", variants=(("-n", "7"),)),
    _family("kraken", "kraken/v2/dga_v2.py", variants=(("-t", "1", "-s", "a"), ("-t", "2", "-s", "b"))),
    _family("locky", "locky/dgav2.py", step_days=2),
    _family("m0yv", "m0yv/dga-td.py"),
    _family("monerodownloader", "monerodownloader/dga.py"),
    _family("murofet", ("murofet/v1/dga.py", "murofet/v3/dga.py")),  # v2 takes 10 s a run
    _family("mydoom", "mydoom/dga.py"),
    _family("necurs", "necurs/dga.py"),
    _family("newgoz", "newgoz/dga.py"),
    _family("nymaim", "nymaim/dga.py"),
    _family("orchard", "orchard/dga.py"),
    _family("padcrypt", "padcrypt/dga.py"),
    _family("pitou", "pitou/dga.py"),
    _family("proslikefan", "proslikefan/dga.py"),
    _family("pushdo", "pushdo/dga.py"),
    _family("pykspa", "pykspa/precursor/dga.py", variants=(("-n", "100"),)),
    _family("qadars", "qadars/dga.py"),
    _family("qakbot", "qakbot/dga.py"),
    _family("ranbyus", "ranbyus/september/ranbyus_reloaded.py"),
    _family("sharkbot", "sharkbot/dga.py", variants=(("-v", "2.8"), ("-v", "2.1"), ("-v", "1.63"), ("-v", "0.0"))),
    _family("sisron", "sisron/dga.py"),
    _family("symmi", "symmi/dga.py"),
    _family("tempedreve", "tempedreve/dga.py"),
    _family("tufik", "tufik/dga.py"),
    _family("unnamed_javascript", "unnamed_javascript_dga/dga.py"),
    _family("verblecon", "verblecon/dga.py", step_days=1),
    _family("zloader", "zloader/dga.py"),
    # Seeded by a number or a name: random seeds give the same kind of names.
    _family("dircrypt", "dircrypt/dga.py", date_flag=None, variants=(("{seed}",),), seed="hex", seed_runs=250),
    _family("dnschanger", "dnschanger/dga.py", date_flag=None, variants=(("{seed}",),), seed="int", seed_runs=1300),
    _family("ramnit", "ramnit/dga.py", date_flag=None, variants=(("-s", "{seed}", "-x", "30"),), seed="hex",
            seed_runs=250),
    _family("shiotob", "shiotob/dga.py", date_flag=None, variants=(("{seed}",),), seed="domain", seed_runs=3),
    # One fixed list each.
    _family("banjori", "banjori/dga.py", date_flag=None),
    _family("dmsniff", "dmsniff/dga.py", date_flag=None, variants=(("sn",), ("al",))),
    _family("fobber", "fobber/dga.py", date_flag=None, variants=(("1",), ("2",))),
    _family("fosniw", "fosniw/dga.py", date_flag=None, variants=(("--prefix", "winsoft"), ("--prefix", "koreasys"))),
    _family("ngioweb", "ngioweb/dga.py", date_flag=None),
    _family("qsnatch", "qsnatch/dga_a.py", date_flag=None),
    _family("ramdo", "ramdo/dga.py", date_flag=None),
    _family("reconyc", "reconyc/dga.py", date_flag=None),
    _family("simda", "simda/dga.py", date_flag=None),
    _family("tinba", "tinba/dga.py", date_flag=None),
    _family("vawtrak", "vawtrak/dga3.py", date_flag=None),
    # Dictionary-based: words joined together. Known to evade character
    # statistics (README §7.8.6), so tested separately and never trained on.
    _family("gozi", "gozi/dga.py", variants=(("-w", "luther"), ("-w", "nasa"), ("-w", "gpl"), ("-w", "rfc4343")),
            dictionary=True),
    _family("nymaim2", "nymaim2/dga.py", dictionary=True),
    _family("suppobox", "suppobox/dga.py", date_flag="-t", date_format="%Y-%m-%d 12:00:00",
            variants=(("1",), ("2",), ("3",)), dictionary=True),
]


# ─── Downloads ──────────────────────────────────────────────────────────────


def fetch(url: str, path: Path, attempts: int = 4) -> Path:
    """Download `url` to `path` once; later calls reuse the file. Retries rate limits."""
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url}", flush=True)
    partial = path.with_suffix(path.suffix + ".part")
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=120) as response, open(partial, "wb") as out:
                out.write(response.read())
            break
        except urllib.error.HTTPError as error:  # Tranco answers 429 to quick repeats
            if error.code != 429 or attempt == attempts - 1:
                raise
            time.sleep(10 * (attempt + 1))
    partial.rename(path)
    return path


def tranco(cache: Path, list_id: str) -> list[tuple[int, str]]:
    """(rank, domain) for a pinned Tranco top million."""
    path = fetch(f"https://tranco-list.eu/download/{list_id}/1000000", cache / f"tranco_{list_id}.csv")
    with open(path, newline="") as stream:
        return [(int(rank), domain.strip().lower()) for rank, domain in csv.reader(stream)]


def blocklist(cache: Path) -> tuple[set[str], dict]:
    """Every name in the BLOCKLISTS host files, and where each file came from."""
    names, sources = set(), {}
    for name, url in BLOCKLISTS.items():
        path = fetch(url, cache / f"blocklist_{name}.txt")
        found = set()
        for line in path.read_text(errors="replace").splitlines():
            fields = line.split("#", 1)[0].split()
            if fields:
                try:
                    found.add(normalise(fields[-1]))
                except ValueError:
                    pass
        names |= found
        downloaded = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        sources[name] = {"url": url, "domains": len(found), "downloaded": downloaded.isoformat(timespec="seconds"),
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    return names, sources


def bader_checkout(cache: Path) -> Path:
    """The DGA reimplementations at BADER_COMMIT."""
    repo = cache / f"dga_reimplementations_{BADER_COMMIT[:7]}"
    if not (repo / "README.md").exists():
        repo.mkdir(parents=True, exist_ok=True)
        for args in (["init", "-q"], ["remote", "add", "origin", BADER_REPO],
                     ["fetch", "-q", "--depth", "1", "origin", BADER_COMMIT], ["checkout", "-q", "FETCH_HEAD"]):
            subprocess.run(["git", *args], cwd=repo, check=True)
    return repo


def netlab(cache: Path) -> list[tuple[str, str]]:
    """(family, domain) for every DGA name in chrmor's file (no header: kind, family, domain)."""
    with open(fetch(CHRMOR_URL, cache / f"chrmor_{CHRMOR_COMMIT[:7]}.csv"), newline="") as stream:
        return [(family, domain) for kind, family, domain in csv.reader(stream) if kind == "dga"]


def write_word_list(cache: Path, path: Path) -> int:
    """config/english_words.txt from the pinned SCOWL release: every word of 3+ ASCII letters."""
    import zipfile

    archive = fetch(SCOWL_URL, cache / "scowl_en_US.zip")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SCOWL_SHA256:
        raise SystemExit(f"{archive} does not match the pinned SHA-256")
    with zipfile.ZipFile(archive) as bundle:
        dic = bundle.read("en_US.dic").decode("utf-8", errors="replace").splitlines()[1:]  # line 1: the count
        readme = bundle.read("README_en_US.txt").decode("utf-8", errors="replace")
    words = sorted({w for w in (line.split("/")[0].strip().lower() for line in dic) if re.fullmatch("[a-z]{3,}", w)})
    notice = readme[readme.index("Copyright 2000"):readme.index("SCOWL is derived")].strip()
    header = ["English words for the DGA classifier's word features (ml/dga/features.py, WordList).",
              "Every word of 3+ ASCII letters, lower-cased, from SCOWL's en_US Hunspell dictionary",
              f"({SCOWL_URL.rsplit('/', 1)[1]}, https://github.com/en-wl/wordlist, sha256 {SCOWL_SHA256}),",
              "without affix flags. Rebuild: python -m ml.dga.data --words", "", *notice.splitlines()]
    path.write_text("".join(f"# {line}".rstrip() + "\n" for line in header) + "\n".join(words) + "\n")
    return len(words)


# ─── Generated DGA domains ──────────────────────────────────────────────────


def _run(repo: Path, family: Family, script: str, args: tuple[str, ...], date: dt.date | None) -> list[str] | None:
    """One run of a family's script: the names it prints, or None if it failed."""
    path = repo / script
    # -I: only the standard library, nothing from the checkout's directory.
    # The scripts read their word lists relative to their own directory.
    command = [sys.executable, "-I", path.name, *args]
    if date is not None:
        command += [family.date_flag, date.strftime(family.date_format)]
    result = subprocess.run(command, cwd=path.parent, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"  {family.name} ({' '.join(command[2:])}) failed: {result.stderr.strip()[-200:]}", flush=True)
        return None
    return [line for line in (word.strip().lower() for word in result.stdout.split()) if _NAME.match(line)]


def _seed(kind: str, rng: random.Random) -> str:
    if kind == "hex":
        return f"{rng.getrandbits(32):08X}"
    if kind == "int":
        return str(rng.getrandbits(31))
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(12)) + ".net"


def jobs_for(family: Family, rng: random.Random) -> list[tuple[str, tuple[str, ...], dt.date | None]]:
    """(script, arguments, date) for every run of a family."""
    if family.seed:
        runs = [tuple(a.replace("{seed}", _seed(family.seed, rng)) for a in variant)
                for _ in range(family.seed_runs) for variant in family.variants]
        return [(script, args, None) for script in family.scripts for args in runs]
    if family.date_flag is None:
        dates: list[dt.date | None] = [None]
    else:
        days = (LAST_DATE - FIRST_DATE).days
        dates = [FIRST_DATE + dt.timedelta(days=d) for d in range(0, days + 1, family.step_days)]
    return [(script, args, date) for date in dates for script in family.scripts for args in family.variants]


def generate(repo: Path, family: Family, per_family: int, seed: int, workers: int = 8) -> tuple[list[tuple[str, str]], int]:
    """Up to `per_family` (domain, date) pairs spread evenly over the runs, and how many runs failed."""
    rng = random.Random(f"{seed}:{family.name}")
    jobs = jobs_for(family, rng)
    take = max(1, -(-per_family // len(jobs)))  # ceiling: an even share per run
    with ThreadPoolExecutor(workers) as pool:
        outputs = list(pool.map(lambda job: (job[2], _run(repo, family, *job)), jobs))
    failed = sum(names is None for _, names in outputs)
    if failed == len(jobs):
        raise RuntimeError(f"every run of {family.name} failed")
    picked, seen = [], set()
    for date, names in outputs:
        fresh = [n for n in dict.fromkeys(names or []) if n not in seen]
        for name in rng.sample(fresh, min(take, len(fresh))):
            seen.add(name)
            picked.append((name, date.isoformat() if date else ""))
    rng.shuffle(picked)
    return picked[:per_family], failed


# ─── The dataset ────────────────────────────────────────────────────────────


def build(out: Path, per_family: int, benign: int | None, seed: int) -> dict:
    """Write dga_dataset.csv, allowlist_top100k.txt, external_netlab.csv and blocklist_snapshot.txt to `out`."""
    cache = out / "cache"
    ranked = tranco(cache, TRANCO_LIST)
    older = [{d for _, d in tranco(cache, list_id)} for list_id in TRANCO_HISTORY]
    blocked, blocklists = blocklist(cache)
    allowlist = [d for r, d in ranked if r <= ALLOWLIST_TOP]
    pool = [(r, d) for r, d in ranked if r > ALLOWLIST_TOP]
    if benign is not None and benign < len(pool):
        pool = sorted(random.Random(seed).sample(pool, benign))
    popular = {d for _, d in ranked}

    rows, seen = [], set()
    dropped = {"invalid": 0, "duplicate": 0, "popular": 0, "benign_blocklisted": 0}

    def add(domain, label, family, kind, date="", rank="", source="", stable=""):
        try:
            domain = normalise(domain)
        except ValueError:
            dropped["invalid"] += 1
            return False
        if domain in seen:
            dropped["duplicate"] += 1
            return False
        if label == 1 and domain in popular:  # a generated name that is a real, popular site
            dropped["popular"] += 1
            return False
        if label == 0 and domain in blocked:  # on a malware list: not something to call benign
            dropped["benign_blocklisted"] += 1
            return False
        seen.add(domain)
        rows.append([domain, label, family, kind, date, rank, source, stable])
        return True

    for rank, domain in pool:
        add(domain, 0, "benign", "benign", rank=rank, source="tranco", stable=int(all(domain in o for o in older)))

    repo = bader_checkout(cache)
    families, failed_runs = {}, {}
    for family in FAMILIES:
        names, failed = generate(repo, family, per_family, seed)
        families[family.name] = sum(add(domain, 1, family.name, "dictionary" if family.dictionary else "dga",
                                        date=date, source="bader") for domain, date in names)
        if failed:
            failed_runs[family.name] = failed
        print(f"  {family.name:20} {families[family.name]:6} domains", flush=True)

    # Netlab's real names: families we can't generate are trained on (capped
    # like the generated ones); the others are kept for the external test.
    generated = {f.name for f in FAMILIES}
    by_family: dict[str, list[str]] = {}
    for family, domain in netlab(cache):
        by_family.setdefault(family, []).append(domain)
    external, overlap = [], 0
    for family, domains in sorted(by_family.items()):
        kind = "dictionary" if family in CHRMOR_DICTIONARY else "dga"
        if family not in generated:
            rng = random.Random(f"{seed}:netlab:{family}")
            chosen = rng.sample(domains, min(per_family, len(domains)))
            families[f"{family} (netlab)"] = sum(add(d, 1, family, kind, source="netlab") for d in chosen)
            print(f"  {family + ' (netlab)':20} {families[f'{family} (netlab)']:6} domains", flush=True)
            continue
        for domain in domains:  # only names the dataset doesn't have: a test of unseen names
            try:
                domain = normalise(domain)
            except ValueError:
                continue
            if domain in seen:
                overlap += 1
                continue
            external.append([domain, 1, family, kind, "", "", "netlab", ""])

    write_csv(out / "dga_dataset.csv", rows)
    write_csv(out / "external_netlab.csv", external)
    (out / "allowlist_top100k.txt").write_text("\n".join(allowlist) + "\n")
    (out / "blocklist_snapshot.txt").write_text("\n".join(sorted(blocked)) + "\n")

    benign_rows = [r for r in rows if r[1] == 0]
    summary = {
        "tranco_list": TRANCO_LIST, "tranco_history": TRANCO_HISTORY, "bader_commit": BADER_COMMIT,
        "chrmor_commit": CHRMOR_COMMIT,
        "benign": len(benign_rows), "benign_stable": sum(r[7] == 1 for r in benign_rows),
        "dga": sum(1 for r in rows if r[3] == "dga"), "dictionary": sum(1 for r in rows if r[3] == "dictionary"),
        "families": families, "dropped": dropped, "failed_runs": failed_runs, "allowlist": len(allowlist),
        "external": len(external), "external_overlap": overlap, "blocklists": blocklists,
    }
    (out / "dataset_info.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def write_csv(path: Path, rows: list[list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(COLUMNS)
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["label"] = int(row["label"])
        row["stable"] = row.get("stable") == "1"
    return rows


# ─── A tiny offline dataset, for tests and smoke runs ───────────────────────

_SYLLABLES = ["ka", "lo", "mi", "ra", "ne", "to", "su", "vi", "pe", "do", "ga", "li", "mo", "ta", "ri", "ze"]
_WORDS = ["apple", "river", "stone", "cloud", "green", "light", "north", "music", "paper", "smart", "travel", "house"]


def build_smoke(out: Path, per_family: int = 300, benign: int = 3000, seed: int = 1) -> dict:
    """Same files and columns as build(), from made-up names: no network needed."""
    rng = random.Random(seed)
    rows, seen = [], set()
    while len(rows) < benign:  # pronounceable names, like most real sites; one in ten not stable
        label = "".join(rng.choice(_SYLLABLES) for _ in range(rng.randint(2, 5)))
        domain = f"{label}{rng.choice(['', str(rng.randint(1, 99))])}.{rng.choice(['com', 'net', 'org', 'io'])}"
        if domain not in seen:
            seen.add(domain)
            rows.append([domain, 0, "benign", "benign", "", ALLOWLIST_TOP + len(rows) + 1, "smoke",
                         int(rng.random() > 0.1)])
    styles = {
        "hexish": lambda: "".join(rng.choice("0123456789abcdef") for _ in range(16)),
        "consonants": lambda: "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(rng.randint(10, 18))),
        "alnum": lambda: "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12)),
        "wordy": lambda: rng.choice(_WORDS) + rng.choice(_WORDS),
    }
    for name, make in styles.items():
        kind = "dictionary" if name == "wordy" else "dga"
        made = 0
        while made < per_family:
            day = FIRST_DATE + dt.timedelta(days=rng.randint(0, (LAST_DATE - FIRST_DATE).days))
            domain = f"{make()}.{rng.choice(['com', 'net', 'biz', 'ru'])}"
            if domain not in seen:
                seen.add(domain)
                rows.append([domain, 1, name, kind, day.isoformat(), "", "smoke", ""])
                made += 1
    write_csv(out / "dga_dataset.csv", rows)
    dga = [r for r in rows if r[1] == 1]
    write_csv(out / "external_netlab.csv", [[f"x{r[0]}", *r[1:6], "netlab", ""] for r in dga[::5]])  # renamed: unseen
    (out / "blocklist_snapshot.txt").write_text("\n".join(r[0] for r in dga[::50]) + "\n")
    (out / "allowlist_top100k.txt").write_text("kalomi.com\nrivertoga.net\nexample.com\n")
    summary = {"smoke": True, "rows": len(rows)}
    (out / "dataset_info.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("ml/data"))
    parser.add_argument("--per-family", type=int, default=6000, help="names per DGA family (generated or netlab)")
    parser.add_argument("--benign", type=int, default=None, help="sample this many benign names (default: all)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke", action="store_true", help="tiny made-up dataset, no network")
    parser.add_argument("--words", action="store_true", help="rebuild config/english_words.txt from SCOWL")
    args = parser.parse_args()
    if args.words:
        from .features import WORDS_PATH

        print(f"{write_word_list(args.out / 'cache', WORDS_PATH)} words in {WORDS_PATH}")
        return
    summary = build_smoke(args.out) if args.smoke else build(args.out, args.per_family, args.benign, args.seed)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
