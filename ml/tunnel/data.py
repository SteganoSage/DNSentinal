"""Building the tunnel dataset reproducibly (EVALUATION.md E8; sources in ml/DATA.md).

Every source is pinned, so anyone (or a Kaggle/Colab notebook) gets the
same data. Captures are turned into query events (pcap.py), the same
events the resolver gives the detector; windows are cut later, by the
pipeline, with the detector's own code.

graphtunnel  ggyggy666/DNS-Tunnel-Datasets (the GraphTunnel paper's data) at
             the commit in graphtunnel_files.json, which also pins each
             file's size and git blob SHA-1 (checked after download):
               tunnel/        dnscat2, dnspot, iodine, DNS-shell, tuns, in every
                              record type each supports ("known" tools)
               unkownTunnel/  cobaltstrike, dns2tcp, ozymandns, tcp-over-dns
                              ("unknown": tools held out of training)
               crossEndPoint/ AndIodine, iodine's Android client ("android")
               normal/        a client resolving Cloudflare's top 1M domains ("crawl")
               wildcard/      subdomains of wildcard-DNS domains: many unique
                              names under one domain, but no tunnel ("wildcard")
             The pcapng files in the subfolders hold the same packets as the
             whole captures again and are not used (tunnel/dns2tcp-key/ is
             unkownTunnel/dns2tcp-key.pcap).
stratosphere The Stratosphere Lab's normal captures (CTU-Normal-*): real
             people's machines browsing for hours ("browsing"). Most are
             full captures; only their DNS is kept. No published hashes, so
             sizes are pinned and the SHA-256 goes into dataset_info.json.
allowlist    The Tranco top 100k of the list the DGA data pins (ml.dga.data.TRANCO_LIST):
             popular domains the deployed detector skips; the pipeline reports
             false alerts with and without it.
local        Your own captures, if --local DIR is given: DIR/benign/**.pcap*
             and DIR/tunnel/<tool>/**.pcap* (e.g. iodine through DNSentinel
             in the lab, E8; normal use of your own devices, W1).

A tunnel capture's tunnel is the registrable domain it queries most
(captures.csv: tunnel_domain); the pipeline labels that domain's windows as
tunnel and leaves the capture's other traffic out.

    python -m ml.tunnel.data --out ml/data/tunnel            # downloads (~6.8 GB) and parses
    python -m ml.tunnel.data --out x --browsing small        # only the smaller browsing captures (~1.1 GB)
    python -m ml.tunnel.data --out /tmp/x --smoke            # tiny made-up dataset for tests
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import http.client
import json
import random
import shutil
import string
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

from analyzer.detectors.tunnel import registrable_domain

from ..dga.data import TRANCO_LIST
from ..dga.progress import log
from .pcap import COLUMNS as EVENT_COLUMNS
from .pcap import Stats, read_events

HERE = Path(__file__).resolve().parent
GRAPHTUNNEL = json.loads((HERE / "graphtunnel_files.json").read_text())
GRAPHTUNNEL_URL = "https://raw.githubusercontent.com/{repository}/{commit}/{path}"
GRAPHTUNNEL_SETS = {"tunnel": "known", "unkownTunnel": "unknown", "crossEndPoint": "android",
                    "normal": "crawl", "wildcard": "wildcard"}
TOOL_NAMES = {"cobalstrike": "cobaltstrike"}  # the repository's spelling
RECORD_SUFFIXES = {"a", "cname", "mx", "null", "private", "srv", "txt", "key"}

STRATOSPHERE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/"
STRATOSPHERE = {  # capture -> (file, bytes); 20-31 browse Alexa/Moz top sites for hours, 4 is a home network
    "CTU-Normal-4": ("CTU-Normal-4-only-DNS/2015-03-24_capture1-only-dns.pcap", 772_961),
    "CTU-Normal-20": ("CTU-Normal-20/2017-04-30_win-normal.pcap", 282_415_864),
    "CTU-Normal-21": ("CTU-Normal-21/2017-05-02_kali-normal.pcap", 311_638_284),
    "CTU-Normal-22": ("CTU-Normal-22/2017-05-02_kali-normal.pcap", 1_716_205_752),
    "CTU-Normal-23": ("CTU-Normal-23/2017-04-18_win-normal.pcap", 294_700_097),
    "CTU-Normal-24": ("CTU-Normal-24/2017-04-19_win-normal.pcap", 211_351_915),
    "CTU-Normal-25": ("CTU-Normal-25/2017-04-25_win-normal.pcap", 505_548_690),
    "CTU-Normal-26": ("CTU-Normal-26/2017-04-28_normal.pcap", 118_444_523),
    "CTU-Normal-27": ("CTU-Normal-27/2017_04_30-normal.pcap", 444_866_158),
    "CTU-Normal-28": ("CTU-Normal-28/2017-05-01_normal.pcap", 143_630_116),
    "CTU-Normal-29": ("CTU-Normal-29/2017-05-01_normal.pcap", 457_410_237),
    "CTU-Normal-30": ("CTU-Normal-30/2017-05-01_normal.pcap", 872_945_153),
    "CTU-Normal-31": ("CTU-Normal-31/2017-05-01_normal.pcap", 760_328_169),
    "CTU-Normal-32": ("CTU-Normal-32/2017-05-02_normal.only-dns.pcap", 21_676_257),
}
SMALL_BROWSING = 300_000_000  # --browsing small: captures up to this size
ALLOWLIST_URL = f"https://tranco-list.eu/download/{TRANCO_LIST}/100000"

CAPTURE_COLUMNS = ["capture", "source", "set", "label", "tool", "rtype", "tunnel_domain", "file", "bytes",
                   "digest", "queries", "clients", "start", "end", "hours"]
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")


@dataclass
class Capture:
    capture: str     # "graphtunnel/tunnel/iodine-txt"
    source: str      # graphtunnel | stratosphere | local | smoke
    set: str         # known | unknown | android | crawl | wildcard | browsing | local
    label: str       # tunnel | benign
    tool: str = ""
    rtype: str = ""  # the tunnel's most asked record type
    tunnel_domain: str = ""
    file: str = ""
    bytes: int = 0
    digest: str = ""  # git blob SHA-1 (graphtunnel) or SHA-256
    queries: int = 0
    clients: int = 0
    start: float = 0.0
    end: float = 0.0
    hours: float = 0.0


# ─── Downloads ──────────────────────────────────────────────────────────────


def fetch(url: str, path: Path, size: int | None = None, attempts: int = 6) -> Path:
    """Download `url` to `path` once, resuming after a dropped connection; checks the size if given."""
    if path.exists() and (size is None or path.stat().st_size == size):
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    for attempt in range(attempts):
        have = partial.stat().st_size if partial.exists() else 0
        if size is not None and have == size:
            break
        request = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                resumed = have and response.status == 206
                with open(partial, "ab" if resumed else "wb") as out:
                    shutil.copyfileobj(response, out, 1 << 20)
            if size is None or partial.stat().st_size == size:
                break
        except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError) as error:
            if attempt == attempts - 1:
                raise
            log(f"  retrying {url}: {error}")
        time.sleep(5 * (attempt + 1))
    if size is not None and partial.stat().st_size != size:
        raise RuntimeError(f"{url}: got {partial.stat().st_size} bytes, expected {size}")
    partial.rename(path)
    return path


def git_blob_sha1(path: Path) -> str:
    digest = hashlib.sha1(b"blob %d\0" % path.stat().st_size)
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ─── The captures ───────────────────────────────────────────────────────────


def graphtunnel_capture(path: str) -> Capture:
    """What a GraphTunnel file holds, from where it is in the repository."""
    folder, stem = path.split("/")[0], Path(path).stem
    kind = GRAPHTUNNEL_SETS[folder]
    if kind in ("crawl", "wildcard"):
        return Capture(f"graphtunnel/{folder}/{stem}", "graphtunnel", kind, "benign", file=path)
    parts = stem.lower().split("-")
    if len(parts) > 1 and parts[-1] in RECORD_SUFFIXES:
        parts = parts[:-1]
    tool = TOOL_NAMES.get("-".join(parts), "-".join(parts))
    return Capture(f"graphtunnel/{folder}/{stem}", "graphtunnel", kind, "tunnel", tool=tool, file=path)


def captures_for(browsing: str, local: Path | None) -> list[tuple[Capture, str | None, Path | None, int | None]]:
    """(capture, URL or None, local file or None, expected size) for every capture to build."""
    jobs = []
    for path, (size, _) in GRAPHTUNNEL["files"].items():
        url = GRAPHTUNNEL_URL.format(repository=GRAPHTUNNEL["repository"], commit=GRAPHTUNNEL["commit"], path=path)
        jobs.append((graphtunnel_capture(path), url, None, size))
    for name, (path, size) in STRATOSPHERE.items():
        if browsing == "all" or (browsing == "small" and size <= SMALL_BROWSING):
            jobs.append((Capture(f"stratosphere/{name}", "stratosphere", "browsing", "benign", file=path),
                         STRATOSPHERE_URL + path, None, size))
    if local:
        for file in sorted(p for p in local.rglob("*") if p.suffix.lower() in CAPTURE_SUFFIXES):
            relative = file.relative_to(local)
            if relative.parts[0] == "benign":
                capture = Capture(f"local/{relative.with_suffix('').as_posix()}", "local", "local", "benign")
            elif relative.parts[0] == "tunnel" and len(relative.parts) > 2:
                capture = Capture(f"local/{relative.with_suffix('').as_posix()}", "local", "local", "tunnel",
                                  tool=relative.parts[1].lower())
            else:
                log(f"  skipping {file}: put captures in {local}/benign/ or {local}/tunnel/<tool>/")
                continue
            capture.file = str(file)
            jobs.append((capture, None, file, None))
    return jobs


def _cache_name(capture: str) -> str:
    return capture.replace("/", "__") + ".csv.gz"


def summarise(capture: Capture, events: list) -> Capture:
    """Fill in a capture's counts, span and (for a tunnel) its domain and record type."""
    capture.queries = len(events)
    capture.clients = len({e.client for e in events})
    if events:
        capture.start, capture.end = events[0].timestamp, events[-1].timestamp
        capture.hours = round((capture.end - capture.start) / 3600, 4)
    if capture.label == "tunnel" and events:
        domains = Counter(registrable_domain(e.qname) for e in events)
        capture.tunnel_domain = domains.most_common(1)[0][0]
        types = Counter(e.qtype for e in events if registrable_domain(e.qname) == capture.tunnel_domain)
        capture.rtype = types.most_common(1)[0][0]
    return capture


def write_events(path: Path, capture: str, events: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    with gzip.open(partial, "wt", newline="", compresslevel=6) as stream:
        writer = csv.writer(stream)
        for e in events:
            writer.writerow([capture, f"{e.timestamp:.6f}", e.client, e.qname, e.qtype, e.rcode, e.response_size])
    partial.rename(path)


def _build_one(capture: Capture, url: str | None, file: Path | None, size: int | None, cache: Path,
               keep_pcaps: bool) -> tuple[Capture, dict]:
    events_path = cache / "events" / _cache_name(capture.capture)
    meta_path = events_path.with_name(events_path.name.replace(".csv.gz", ".json"))
    if events_path.exists() and meta_path.exists():  # built before: reuse
        meta = json.loads(meta_path.read_text())
        return Capture(**meta["capture"]), meta["stats"]
    if file is None:
        file = fetch(url, cache / "pcaps" / capture.source / Path(capture.file), size)
    capture.bytes = file.stat().st_size
    if capture.source == "graphtunnel":
        capture.digest = git_blob_sha1(file)
        expected = GRAPHTUNNEL["files"][capture.file][1]
        if capture.digest != expected:
            file.unlink()
            raise RuntimeError(f"{capture.file}: git blob SHA-1 {capture.digest}, expected {expected}")
    else:
        capture.digest = sha256(file)
    stats = Stats()
    events = read_events(file, stats)
    summarise(capture, events)
    write_events(events_path, capture.capture, events)
    meta_path.write_text(json.dumps({"capture": asdict(capture), "stats": asdict(stats)}) + "\n")
    if url is not None and not keep_pcaps and capture.bytes > 50_000_000:  # big full captures: keep only the DNS
        file.unlink()
    return capture, asdict(stats)


def build(out: Path, cache: Path, browsing: str = "all", local: Path | None = None, workers: int = 4,
          keep_pcaps: bool = False) -> dict:
    """Write events.csv.gz, captures.csv and dataset_info.json to `out`."""
    started = time.monotonic()
    jobs = captures_for(browsing, local)
    total = sum(size or 0 for _, url, _, size in jobs if url)
    log(f"{len(jobs)} captures, {total / 1e9:.1f} GB to download (less if cached in {cache})")
    built: dict[str, tuple[Capture, dict]] = {}
    # big files first, so the long downloads overlap the many small ones
    jobs.sort(key=lambda job: -(job[3] or 0))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_build_one, *job, cache, keep_pcaps): job[0].capture for job in jobs}
        for done, future in enumerate(as_completed(futures), 1):
            capture, stats = future.result()
            built[capture.capture] = (capture, stats)
            log(f"  [{done}/{len(jobs)}] {capture.capture}: {capture.queries} queries, "
                f"{capture.hours:.2f} h{', tunnel ' + capture.tunnel_domain if capture.tunnel_domain else ''}")
    tranco = fetch(ALLOWLIST_URL, cache / f"tranco_{TRANCO_LIST}_top100k.csv")
    with open(tranco, newline="") as stream:
        popular = [row[1].strip().lower() for row in csv.reader(stream) if len(row) > 1]
    out.mkdir(parents=True, exist_ok=True)
    (out / "allowlist_top100k.txt").write_text("\n".join(popular) + "\n")
    return _write(out, cache, built, {
        "graphtunnel": {"repository": GRAPHTUNNEL["repository"], "commit": GRAPHTUNNEL["commit"]},
        "stratosphere": {"url": STRATOSPHERE_URL, "browsing": browsing},
        "allowlist": {"url": ALLOWLIST_URL, "domains": len(popular)},
        "local": str(local) if local else None,
    }, started)


def _write(out: Path, cache: Path, built: dict, sources: dict, started: float) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    names = sorted(built)
    with gzip.open(out / "events.csv.gz.part", "wt", newline="", compresslevel=6) as stream:
        stream.write(",".join(["capture", *EVENT_COLUMNS]) + "\n")
        for name in names:
            with gzip.open(cache / "events" / _cache_name(name), "rt", newline="") as part:
                shutil.copyfileobj(part, stream)
    (out / "events.csv.gz.part").rename(out / "events.csv.gz")
    with open(out / "captures.csv", "w", newline="") as stream:
        writer = csv.DictWriter(stream, CAPTURE_COLUMNS)
        writer.writeheader()
        for name in names:
            writer.writerow(asdict(built[name][0]))
    totals = Counter()
    for _, stats in built.values():
        totals.update({k: v for k, v in stats.items() if isinstance(v, int)})
    by_set = {}
    for capture, _ in built.values():
        entry = by_set.setdefault(capture.set, {"label": capture.label, "captures": 0, "queries": 0, "hours": 0.0,
                                                "tools": set()})
        entry["captures"] += 1
        entry["queries"] += capture.queries
        entry["hours"] = round(entry["hours"] + capture.hours, 3)
        if capture.tool:
            entry["tools"].add(capture.tool)
    for entry in by_set.values():
        entry["tools"] = sorted(entry["tools"])
    info = {
        "built": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
        "sources": sources,
        "captures": len(built),
        "queries": sum(c.queries for c, _ in built.values()),
        "sets": dict(sorted(by_set.items())),
        "packets": dict(totals),
        "events_sha256": sha256(out / "events.csv.gz"),
    }
    (out / "dataset_info.json").write_text(json.dumps(info, indent=1) + "\n")
    log(f"wrote {out}: {info['captures']} captures, {info['queries']} queries")
    return info


# ─── A tiny made-up dataset, for tests ──────────────────────────────────────


def _base32(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase + "234567") for _ in range(length))


def build_smoke(out: Path, seed: int = 1) -> dict:
    """Made-up captures shaped like the real sets: tunnels of several tools and benign browsing."""
    from .pcap import Query

    rng = random.Random(seed)
    cache = out / "cache"
    built = {}
    start = 1_700_000_000.0

    def add(capture: Capture, events: list) -> None:
        events.sort(key=lambda e: e.timestamp)
        summarise(capture, events)
        write_events(cache / "events" / _cache_name(capture.capture), capture.capture, events)
        built[capture.capture] = (capture, {"queries": len(events)})

    tools = {"known": ["alpha", "bravo", "charlie"], "unknown": ["delta"], "android": ["echo"]}
    for kind, names in tools.items():
        for tool in names:
            for rtype in ("TXT", "CNAME"):
                t, events = start + rng.uniform(0, 3600), []
                interval = rng.uniform(0.2, 1.0)
                for i in range(rng.randint(400, 700)):
                    t += rng.expovariate(1 / interval)
                    sub = ".".join(_base32(rng, rng.randint(20, 50)) for _ in range(rng.randint(1, 3)))
                    events.append(Query(t, "10.0.0.66", f"{sub}.t.{tool}-tunnel.test", rtype, "NOERROR",
                                        rng.randint(100, 400)))
                add(Capture(f"smoke/{kind}/{tool}-{rtype.lower()}", "smoke", kind, "tunnel", tool=tool), events)
    sites = [f"site{i}.example" for i in range(300)]
    for n in range(12):
        kind = "browsing" if n < 6 else "crawl" if n < 10 else "wildcard"
        t, events = start + n * 7200, []
        for _ in range(rng.randint(1500, 2500)):
            t += rng.expovariate(1 / 2.0)
            site = sites[min(int(rng.paretovariate(1.2)) - 1, len(sites) - 1)] if kind != "crawl" else rng.choice(sites)
            prefix = rng.choice(["www", "cdn", "api", "img", "static", "a1"]) if kind == "browsing" else (
                _base32(rng, rng.randint(6, 30)) if kind == "wildcard" else "")
            name = f"{prefix}.{site}" if prefix else site
            events.append(Query(t, f"192.168.1.{10 + n}", name, rng.choice(["A", "AAAA", "HTTPS"]),
                                "NXDOMAIN" if rng.random() < 0.02 else "NOERROR", rng.randint(40, 300)))
        add(Capture(f"smoke/{kind}/{n:02d}", "smoke", kind, "benign"), events)
    out.mkdir(parents=True, exist_ok=True)
    (out / "allowlist_top100k.txt").write_text("".join(f"{site}\n" for site in sites[:20]))
    return _write(out, cache, built, {"smoke": seed}, time.monotonic())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, help="downloads and parsed captures (default: OUT/cache)")
    parser.add_argument("--browsing", choices=("all", "small", "none"), default="all",
                        help="Stratosphere browsing captures: all (~6.1 GB), small (~1.1 GB) or none")
    parser.add_argument("--local", type=Path, help="your own captures: LOCAL/benign/, LOCAL/tunnel/<tool>/")
    parser.add_argument("--workers", type=int, default=4, help="downloads at a time")
    parser.add_argument("--keep-pcaps", action="store_true", help="keep the big full captures after parsing")
    parser.add_argument("--smoke", action="store_true", help="a tiny made-up dataset, no network")
    args = parser.parse_args()
    if args.smoke:
        build_smoke(args.out)
    else:
        build(args.out, args.cache or args.out / "cache", args.browsing, args.local, args.workers, args.keep_pcaps)


if __name__ == "__main__":
    main()
