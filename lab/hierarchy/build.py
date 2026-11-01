#!/usr/bin/env python3
"""The lab's DNS hierarchy, written as NSD zone files and configs (EVALUATION.md §3.1).

    python3 lab/hierarchy/build.py                       # lab/hierarchy/out/
    python3 lab/hierarchy/build.py --popular top.csv --count 10000   # also W3: Tranco's top names

One source for every zone, so the crafted cases can't drift apart:

  root  10.53.2.10   .
  tld   10.53.2.11   lab. test. com. net. org. info.
  auth  10.53.2.20   example.lab bank.lab cloaked.lab tracker.lab auth.lab lame.lab noglue.lab
                     example.net, a DGA command server under .info, the command servers of the
                     pipeline experiment's DGA families (lab/traffic_gen/dga_families.txt),
                     and, with --popular, one zone per popular name
  quirks 10.53.2.30  attacker.lab slow.lab nocase.lab nxns.lab deep.lab (lab/servers/quirks.py: what NSD
                     won't do; deep.lab's cuts must each be a referral, and NSD answers from its deepest zone)
  iodined 10.53.2.40 tunnel.lab, dnscat2 10.53.2.41 dnscat.lab, rebind 10.53.2.50 rebind.lab

With --popular, each of the first --count names in a "rank,domain" list (the Tranco top 100k
the DGA allowlist uses) gets a zone on auth with an apex A, www A/AAAA and a few hosts, so
workload W3 resolves offline as it would on the internet: through the root, a TLD, a referral.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ROOT_IP, TLD_IP, AUTH_IP, QUIRKS_IP = "10.53.2.10", "10.53.2.11", "10.53.2.20", "10.53.2.30"
IODINE_IP, DNSCAT_IP, REBIND_IP, NOBODY_IP = "10.53.2.40", "10.53.2.41", "10.53.2.50", "10.53.2.99"
TLDS = ("lab", "test", "com", "net", "org", "info")
SERIAL = "2026110101"
HERE = Path(__file__).resolve().parent


def soa(origin: str, ns: str) -> str:
    return (f"$ORIGIN {origin}\n$TTL 3600\n"
            f"@ IN SOA {ns} hostmaster.lab. ( {SERIAL} 3600 600 604800 300 )\n")


def root_zone() -> str:
    lines = [soa(".", "a.root-servers.lab."), "@ IN NS a.root-servers.lab.", f"a.root-servers.lab. IN A {ROOT_IP}"]
    lines += [f"{tld}. 86400 IN NS ns.nic.lab." for tld in TLDS]
    lines.append(f"ns.nic.lab. 86400 IN A {TLD_IP}")  # glue: the TLD server's name is under a TLD it serves
    return "\n".join(lines) + "\n"


def lab_zone() -> str:
    z = [soa("lab.", "ns.nic.lab."), "@ IN NS ns.nic.lab.", f"ns.nic IN A {TLD_IP}", f"a.root-servers IN A {ROOT_IP}"]
    # ordinary zones on auth, glue in the delegation
    for zone in ("example", "bank", "auth", "lame"):
        z.append(f"{zone} 86400 IN NS ns1.{zone}.lab.")
    for zone in ("example", "bank", "auth"):
        z.append(f"ns1.{zone} 86400 IN A {AUTH_IP}")
    # name servers in a sibling zone (glue from the other delegation)
    for zone in ("cloaked", "tracker"):
        z.append(f"{zone} 86400 IN NS ns1.auth.lab.")
    # no glue: its name server is under another TLD, to be resolved on the way
    z.append("noglue 86400 IN NS ns.example.net.")
    # a lame delegation: the first name server never answers
    z += [f"ns1.lame 86400 IN A {NOBODY_IP}", "lame 86400 IN NS ns2.lame.lab.", f"ns2.lame 86400 IN A {AUTH_IP}"]
    # misbehaving servers (lab/servers/quirks.py), tunnels (E8), rebinding (E13)
    for zone, ip in (("attacker", QUIRKS_IP), ("slow", QUIRKS_IP), ("nocase", QUIRKS_IP), ("nxns", QUIRKS_IP),
                     ("deep", QUIRKS_IP), ("exfil", QUIRKS_IP),
                     ("tunnel", IODINE_IP), ("dnscat", DNSCAT_IP), ("rebind", REBIND_IP)):
        z += [f"{zone} 86400 IN NS ns.{zone}.lab.", f"ns.{zone} 86400 IN A {ip}"]
    return "\n".join(z) + "\n"


def tld_zone(tld: str, delegated: list[str]) -> str:
    z = [soa(f"{tld}.", "ns.nic.lab."), "@ IN NS ns.nic.lab."]
    for name in delegated:  # a name under this TLD, served on auth
        z.append(f"{name}. 86400 IN NS ns1.auth.lab.")
    return "\n".join(z) + "\n"


def example_lab() -> str:
    z = [soa("example.lab.", "ns1.example.lab."), "@ IN NS ns1.example.lab.", f"ns1 IN A {AUTH_IP}",
         "@ 300 IN A 192.0.2.1",
         "www 300 IN A 192.0.2.1", "www 300 IN AAAA 2001:db8::1",
         "mail 3600 IN A 192.0.2.2", "@ 3600 IN MX 10 mail.example.lab.",
         '@ 3600 IN TXT "v=spf1 mx -all"',
         # TTLs from one second to a day: caching (E3) and serve-stale (E4)
         "ttl1 1 IN A 192.0.2.11", "ttl60 60 IN A 192.0.2.12", "ttl3600 3600 IN A 192.0.2.13",
         "ttl86400 86400 IN A 192.0.2.14",
         # a CNAME into another zone
         "alias 300 IN CNAME www.bank.lab.",
         # an empty non-terminal: c.example.lab and b.c.example.lab exist only as parents
         "a.b.c 300 IN A 192.0.2.20",
         # names the block lists know (E12): an ad host, and a tracker cloaked behind a first-party CNAME
         "ads 300 IN A 192.0.2.30", "metrics 300 IN CNAME collect.tracker.lab.",
         # a public name pointing into the LAN: rebinding protection (E13, the simple case)
         "router 300 IN A 192.168.1.1"]
    # CNAME chains of 1 to 8 hops: chainN -> chainN-1 -> ... -> www
    for hops in range(1, 9):
        for i in range(hops, 0, -1):
            target = "www.example.lab." if i == 1 else f"chain{hops}-{i - 1}.example.lab."
            name = f"chain{hops}" if i == hops else f"chain{hops}-{i}"
            z.append(f"{name} 300 IN CNAME {target}")
    # a TXT too large for 512-byte UDP: the answer is truncated and retried over TCP
    strings = " ".join(f'"{hashlib.sha256(str(i).encode()).hexdigest()[:60]}"' for i in range(30))
    z.append(f"big 300 IN TXT {strings}")
    return "\n".join(z) + "\n"


def simple_zone(origin: str, records: list[str], ns: str = "ns1.auth.lab.") -> str:
    return soa(origin, ns) + f"@ IN NS {ns}\n" + "\n".join(records) + "\n"


def c2_records() -> dict[str, list[str]]:
    """The DGA families' command servers (lab/traffic_gen/dga_families.txt): each resolves, the rest don't."""
    path = HERE.parent / "traffic_gen" / "dga_families.txt"
    zones: dict[str, list[str]] = {}
    if not path.exists():
        return {}
    servers = [line.split()[2] for line in path.read_text().splitlines() if " c2 " in line]
    for i, name in enumerate(servers):
        address = f"192.0.2.{200 + i}"
        if name.count(".") == 1:
            zones.setdefault(name, []).extend([f"@ 300 IN A {address}", f"www 300 IN A {address}"])
        else:  # under dynamic DNS (ddns.net): the provider's zone holds the generated name
            parent = name.split(".", 1)[1]
            zones.setdefault(parent, []).append(f"{name}. 60 IN A {address}")
    return zones


def auth_zones(popular: list[str]) -> dict[str, str]:
    zones = {
        "example.lab": example_lab(),
        "bank.lab": simple_zone("bank.lab.", [f"ns1 IN A {AUTH_IP}", "@ 300 IN A 192.0.2.80", "www 300 IN A 192.0.2.80",
                                              "login 300 IN A 192.0.2.81"], "ns1.bank.lab."),
        "auth.lab": simple_zone("auth.lab.", [f"ns1 IN A {AUTH_IP}"], "ns1.auth.lab."),
        "tracker.lab": simple_zone("tracker.lab.", ["collect 300 IN A 192.0.2.66", "pixel 300 IN A 192.0.2.67"]),
        "cloaked.lab": simple_zone("cloaked.lab.", ["@ 300 IN A 192.0.2.70",
                                                    "metrics 300 IN CNAME collect.tracker.lab."]),
        "lame.lab": simple_zone("lame.lab.", [f"ns1 IN A {NOBODY_IP}", f"ns2 IN A {AUTH_IP}",
                                              "www 300 IN A 192.0.2.90"], "ns2.lame.lab."),
        "noglue.lab": simple_zone("noglue.lab.", ["www 300 IN A 192.0.2.101"], "ns.example.net."),
        "example.net": simple_zone("example.net.", [f"ns 86400 IN A {AUTH_IP}", "www 300 IN A 192.0.2.100"]),
        # a DGA's live command server: one generated name that resolves (E7, score fusion)
        "mdexmtiwmjia.info": simple_zone("mdexmtiwmjia.info.", ["@ 300 IN A 192.0.2.77", "www 300 IN A 192.0.2.77"]),
    }
    for rank, name in enumerate(popular, 1):
        # stable made-up addresses from the name: the same lab every build
        h = hashlib.sha256(name.encode()).digest()
        a = f"198.18.{h[0]}.{h[1] or 1}"
        zones[name] = simple_zone(f"{name}.", [
            f"@ 300 IN A {a}", f"www 300 IN A {a}", f"www 300 IN AAAA 2001:db8:{h[2]:x}{h[3]:02x}::{rank:x}",
            f"cdn 60 IN A 198.19.{h[4]}.{h[5] or 1}", f"api 300 IN CNAME www.{name}.",
            f"mail 3600 IN A 198.18.{h[6]}.{h[7] or 1}", f"@ 3600 IN MX 10 mail.{name}."])
    for zone, records in c2_records().items():  # merged into a popular zone of the same name (ddns.net)
        zones[zone] = zones[zone] + "\n".join(records) + "\n" if zone in zones else simple_zone(f"{zone}.", records)
    return zones


def nsd_conf(ip: str, zones: list[str]) -> str:
    conf = [f"server:\n  ip-address: {ip}\n  port: 53\n  username: \"\"\n  zonesdir: \"/dnsentinel/lab/hierarchy/out/zones\"\n"
            "  database: \"\"\n  zonelistfile: \"/tmp/nsd.zonelist\"\n  xfrdfile: \"/tmp/nsd.xfrd\"\n"
            "  pidfile: \"\"\n  hide-version: yes\n  verbosity: 1\n  server-count: 1\n"
            "remote-control:\n  control-enable: no\n"]
    for zone in zones:
        conf.append(f"zone:\n  name: \"{zone}\"\n  zonefile: \"{zone if zone != '.' else 'root'}.zone\"\n")
    return "".join(conf)


def read_popular(path: Path, count: int) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name = line.split("#", 1)[0].strip().rsplit(",", 1)[-1].strip().lower().rstrip(".")
        if name.count(".") == 1 and name.rsplit(".", 1)[1] in TLDS and name not in names:
            names.append(name)  # only TLDs the lab has; one label below them
        if len(names) >= count:
            break
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=HERE / "out")
    parser.add_argument("--popular", type=Path, help="a 'rank,domain' list (Tranco) for workload W3")
    parser.add_argument("--count", type=int, default=10000, help="how many popular names (default 10000)")
    args = parser.parse_args()
    popular = read_popular(args.popular, args.count) if args.popular else []

    zones_dir = args.out / "zones"
    zones_dir.mkdir(parents=True, exist_ok=True)
    for old in zones_dir.glob("*.zone"):
        old.unlink()
    auth = auth_zones(popular)
    by_tld: dict[str, list[str]] = {tld: [] for tld in TLDS}
    for name in auth:
        if name.count(".") == 1 and name.rsplit(".", 1)[1] in by_tld and not name.endswith(".lab"):
            by_tld[name.rsplit(".", 1)[1]].append(name)

    (zones_dir / "root.zone").write_text(root_zone())
    (zones_dir / "lab.zone").write_text(lab_zone())
    for tld in TLDS:
        if tld != "lab":
            (zones_dir / f"{tld}.zone").write_text(tld_zone(tld, by_tld[tld]))
    for name, text in auth.items():
        (zones_dir / f"{name}.zone").write_text(text)

    (args.out / "root.conf").write_text(nsd_conf(ROOT_IP, ["."]))
    (args.out / "tld.conf").write_text(nsd_conf(TLD_IP, list(TLDS)))
    (args.out / "auth.conf").write_text(nsd_conf(AUTH_IP, list(auth)))
    (args.out / "root.hints").write_text(f".  3600000  NS  a.root-servers.lab.\n"
                                         f"a.root-servers.lab.  3600000  A  {ROOT_IP}\n")
    (args.out / "popular.txt").write_text("".join(f"{i},{n}\n" for i, n in enumerate(popular, 1)))
    print(f"{args.out}: {len(auth) + len(TLDS) + 1} zones ({len(popular)} popular names); "
          f"root {ROOT_IP}, TLDs {TLD_IP}, auth {AUTH_IP}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
