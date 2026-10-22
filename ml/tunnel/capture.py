"""Capture ordinary DNS traffic with Wireshark and export query records."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def capture(interface: str, duration: int, pcap: Path, tshark: str) -> None:
    dumpcap = shutil.which("dumpcap") or r"C:\Program Files\Wireshark\dumpcap.exe"
    if not Path(dumpcap).exists():
        raise RuntimeError(
            "Wireshark dumpcap was not found; install Wireshark and select a capture interface"
        )
    pcap.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [dumpcap, "-i", interface, "-a", f"duration:{duration}", "-w", str(pcap)],
        check=True,
    )
    if not Path(tshark).exists() and shutil.which(tshark) is None:
        raise RuntimeError("Wireshark tshark was not found; cannot extract the saved capture")


def extract_queries(tshark: str, pcap: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        tshark,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        "dns.flags.response == 0 && dns.qry.name",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "dns.qry.name",
    ]
    with output.open("w", encoding="utf-8", newline="") as stream:
        stream.write("timestamp,src_ip,qname\n")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            fields = line.rstrip("\r\n").split("\t", 3)
            if len(fields) == 4 and fields[0] and fields[3]:
                stream.write(f"{fields[0]},{fields[1] or fields[2]},{fields[3]}\n")
        stderr = process.stderr.read() if process.stderr is not None else ""
        if process.wait() != 0:
            raise RuntimeError(f"tshark could not read {pcap}: {stderr.strip()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, help="Wireshark capture interface")
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument(
        "--tshark",
        default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe",
    )
    args = parser.parse_args()
    capture(args.interface, args.duration, args.pcap, args.tshark)
    extract_queries(args.tshark, args.pcap, args.queries)


if __name__ == "__main__":
    main()
