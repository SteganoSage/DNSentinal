#!/usr/bin/env python3
"""A1 — the cache-poisoning model (EVALUATION.md §4), and figure F6.

Off-path Kaminsky poisoning: the attacker must match every random value in the resolver's
upstream query in one race window. With N equally likely combinations and k distinct forged
guesses landed per window, each window succeeds with probability k/N, windows are independent
(a fresh random name each time), so the forged packets to success are geometric with mean N/k.

This script is pure arithmetic over that model — no attack. It writes the model curve
(expected forged packets vs bits of entropy, N = 2^b) and overlays the measured points from an
E5 run, if given. F6 is log-scale: measured points, the model line, extrapolated to full entropy.

    python3 bench/drivers/a1_model.py --out bench/plots/F6_poisoning.png \
        --measured 8:256                 # bits:forged_packets from lab/attacks/kaminsky.py
"""

from __future__ import annotations

import argparse
from pathlib import Path

# DNSentinel's randomised fields (hardened): 16-bit ID, Linux ephemeral port range, 0x20 case.
ID_BITS = 16
PORT_RANGE = 60999 - 32768 + 1          # Linux default ephemeral ports
MIN_NAME_LETTERS = 8                     # a modest Kaminsky random label; 0x20 adds 2^L on top


def expected_packets(bits: float) -> float:
    """Mean forged packets to success = N, with N = 2^bits equally likely combinations (k = 1 per window)."""
    return 2.0 ** bits


def hardened_combinations(name_letters: int) -> float:
    return (2 ** ID_BITS) * PORT_RANGE * (2 ** name_letters)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--measured", nargs="*", default=[], help="bits:packets points, e.g. 8:256")
    args = parser.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    bits = [b / 2 for b in range(2, 97)]  # 1 .. 48 bits
    model = [expected_packets(b) for b in bits]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(bits, model, label="model: expected forged packets = $2^b$", color="#4c72b0")

    for point in args.measured:
        b, packets = point.split(":")
        ax.scatter([float(b)], [float(packets)], color="#c44e52", zorder=5, s=60,
                   label=f"measured: {b}-bit ID, fixed port → {packets} packets")

    full = ID_BITS + (PORT_RANGE.bit_length() - 1) + MIN_NAME_LETTERS
    ax.axvline(full, color="#555", linestyle="--", linewidth=1)
    ax.text(full - 0.5, 10, f"DNSentinel hardened\n≈ {full} bits "
            f"($2^{{16}}$ ID × {PORT_RANGE:,} ports × $2^{{{MIN_NAME_LETTERS}}}$ case)",
            ha="right", fontsize=8)
    ax.set_yscale("log")
    ax.set_xlabel("bits of entropy the attacker must guess ($b$)")
    ax.set_ylabel("expected forged packets to success (log)")
    ax.set_title("A1: off-path cache-poisoning cost vs entropy (F6)")
    ax.grid(alpha=0.3, which="both")
    ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, dpi=150)
    plt.close(fig)

    print(f"A1 model, worked numbers:")
    print(f"  8-bit ID, fixed port (weak): N = {2**8} -> ~{2**8} forged packets (measured: see F6)")
    print(f"  hardened (16-bit ID x {PORT_RANGE:,} ports x 2^{MIN_NAME_LETTERS} case): "
          f"N = {hardened_combinations(MIN_NAME_LETTERS):.3g} ~= 2^{full}")
    r = 100_000
    print(f"  at {r:,} forged packets/s, expected time to poison hardened: "
          f"{hardened_combinations(MIN_NAME_LETTERS) / r / 3.15e7:.1f} years (one window's worth of guesses per name)")
    print(f"  wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
