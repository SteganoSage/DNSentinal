#!/usr/bin/env bash
# Build and run the ns-3 link-profile simulation (link_profiles.cc), then plot it.
#
#   sim/ns3/run.sh                # results in ~/dnsentinel-sim (off /mnt: faster on WSL)
#   sim/ns3/run.sh /some/dir      # ...or there
#
# Needs ns-3 (sudo apt install ns3 libns3-dev) and python3 with matplotlib.
# Writes link_profiles.csv (one row per lookup), summary.txt (the table it
# prints) and link_profiles.png (the figure).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$HOME/dnsentinel-sim}"
mkdir -p "$out"

modules=(ns3-core ns3-network ns3-internet ns3-point-to-point)
if ! pkg-config --exists "${modules[@]}"; then
    echo "ns-3 not found: sudo apt install ns3 libns3-dev" >&2
    exit 1
fi
# Ubuntu's ns-3 .pc files name libsqlite3.so and libgsl.so, which only their
# -dev packages install. The ns-3 libraries already link the runtime
# versions, so leave out paths that don't exist.
libs=()
for flag in $(pkg-config --libs "${modules[@]}"); do
    [[ $flag == /* && ! -e $flag ]] && continue
    libs+=("$flag")
done

echo "building $out/link_profiles ..."
# shellcheck disable=SC2046  # pkg-config output is meant to split into flags
g++ -std=c++20 -O2 -o "$out/link_profiles" "$here/link_profiles.cc" $(pkg-config --cflags "${modules[@]}") "${libs[@]}"
"$out/link_profiles" --out="$out/link_profiles.csv" | tee "$out/summary.txt"
python3 "$here/plot_link_profiles.py" "$out/link_profiles.csv" "$out/link_profiles.png"
