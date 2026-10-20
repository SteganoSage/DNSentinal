#!/usr/bin/env bash
# Download the public block lists into config/lists/feeds/ (not committed).
# A running dnsentinel notices the new files within policy.reload_check_seconds
# and reloads them, or at once on SIGHUP: pkill -HUP dnsentinel
#
# usage: config/lists/download_feeds.sh
set -euo pipefail

feeds="$(cd "$(dirname "$0")" && pwd)/feeds"
mkdir -p "$feeds"

# name  url  (licence)
sources=(
    "ads      https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"  # MIT
    "trackers https://v.firebog.net/hosts/Easyprivacy.txt"                       # EasyPrivacy, GPLv3 / CC BY-SA
    "malware  https://urlhaus.abuse.ch/downloads/hostfile/"                      # abuse.ch URLhaus, CC0
    # Not a block list: the popular sites ml.dga never scores. Tranco list 64VVX, the one the
    # DGA model was trained against (ml/DATA.md); free for research, cite Le Pochat et al. 2019.
    "tranco_top100k https://tranco-list.eu/download/64VVX/100000"
)

{
    echo "# downloaded $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# file  lines  sha256  url"
} > "$feeds/SOURCES.txt.tmp"

for entry in "${sources[@]}"; do
    read -r name url <<< "$entry"
    echo "fetching $name.txt from $url"
    curl -fsSL --retry 2 --max-time 120 -o "$feeds/$name.txt.tmp" "$url"
    mv "$feeds/$name.txt.tmp" "$feeds/$name.txt"  # replaced in one step: never read half-written
    echo "$name.txt  $(wc -l < "$feeds/$name.txt")  $(sha256sum "$feeds/$name.txt" | cut -d' ' -f1)  $url" \
        >> "$feeds/SOURCES.txt.tmp"
done
mv "$feeds/SOURCES.txt.tmp" "$feeds/SOURCES.txt"
cat "$feeds/SOURCES.txt"
