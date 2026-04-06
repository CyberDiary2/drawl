#!/usr/bin/env bash
# asnscan.sh - look up a company's IP ranges by ASN or name and scan them
# usage:
#   ./asnscan.sh tesla            # search by company name, pick ASN interactively
#   ./asnscan.sh AS13335          # scan directly by ASN number
set -euo pipefail

QUERY="${1:-}"
if [ -z "$QUERY" ]; then
    echo "usage: ./asnscan.sh <company name or ASN>"
    exit 1
fi

# if given an ASN directly, skip search
if [[ "$QUERY" =~ ^[Aa][Ss][0-9]+$ ]]; then
    ASN="${QUERY^^}"
    ASN_NUM="${ASN:2}"
else
    echo "[asnscan] searching for: $QUERY"
    RESULTS=$(curl -s "https://api.bgpview.io/search?query=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$QUERY")")
    COUNT=$(echo "$RESULTS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['data']['asns']))")

    if [ "$COUNT" -eq 0 ]; then
        echo "[asnscan] no ASNs found for: $QUERY"
        exit 1
    fi

    echo ""
    echo "$RESULTS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for i,a in enumerate(d['data']['asns']):
    print(f\"  [{i}] AS{a['asn']} — {a['name']} — {a.get('description','')}\")
"
    echo ""
    read -rp "select ASN number [0]: " IDX
    IDX="${IDX:-0}"

    ASN_NUM=$(echo "$RESULTS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d['data']['asns'][$IDX]['asn'])
")
fi

echo "[asnscan] fetching prefixes for AS${ASN_NUM}..."
PREFIXES=$(curl -s "https://api.bgpview.io/asn/${ASN_NUM}/prefixes")
CIDR_LIST=$(echo "$PREFIXES" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['data']['ipv4_prefixes']:
    print(p['prefix'])
")

COUNT=$(echo "$CIDR_LIST" | grep -c '.' || true)
if [ "$COUNT" -eq 0 ]; then
    echo "[asnscan] no IPv4 prefixes found for AS${ASN_NUM}"
    exit 1
fi

echo "[asnscan] found $COUNT prefixes for AS${ASN_NUM}:"
echo "$CIDR_LIST" | sed 's/^/  /'
echo ""
read -rp "start scanning all $COUNT ranges? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "[asnscan] saving ranges to /tmp/as${ASN_NUM}_ranges.txt"
    echo "$CIDR_LIST" > "/tmp/as${ASN_NUM}_ranges.txt"
    echo "[asnscan] run manually: while read c; do ./scan.sh \"\$c\"; done < /tmp/as${ASN_NUM}_ranges.txt"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL=0
DONE=0

while IFS= read -r cidr; do
    DONE=$((DONE + 1))
    echo ""
    echo "[asnscan] [$DONE/$COUNT] scanning $cidr..."
    cd "$SCRIPT_DIR" && ./scan.sh "$cidr"
done <<< "$CIDR_LIST"

echo ""
echo "[asnscan] done — scanned $COUNT ranges for AS${ASN_NUM}"
