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
    ASN_NUM="${QUERY^^}"
    ASN_NUM="${ASN_NUM:2}"
else
    echo "[asnscan] searching for: $QUERY"
    RESULTS=$(curl -s "https://api.hackertarget.com/aslookup/?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$QUERY")")

    if [ -z "$RESULTS" ] || echo "$RESULTS" | grep -q "error\|API count"; then
        echo "[asnscan] no results found for: $QUERY"
        echo "$RESULTS"
        exit 1
    fi

    echo ""
    echo "$RESULTS" | nl -v0 | sed 's/^\s*\([0-9]*\)\s*/  [\1] /'
    echo ""
    read -rp "select entry number [0]: " IDX
    IDX="${IDX:-0}"
    ASN_NUM=$(echo "$RESULTS" | sed -n "$((IDX+1))p" | grep -oP '^\d+')
fi

echo "[asnscan] fetching prefixes for AS${ASN_NUM}..."
CIDR_LIST=$(curl -s "https://api.hackertarget.com/aslookup/?q=AS${ASN_NUM}" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+')

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
    echo "$CIDR_LIST" > "/tmp/as${ASN_NUM}_ranges.txt"
    echo "[asnscan] saved to /tmp/as${ASN_NUM}_ranges.txt"
    echo "[asnscan] run: cat /tmp/as${ASN_NUM}_ranges.txt | tr '\n' ' ' | xargs -I{} ./scan.sh {}"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DONE=0

while IFS= read -r cidr; do
    DONE=$((DONE + 1))
    echo ""
    echo "[asnscan] [$DONE/$COUNT] scanning $cidr..."
    cd "$SCRIPT_DIR" && ./scan.sh "$cidr"
done <<< "$CIDR_LIST"

echo ""
echo "[asnscan] done — scanned $COUNT ranges for AS${ASN_NUM}"
