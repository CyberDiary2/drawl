#!/usr/bin/env bash
# re-run banner grab and ingest without re-scanning
set -euo pipefail

DATA_DIR="${DATA_DIR:-./data}"
DB="${DB:-./drawl.db}"

> "$DATA_DIR/banners.jsonl"

TMPFILE=$(mktemp)

for port_module in "80:http" "443:http" "8080:http" "8443:http" "22:ssh" "3306:mysql" "6379:redis" "9200:http" "21:ftp" "5432:postgres" "27017:mongodb"; do
  port="${port_module%%:*}"
  module="${port_module##*:}"
  grep ":${port}$" "$DATA_DIR/targets.txt" | cut -d: -f1 > "$TMPFILE" || true
  count=$(wc -l < "$TMPFILE")
  if [ "$count" -gt 0 ]; then
    echo "[drawl] grabbing banners on port $port ($module) — $count targets..."
    zgrab2 "$module" --port "$port" --goroutines 100 --input-file "$TMPFILE" \
      >> "$DATA_DIR/banners.jsonl" 2>/dev/null || true
  fi
done

rm -f "$TMPFILE"

echo "[drawl] ingesting into database..."
venv/bin/python3 -m drawl.ingest "$DATA_DIR/banners.jsonl"

echo "[drawl] tagging CVEs..."
venv/bin/python3 -m drawl.cves "$DB"

echo "[drawl] done. $(wc -l < "$DATA_DIR/banners.jsonl") banners grabbed."
