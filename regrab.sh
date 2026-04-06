#!/usr/bin/env bash
# re-run banner grab and ingest without re-scanning
set -euo pipefail

DATA_DIR="${DATA_DIR:-./data}"
DB="${DB:-./drawl.db}"

> "$DATA_DIR/banners.jsonl"

for port_module in "80:http" "443:http" "8080:http" "8443:http" "22:ssh" "3306:mysql" "6379:redis" "9200:http" "21:ftp" "5432:postgres" "27017:mongodb"; do
  port="${port_module%%:*}"
  module="${port_module##*:}"
  targets=$(grep ":${port}$" "$DATA_DIR/targets.txt" || true)
  if [ -n "$targets" ]; then
    echo "[drawl] grabbing banners on port $port ($module)..."
    echo "$targets" | cut -d: -f1 | zgrab2 "$module" --port "$port" --goroutines 100 \
      >> "$DATA_DIR/banners.jsonl" 2>/dev/null || true
  fi
done

echo "[drawl] ingesting into database..."
venv/bin/python3 -m drawl.ingest "$DATA_DIR/banners.jsonl"

echo "[drawl] tagging CVEs..."
venv/bin/python3 -m drawl.cves "$DB"

echo "[drawl] done. $(wc -l < "$DATA_DIR/banners.jsonl") banners grabbed."
