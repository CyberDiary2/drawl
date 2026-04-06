#!/usr/bin/env bash
# drawl scan pipeline
# usage: ./scan.sh [CIDR] [--ports 80,443,...] [--rate 50000]
set -euo pipefail

CIDR="${1:-0.0.0.0/0}"
PORTS="${PORTS:-80,443,22,21,3306,5432,6379,27017,9200,8080,8443}"
RATE="${RATE:-50000}"
EXCLUDE="${EXCLUDE:-/etc/masscan/exclude.conf}"
DATA_DIR="${DATA_DIR:-./data}"
DB="${DB:-./drawl.db}"
ZGRAB_CONFIG="${ZGRAB_CONFIG:-./zgrab.ini}"

mkdir -p "$DATA_DIR"

echo "[drawl] scanning $CIDR on ports $PORTS at ${RATE}pps"

# Phase 1: port discovery
masscan "$CIDR" \
  -p"$PORTS" \
  --rate "$RATE" \
  ${EXCLUDE:+--excludefile "$EXCLUDE"} \
  -oJ "$DATA_DIR/open_ports.json"

echo "[drawl] parsing masscan output..."
python3 -m drawl.parse_masscan "$DATA_DIR/open_ports.json" > "$DATA_DIR/targets.txt"

TARGET_COUNT=$(wc -l < "$DATA_DIR/targets.txt")
echo "[drawl] $TARGET_COUNT open ports found, starting banner grab..."

# Phase 2: banner grabbing
zgrab2 multiple \
  --config "$ZGRAB_CONFIG" \
  --input-file "$DATA_DIR/targets.txt" \
  --output-file "$DATA_DIR/banners.jsonl" \
  --goroutines 500

echo "[drawl] ingesting into database..."
python3 -m drawl.ingest "$DATA_DIR/banners.jsonl"

echo "[drawl] tagging hosts with CVE signatures..."
python3 -m drawl.cves "$DB"

echo "[drawl] scan complete. DB: $DB"
