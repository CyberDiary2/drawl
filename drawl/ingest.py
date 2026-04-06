"""
Ingest zgrab2 JSONL output into the drawl database.

Usage:
    python -m drawl.ingest banners.jsonl
    cat banners.jsonl | python -m drawl.ingest -
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

from .db import DB_PATH, get_conn, init_db, upsert_host


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_http(data: dict) -> dict:
    """Pull fields from zgrab2 http module result."""
    out = {}
    try:
        resp = data["http"]["result"]["response"]
        out["http_status"] = resp.get("status_code")
        headers = resp.get("headers", {})
        # zgrab2 returns headers as lists
        out["server_header"] = _first(headers.get("server"))
        out["content_type"] = _first(headers.get("content_type"))
        out["http_redirect"] = _first(headers.get("location"))
        body = resp.get("body", "")
        out["banner"] = body[:512] if body else None
        out["response_hash"] = hashlib.md5(body[:10240].encode(errors="ignore")).hexdigest() if body else None
        # title
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        out["http_title"] = m.group(1).strip()[:256] if m else None
    except (KeyError, TypeError):
        pass
    return out


def extract_tls(data: dict) -> dict:
    """Pull TLS cert fields from zgrab2 tls result."""
    out = {}
    try:
        cert = data["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["parsed"]
        cns = cert.get("subject", {}).get("common_name", [])
        out["tls_cn"] = cns[0] if cns else None
        sans = cert.get("extensions", {}).get("subject_alt_name", {}).get("dns_names", [])
        out["tls_domains"] = ",".join(sans[:50]) if sans else None
    except (KeyError, TypeError):
        pass
    return out


def extract_ssh(data: dict) -> dict:
    out = {}
    try:
        out["ssh_version"] = data["ssh"]["result"]["server_id"]["raw"][:128]
        out["banner"] = out["ssh_version"]
    except (KeyError, TypeError):
        pass
    return out


def _first(val):
    """zgrab2 returns header values as lists."""
    if isinstance(val, list) and val:
        return val[0]
    return val


SERVICE_MAP = {
    80: "http", 443: "https", 22: "ssh", 21: "ftp",
    25: "smtp", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
    8080: "http-alt", 8443: "https-alt",
}


def parse_record(line: str) -> dict | None:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    ip = entry.get("ip")
    port = entry.get("port")
    # zgrab2 embeds port inside data.<module>.port when not at top level
    if not port and entry.get("data"):
        for module_data in entry["data"].values():
            if isinstance(module_data, dict):
                port = module_data.get("port")
                if port:
                    break
    if not ip or not port:
        return None

    data = entry.get("data", {})
    protocol = list(data.keys())[0] if data else None

    record = {
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "service": SERVICE_MAP.get(port, protocol),
        "banner": None,
        "http_status": None,
        "http_title": None,
        "http_redirect": None,
        "server_header": None,
        "content_type": None,
        "tls_cn": None,
        "tls_domains": None,
        "ssh_version": None,
        "response_hash": None,
        "last_seen": now(),
    }

    if "http" in data:
        record.update(extract_http(data))
        if "tls" in data.get("http", {}).get("result", {}):
            record.update(extract_tls({"tls": data["http"]["result"]["tls"]}))
    if "tls" in data:
        record.update(extract_tls(data))
    if "ssh" in data:
        record.update(extract_ssh(data))

    return record


def ingest(source, db_path=DB_PATH, batch_size=500):
    init_db(db_path)
    inserted = 0
    skipped = 0
    batch = []

    with get_conn(db_path) as conn:
        for line in source:
            line = line.strip()
            if not line:
                continue
            record = parse_record(line)
            if record:
                batch.append(record)
            else:
                skipped += 1

            if len(batch) >= batch_size:
                for r in batch:
                    upsert_host(conn, r)
                inserted += len(batch)
                print(f"\r[drawl] ingested {inserted}...", end="", flush=True)
                batch = []

        for r in batch:
            upsert_host(conn, r)
        inserted += len(batch)

    print(f"\r[drawl] done — {inserted} records ingested, {skipped} skipped")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1]) as f:
            ingest(f)
    else:
        ingest(sys.stdin)
