import sys; sys.path.insert(0, '.')
from drawl.db import get_conn, init_db, upsert_host
from datetime import datetime, timezone

init_db()
now = datetime.now(timezone.utc).isoformat()

hosts = [
    {
        "ip": "1.2.3.4", "port": 80, "protocol": "http", "service": "http",
        "banner": "<title>Apache2 Ubuntu Default Page</title>",
        "http_status": 200, "http_title": "Apache2 Ubuntu Default Page",
        "http_redirect": None, "server_header": "Apache/2.4.49 (Ubuntu)",
        "content_type": "text/html", "tls_cn": None, "tls_domains": None,
        "ssh_version": None, "response_hash": "abc123", "last_seen": now,
    },
    {
        "ip": "1.2.3.4", "port": 22, "protocol": "ssh", "service": "ssh",
        "banner": "SSH-2.0-OpenSSH_8.2", "http_status": None, "http_title": None,
        "http_redirect": None, "server_header": None, "content_type": None,
        "tls_cn": None, "tls_domains": None, "ssh_version": "SSH-2.0-OpenSSH_8.2",
        "response_hash": None, "last_seen": now,
    },
    {
        "ip": "5.6.7.8", "port": 443, "protocol": "https", "service": "https",
        "banner": None, "http_status": 200, "http_title": "GitLab",
        "http_redirect": None, "server_header": "nginx", "content_type": "text/html",
        "tls_cn": "gitlab.example.com", "tls_domains": "gitlab.example.com",
        "ssh_version": None, "response_hash": "def456", "last_seen": now,
    },
    {
        "ip": "9.10.11.12", "port": 6379, "protocol": "redis", "service": "redis",
        "banner": "redis_version:7.0.1", "http_status": None, "http_title": None,
        "http_redirect": None, "server_header": None, "content_type": None,
        "tls_cn": None, "tls_domains": None, "ssh_version": None,
        "response_hash": None, "last_seen": now,
    },
    {
        "ip": "9.10.11.12", "port": 9200, "protocol": "http", "service": "elasticsearch",
        "banner": '{"cluster_name":"my-cluster"}', "http_status": 200,
        "http_title": "elasticsearch", "http_redirect": None, "server_header": None,
        "content_type": "application/json", "tls_cn": None, "tls_domains": None,
        "ssh_version": None, "response_hash": None, "last_seen": now,
    },
]

with get_conn() as conn:
    for h in hosts:
        upsert_host(conn, h)

print("seeded", len(hosts), "hosts")
