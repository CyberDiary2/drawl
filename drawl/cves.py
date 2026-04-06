"""
CVE / misconfiguration tag matching.

Each signature matches against one or more fields of a host record.
After ingest, run:
    python -m drawl.cves

Signatures are pattern-matched against: server_header, http_title,
banner, ssh_version, tls_cn, service, port.
"""
import re
import sys
from .db import DB_PATH, get_conn

# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------
# Each entry:
#   tag         — CVE ID or short label
#   severity    — critical / high / medium / low / info
#   description — human readable
#   match       — list of (field, regex) — ANY match triggers the tag
# ---------------------------------------------------------------------------

SIGNATURES = [
    # -------------------------------------------------------------------------
    # Critical
    # -------------------------------------------------------------------------
    {
        "tag": "CVE-2021-44228",
        "severity": "critical",
        "description": "Log4Shell — Apache Log4j RCE",
        "match": [
            ("server_header", r"log4j"),
            ("http_title",    r"log4j"),
            ("banner",        r"log4j"),
        ],
    },
    {
        "tag": "CVE-2022-22965",
        "severity": "critical",
        "description": "Spring4Shell — Spring Framework RCE",
        "match": [
            ("server_header", r"spring"),
            ("http_title",    r"spring"),
            ("banner",        r"springframework"),
        ],
    },
    {
        "tag": "CVE-2021-26855",
        "severity": "critical",
        "description": "ProxyLogon — Microsoft Exchange SSRF/RCE",
        "match": [
            ("http_title",    r"microsoft exchange|outlook web"),
            ("server_header", r"microsoft-iis"),
            ("tls_cn",        r"mail\.|exchange\.|owa\."),
        ],
    },
    {
        "tag": "CVE-2019-19781",
        "severity": "critical",
        "description": "Citrix ADC / Gateway path traversal RCE",
        "match": [
            ("http_title",    r"citrix|netscaler"),
            ("server_header", r"citrix|netscaler"),
            ("banner",        r"citrix|netscaler"),
        ],
    },
    {
        "tag": "CVE-2021-26084",
        "severity": "critical",
        "description": "Confluence Server OGNL injection RCE",
        "match": [
            ("http_title",    r"confluence"),
            ("server_header", r"confluence"),
            ("banner",        r"confluence"),
        ],
    },
    {
        "tag": "CVE-2022-26134",
        "severity": "critical",
        "description": "Confluence Server OGNL injection RCE (2022)",
        "match": [
            ("http_title",    r"confluence"),
        ],
    },
    {
        "tag": "CVE-2017-5638",
        "severity": "critical",
        "description": "Apache Struts Jakarta multipart RCE",
        "match": [
            ("server_header", r"struts"),
            ("http_title",    r"struts"),
            ("banner",        r"apache struts"),
        ],
    },
    {
        "tag": "CVE-2014-0160",
        "severity": "critical",
        "description": "Heartbleed — OpenSSL memory disclosure",
        "match": [
            ("banner",        r"openssl/1\.0\.1[a-f]"),
            ("server_header", r"openssl/1\.0\.1[a-f]"),
        ],
    },
    {
        "tag": "CVE-2021-22205",
        "severity": "critical",
        "description": "GitLab ExifTool RCE (unauthenticated)",
        "match": [
            ("http_title",    r"gitlab"),
            ("server_header", r"gitlab"),
        ],
    },
    {
        "tag": "CVE-2023-46604",
        "severity": "critical",
        "description": "Apache ActiveMQ RCE",
        "match": [
            ("http_title",    r"activemq"),
            ("banner",        r"activemq"),
        ],
    },

    # -------------------------------------------------------------------------
    # High
    # -------------------------------------------------------------------------
    {
        "tag": "CVE-2019-7609",
        "severity": "high",
        "description": "Kibana prototype pollution RCE",
        "match": [
            ("http_title",    r"kibana"),
            ("banner",        r"kibana"),
        ],
    },
    {
        "tag": "CVE-2017-1000353",
        "severity": "high",
        "description": "Jenkins Java deserialization RCE",
        "match": [
            ("http_title",    r"jenkins"),
            ("server_header", r"jenkins"),
            ("banner",        r"jenkins"),
        ],
    },
    {
        "tag": "CVE-2018-1000861",
        "severity": "high",
        "description": "Jenkins Stapler web framework RCE",
        "match": [
            ("http_title",    r"jenkins"),
        ],
    },
    {
        "tag": "CVE-2020-1938",
        "severity": "high",
        "description": "Ghostcat — Apache Tomcat AJP file read/inclusion",
        "match": [
            ("server_header", r"apache-coyote|tomcat"),
            ("http_title",    r"apache tomcat"),
            ("banner",        r"apache tomcat"),
        ],
    },
    {
        "tag": "CVE-2021-41773",
        "severity": "high",
        "description": "Apache HTTP Server 2.4.49 path traversal / RCE",
        "match": [
            ("server_header", r"apache/2\.4\.49"),
        ],
    },
    {
        "tag": "CVE-2021-42013",
        "severity": "high",
        "description": "Apache HTTP Server 2.4.50 path traversal / RCE",
        "match": [
            ("server_header", r"apache/2\.4\.50"),
        ],
    },
    {
        "tag": "CVE-2023-44487",
        "severity": "high",
        "description": "HTTP/2 Rapid Reset DDoS (affects many servers)",
        "match": [
            ("server_header", r"nginx/1\.(2[0-4]|1[0-9])\.|apache/2\.[24]\."),
        ],
    },
    {
        "tag": "CVE-2022-0847",
        "severity": "high",
        "description": "Dirty Pipe — Linux kernel privilege escalation",
        "match": [
            ("ssh_version",   r"linux"),
            ("banner",        r"linux 5\.[8-9]\.|linux 5\.1[0-6]\."),
        ],
    },
    {
        "tag": "CVE-2019-11043",
        "severity": "high",
        "description": "PHP-FPM nginx buffer underflow RCE",
        "match": [
            ("server_header", r"nginx"),
            ("banner",        r"php"),
        ],
    },

    # -------------------------------------------------------------------------
    # Medium
    # -------------------------------------------------------------------------
    {
        "tag": "CVE-2017-9841",
        "severity": "medium",
        "description": "PHPUnit RCE via /vendor/phpunit path",
        "match": [
            ("http_title",    r"phpunit"),
            ("banner",        r"phpunit"),
        ],
    },
    {
        "tag": "CVE-2020-5902",
        "severity": "medium",
        "description": "F5 BIG-IP TMUI RCE",
        "match": [
            ("http_title",    r"big-?ip|f5"),
            ("server_header", r"big-?ip"),
            ("banner",        r"big-?ip"),
        ],
    },
    {
        "tag": "CVE-2021-3129",
        "severity": "medium",
        "description": "Laravel Ignition file write leading to RCE",
        "match": [
            ("http_title",    r"laravel|ignition"),
            ("banner",        r"laravel"),
        ],
    },
    {
        "tag": "CVE-2023-34362",
        "severity": "medium",
        "description": "MOVEit Transfer SQL injection",
        "match": [
            ("http_title",    r"moveit"),
            ("banner",        r"moveit"),
        ],
    },

    # -------------------------------------------------------------------------
    # Misconfigurations / exposed services (info/high)
    # -------------------------------------------------------------------------
    {
        "tag": "exposed:redis",
        "severity": "high",
        "description": "Redis exposed without authentication",
        "match": [
            ("service",  r"^redis$"),
            ("banner",   r"redis_version"),
        ],
    },
    {
        "tag": "exposed:elasticsearch",
        "severity": "high",
        "description": "Elasticsearch exposed without authentication",
        "match": [
            ("service",  r"^elasticsearch$"),
            ("banner",   r"\"cluster_name\""),
            ("http_title", r"elasticsearch"),
        ],
    },
    {
        "tag": "exposed:mongodb",
        "severity": "high",
        "description": "MongoDB exposed without authentication",
        "match": [
            ("service",  r"^mongodb$"),
            ("banner",   r"mongod"),
        ],
    },
    {
        "tag": "exposed:mysql",
        "severity": "medium",
        "description": "MySQL exposed to internet",
        "match": [
            ("service",  r"^mysql$"),
            ("banner",   r"mysql"),
        ],
    },
    {
        "tag": "exposed:postgresql",
        "severity": "medium",
        "description": "PostgreSQL exposed to internet",
        "match": [
            ("service",  r"^postgresql$"),
        ],
    },
    {
        "tag": "exposed:docker-api",
        "severity": "critical",
        "description": "Docker daemon API exposed to internet",
        "match": [
            ("http_title", r"docker"),
            ("banner",     r"\"docker\""),
        ],
    },
    {
        "tag": "exposed:kubernetes",
        "severity": "high",
        "description": "Kubernetes API server exposed to internet",
        "match": [
            ("http_title", r"kubernetes"),
            ("banner",     r"\"kind\":\"Status\""),
        ],
    },
    {
        "tag": "exposed:phpmyadmin",
        "severity": "medium",
        "description": "phpMyAdmin exposed to internet",
        "match": [
            ("http_title", r"phpmyadmin"),
            ("banner",     r"phpmyadmin"),
        ],
    },
    {
        "tag": "exposed:grafana",
        "severity": "info",
        "description": "Grafana dashboard exposed",
        "match": [
            ("http_title", r"grafana"),
            ("banner",     r"grafana"),
        ],
    },
    {
        "tag": "exposed:jupyter",
        "severity": "high",
        "description": "Jupyter Notebook exposed (often unauthenticated)",
        "match": [
            ("http_title", r"jupyter"),
            ("banner",     r"jupyter"),
        ],
    },
    {
        "tag": "exposed:gitlab",
        "severity": "info",
        "description": "GitLab instance exposed",
        "match": [
            ("http_title", r"gitlab"),
        ],
    },
    {
        "tag": "exposed:sonarqube",
        "severity": "medium",
        "description": "SonarQube exposed to internet",
        "match": [
            ("http_title", r"sonarqube"),
            ("banner",     r"sonarqube"),
        ],
    },
    {
        "tag": "exposed:ansible-tower",
        "severity": "high",
        "description": "Ansible Tower / AWX exposed",
        "match": [
            ("http_title", r"ansible tower|awx"),
        ],
    },
    {
        "tag": "info:login-panel",
        "severity": "info",
        "description": "Login panel detected",
        "match": [
            ("http_title", r"login|sign in|signin|log in|admin panel|administrator"),
        ],
    },
    {
        "tag": "info:default-page",
        "severity": "info",
        "description": "Default web server page",
        "match": [
            ("http_title", r"apache2? (ubuntu|debian|centos|default)|welcome to nginx|iis windows server|default web site"),
        ],
    },
    {
        "tag": "info:directory-listing",
        "severity": "low",
        "description": "Directory listing enabled",
        "match": [
            ("http_title", r"index of /"),
            ("banner",     r"<title>index of /"),
        ],
    },
]

# Precompile all regexes
_COMPILED = []
for sig in SIGNATURES:
    _COMPILED.append({
        **sig,
        "match": [(field, re.compile(pattern, re.IGNORECASE)) for field, pattern in sig["match"]],
    })


def tag_host(record: dict) -> list[dict]:
    """Return list of tag dicts that match this host record."""
    hits = []
    for sig in _COMPILED:
        for field, pattern in sig["match"]:
            value = record.get(field)
            if value and pattern.search(str(value)):
                hits.append({
                    "ip": record["ip"],
                    "port": record["port"],
                    "tag": sig["tag"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "matched_field": field,
                    "matched_value": str(value)[:256],
                })
                break  # one match per signature is enough
    return hits


def run_tagger(db_path=DB_PATH, batch_size=500):
    """Scan all hosts in DB and apply CVE/misconfiguration tags."""
    from .db import get_conn

    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM tags")  # retag from scratch each run
        total = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        print(f"[drawl:tagger] tagging {total} hosts...")

        offset = 0
        tagged = 0
        while True:
            rows = conn.execute(
                "SELECT * FROM hosts LIMIT ? OFFSET ?", [batch_size, offset]
            ).fetchall()
            if not rows:
                break
            for row in rows:
                record = dict(row)
                for tag in tag_host(record):
                    conn.execute("""
                        INSERT OR REPLACE INTO tags
                            (ip, port, tag, severity, description, matched_field, matched_value)
                        VALUES
                            (:ip, :port, :tag, :severity, :description, :matched_field, :matched_value)
                    """, tag)
                    tagged += 1
            offset += batch_size
            print(f"\r[drawl:tagger] processed {min(offset, total)}/{total}...", end="", flush=True)

    print(f"\r[drawl:tagger] done — {tagged} tags applied to {total} hosts")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DB_PATH
    run_tagger(path)
