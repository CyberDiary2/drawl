"""
Database schema and helpers. Uses plain SQLite — no ORM.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "drawl.db"


def connect(path: str | Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


@contextmanager
def get_conn(path: str | Path = DB_PATH):
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT,
    service         TEXT,
    banner          TEXT,
    http_status     INTEGER,
    http_title      TEXT,
    http_redirect   TEXT,
    server_header   TEXT,
    content_type    TEXT,
    tls_cn          TEXT,
    tls_domains     TEXT,       -- comma-separated SANs
    ssh_version     TEXT,
    response_hash   TEXT,
    hostname        TEXT,
    last_seen       TEXT NOT NULL,
    PRIMARY KEY (ip, port)
);

CREATE INDEX IF NOT EXISTS idx_port     ON hosts(port);
CREATE INDEX IF NOT EXISTS idx_service  ON hosts(service);
CREATE INDEX IF NOT EXISTS idx_http_status ON hosts(http_status);
CREATE INDEX IF NOT EXISTS idx_tls_cn   ON hosts(tls_cn);
CREATE INDEX IF NOT EXISTS idx_last_seen ON hosts(last_seen);

CREATE TABLE IF NOT EXISTS tags (
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    tag         TEXT NOT NULL,
    severity    TEXT,
    description TEXT,
    matched_field TEXT,
    matched_value TEXT,
    PRIMARY KEY (ip, port, tag),
    FOREIGN KEY (ip, port) REFERENCES hosts(ip, port) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tag      ON tags(tag);
CREATE INDEX IF NOT EXISTS idx_severity ON tags(severity);

CREATE VIRTUAL TABLE IF NOT EXISTS hosts_fts USING fts5(
    ip, service, http_title, server_header, tls_cn, tls_domains, banner,
    content=hosts,
    content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS hosts_ai AFTER INSERT ON hosts BEGIN
    INSERT INTO hosts_fts(rowid, ip, service, http_title, server_header, tls_cn, tls_domains, banner)
    VALUES (new.rowid, new.ip, new.service, new.http_title, new.server_header, new.tls_cn, new.tls_domains, new.banner);
END;

CREATE TRIGGER IF NOT EXISTS hosts_au AFTER UPDATE ON hosts BEGIN
    INSERT INTO hosts_fts(hosts_fts, rowid, ip, service, http_title, server_header, tls_cn, tls_domains, banner)
    VALUES ('delete', old.rowid, old.ip, old.service, old.http_title, old.server_header, old.tls_cn, old.tls_domains, old.banner);
    INSERT INTO hosts_fts(rowid, ip, service, http_title, server_header, tls_cn, tls_domains, banner)
    VALUES (new.rowid, new.ip, new.service, new.http_title, new.server_header, new.tls_cn, new.tls_domains, new.banner);
END;
"""


def init_db(path: str | Path = DB_PATH):
    with get_conn(path) as conn:
        conn.executescript(SCHEMA)
        # migrate: add hostname column if missing
        cols = [r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()]
        if "hostname" not in cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN hostname TEXT")
    print(f"[drawl] database ready: {path}")


def upsert_host(conn: sqlite3.Connection, record: dict):
    conn.execute("""
        INSERT INTO hosts (
            ip, port, protocol, service, banner,
            http_status, http_title, http_redirect, server_header, content_type,
            tls_cn, tls_domains, ssh_version, response_hash, last_seen
        ) VALUES (
            :ip, :port, :protocol, :service, :banner,
            :http_status, :http_title, :http_redirect, :server_header, :content_type,
            :tls_cn, :tls_domains, :ssh_version, :response_hash, :last_seen
        )
        ON CONFLICT(ip, port) DO UPDATE SET
            protocol        = excluded.protocol,
            service         = excluded.service,
            banner          = excluded.banner,
            http_status     = excluded.http_status,
            http_title      = excluded.http_title,
            http_redirect   = excluded.http_redirect,
            server_header   = excluded.server_header,
            content_type    = excluded.content_type,
            tls_cn          = excluded.tls_cn,
            tls_domains     = excluded.tls_domains,
            ssh_version     = excluded.ssh_version,
            response_hash   = excluded.response_hash,
            last_seen       = excluded.last_seen
    """, record)
