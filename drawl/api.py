"""
drawl query API + web UI.

Run:
    uvicorn drawl.api:app --host 0.0.0.0 --port 8000
"""
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from typing import Optional
import math

from .db import DB_PATH, connect

app = FastAPI(title="drawl", docs_url="/api/docs")


def db():
    conn = connect()
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Shared CSS + nav
# ---------------------------------------------------------------------------

BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d0d0d; color: #e0e0e0; font-family: monospace; font-size: 14px; }
a { color: #ff4444; text-decoration: none; }
a:hover { text-decoration: underline; }
header { padding: 14px 24px; border-bottom: 1px solid #1f1f1f; display: flex; align-items: center; gap: 24px; }
header h1 { color: #ff4444; font-size: 20px; letter-spacing: 3px; }
nav a { color: #888; font-size: 13px; }
nav a:hover, nav a.active { color: #e0e0e0; }
nav { display: flex; gap: 16px; }
.container { padding: 20px 24px; }
input, select {
  background: #1a1a1a; border: 1px solid #2a2a2a; color: #e0e0e0;
  padding: 6px 10px; border-radius: 3px; font-family: monospace; font-size: 13px;
}
input[type=text] { width: 300px; }
button {
  background: #ff4444; color: #fff; border: none; padding: 6px 18px;
  border-radius: 3px; cursor: pointer; font-family: monospace;
}
button:hover { background: #cc3333; }
table { width: 100%; border-collapse: collapse; }
th {
  background: #111; padding: 8px 12px; text-align: left; color: #555;
  font-weight: normal; border-bottom: 1px solid #1f1f1f;
  position: sticky; top: 0; font-size: 12px; text-transform: uppercase;
}
td { padding: 7px 12px; border-bottom: 1px solid #161616; vertical-align: top; }
tr:hover td { background: #131313; }
.ip    { color: #4fc3f7; }
.port  { color: #888; }
.svc   { color: #81c784; font-size: 12px; }
.s2    { color: #81c784; }
.s3    { color: #ffb74d; }
.s4    { color: #e57373; }
.s5    { color: #ba68c8; }
.title { color: #e0e0e0; }
.dim   { color: #555; font-size: 12px; }
.tag-critical { color: #ff4444; font-size: 11px; font-weight: bold; }
.tag-high     { color: #ff8c00; font-size: 11px; }
.tag-medium   { color: #ffd700; font-size: 11px; }
.tag-low      { color: #81c784; font-size: 11px; }
.tag-info     { color: #555;    font-size: 11px; }
.pill {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 11px; margin: 1px;
}
.pill-critical { background: #3d0000; color: #ff4444; }
.pill-high     { background: #2d1a00; color: #ff8c00; }
.pill-medium   { background: #2d2600; color: #ffd700; }
.pill-low      { background: #0d2010; color: #81c784; }
.pill-info     { background: #1a1a1a; color: #666; }
.card {
  background: #111; border: 1px solid #1f1f1f; border-radius: 4px;
  padding: 16px 20px;
}
.card h3 { color: #555; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
.card .big { font-size: 28px; color: #e0e0e0; }
.card .sub { font-size: 11px; color: #444; margin-top: 4px; }
.grid { display: grid; gap: 16px; }
.grid-4 { grid-template-columns: repeat(4, 1fr); }
.grid-2 { grid-template-columns: repeat(2, 1fr); }
.bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; }
.bar-label { width: 140px; color: #888; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }
.bar-track { flex: 1; background: #1a1a1a; border-radius: 2px; height: 10px; }
.bar-fill  { background: #ff4444; border-radius: 2px; height: 10px; min-width: 2px; }
.bar-count { width: 60px; text-align: right; color: #555; }
.search-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.pagination { padding: 12px 0; display: flex; gap: 8px; align-items: center; color: #444; font-size: 12px; }
.none { padding: 40px; color: #333; text-align: center; }
.truncate { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
"""

NAV = """
<header>
  <h1>drawl</h1>
  <nav>
    <a href="/" class="{dash_active}">dashboard</a>
    <a href="/search" class="{search_active}">search</a>
    <a href="/cve" class="{cve_active}">cve tags</a>
    <a href="/api/docs" class="{api_active}">api</a>
  </nav>
  <span style="margin-left:auto;color:#333;font-size:11px" id="hdr-total"></span>
</header>
<script>
fetch('/api/stats').then(r=>r.json()).then(d=>{{
  const el = document.getElementById('hdr-total');
  if(el) el.textContent = d.total.toLocaleString() + ' hosts';
}});
</script>
"""


def nav(active="dash"):
    return NAV.format(
        dash_active="active" if active == "dash" else "",
        search_active="active" if active == "search" else "",
        cve_active="active" if active == "cve" else "",
        api_active="active" if active == "api" else "",
    )


def render_page(title, body, active="dash"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — drawl</title>
<style>{BASE_CSS}</style>
</head>
<body>
{nav(active)}
{body}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SERVICE_MAP = {
    80: "http", 443: "https", 22: "ssh", 21: "ftp",
    25: "smtp", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
    8080: "http-alt", 8443: "https-alt",
}


def sc_class(code):
    if code is None:
        return ""
    return f"s{str(code)[0]}"


def pill(tag, severity):
    return f'<span class="pill pill-{severity}" title="{tag}">{tag}</span>'


def bar_chart(rows, label_key, count_key, max_val, link_param=None):
    out = []
    for r in rows:
        label = str(r[label_key]) if r[label_key] else "—"
        count = r[count_key]
        pct = int((count / max_val) * 100) if max_val else 0
        if link_param:
            href = f"/search?{link_param}={label}"
            label_html = f'<a href="{href}" style="color:#888">{label}</a>'
            count_html = f'<a href="{href}" style="color:#555">{count:,}</a>'
        else:
            label_html = label
            count_html = f"{count:,}"
        out.append(f"""
        <div class="bar-row">
          <span class="bar-label" title="{label}">{label_html}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
          <span class="bar-count">{count_html}</span>
        </div>""")
    return "\n".join(out)


def build_where(q="", ip="", port=None, service="", status=None, tag="", hostname=""):
    clauses, params = [], []
    if ip:
        if "/" in ip:
            prefix = ip.split("/")[0].rsplit(".", 1)[0]
            clauses.append("ip LIKE ?")
            params.append(f"{prefix}.%")
        else:
            clauses.append("ip = ?")
            params.append(ip)
    if port is not None:
        clauses.append("port = ?")
        params.append(port)
    if service:
        clauses.append("service = ?")
        params.append(service)
    if status is not None:
        clauses.append("http_status = ?")
        params.append(status)
    if hostname:
        # support wildcards: *.example.com -> %.example.com
        pattern = hostname.replace("*", "%")
        clauses.append("(hostname LIKE ? OR tls_cn LIKE ? OR tls_domains LIKE ?)")
        params.extend([pattern, pattern, f"%{pattern}%"])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def host_rows(rows, tag_map=None):
    if not rows:
        return '<tr><td colspan="9" class="none">no results</td></tr>'
    out = []
    for r in rows:
        r = dict(r)
        sc = r.get("http_status")
        tags_html = ""
        if tag_map:
            host_tags = tag_map.get((r["ip"], r["port"]), [])
            host_tags.sort(key=lambda t: SEVERITY_ORDER.get(t["severity"], 9))
            tags_html = " ".join(pill(t["tag"], t["severity"]) for t in host_tags[:3])
            if len(host_tags) > 3:
                tags_html += f'<span class="dim">+{len(host_tags)-3}</span>'
        hostname_display = r.get('hostname') or r.get('tls_cn') or ''
        out.append(f"""<tr>
          <td class="ip"><a href="/host/{r['ip']}">{r['ip']}</a></td>
          <td class="dim truncate" title="{hostname_display}">{hostname_display[:35]}</td>
          <td class="port">{r['port']}</td>
          <td class="svc">{r.get('service') or ''}</td>
          <td class="{sc_class(sc)}">{sc or ''}</td>
          <td><span class="truncate" title="{r.get('http_title') or ''}">{(r.get('http_title') or '')[:50]}</span></td>
          <td class="dim truncate">{(r.get('server_header') or '')[:35]}</td>
          <td>{tags_html}</td>
          <td class="dim">{(r.get('last_seen') or '')[:10]}</td>
        </tr>""")
    return "\n".join(out)


def fetch_tags_for(conn, rows):
    """Return dict (ip, port) -> [tag dicts] for a result set."""
    if not rows:
        return {}
    keys = [(r["ip"], r["port"]) for r in rows]
    placeholders = ",".join("(?,?)" for _ in keys)
    flat = [v for pair in keys for v in pair]
    tag_rows = conn.execute(
        f"SELECT * FROM tags WHERE (ip, port) IN ({placeholders})", flat
    ).fetchall()
    result = {}
    for t in tag_rows:
        t = dict(t)
        result.setdefault((t["ip"], t["port"]), []).append(t)
    return result


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard():
    conn = db()

    total       = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    live_http   = conn.execute("SELECT COUNT(*) FROM hosts WHERE http_status BETWEEN 200 AND 399").fetchone()[0]
    open_ssh    = conn.execute("SELECT COUNT(*) FROM hosts WHERE port=22").fetchone()[0]
    total_tags  = conn.execute("SELECT COUNT(DISTINCT ip||':'||port) FROM tags").fetchone()[0]
    critical    = conn.execute("SELECT COUNT(*) FROM tags WHERE severity='critical'").fetchone()[0]

    top_ports   = conn.execute("SELECT port, COUNT(*) n FROM hosts GROUP BY port ORDER BY n DESC LIMIT 10").fetchall()
    top_svcs    = conn.execute("SELECT service, COUNT(*) n FROM hosts WHERE service IS NOT NULL GROUP BY service ORDER BY n DESC LIMIT 10").fetchall()
    top_servers = conn.execute("SELECT server_header, COUNT(*) n FROM hosts WHERE server_header IS NOT NULL GROUP BY server_header ORDER BY n DESC LIMIT 10").fetchall()
    top_cves    = conn.execute("""
        SELECT tag, severity, description, COUNT(*) n
        FROM tags GROUP BY tag ORDER BY MIN(CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 ELSE 4 END), n DESC LIMIT 15
    """).fetchall()
    recent      = conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 10").fetchall()
    recent_tags = fetch_tags_for(conn, recent)
    conn.close()

    max_port = top_ports[0]["n"] if top_ports else 1
    max_svc  = top_svcs[0]["n"]  if top_svcs  else 1
    max_srv  = top_servers[0]["n"] if top_servers else 1

    cve_rows = ""
    for r in top_cves:
        r = dict(r)
        cve_rows += f"""<tr>
          <td>{pill(r['tag'], r['severity'])}</td>
          <td class="tag-{r['severity']}">{r['severity']}</td>
          <td class="dim">{r['description']}</td>
          <td style="text-align:right;color:#555">{r['n']:,}</td>
        </tr>"""
    cve_table = '<div class="none">run python -m drawl.cves to tag hosts</div>' if not top_cves else f"<table><tbody>{cve_rows}</tbody></table>"

    body = f"""
<div class="container">
  <div class="grid grid-4" style="margin-bottom:20px">
    <div class="card">
      <h3>total hosts</h3>
      <div class="big">{total:,}</div>
    </div>
    <div class="card">
      <h3>live http</h3>
      <div class="big">{live_http:,}</div>
      <div class="sub">{int(live_http/total*100) if total else 0}% of hosts</div>
    </div>
    <div class="card">
      <h3>open ssh</h3>
      <div class="big">{open_ssh:,}</div>
    </div>
    <div class="card">
      <h3>flagged hosts</h3>
      <div class="big">{total_tags:,}</div>
      <div class="sub" style="color:#ff4444">{critical:,} critical</div>
    </div>
  </div>

  <div class="grid grid-2" style="margin-bottom:20px">
    <div class="card">
      <h3>top ports</h3>
      {bar_chart(top_ports, 'port', 'n', max_port, link_param='port')}
    </div>
    <div class="card">
      <h3>top services</h3>
      {bar_chart(top_svcs, 'service', 'n', max_svc, link_param='service')}
    </div>
  </div>

  <div class="grid grid-2" style="margin-bottom:20px">
    <div class="card">
      <h3>top server headers</h3>
      {bar_chart(top_servers, 'server_header', 'n', max_srv, link_param='q')}
    </div>
    <div class="card">
      <h3>cve / misconfiguration hits</h3>
      {cve_table}
    </div>
  </div>

  <div class="card">
    <h3>recently seen</h3>
    <div style="overflow-x:auto;margin-top:8px">
    <table>
      <thead><tr>
        <th>ip</th><th>port</th><th>service</th><th>status</th>
        <th>title</th><th>server</th><th>tls/cn</th><th>tags</th><th>last seen</th>
      </tr></thead>
      <tbody>{host_rows(recent, recent_tags)}</tbody>
    </table>
    </div>
  </div>
</div>
"""
    return HTMLResponse(render_page("dashboard", body, active="dash"))


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.get("/search", response_class=HTMLResponse)
def search_page(
    q: str = "",
    ip: str = "",
    port: str = "",
    service: str = "",
    status: str = "",
    tag: str = "",
    hostname: str = "",
    page: int = 1,
):
    port = int(port) if port.strip() else None
    status = int(status) if status.strip() else None
    conn = db()
    page_size = 50
    offset = (page - 1) * page_size
    where, params = build_where(q=q, ip=ip, port=port, service=service, status=status, hostname=hostname)

    # Tag filter — join to tags table
    if tag:
        if where:
            tag_where = where + " AND h.rowid IN (SELECT rowid FROM hosts WHERE ip IN (SELECT ip FROM tags WHERE tag=?) AND port IN (SELECT port FROM tags WHERE tag=?))"
        else:
            tag_where = "WHERE ip IN (SELECT ip FROM tags WHERE tag=?) AND port IN (SELECT port FROM tags WHERE tag=?)"
        tag_params = list(params) + [tag, tag]
    else:
        tag_where = where
        tag_params = list(params)

    if q:
        fts_extra = ("AND " + tag_where[6:]) if tag_where else ""
        fts_params_full = [q] + tag_params
        rows = conn.execute(f"""
            SELECT h.* FROM hosts h
            JOIN hosts_fts f ON h.rowid = f.rowid
            WHERE hosts_fts MATCH ? {fts_extra}
            ORDER BY h.last_seen DESC LIMIT {page_size} OFFSET {offset}
        """, fts_params_full).fetchall()
        total = conn.execute(f"""
            SELECT COUNT(*) FROM hosts h JOIN hosts_fts f ON h.rowid=f.rowid
            WHERE hosts_fts MATCH ? {fts_extra}
        """, fts_params_full).fetchone()[0]
    else:
        rows = conn.execute(
            f"SELECT h.* FROM hosts h {tag_where} ORDER BY h.last_seen DESC LIMIT {page_size} OFFSET {offset}",
            tag_params
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM hosts h {tag_where}", tag_params).fetchone()[0]

    tag_map = fetch_tags_for(conn, rows)

    # Dropdowns
    ports    = [r[0] for r in conn.execute("SELECT DISTINCT port FROM hosts ORDER BY port").fetchall()]
    services = [r[0] for r in conn.execute("SELECT DISTINCT service FROM hosts WHERE service IS NOT NULL ORDER BY service").fetchall()]
    all_tags = [r[0] for r in conn.execute("SELECT DISTINCT tag FROM tags ORDER BY tag").fetchall()]
    conn.close()

    STATUS_OPTS = [200, 301, 302, 401, 403, 404, 500]

    def opt(val, current, label=None):
        sel = 'selected' if str(current) == str(val) else ''
        return f'<option value="{val}" {sel}>{label or val}</option>'

    port_opts    = "\n".join(opt(p, port or "") for p in ports)
    service_opts = "\n".join(opt(s, service) for s in services)
    status_opts  = "\n".join(opt(s, status or "") for s in STATUS_OPTS)
    tag_opts     = "\n".join(opt(t, tag) for t in all_tags)

    pages = math.ceil(total / page_size) if total else 1

    def plink(p):
        return f"?q={q}&ip={ip}&hostname={hostname}&port={port or ''}&service={service}&status={status or ''}&tag={tag}&page={p}"

    pagination = ""
    if page > 1:
        pagination += f'<a href="{plink(page-1)}">← prev</a> '
    pagination += f"page {page} of {pages} &nbsp;·&nbsp; {total:,} results"
    if page < pages:
        pagination += f' <a href="{plink(page+1)}">next →</a>'

    body = f"""
<div class="container">
  <div class="search-bar">
    <input type="text" id="q" placeholder='nginx, "index of /", CVE-2021...' value="{q}">
    <input type="text" id="ip" placeholder="1.2.3.4 or CIDR" value="{ip}" style="width:150px">
    <input type="text" id="hostname" placeholder="*.example.com" value="{hostname}" style="width:180px">
    <select id="port"><option value="">all ports</option>{port_opts}</select>
    <select id="service"><option value="">all services</option>{service_opts}</select>
    <select id="status"><option value="">all status</option>{status_opts}</select>
    <select id="tag"><option value="">all tags</option>{tag_opts}</select>
    <button onclick="dosearch()">search</button>
  </div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>ip</th><th>hostname</th><th>port</th><th>service</th><th>status</th>
      <th>title</th><th>server</th><th>tags</th><th>last seen</th>
    </tr></thead>
    <tbody>{host_rows(rows, tag_map)}</tbody>
  </table>
  </div>
  <div class="pagination">{pagination}</div>
</div>
<script>
function dosearch() {{
  const p = new URLSearchParams({{
    q: document.getElementById('q').value,
    ip: document.getElementById('ip').value,
    hostname: document.getElementById('hostname').value,
    port: document.getElementById('port').value,
    service: document.getElementById('service').value,
    status: document.getElementById('status').value,
    tag: document.getElementById('tag').value,
    page: 1,
  }});
  window.location.href = '/search?' + p.toString();
}}
document.getElementById('q').addEventListener('keydown', e => {{ if(e.key==='Enter') dosearch(); }});
document.getElementById('hostname').addEventListener('keydown', e => {{ if(e.key==='Enter') dosearch(); }});
</script>
"""
    return HTMLResponse(render_page("search", body, active="search"))


# ---------------------------------------------------------------------------
# CVE tag browser
# ---------------------------------------------------------------------------

@app.get("/cve", response_class=HTMLResponse)
def cve_page(severity: str = ""):
    conn = db()
    where = "WHERE severity = ?" if severity else ""
    params = [severity] if severity else []
    tags = conn.execute(f"""
        SELECT tag, severity, description, COUNT(*) n
        FROM tags {where}
        GROUP BY tag
        ORDER BY MIN(CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 ELSE 4 END), n DESC
    """, params).fetchall()
    conn.close()

    SEVS = ["", "critical", "high", "medium", "low", "info"]

    def sev_link(s):
        label = s or "all"
        active = "color:#e0e0e0" if severity == s else ""
        return f'<a href="/cve?severity={s}" style="{active}">{label}</a>'

    sev_nav = " &nbsp;·&nbsp; ".join(sev_link(s) for s in SEVS)

    rows = ""
    for r in tags:
        r = dict(r)
        rows += f"""<tr>
          <td>{pill(r['tag'], r['severity'])}</td>
          <td class="tag-{r['severity']}">{r['severity']}</td>
          <td class="dim">{r['description']}</td>
          <td style="text-align:right">
            <a href="/search?tag={r['tag']}">{r['n']:,} hosts</a>
          </td>
        </tr>"""

    if not tags:
        tags_content = '<div class="none">no tags found — run: python -m drawl.cves</div>'
    else:
        tags_content = f"<table><thead><tr><th>tag / cve</th><th>severity</th><th>description</th><th style='text-align:right'>hits</th></tr></thead><tbody>{rows}</tbody></table>"

    body = f"""
<div class="container">
  <div style="margin-bottom:16px;color:#555;font-size:13px">{sev_nav}</div>
  {tags_content}
</div>
"""
    return HTMLResponse(render_page("cve tags", body, active="cve"))


# ---------------------------------------------------------------------------
# Host detail
# ---------------------------------------------------------------------------

@app.get("/host/{ip}", response_class=HTMLResponse)
def host_page(ip: str):
    conn = db()
    rows = conn.execute("SELECT * FROM hosts WHERE ip=? ORDER BY port", [ip]).fetchall()
    if not rows:
        conn.close()
        raise HTTPException(status_code=404, detail="not found")
    tags = conn.execute("SELECT * FROM tags WHERE ip=? ORDER BY severity", [ip]).fetchall()
    conn.close()

    port_rows = ""
    for r in rows:
        r = dict(r)
        sc = r.get("http_status")
        port_rows += f"""<tr>
          <td class="port">{r['port']}</td>
          <td class="svc">{r.get('service') or ''}</td>
          <td class="{sc_class(sc)}">{sc or ''}</td>
          <td class="truncate" title="{r.get('http_title') or ''}">{(r.get('http_title') or '')[:60]}</td>
          <td class="dim">{(r.get('server_header') or '')[:50]}</td>
          <td class="dim">{(r.get('tls_cn') or '')[:40]}</td>
          <td class="dim">{(r.get('last_seen') or '')[:10]}</td>
        </tr>"""

    tag_rows = ""
    for t in tags:
        t = dict(t)
        tag_rows += f"""<tr>
          <td>{pill(t['tag'], t['severity'])}</td>
          <td class="tag-{t['severity']}">{t['severity']}</td>
          <td class="dim">{t.get('description') or ''}</td>
          <td class="dim">{t.get('matched_field') or ''}</td>
          <td class="dim truncate" title="{t.get('matched_value') or ''}">{(t.get('matched_value') or '')[:80]}</td>
        </tr>"""

    if not tag_rows:
        tag_card = '<div class="card"><h3>tags / cve matches</h3><div class="none" style="padding:16px">no tags</div></div>'
    else:
        tag_card = f'<div class="card"><h3>tags / cve matches</h3><div style="overflow-x:auto;margin-top:8px"><table><thead><tr><th>tag</th><th>severity</th><th>description</th><th>field</th><th>value</th></tr></thead><tbody>{tag_rows}</tbody></table></div></div>'

    body = f"""
<div class="container">
  <h2 style="color:#4fc3f7;margin-bottom:16px">{ip}</h2>

  <div class="card" style="margin-bottom:16px">
    <h3>open ports</h3>
    <div style="overflow-x:auto;margin-top:8px">
    <table>
      <thead><tr>
        <th>port</th><th>service</th><th>status</th><th>title</th>
        <th>server</th><th>tls/cn</th><th>last seen</th>
      </tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
    </div>
  </div>

  {tag_card}
</div>
"""
    return HTMLResponse(render_page(ip, body, active="search"))


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@app.get("/api/search")
def api_search(
    q: str = "",
    ip: str = "",
    port: Optional[int] = None,
    service: str = "",
    status: Optional[int] = None,
    tag: str = "",
    page: int = 1,
    limit: int = Query(default=50, le=500),
):
    conn = db()
    offset = (page - 1) * limit
    where, params = build_where(q=q, ip=ip, port=port, service=service, status=status)

    if tag:
        extra = f"{'AND' if where else 'WHERE'} ip IN (SELECT ip FROM tags WHERE tag=?) AND port IN (SELECT port FROM tags WHERE tag=?)"
        where = (where + " " + extra).strip()
        params = list(params) + [tag, tag]

    if q:
        rows = conn.execute(f"""
            SELECT h.* FROM hosts h JOIN hosts_fts f ON h.rowid=f.rowid
            WHERE hosts_fts MATCH ? {'AND ' + where[6:] if where else ''}
            ORDER BY h.last_seen DESC LIMIT {limit} OFFSET {offset}
        """, [q] + list(params)).fetchall()
        total = conn.execute(f"""
            SELECT COUNT(*) FROM hosts h JOIN hosts_fts f ON h.rowid=f.rowid
            WHERE hosts_fts MATCH ? {'AND ' + where[6:] if where else ''}
        """, [q] + list(params)).fetchone()[0]
    else:
        rows = conn.execute(
            f"SELECT * FROM hosts {where} ORDER BY last_seen DESC LIMIT {limit} OFFSET {offset}", params
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM hosts {where}", params).fetchone()[0]

    conn.close()
    return {"total": total, "page": page, "results": [dict(r) for r in rows]}


@app.get("/api/host/{ip}")
def api_host(ip: str):
    conn = db()
    rows = conn.execute("SELECT * FROM hosts WHERE ip=? ORDER BY port", [ip]).fetchall()
    tags = conn.execute("SELECT * FROM tags WHERE ip=? ORDER BY severity", [ip]).fetchall()
    conn.close()
    if not rows:
        raise HTTPException(status_code=404, detail="host not found")
    return {"ip": ip, "ports": [dict(r) for r in rows], "tags": [dict(t) for t in tags]}


@app.get("/api/stats")
def api_stats():
    conn = db()
    total      = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    top_ports  = conn.execute("SELECT port, COUNT(*) n FROM hosts GROUP BY port ORDER BY n DESC LIMIT 10").fetchall()
    top_svcs   = conn.execute("SELECT service, COUNT(*) n FROM hosts WHERE service IS NOT NULL GROUP BY service ORDER BY n DESC LIMIT 10").fetchall()
    top_server = conn.execute("SELECT server_header, COUNT(*) n FROM hosts WHERE server_header IS NOT NULL GROUP BY server_header ORDER BY n DESC LIMIT 10").fetchall()
    top_tags   = conn.execute("SELECT tag, severity, COUNT(*) n FROM tags GROUP BY tag ORDER BY n DESC LIMIT 20").fetchall()
    conn.close()
    return {
        "total": total,
        "top_ports":   [dict(r) for r in top_ports],
        "top_services":[dict(r) for r in top_svcs],
        "top_servers": [dict(r) for r in top_server],
        "top_tags":    [dict(r) for r in top_tags],
    }
