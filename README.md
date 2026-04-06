# drawl

Drew's Asset-Wide Listener — a self-hosted internet scanner and search interface. Scan IP ranges for open ports, grab banners, fingerprint services, and flag known CVEs and misconfigurations.

---

## Requirements

- Python 3.11+
- [masscan](https://github.com/robertdavidgraham/masscan)
- [zgrab2](https://github.com/zmap/zgrab2)

---

## Installation

```bash
git clone https://github.com/yourusername/drawl.git
cd drawl

python3 -m venv venv
source venv/bin/activate

pip install fastapi "uvicorn[standard]"
```

---

## Quick Start (local test with fake data)

**1. Initialize the database**
```bash
python3 -c "from drawl.db import init_db; init_db()"
```

**2. Seed with test data**
```bash
python3 seed.py
```

**3. Tag hosts with CVE signatures**
```bash
python3 -m drawl.cves
```

**4. Start the web UI**
```bash
uvicorn drawl.api:app --host 127.0.0.1 --port 8000
```

**5. Open your browser**

Go to `http://localhost:8000`

---

## Running a Real Scan (VPS only)

> Do not run masscan from your home connection. Use a VPS. See the responsible scanning section below.

**1. Scan a CIDR range for open ports**
```bash
masscan 1.2.3.0/24 -p80,443,22,21,3306,5432,6379,27017,9200,8080,8443 \
  --rate 50000 \
  --excludefile /etc/masscan/exclude.conf \
  -oJ data/open_ports.json
```

**2. Parse masscan output into targets for zgrab2**
```bash
python3 -m drawl.parse_masscan data/open_ports.json > data/targets.txt
```

**3. Grab banners with zgrab2**
```bash
zgrab2 multiple --config zgrab.ini \
  --input-file data/targets.txt \
  --output-file data/banners.jsonl \
  --goroutines 500
```

**4. Ingest into the database**
```bash
python3 -m drawl.ingest data/banners.jsonl
```

**5. Tag with CVE signatures**
```bash
python3 -m drawl.cves
```

**6. Start the web UI**
```bash
uvicorn drawl.api:app --host 0.0.0.0 --port 8000
```

Or use the all-in-one scan script:
```bash
./scan.sh 1.2.3.0/24
```

---

## Web UI

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Stats, top ports/services, CVE hits, recent hosts |
| Search | `/search` | Filter by IP, port, service, status, CVE tag |
| CVE Tags | `/cve` | Browse all matched CVEs and misconfigs |
| Host Detail | `/host/<ip>` | All ports and tags for a single IP |
| API Docs | `/api/docs` | Swagger UI |

---

## Configuration

Override settings with environment variables or a `.env` file:

```bash
HTTP_TIMEOUT=5
HTTP_CONCURRENCY=75
```

---

## Responsible Scanning

- Only scan IP ranges you own or have written permission to scan
- Set a PTR record on your scanner IP explaining what it is
- Honor opt-out requests — maintain an exclude list
- Keep scan rates reasonable (50k pps or below)
- Do not scan from a residential connection
- Pull and merge the [Rapid7 opt-out list](https://opendata.rapid7.com/opendata/opt-out/) regularly

---

## Project Structure

```
drawl/
├── drawl/
│   ├── api.py          # FastAPI web UI and JSON API
│   ├── cves.py         # CVE / misconfiguration signature engine
│   ├── db.py           # SQLite schema and helpers
│   ├── ingest.py       # zgrab2 JSONL → database
│   └── parse_masscan.py # masscan JSON → target list
├── scan.sh             # Full pipeline script
├── zgrab.ini           # zgrab2 module config
└── seed.py             # Fake data for local testing
```
