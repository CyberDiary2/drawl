"""
Parse masscan JSON output into ip:port lines for zgrab2.

Usage:
    masscan ... -oJ scan.json
    python -m drawl.parse_masscan scan.json > targets.txt
    zgrab2 multiple -c zgrab.ini < targets.txt > banners.jsonl
"""
import json
import sys
from pathlib import Path


def parse(path: str) -> list[str]:
    """Return list of 'ip:port' strings from masscan JSON output."""
    targets = []
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError:
        # masscan sometimes writes invalid JSON at the end — parse line by line
        data = []
        with open(path) as f:
            for line in f:
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    for entry in data:
        ip = entry.get("ip")
        for port_info in entry.get("ports", []):
            port = port_info.get("port")
            if ip and port and port_info.get("status") == "open":
                targets.append(f"{ip}:{port}")

    return targets


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m drawl.parse_masscan <masscan.json>", file=sys.stderr)
        sys.exit(1)

    for target in parse(sys.argv[1]):
        print(target)
