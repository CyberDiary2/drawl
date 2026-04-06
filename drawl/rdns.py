"""
Reverse DNS resolution for all IPs in the database.

Usage:
    python -m drawl.rdns
    python -m drawl.rdns --concurrency 200
"""
import asyncio
import sys
import socket
from .db import DB_PATH, connect


async def resolve(ip: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.getfqdn, ip)
        # getfqdn returns the IP itself if no PTR record
        return result if result != ip else None
    except Exception:
        return None


async def run_rdns(db_path=DB_PATH, concurrency=200):
    conn = connect(db_path)
    # get distinct IPs that don't have a hostname yet
    ips = [r[0] for r in conn.execute(
        "SELECT DISTINCT ip FROM hosts WHERE hostname IS NULL"
    ).fetchall()]
    conn.close()

    if not ips:
        print("[drawl:rdns] all IPs already resolved")
        return

    print(f"[drawl:rdns] resolving {len(ips):,} IPs...")
    resolved = 0
    sem = asyncio.Semaphore(concurrency)

    async def bounded(ip):
        nonlocal resolved
        async with sem:
            hostname = await resolve(ip)
            if hostname:
                conn = connect(db_path)
                conn.execute("UPDATE hosts SET hostname=? WHERE ip=?", [hostname, ip])
                conn.commit()
                conn.close()
                resolved += 1

    await asyncio.gather(*[bounded(ip) for ip in ips])
    print(f"[drawl:rdns] done — {resolved:,} hostnames resolved out of {len(ips):,} IPs")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrency", type=int, default=200)
    args = parser.parse_args()
    asyncio.run(run_rdns(concurrency=args.concurrency))
