#!/usr/bin/env python3
"""
load_scan.py - ingest Get-PendingUpdates.ps1 output into PostgreSQL.

Usage:
    load_scan.py --scan-dir /var/lib/patchmgr/scans/<run_id> --run-id <uuid> [--source MicrosoftUpdate]

Reads every *.json in --scan-dir, upserts hosts, inserts available_updates and
installed_hotfixes, and closes out the scan_runs row.

Connection comes from standard libpq env vars (PGHOST/PGDATABASE/PGUSER/PGPASSWORD)
or a DSN in PATCHMGR_DSN.
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras

LOG = logging.getLogger("load_scan")

SEVERITY_RANK = {
    "critical": 4,
    "important": 3,
    "security": 3,     # Ubuntu -security pocket: no finer grading available locally
    "moderate": 2,
    "low": 1,
    "unspecified": 0,
}


def severity_rank(sev):
    return SEVERITY_RANK.get((sev or "").strip().lower(), 0)


def normalise_kb(value):
    """Return KB####### form, or None."""
    if value is None:
        return None
    s = str(value).strip().upper()
    if not s:
        return None
    if s.startswith("KB"):
        return s
    if s.isdigit():
        return "KB" + s
    return s


def as_list(value):
    """PowerShell ConvertTo-Json collapses single-element arrays into scalars."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_ts(value):
    if not value:
        return None
    s = str(value)
    # WMI CIM dates arrive as ISO already via ConvertTo-Json; be tolerant anyway.
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        # /Date(1712345678000)/ style
        if s.startswith("/Date("):
            try:
                ms = int(s[6:].split(")")[0].split("+")[0].split("-")[0])
                return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            except (ValueError, IndexError):
                return None
        LOG.warning("unparseable timestamp: %r", value)
        return None


def upsert_host(cur, doc, ring_map):
    os_info = doc.get("os") or {}
    reboot = doc.get("reboot") or {}
    hostname = doc["hostname"]

    cur.execute(
        """
        INSERT INTO hosts (hostname, fqdn, os_family, os_name, os_product, os_build, os_ubr,
                           display_version, ring, last_seen, last_boot,
                           reboot_pending, reboot_reasons, scan_ok, scan_error)
        VALUES (%(hostname)s, %(fqdn)s, %(os_family)s, %(os_name)s, %(os_product)s, %(os_build)s, %(os_ubr)s,
                %(display_version)s, %(ring)s, now(), %(last_boot)s,
                %(reboot_pending)s, %(reboot_reasons)s, %(scan_ok)s, %(scan_error)s)
        ON CONFLICT (hostname) DO UPDATE SET
            fqdn            = EXCLUDED.fqdn,
            os_family       = EXCLUDED.os_family,
            os_name         = EXCLUDED.os_name,
            os_product      = EXCLUDED.os_product,
            os_build        = EXCLUDED.os_build,
            os_ubr          = EXCLUDED.os_ubr,
            display_version = EXCLUDED.display_version,
            ring            = EXCLUDED.ring,
            last_seen       = now(),
            last_boot       = EXCLUDED.last_boot,
            reboot_pending  = EXCLUDED.reboot_pending,
            reboot_reasons  = EXCLUDED.reboot_reasons,
            scan_ok         = EXCLUDED.scan_ok,
            scan_error      = EXCLUDED.scan_error
        RETURNING host_id
        """,
        {
            "hostname": hostname,
            "fqdn": doc.get("fqdn"),
            "os_family": doc.get("os_family", "windows"),
            "os_name": os_info.get("product_name"),
            "os_product": os_info.get("product_name"),
            "os_build": os_info.get("build"),
            "os_ubr": os_info.get("ubr"),
            "display_version": os_info.get("display_version"),
            "ring": ring_map.get(hostname.lower(), "prod"),
            "last_boot": parse_ts(os_info.get("last_boot")),
            "reboot_pending": bool(reboot.get("pending", False)),
            "reboot_reasons": as_list(reboot.get("reasons")),
            "scan_ok": bool(doc.get("scan_ok", False)),
            "scan_error": doc.get("scan_error"),
        },
    )
    return cur.fetchone()[0]


def load_updates(cur, run_id, host_id, doc):
    rows = []
    for u in as_list(doc.get("updates")):
        # Linux scanners emit patch_id + components directly; the Windows scanner
        # still emits kb[] and is mapped here so it needs no changes.
        kb_all = [normalise_kb(k) for k in as_list(u.get("kb"))]
        kb_all = [k for k in kb_all if k]
        patch_id = u.get("patch_id") or (kb_all[0] if kb_all else None)
        components = as_list(u.get("components")) or kb_all
        sev = u.get("severity") or u.get("msrc_severity") or "Unspecified"
        rows.append(
            (
                run_id,
                host_id,
                u.get("update_id") or patch_id,
                u.get("revision"),
                patch_id,
                components,
                u.get("title") or "(untitled)",
                sev,
                severity_rank(sev),
                as_list(u.get("categories")),
                [str(c) for c in as_list(u.get("cve_ids"))],
                int(u.get("size_bytes") or 0),
                bool(u.get("is_downloaded")),
                bool(u.get("reboot_required")),
                parse_ts(u.get("release_date")),
                u.get("support_url"),
            )
        )

    if not rows:
        return 0

    psycopg2.extras.execute_values(
        cur,
        """
        INSERT INTO available_updates
            (run_id, host_id, update_id, revision, patch_id, components, title,
             severity, severity_rank, categories, cve_ids, size_bytes,
             is_downloaded, reboot_required, release_date, support_url)
        VALUES %s
        ON CONFLICT (run_id, host_id, update_id) DO NOTHING
        """,
        rows,
        page_size=200,
    )
    return len(rows)


def load_hotfixes(cur, host_id, doc):
    rows = []
    for h in as_list(doc.get("installed_kbs")):
        kb = normalise_kb(h.get("kb"))
        if not kb:
            continue
        rows.append((host_id, kb, h.get("description"), parse_ts(h.get("installed_on"))))

    if not rows:
        return 0

    psycopg2.extras.execute_values(
        cur,
        """
        INSERT INTO installed_hotfixes (host_id, kb, description, installed_on)
        VALUES %s
        ON CONFLICT (host_id, kb) DO UPDATE
            SET installed_on = COALESCE(EXCLUDED.installed_on, installed_hotfixes.installed_on)
        """,
        rows,
        page_size=200,
    )
    return len(rows)


def seed_approvals(cur, run_id):
    """
    Every newly-seen KB lands as 'pending' for every ring. Nothing installs until
    an operator flips it to 'approved'. This is the WSUS approval gate equivalent.
    """
    cur.execute(
        """
        INSERT INTO patch_approvals (patch_id, ring, status)
        SELECT DISTINCT a.patch_id, r.ring, 'pending'
        FROM available_updates a
        CROSS JOIN (SELECT DISTINCT ring FROM hosts) r
        WHERE a.run_id = %s AND a.patch_id IS NOT NULL
        ON CONFLICT (kb, ring) DO NOTHING
        """,
        (run_id,),
    )
    return cur.rowcount


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scan-dir", required=True, type=Path)
    p.add_argument("--run-id", required=True)
    p.add_argument("--source", default="MicrosoftUpdate")
    p.add_argument("--initiated-by", default=os.environ.get("USER", "ansible"))
    p.add_argument("--ring-map", type=Path,
                   help="Optional JSON {hostname: ring} to stamp ring membership")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    run_id = str(uuid.UUID(args.run_id))  # validates
    ring_map = {}
    if args.ring_map and args.ring_map.exists():
        ring_map = {k.lower(): v for k, v in json.loads(args.ring_map.read_text()).items()}

    # Underscore-prefixed files (_rings.json) are run metadata, not host scans.
    files = sorted(f for f in args.scan_dir.glob("*.json") if not f.name.startswith("_"))
    if not files:
        LOG.error("no scan files in %s", args.scan_dir)
        return 2

    dsn = os.environ.get("PATCHMGR_DSN")
    conn = psycopg2.connect(dsn) if dsn else psycopg2.connect()
    conn.autocommit = False

    ok = failed = total_updates = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (run_id, source, initiated_by)
                VALUES (%s, %s, %s)
                ON CONFLICT (run_id) DO NOTHING
                """,
                (run_id, args.source, args.initiated_by),
            )

            for f in files:
                try:
                    doc = json.loads(f.read_text(encoding="utf-8-sig"))
                except json.JSONDecodeError as e:
                    LOG.error("%s: bad JSON (%s)", f.name, e)
                    failed += 1
                    continue

                if not doc.get("hostname"):
                    LOG.error("%s: no hostname field", f.name)
                    failed += 1
                    continue

                host_id = upsert_host(cur, doc, ring_map)

                if doc.get("scan_ok"):
                    n = load_updates(cur, run_id, host_id, doc)
                    load_hotfixes(cur, host_id, doc)
                    total_updates += n
                    ok += 1
                    LOG.info("%-20s %3d pending", doc["hostname"], n)
                else:
                    failed += 1
                    LOG.warning("%-20s scan failed: %s",
                                doc["hostname"], doc.get("scan_error"))

            new_appr = seed_approvals(cur, run_id)

            cur.execute(
                """
                UPDATE scan_runs
                   SET finished_at = now(), host_count = %s, ok_count = %s, failed_count = %s
                 WHERE run_id = %s
                """,
                (len(files), ok, failed, run_id),
            )

        conn.commit()
    except Exception:
        conn.rollback()
        LOG.exception("load failed, rolled back")
        return 1
    finally:
        conn.close()

    LOG.info("run %s: %d hosts (%d ok, %d failed), %d pending updates, %d new approval rows",
             run_id, len(files), ok, failed, total_updates, new_appr)
    return 0 if failed == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
