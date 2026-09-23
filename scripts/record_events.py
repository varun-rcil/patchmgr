#!/usr/bin/env python3
"""
record_events.py - write patch actions into the patch_events audit table.

Two input modes:
  --json  <win_updates result>   the ansible.windows.win_updates return object
  --events-json <list>           generic events from the Linux plays:
                                 [{"patch_id","action","result","message"}, ...]

The return shape of win_updates changed between collection versions:
  ansible.windows < 2.0 : result['updates'] is a dict keyed by update GUID
  ansible.windows >= 2.0: result['updates'] is a list of dicts
Both are handled.
"""

import argparse
import json
import os
import sys

import psycopg2


def iter_updates(container):
    """Yield update dicts from either the dict-keyed or list shape."""
    if not container:
        return
    if isinstance(container, dict):
        for update_id, body in container.items():
            if isinstance(body, dict):
                body.setdefault("id", update_id)
                yield body
    elif isinstance(container, list):
        for body in container:
            if isinstance(body, dict):
                yield body


def primary_kb(update):
    kbs = update.get("kb") or []
    if isinstance(kbs, str):
        kbs = [kbs]
    if not kbs:
        return None
    kb = str(kbs[0]).upper()
    return kb if kb.startswith("KB") else "KB" + kb


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hostname", required=True)
    p.add_argument("--json", help="win_updates result as JSON (Windows mode)")
    p.add_argument("--events-json", help="generic events list as JSON (Linux mode)")
    p.add_argument("--run-id", default=None)
    args = p.parse_args()

    if bool(args.json) == bool(args.events_json):
        print("exactly one of --json / --events-json is required", file=sys.stderr)
        return 1

    rows = []
    if args.events_json:
        try:
            for e in json.loads(args.events_json):
                rows.append((e.get("patch_id"), e.get("title"),
                             e.get("action", "install"), e.get("result", "success"),
                             e.get("hresult"), e.get("message")))
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            print(f"bad events JSON: {exc}", file=sys.stderr)
            return 1
        result = {}
    else:
        try:
            result = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(f"bad result JSON: {e}", file=sys.stderr)
            return 1

    installed_ids = set()
    for u in iter_updates(result.get("updates")) if not args.events_json else []:
        kb = primary_kb(u)
        title = u.get("title")
        hres = u.get("failure_hresult_code")
        # An update present in `filtered_updates` was skipped by accept/reject rules.
        if hres:
            rows.append((kb, title, "install", "failed", str(hres),
                         u.get("failure_msg") or "install failed"))
        elif u.get("installed"):
            installed_ids.add(u.get("id"))
            rows.append((kb, title, "install", "success", None, None))
        elif u.get("downloaded"):
            rows.append((kb, title, "download", "success", None, None))

    for u in iter_updates(result.get("filtered_updates")) if not args.events_json else []:
        rows.append((primary_kb(u), u.get("title"), "install", "skipped", None,
                     "filtered by accept_list/reject_list: "
                     + str(u.get("filtered_reason", "unspecified"))))

    if result.get("reboot_required"):
        rows.append((None, None, "reboot", "skipped", None, "reboot required after this run"))

    if not rows:
        rows.append((None, None, "install", "skipped", None,
                     "no updates matched the approved accept_list"))

    dsn = os.environ.get("PATCHMGR_DSN")
    conn = psycopg2.connect(dsn) if dsn else psycopg2.connect()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE hostname = %s", (args.hostname,))
            row = cur.fetchone()
            host_id = row[0] if row else None

            for kb, title, action, res, hresult, msg in rows:
                cur.execute(
                    """
                    INSERT INTO patch_events
                        (host_id, hostname, patch_id, title, action, result, hresult, message, run_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (host_id, args.hostname, kb, title, action, res, hresult, msg, args.run_id),
                )
    finally:
        conn.close()

    print(f"recorded {len(rows)} event(s) for {args.hostname}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
