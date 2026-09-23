#!/usr/bin/env bash
#
# approve.sh - the approval gate CLI, one mechanism for every OS.
#
# Patch ids by family:
#   Windows        KB5034129            (bare digits are auto-prefixed)
#   RHEL family    RHSA-2026:0123       (also RHBA/RHEA, ALSA, RLSA - verbatim)
#   Ubuntu/Debian  openssl              (binary package name - verbatim,
#                                        package names are case-sensitive)
#
#   approve.sh list                          # everything pending, worst first
#   approve.sh list prod
#   approve.sh approve canary KB5034129 RHSA-2026:0123 openssl
#   approve.sh approve prod KB5034129 --not-before 2026-09-15
#   approve.sh reject prod RHSA-2026:0999 --note "kernel regression, INC-4471"
#   approve.sh promote canary prod           # copy approvals; failed installs skipped
#   approve.sh status RHSA-2026:0123

set -euo pipefail

PSQL=(psql "${PATCHMGR_DSN:-postgresql://patchmgr@localhost/patchmgr}" -v ON_ERROR_STOP=1)
WHO="${SUDO_USER:-${USER:-unknown}}"

usage() { sed -n '3,19p' "$0"; exit 1; }
[[ $# -ge 1 ]] || usage

# Single-quote-safe literal for SQL. Package names can contain + and . legally.
q() { printf "%s" "${1//\'/\'\'}"; }

norm_id() {
  local id="$1"
  if [[ "$id" =~ ^[0-9]+$ ]]; then echo "KB$id"
  elif [[ "$id" =~ ^[Kk][Bb][0-9]+$ ]]; then echo "${id^^}"
  else echo "$id"    # errata ids and package names pass through untouched
  fi
}

cmd="$1"; shift

case "$cmd" in

  list)
    ring="${1:-}"
    filter=""
    [[ -n "$ring" ]] && filter="AND ring = '$(q "$ring")'"
    "${PSQL[@]}" -P pager=off -c "
      SELECT patch_id, os_family AS os, ring, severity, affected_hosts AS hosts,
             age_days AS age_d, approval_status AS status,
             left(title, 55) AS title
      FROM v_patch_rollup
      WHERE approval_status = 'pending' $filter
      ORDER BY severity_rank DESC, age_days DESC NULLS LAST, affected_hosts DESC;"
    ;;

  approve|reject|defer)
    [[ $# -ge 2 ]] || { echo "usage: approve.sh $cmd <ring> <patch-id...> [--note TEXT] [--not-before YYYY-MM-DD]" >&2; exit 1; }
    ring="$1"; shift
    ids=(); note=""; not_before="NULL"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --note)       note="$2"; shift 2 ;;
        --not-before) not_before="'$(q "$2")'"; shift 2 ;;
        *)            ids+=("$(norm_id "$1")"); shift ;;
      esac
    done
    [[ ${#ids[@]} -gt 0 ]] || { echo "no patch ids given" >&2; exit 1; }

    status="approved"
    [[ "$cmd" == "reject" ]] && status="rejected"
    [[ "$cmd" == "defer"  ]] && status="deferred"

    note_sql="NULL"
    [[ -n "$note" ]] && note_sql="'$(q "$note")'"

    for pid in "${ids[@]}"; do
      "${PSQL[@]}" -q -c "
        INSERT INTO patch_approvals (patch_id, ring, status, approved_by, decided_at, not_before, notes)
        VALUES ('$(q "$pid")', '$(q "$ring")', '$status', '$(q "$WHO")', now(), $not_before, $note_sql)
        ON CONFLICT (patch_id, ring) DO UPDATE SET
          status      = EXCLUDED.status,
          approved_by = EXCLUDED.approved_by,
          decided_at  = now(),
          not_before  = EXCLUDED.not_before,
          notes       = COALESCE(EXCLUDED.notes, patch_approvals.notes);"
      echo "$status  $pid  ring=$ring  by=$WHO"
    done
    ;;

  promote)
    [[ $# -eq 2 ]] || { echo "usage: approve.sh promote <from-ring> <to-ring>" >&2; exit 1; }
    from="$(q "$1")"; to="$(q "$2")"
    # Only promote ids that did not FAIL anywhere in the source ring.
    "${PSQL[@]}" -c "
      INSERT INTO patch_approvals (patch_id, ring, status, approved_by, decided_at, notes)
      SELECT a.patch_id, '$to', 'approved', '$(q "$WHO")', now(), 'promoted from $from'
      FROM patch_approvals a
      WHERE a.ring = '$from' AND a.status = 'approved'
        AND NOT EXISTS (
          SELECT 1 FROM patch_events e
          JOIN hosts h ON h.host_id = e.host_id
          WHERE e.patch_id = a.patch_id AND h.ring = '$from'
            AND e.action = 'install' AND e.result = 'failed'
        )
      ON CONFLICT (patch_id, ring) DO UPDATE SET
        status = 'approved', approved_by = '$(q "$WHO")', decided_at = now()
      RETURNING patch_id;"
    echo "Promoted $1 -> $2 (ids with failed installs in $1 were skipped)"
    ;;

  status)
    [[ $# -eq 1 ]] || { echo "usage: approve.sh status <patch-id>" >&2; exit 1; }
    pid="$(norm_id "$1")"
    "${PSQL[@]}" -P pager=off -c "
      SELECT ring, status, approved_by, decided_at, not_before, notes
      FROM patch_approvals WHERE patch_id = '$(q "$pid")' ORDER BY ring;"
    "${PSQL[@]}" -P pager=off -c "
      SELECT hostname, ring, os_family FROM v_pending_updates
      WHERE patch_id = '$(q "$pid")' ORDER BY ring, hostname;"
    ;;

  *) usage ;;
esac
