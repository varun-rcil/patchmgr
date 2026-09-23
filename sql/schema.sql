-- patchmgr schema
-- Run as:  psql -U postgres -d patchmgr -f schema.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Inventory
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hosts (
    host_id         BIGSERIAL PRIMARY KEY,
    hostname        TEXT NOT NULL UNIQUE,
    fqdn            TEXT,
    os_family       TEXT NOT NULL DEFAULT 'windows',   -- windows | rhel | debian
    os_name         TEXT,
    ip_address      INET,
    os_product      TEXT,
    os_build        TEXT,            -- e.g. 10.0.20348.2966  (UBR is the real patch level)
    os_ubr          INTEGER,
    display_version TEXT,            -- e.g. 21H2
    ring            TEXT NOT NULL DEFAULT 'prod',   -- canary | pilot | prod
    environment     TEXT,
    owner_team      TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_boot       TIMESTAMPTZ,
    reboot_pending  BOOLEAN NOT NULL DEFAULT false,
    reboot_reasons  TEXT[],
    scan_ok         BOOLEAN NOT NULL DEFAULT true,
    scan_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_ring ON hosts (ring);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts (last_seen DESC);

-- ---------------------------------------------------------------------------
-- Scan runs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    source       TEXT,               -- MicrosoftUpdate | WindowsUpdate | WSUS
    host_count   INTEGER DEFAULT 0,
    ok_count     INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    initiated_by TEXT
);

-- ---------------------------------------------------------------------------
-- Pending updates, one row per (run, host, update)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS available_updates (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    host_id         BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    update_id       TEXT NOT NULL,
    revision        INTEGER,
    patch_id              TEXT,            -- primary KB, normalised to KB#######
    components          TEXT[],
    title           TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'Unspecified',
    severity_rank   SMALLINT NOT NULL DEFAULT 0,   -- 4=Critical 3=Important 2=Moderate 1=Low 0=Unspecified; Ubuntu 'Security'=3
    categories      TEXT[],
    cve_ids         TEXT[],
    size_bytes      BIGINT DEFAULT 0,
    is_downloaded   BOOLEAN DEFAULT false,
    reboot_required BOOLEAN DEFAULT false,
    release_date    TIMESTAMPTZ,
    support_url     TEXT,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, host_id, update_id)
);

CREATE INDEX IF NOT EXISTS idx_avail_host ON available_updates (host_id);
CREATE INDEX IF NOT EXISTS idx_avail_kb ON available_updates (patch_id);
CREATE INDEX IF NOT EXISTS idx_avail_run ON available_updates (run_id);
CREATE INDEX IF NOT EXISTS idx_avail_sev ON available_updates (severity_rank DESC);

-- ---------------------------------------------------------------------------
-- Installed hotfixes (Win32_QuickFixEngineering snapshot)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS installed_hotfixes (
    host_id      BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    patch_id           TEXT NOT NULL,
    description  TEXT,
    installed_on TIMESTAMPTZ,
    PRIMARY KEY (host_id, patch_id)
);

-- ---------------------------------------------------------------------------
-- Approval gate. Replaces the WSUS approve/decline workflow, and is the
-- errata gate for RHEL and the package gate for Ubuntu - one mechanism, all OSes.
-- The apply playbook builds its accept_list from rows where status='approved'.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_approvals (
    patch_id           TEXT NOT NULL,
    ring         TEXT NOT NULL DEFAULT 'prod',
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'rejected', 'deferred')),
    approved_by  TEXT,
    decided_at   TIMESTAMPTZ,
    not_before   DATE,            -- earliest date this KB may be applied to this ring
    notes        TEXT,
    PRIMARY KEY (patch_id, ring)
);

-- ---------------------------------------------------------------------------
-- Audit trail of actual patch actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patch_events (
    event_id   BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    host_id    BIGINT REFERENCES hosts(host_id) ON DELETE SET NULL,
    hostname   TEXT NOT NULL,
    patch_id         TEXT,
    title      TEXT,
    action     TEXT NOT NULL,      -- download | install | reboot | rollback | scan
    result     TEXT NOT NULL,      -- success | failed | skipped
    hresult    TEXT,
    message    TEXT,
    run_id     UUID
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON patch_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_host ON patch_events (host_id);

-- ---------------------------------------------------------------------------
-- Views for Grafana. Everything reads "latest run only" unless stated.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_latest_run AS
SELECT run_id, started_at, finished_at, source
FROM scan_runs
WHERE finished_at IS NOT NULL
ORDER BY started_at DESC
LIMIT 1;

CREATE OR REPLACE VIEW v_pending_updates AS
SELECT
    h.hostname,
    h.ring,
    h.os_family,
    h.os_build,
    h.reboot_pending,
    a.patch_id,
    a.title,
    a.severity,
    a.severity_rank,
    a.size_bytes,
    a.is_downloaded,
    a.release_date,
    a.cve_ids,
    a.support_url,
    COALESCE(ap.status, 'pending') AS approval_status,
    ap.not_before,
    EXTRACT(DAY FROM now() - a.release_date)::INT AS age_days
FROM available_updates a
JOIN hosts h  ON h.host_id = a.host_id
JOIN v_latest_run lr ON lr.run_id = a.run_id
LEFT JOIN patch_approvals ap ON ap.patch_id = a.patch_id AND ap.ring = h.ring;

-- One row per (KB, ring). This is the "what can I download and apply" worklist.
-- Granularity is per-ring because approval is per-ring: KB5034129 may be approved
-- for canary and still pending for prod.
--
-- NOTE: CVE aggregation is deliberately kept in a separate CTE. Unnesting the
-- cve_ids array in the same query as SUM(size_bytes) multiplies each update row
-- by its CVE count and inflates the download total.
CREATE OR REPLACE VIEW v_patch_rollup AS
WITH latest AS (
    SELECT a.*, h.ring, h.os_family
    FROM available_updates a
    JOIN v_latest_run lr ON lr.run_id = a.run_id
    JOIN hosts h ON h.host_id = a.host_id
    WHERE a.patch_id IS NOT NULL
),
agg AS (
    SELECT
        patch_id,
        ring,
        MAX(os_family)              AS os_family,   -- a patch_id never spans families
        MIN(title)                  AS title,
        MAX(severity_rank)          AS severity_rank,
        COUNT(DISTINCT host_id)     AS affected_hosts,
        MAX(size_bytes)             AS size_bytes,          -- one copy of the payload
        SUM(size_bytes)             AS total_download_bytes, -- if every host pulls its own
        bool_or(reboot_required)    AS needs_reboot,
        MIN(release_date)           AS release_date,
        MIN(support_url)            AS support_url
    FROM latest
    GROUP BY patch_id, ring
),
cves AS (
    SELECT l.patch_id, array_agg(DISTINCT c) AS cve_ids
    FROM latest l, unnest(l.cve_ids) AS c
    GROUP BY l.patch_id
)
SELECT
    agg.patch_id,
    agg.ring,
    agg.os_family,
    agg.title,
    -- Derive the label from the numeric rank. Sorting the text directly puts
    -- 'Moderate' above 'Critical'.
    CASE agg.severity_rank
        WHEN 4 THEN 'Critical'
        WHEN 3 THEN 'Important'
        WHEN 2 THEN 'Moderate'
        WHEN 1 THEN 'Low'
        ELSE 'Unspecified'
    END                                                    AS severity,
    agg.severity_rank,
    agg.affected_hosts,
    agg.size_bytes,
    agg.total_download_bytes,
    agg.needs_reboot,
    agg.release_date,
    EXTRACT(DAY FROM now() - agg.release_date)::INT        AS age_days,
    cves.cve_ids,
    agg.support_url,
    COALESCE(ap.status, 'pending')                         AS approval_status,
    ap.not_before,
    ap.approved_by
FROM agg
LEFT JOIN cves ON cves.patch_id = agg.patch_id
LEFT JOIN patch_approvals ap ON ap.patch_id = agg.patch_id AND ap.ring = agg.ring;

CREATE OR REPLACE VIEW v_host_compliance AS
SELECT
    h.hostname,
    h.ring,
    h.os_family,
    h.os_build,
    h.display_version,
    h.last_seen,
    h.reboot_pending,
    h.scan_ok,
    h.scan_error,
    COUNT(a.id)                                                          AS pending_total,
    COUNT(a.id) FILTER (WHERE a.severity_rank = 4)                       AS pending_critical,
    COUNT(a.id) FILTER (WHERE a.severity_rank = 3)                       AS pending_important,
    COALESCE(SUM(a.size_bytes), 0)                                       AS download_bytes,
    MAX(EXTRACT(DAY FROM now() - a.release_date))::INT                   AS oldest_missing_days
FROM hosts h
LEFT JOIN available_updates a
       ON a.host_id = h.host_id
      AND a.run_id = (SELECT run_id FROM v_latest_run)
GROUP BY h.host_id;

-- Trend: pending count per run, for the compliance-over-time panel.
CREATE OR REPLACE VIEW v_compliance_trend AS
SELECT
    sr.started_at                                          AS ts,
    COUNT(DISTINCT a.host_id)                              AS hosts_with_pending,
    COUNT(a.id)                                            AS pending_total,
    COUNT(a.id) FILTER (WHERE a.severity_rank >= 3)        AS pending_high
FROM scan_runs sr
LEFT JOIN available_updates a ON a.run_id = sr.run_id
WHERE sr.finished_at IS NOT NULL
GROUP BY sr.run_id, sr.started_at
ORDER BY sr.started_at;

-- ---------------------------------------------------------------------------
-- Read-only role for Grafana
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grafana_ro') THEN
        CREATE ROLE grafana_ro LOGIN PASSWORD 'CHANGE_ME_grafana';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE patchmgr TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_ro;
