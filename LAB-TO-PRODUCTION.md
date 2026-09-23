# patchmgr — Lab (VMware Workstation) to Production (Nutanix AHV)

A complete run: build the lab, prove the system with a written test plan,
produce the evidence reports, then cut over to production. Treat the test-case
IDs (TC-xx) as your checklist; each has an expected result and a pass
criterion, and the final section tells you which artifacts to keep as the
acceptance record.

---

## 1. Prerequisites

### 1.1 Workstation host

| Item | Minimum | Comfortable |
|---|---|---|
| CPU | 8 cores, VT-x/AMD-V enabled in BIOS | 12+ cores |
| RAM | 32 GB | 48–64 GB |
| Disk | 300 GB free SSD | 500 GB NVMe |
| VMware Workstation | 17.x Pro | — |

The RAM figure is the real constraint: the control node wants 16 GB when the
Wazuh all-in-one stack is on it (the indexer OOMs below ~8 GB alone). If your
host has 32 GB total, run the control node at 12 GB, **skip Greenbone in the
lab**, and keep the target VMs small — the pipeline is what you are testing,
not scan throughput.

### 1.2 Installation media

* Ubuntu Server 24.04 LTS ISO (control node, and one Ubuntu target)
* Windows Server 2022 ISO (eval is fine — 180 days)
* One RHEL-family ISO. **Rocky Linux 9 minimal is the best lab pick**: free,
  ships full errata metadata (so severities work), and behaves like RHEL 9.
  Add AlmaLinux or a developer-subscription RHEL if you want a second flavour.
* Optional, only if you must prove the EL7 path: CentOS 7 ISO — knowing that
  its repos are frozen and carry no errata (the scanner will say so; that
  *is* the test).

### 1.3 Network plan

Use one **NAT network** (VMnet8) so guests reach the internet for updates and
each other for management, with static IPs — remember, no AD means no DNS, and
every config in the repo carries IPs for exactly this reason.

| VM | IP (example VMnet8) | vCPU | RAM | Disk | Ring |
|---|---|---|---|---|---|
| `ctrl` (Ubuntu 24.04) | 192.168.100.10 | 4 | 12–16 GB | 100 GB | — |
| `WIN2022-CANARY1` | 192.168.100.101 | 2 | 4 GB | 60 GB | canary |
| `WIN2022-SQL1` | 192.168.100.121 | 2 | 4 GB | 60 GB | prod |
| `ROCKY9-WEB1` | 192.168.100.133 | 1 | 2 GB | 20 GB | canary |
| `RHEL9-APP1` (or Alma) | 192.168.100.131 | 1 | 2 GB | 20 GB | pilot |
| `UBU2404-WEB1` | 192.168.100.141 | 1 | 2 GB | 20 GB | canary |
| `UBU2204-APP1` | 192.168.100.142 | 1 | 2 GB | 20 GB | pilot |

Check *Edit → Virtual Network Editor → VMnet8* for the subnet VMware actually
assigned and adjust; keep static IPs **outside** the VMware DHCP range.

A deliberately incomplete lab is fine — the minimum honest test is one
Windows, one RHEL-family, one Ubuntu target across two rings. The table above
adds a second host per family so ring promotion means something.

### 1.4 Things to decide before you start

* **Service-account password** for `svc_patchmgr` on Windows (goes into
  ansible-vault; one local account per target, same name everywhere).
* **Snapshot policy in the lab**: `snapshot_provider: none` — Workstation has
  no API reachable from inside a guest, so pre-patch snapshots are manual
  (and that is one of the test cases: the run must *say* it skipped them).
* Which patches you will deliberately leave missing: install each target OS
  and then **do not fully update it**. A lab where everything is current has
  nothing to discover. For Windows, pick an install ISO a few months old or
  pause updates after OOBE.

---

## 2. Lab build order

Build in this order; each step has a verification gate before the next.

### Phase 0 — VMs and snapshots (half a day, mostly unattended installs)

1. Create the seven VMs per the table. For every guest: static IP, gateway
   `192.168.100.2` (VMware NAT), DNS `192.168.100.2` or public resolvers.
2. Windows guests: set the hostname to match the inventory name, enable
   nothing else — the bootstrap script does WinRM properly.
3. **Take a Workstation snapshot of every VM named `pre-patchmgr`.** This is
   your reset lever for re-running destructive test cases.

### Phase 1 — Control node (1–2 hours)

```bash
git clone <your-copy> /opt/patchmgr && cd /opt/patchmgr/install
sudo ./bootstrap.sh                     # ansible, postgres, grafana, timers, ssh key, vault_pass
sudo ./install_wazuh.sh                 # skip in a 32 GB host if RAM is tight
sudo ./make_ca.sh init                  # private CA for WinRM certs
```

Gate: `systemctl status grafana-server postgresql`, log in to Grafana on
`http://192.168.100.10:3000`, dashboard loads (empty), and
`psql "$PATCHMGR_DSN" -c '\dv'` lists the five views.

### Phase 2 — Windows targets (30 min per host)

On the control node mint a cert per host (IP SAN — no DNS, remember):

```bash
sudo ./make_ca.sh host WIN2022-CANARY1 --ip 192.168.100.101
```

Copy `Bootstrap-WindowsTarget.ps1` + the PFX + `winrm-ca.pem` to the guest,
then in an elevated PowerShell:

```powershell
.\Bootstrap-WindowsTarget.ps1 -PfxPath .\WIN2022-CANARY1.pfx `
    -ControlNodeIP 192.168.100.10 -CreateServiceAccount
```

Gate per host: from the control node,
`ansible WIN2022-CANARY1 -m ansible.windows.win_ping` → `pong`.
If auth succeeds but later privileged tasks fail, you skipped the
`LocalAccountTokenFilterPolicy` step — the script sets it; a hand-built host
won't have it.

### Phase 3 — Linux targets (10 min per host)

```bash
# control node
cat /etc/patchmgr/ssh/id_ed25519.pub
# each Linux guest, as root
./bootstrap-linux-target.sh --pubkey "ssh-ed25519 AAAA... patchmgr@ctrl"
```

Gate: `ansible linux -m ansible.builtin.ping` → all `pong`, and on the Rocky
host `needs-restarting -r; echo $?` returns 0 or 1, not "command not found".

### Phase 4 — Inventory and first scan

Edit `ansible/inventory/hosts.yml` to your real names/IPs (each host under
its OS group **and** its ring group), vault the Windows password, then:

```bash
ansible-playbook playbooks/patch_scan.yml
```

Gate: the dashboard populates. That gate is formally TC-01 below.

---

## 3. Test plan

Run these in order. **Reset rule:** any TC marked ♻ changes target state; if
you need to repeat it, revert the target's `pre-patchmgr` snapshot, re-run the
relevant bootstrap step if the snapshot predates it, and rescan.

Record every case in a copy of the results table in §4.

### A. Discovery

**TC-01 — Full-fleet scan.** Run `patch_scan.yml` with all targets up.
*Expect:* one JSON per host under `/var/lib/patchmgr/scans/<run_id>/`; every
host appears in the dashboard's Host Compliance panel with `Last scan` =
now; Windows rows show KBs with MSRC severities, Rocky/RHEL rows show
`RHSA-`/`RLSA-` ids with errata severities, Ubuntu rows show package names
with `Security`/`Unspecified`. *Pass:* zero hosts in the Stale-scans tile.

**TC-02 — Unreachable host is a fact, not an error.** Power off
`UBU2204-APP1`, rescan. *Expect:* playbook completes; that host gets a stub
JSON with `scan_error: unreachable…`; dashboard Stale/Error column shows it;
all other hosts still refresh. *Pass:* run exits 0 and the outage is visible
on the dashboard rather than hidden in a log. Power the VM back on.

**TC-03 — Severity mapping is honest.** Compare three sampled rows against
the vendor's own page via the Patch column's advisory link (MSRC for a KB,
access.redhat.com for an RHSA, the `-security` pocket for an Ubuntu package).
*Pass:* severities match the vendor; Ubuntu non-security updates show
`Unspecified`, not an invented rating.

**TC-04 — (optional, CentOS 7 only) No-errata visibility.** Scan the CentOS 7
box. *Expect:* updates appear with `patch_id = package name`, severity
`Unspecified`, category `no-errata`, and the scanner's notes say the repos
carry no errata metadata. *Pass:* the limitation is displayed, not silent.

### B. The approval gate

**TC-05 — Nothing applies without approval. ♻** With zero approvals, run
`patch_apply.yml -e target_ring=canary --limit ring_canary`. *Expect:* the
resolver play fails its assert with the "Nothing approved" message; **no
target is touched**. *Pass:* exit non-zero, no package/KB changes on any host
(spot-check `dnf history` / `apt` log / Windows Update history).

**TC-06 — Mixed-OS approval in one command.** Pick one real pending id per
family from the worklist and:

```bash
scripts/approve.sh approve canary KB50xxxxx RLSA-2026:xxxx <some-pkg>
scripts/approve.sh list canary
```

*Expect:* all three flip to `approved` for canary only; pilot/prod rows for
the same ids remain `pending`. *Pass:* `approve.sh status <id>` shows exactly
one approved ring per id.

**TC-07 — Rejection sticks.** `approve.sh reject canary <different-id> --note
"TC-07"`. *Expect:* id shows `rejected`; a later TC-08 apply must not install
it. *Pass:* verified during TC-08.

### C. Applying — per family ♻

**TC-08 — Canary apply, three ecosystems, one run.**
`patch_apply.yml -e target_ring=canary --limit ring_canary`. *Expect:* the
Windows play installs only the approved KB on `WIN2022-CANARY1`; the RHEL
play runs `dnf update --advisory=<id>` on `ROCKY9-WEB1`; the Ubuntu play
`--only-upgrade`s the approved package on `UBU2404-WEB1`; each play that has
nothing for its family ends itself; reboots happen only where the OS asked
for one. *Pass:* post-run rescan (the canary timer does this automatically)
shows those ids gone from canary's pending list; TC-07's rejected id is still
pending/rejected, **not installed**; `patch_events` has one row per
host×patch with `result=success`.

**TC-09 — Selectivity.** On the Rocky host after TC-08:
`dnf updateinfo list --all | wc -l` still shows the *unapproved* errata
pending. *Pass:* only approved advisories were applied — the apply is a
scalpel, not `dnf update -y`.

**TC-10 — Approval is ring-wide-safe (no-op semantics).** Approve for canary
an Ubuntu package that exists on `UBU2404-WEB1` but **not** on the Windows or
Rocky canary hosts, and re-apply. *Expect:* apt play upgrades where present;
nothing attempts to *install* it anywhere; events log "already current or not
installed" for the no-op case if the package was current. *Pass:* no new
package appears on any host that didn't already have it.

**TC-11 — Reboot policy is obeyed. ♻** Approve a kernel/`linux-image` update
for canary; run once with `-e patch_reboot_allowed=false`. *Expect:* update
installs, host does **not** reboot, play prints the "reboot owed but not
permitted" warning, dashboard Reboot column lights up. Re-run without the
flag: host reboots and comes back inside `patch_reboot_timeout`. *Pass:* both
behaviours observed; uptime confirms exactly one reboot.

**TC-12 — Failure containment. ♻** Break one prod-ring target (e.g. stop
WinRM on `WIN2022-SQL1`, or `chmod 000 /usr/bin/dnf` on an EL prod host),
approve something for prod, apply with `-e target_ring=prod --limit
ring_prod`. *Expect:* the broken host fails; `serial`/`max_fail_percentage`
lets healthy hosts proceed (with 2 prod hosts of a family and 30 % max-fail,
the batch stops — that stop *is* the pass); `patch_events` records
`result=failed`. Restore the host afterwards. *Pass:* failure recorded, blast
radius matched policy.

### D. Rings and promotion

**TC-13 — Promotion copies survivors only.** After a clean TC-08:
`approve.sh promote canary pilot`, apply to pilot. *Expect:* pilot hosts get
exactly the canary-approved set. *Pass:* pilot pending counts drop by the
promoted ids.

**TC-14 — Failed ids are quarantined by promote.** Ensure one id has a
`failed` install event in canary (TC-12 rerun in canary, or insert a
synthetic failed event with `record_events.py --events-json`). Promote again.
*Expect:* that id is **skipped** with the "failed installs … skipped" notice;
all clean ids copy. *Pass:* the failed id's pilot row is still `pending`.

### E. Platform behaviours

**TC-15 — Snapshot honesty in the lab.** With `snapshot_provider: none`,
apply output must show the snapshot step skipped — silently pretending a
snapshot exists would be worse than not taking one. *Pass:* skip is visible
in the run output. (The Nutanix path gets its own test in §5.)

**TC-16 — Unattended schedule.** `systemctl start patchmgr-scan.service`,
then check `systemctl list-timers 'patchmgr*'`. *Expect:* scan service runs
to completion with no TTY (vault password comes from
`/etc/patchmgr/vault_pass`), next timer fires within 6 h + jitter. *Pass:*
journal shows a clean run started by the timer, dashboard `Last scan`
advances without human touch.

**TC-17 — Wazuh corroboration (if installed).** After TC-08, the Wazuh
vulnerability module for the canary hosts should show CVE counts *dropping*
for the patched components within a detector cycle. *Pass:* the two systems
tell the same story from independent evidence (WUA/errata vs installed-
version × CVE feeds). This is also your Ubuntu CVE-depth test — apt said only
`Security`, Wazuh names the CVEs.

**TC-18 — Restore drill.** Revert one canary VM to `pre-patchmgr`, rescan.
*Expect:* its pending count jumps back up; approvals are unchanged (they are
control-node state); a re-apply converges it again. *Pass:* system state is
rebuilt from scan truth, not from stale memory.

---

## 4. Reports — the acceptance record

Keep these five artifacts; together they are the evidence pack that justifies
the production move.

**R1 — Test results table.** One row per TC:

| TC | Date | Operator | Result | Evidence ref | Notes |
|---|---|---|---|---|---|
| TC-01 | | | pass/fail | R2-run-id… | |

**R2 — Run evidence.** For each apply TC: the ansible log
(`journalctl -u patchmgr-apply-canary` or your shell capture), the scan
`run_id` before/after, and the matching rows from:

```sql
SELECT ts, hostname, patch_id, action, result, message
FROM patch_events WHERE ts > now() - interval '1 day' ORDER BY ts;
```

**R3 — Dashboard snapshots.** Grafana → panel → *Share → Snapshot* (or PDF
the page) at three moments: before any approvals (peak pending), after canary
apply, after prod apply. The compliance-trend panel across those dates is the
single most persuasive picture for management.

**R4 — Compliance export.** The formal state at sign-off:

```sql
\copy (SELECT * FROM v_host_compliance ORDER BY ring, hostname)
  TO 'compliance-signoff.csv' CSV HEADER
\copy (SELECT patch_id, os_family, ring, severity, approval_status
       FROM v_patch_rollup ORDER BY severity_rank DESC)
  TO 'patch-state-signoff.csv' CSV HEADER
```

**R5 — Exceptions register.** Every `rejected`/`deferred` id with its
`--note`, straight from `patch_approvals`. In production this is the document
auditors ask for by name.

**Acceptance criteria to leave the lab:** every TC pass (TC-04 optional);
one full canary→pilot→prod cycle completed on schedule by the timers with no
manual fixes; R1–R5 archived.

---

## 5. Moving to production (Nutanix AHV)

### 5.1 What changes and what does not

Nothing in the pipeline logic changes — that is the point of having proven it
in the lab. What changes:

| Concern | Lab | Production |
|---|---|---|
| Hypervisor | Workstation NAT | AHV, real VLANs |
| Snapshots | manual (`none`) | **Prism API, automatic pre-patch** |
| Control node size | 12–16 GB, maybe no Greenbone | 8 vCPU / 16 GB / 200 GB, full stack |
| Scale | ~7 hosts | your fleet, rings re-drawn |
| Credentials | lab passwords | new vault, new CA or the same CA with new host certs, new SSH keypair if key custody demands |

### 5.2 Cutover steps

1. **Deploy the production control node** on AHV from the same repo, same
   `bootstrap.sh`. Do not copy the lab VM: rebuild from the scripts — the lab
   proved the scripts, so use them. Restore nothing except (optionally) the
   Grafana dashboard JSON, which is already in the repo.
2. **Snapshot provider on.** In `group_vars/all.yml`:

   ```yaml
   snapshot_provider: nutanix
   nutanix_pe_host: <prism-element-ip>       # Prism Element VIP, port 9440
   nutanix_user: patchmgr-svc               # least-priv Prism role: VM snapshot only
   ```

   with the password vaulted. Create the Prism service account with a role
   limited to snapshot create/list — it needs nothing else.
3. **Targets.** Run the two bootstrap scripts against production hosts
   (Windows: new per-host certs from your CA with production IP SANs; Linux:
   the pubkey). Populate the real inventory: OS group × ring for every host.
   Draw rings deliberately — canary = machines whose owners expect
   turbulence, prod = serialized, `patch_serial` tuned to what your change
   windows tolerate.
4. **Re-run the smoke subset in production before trusting the timers:**
   TC-01, TC-05, TC-06, TC-08 (against the production canary ring only), plus
   the production-only case:

   **TC-19 — Snapshot gate.** Apply to one canary VM and verify in Prism that
   a `patchmgr-pre-<date>` snapshot exists *before* the install step ran, and
   that the play polls the snapshot task to `Succeeded` before patching.
   *Pass:* timestamp ordering proves patch-after-snapshot. Then delete lab-
   style manual snapshot habits from the runbook — the API does it now.

   **TC-20 — Snapshot failure blocks patching.** Temporarily wrong the Prism
   password, apply. *Expect:* the play fails at the snapshot task and never
   reaches the install step. *Pass:* no patch without a restore point.
   Restore the credential.
5. **Enable the timers** (`patchmgr-scan.timer`, `patchmgr-apply-canary.timer`)
   and let one full weekly cycle run hands-off: Wednesday canary applies,
   you review Thursday, promote Friday, prod in the next window.
6. **First month cadence:** keep `patch_serial` conservative
   (`ring_prod: "25%"` or stricter), review R5 exceptions weekly, and only
   widen serial once two clean cycles are on record.

### 5.3 Production rollback story

Per host: Prism snapshot restore (that is what TC-19/20 bought you), then
`approve.sh reject <ring> <patch-id> --note "INC-…"` so the next run cannot
reinstall it, and `promote` will quarantine it automatically from then on
(TC-14 behaviour). Whole-system: the control node is stateless except
PostgreSQL — `pg_dump` on a timer into your backup target is the only backup
this system needs; targets carry no patchmgr state worth saving.

---

## 6. Known lab-vs-production deltas to keep in mind

* Workstation NAT hands out its own DNS; production VLANs may not — the
  design already assumes IP-everything, so nothing should break, but new host
  certs **must** carry the production IPs in their SANs.
* Lab eval Windows licences expire; production activation changes patch
  applicability slightly (SKU-specific updates). Rescan truth beats lab
  memory.
* RHEL in production with Satellite/RHSM proxies: point the hosts' repos as
  your subscription setup requires; the scanner reads whatever repos are
  enabled and does not care where they live.
* If production Ubuntu uses Pro/ESM, expect `esm` categories in scans — that
  is detection working, not an error.
