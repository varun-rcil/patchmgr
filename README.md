# patchmgr — Linux-hosted patch & vulnerability management for Windows, RHEL 7–10, and Ubuntu

A single Ubuntu 24.04 or RHEL 9 VM that continuously discovers pending Windows
patches, shows them on a dashboard, gates them behind an approval workflow, and
applies them via Ansible — plus agent-based and network-based vulnerability
scanning.

---

## What "a patch" means per OS — read this first

The whole pipeline keys on one `patch_id`, but each OS names patches
differently, and that decides both what you approve and how granular the
apply step can be:

| OS family | Discovery | patch_id | Severity source | Apply granularity |
|---|---|---|---|---|
| Windows Server 2016+ | WUA COM (read-only) | `KB5034129` | MSRC (Critical/Important/…) | per-KB `accept_list` |
| RHEL / Alma / Rocky / Oracle 7–10 | `dnf`/`yum updateinfo` | `RHSA-2026:0123` (ALSA-/RLSA-…) | errata metadata, same scale as MSRC | per-advisory `--advisory=` |
| Ubuntu / Debian | `python3-apt` origins | package name (`openssl`) | `Security` if from a `-security` pocket or ESM, else `Unspecified` | per-package `--only-upgrade` |

Three honest caveats baked into the design rather than papered over:

* **CentOS 7 base repos never carried errata metadata.** Updates there surface
  with `patch_id = package name` and severity `Unspecified` — visible, gated,
  but unrated. The scanner says so in its notes. (Alma and Rocky publish full
  errata; they behave like RHEL.)
* **RHEL 7 is past end-of-maintenance.** New errata require an ELS
  subscription; CentOS 7 gets nothing. The scanner still runs — it just tells
  you the truth about a frozen repo.
* **apt has no advisory objects**, so Ubuntu severity is binary
  (`Security`/`Unspecified`, ranked alongside *Important*) and approval is per
  package. CVE depth for Ubuntu comes from the Wazuh side of the house, which
  maps installed versions against USN/OVAL data.

One consequence worth liking: `approve.sh approve canary KB5034129
RHSA-2026:0123 openssl` is a legal sentence. One gate, one audit trail, one
dashboard — three package ecosystems.

## One thing to settle first: Nessus

The request mentioned an "open-source free Nessus agent." Three separate things
are tangled there, and the distinction changes the design:

- **Nessus is not open source.** It is proprietary software from Tenable with a
  free tier.
- **Nessus Essentials** (the free tier) is capped at **16 IP addresses** and is
  licensed for non-commercial use. If this estate is bigger than 16 hosts or is
  a business, Essentials is not a lawful option.
- **Nessus Agents do not work with Essentials.** Agents report to Nessus Manager
  or Tenable Vulnerability Management, both paid. Essentials only does
  *network* scans from the scanner host.

So "free open-source Nessus agent" does not exist as described. The options that
do:

| Tool | Licence | Model | Windows support | Cap |
|---|---|---|---|---|
| **Wazuh** | GPLv2, genuinely open source | Agent | Native MSI agent, reads hotfixes + software inventory | None |
| **Greenbone CE / OpenVAS** | GPL, genuinely open source | Network, authenticated over SMB | Good with a credential | None |
| Nessus Essentials | Proprietary, free tier | Network only | Good with a credential | 16 IPs, non-commercial |

**This build uses Wazuh + Greenbone.** Together they cover what a single Nessus
Essentials instance would, without the host cap or the licensing question. If
you specifically need Nessus output for an auditor who demands it, run Essentials
alongside for ≤16 hosts — it does not conflict with anything here.

---

## Why the pieces are what they are

**There is no WSUS for Linux.** WSUS is a Windows Server role; it cannot be
hosted here. The approval workflow WSUS gives you is replaced by the
`patch_approvals` table plus `scripts/approve.sh`, which is arguably better
because it is queryable, auditable, and diffable.

**One consequence to plan for:** without WSUS, each Windows host downloads its
updates directly from Microsoft. A 700 MB cumulative update times 50 servers is
35 GB across your internet link. Mitigations, in order of preference:

1. Turn on **Delivery Optimization** in group mode so hosts peer with each other
   on the LAN (`DODownloadMode=2`). Cheapest fix by far.
2. Point `patch_source: WSUS` at an existing WSUS if one already exists
   elsewhere in the estate. The Linux VM still orchestrates; WSUS just serves bits.
3. Accept the bandwidth and schedule downloads separately from installs using
   `-e patch_state=downloaded` during off-hours.

**Why a custom PowerShell scanner instead of just `win_updates`?**
`ansible.windows.win_updates` does not return MSRC severity, download size, CVE
IDs, or support URLs. Those are exactly the fields that make a dashboard
actionable, and they are available from the Windows Update Agent COM API. So
discovery uses `files/Get-PendingUpdates.ps1` (read-only), and *application*
uses `win_updates`, which is well-tested and handles the servicing edge cases.

**Why `become: runas SYSTEM` everywhere?** A WinRM connection gets a network
logon token. The WUA API refuses online searches under one, giving `0x80240438`
or plain access-denied. Running as SYSTEM gets a local token without needing
CredSSP, which you should not enable.

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │  patchmgr VM  (Ubuntu 24.04 / RHEL 9)       │
                    │                                             │
   Grafana :3000 ───┤  Grafana ──── PostgreSQL                    │
   Wazuh   :443  ───┤     ▲            ▲                          │
   Greenbone :9392 ─┤     │            │ load_scan.py             │
                    │     │       ┌────┴──────┐                   │
                    │     └───────┤  Ansible  │ systemd timer     │
                    │             └────┬──────┘ every 6h          │
                    │  Wazuh manager   │  Greenbone scanner       │
                    └──────────────────┼─────────┬────────────────┘
                                       │         │
                     WinRM/HTTPS 5986  │         │ SMB 445 (authenticated scan)
                     NTLM (workgroup)  │         │
                    ┌──────────────────▼─────────▼────────────────┐
                    │  Windows Server 2022 targets                │
                    │  + Wazuh agent (1514/1515 outbound)         │
                    └─────────────────────────────────────────────┘
```

**Data flow:** timer fires → Ansible runs `Get-PendingUpdates.ps1` on every host
under SYSTEM → each host's JSON lands on the control node → `load_scan.py`
upserts into PostgreSQL and seeds every new KB as `pending` → Grafana reads the
views → operator approves KBs → `patch_apply.yml` installs only what is approved
for that ring.

---

## Sizing

Everything on one VM:

| Component | vCPU | RAM | Disk |
|---|---|---|---|
| Ansible + PostgreSQL + Grafana | 2 | 4 GB | 40 GB |
| Wazuh (manager + indexer + dashboard) | 4 | 8 GB | 100 GB |
| Greenbone CE | 2 | 4 GB | 40 GB (feeds are large) |
| **Total, all-in-one** | **8** | **16 GB** | **200 GB SSD** |

16 GB is the floor and it is a real floor — the Wazuh indexer is
Elasticsearch-derived and will OOM-kill below 8 GB for itself. For more than
~200 Windows hosts, or if you want failure isolation, split Wazuh onto its own
VM. The patch-management half (Ansible + Postgres + Grafana) is light and
comfortably handles 500 hosts on 2 vCPU / 4 GB.

---

## Install

### 1. Control node

```bash
git clone <this repo> /tmp/patchmgr && cd /tmp/patchmgr
sudo ./install/bootstrap.sh --pg-password 'strong-secret'
sudo ./install/install_wazuh.sh          # optional but recommended
sudo ./install/install_greenbone.sh      # optional, needs the extra 40GB
```

### 2. Auth model (workgroup — no AD)

With no domain there is no Kerberos and no GPO. The design becomes:

- A **local** administrator (`svc_patchmgr`) on every target, created by the
  bootstrap script. Patching is inherently privileged; there is no lesser right
  that installs updates. Blast radius is reduced instead: the account is denied
  console and RDP logon (user-rights assignment via secedit), so the credential
  works for WinRM and nothing else.
- **NTLM over HTTPS.** NTLM alone cannot authenticate the *server*, so the TLS
  certificate is doing that job — which is why this build ships `make_ca.sh`, a
  small private CA, instead of telling you to set
  `ansible_winrm_server_cert_validation: ignore` and hope. Turn validation off
  only in the throwaway lab.
- The password lives in **ansible-vault** (`group_vars/windows_vault.yml`),
  decrypted for unattended timer runs by `/etc/patchmgr/vault_pass` (0600).
- The bootstrap script sets `LocalAccountTokenFilterPolicy=1`. Without it,
  remote UAC filtering strips the admin token from local accounts over the
  network: WinRM auth *succeeds* and then every privileged call fails with
  Access Denied, which is a miserable thing to debug. The same setting is what
  lets Greenbone's authenticated SMB scan use this account.

Use one password per ring at minimum, per host ideally (host_vars +
per-host vault entries). If you later add AD, `group_vars/windows.yml` has the
Kerberos block commented and ready.

### 3. Windows targets

Issue each host a certificate from the built-in CA, then bootstrap it:

```bash
# on the control node
sudo ./install/make_ca.sh init                                   # once
sudo ./install/make_ca.sh host WIN2022-CANARY1 --ip 192.168.100.101
sudo ./install/make_ca.sh trust                                  # once
```

The `host` command prints the PFX password, the thumbprint, and the exact
commands for the Windows side. Copy the `.pfx` over and run, in elevated
PowerShell:

```powershell
.\Bootstrap-WindowsTarget.ps1 -ControlNodeIP 192.168.100.10 `
    -PfxPath .\WIN2022-CANARY1.pfx -PfxPassword '<printed>' `
    -CreateServiceAccount -ServiceAccountPassword '<pick-a-long-one>'
```

This enables WinRM over HTTPS, removes the plaintext listener, disables Basic
auth, scopes the firewall rule to the control node IP only, raises the WinRM
shell memory quota (the 150 MB default causes intermittent WUA search
failures), creates the locked-down service account, and pins Automatic Updates
to **download-only** (`AUOptions=3`) so Windows never installs outside your
windows. The certificate SAN must contain whatever `ansible_host` is set to —
if you connect by IP, issue with `--ip`.

### 4. Linux targets (RHEL family and Ubuntu)

```bash
# control node — the bootstrap generated a keypair for exactly this
cat /etc/patchmgr/ssh/id_ed25519.pub

# on EACH Linux target, as root
./bootstrap-linux-target.sh --pubkey "ssh-ed25519 AAAA... patchmgr@ctrl"
```

That creates `svc_patchmgr` (key-only, password locked, NOPASSWD sudo —
patching is root work; the control is key custody on the control node),
installs `python3` where the distro doesn't guarantee it (EL7's default is
Python 2, which ansible-core ≥ 2.17 cannot target; EL8 minimal lacks
`/usr/bin/python3` too), plus `yum-utils`/`dnf-utils` for `needs-restarting`
and `python3-apt` on Debian-family.

Then put the host in `inventory/hosts.yml` twice: once under its OS group
(`rhel` / `ubuntu`), once under its ring (`ring_canary` / `ring_pilot` /
`ring_prod`). OS groups decide *how*; rings decide *when*.

### 5. Verify

```bash
# vault the service-account password
sudo /opt/patchmgr/venv/bin/ansible-vault create /opt/patchmgr/ansible/group_vars/windows_vault.yml
#   vault_patchmgr_password: "<the -ServiceAccountPassword value>"
echo '<your-vault-password>' | sudo tee /etc/patchmgr/vault_pass >/dev/null

cd /opt/patchmgr/ansible && source /etc/patchmgr/patchmgr.env
ansible windows -m ansible.windows.win_ping
ansible-playbook playbooks/patch_scan.yml
```

Open Grafana at `http://<vm>:3000`. The dashboard populates after the first scan.

---

## Daily operation

```bash
# What is pending, worst first
scripts/approve.sh list

# Approve for the canary ring — KBs, errata, and apt packages mix freely
scripts/approve.sh approve canary KB5034129 RHSA-2026:0123 openssl

# Patch canary, see what breaks.
# ALWAYS pair the two flags: -e target_ring gates WHAT is approved,
# --limit gates WHO receives it. The playbook runs its Windows, RHEL and
# Ubuntu plays in sequence; a play with nothing approved for its family
# ends itself.
ansible-playbook playbooks/patch_apply.yml -l ring_canary -e ring=canary

# A week later, promote what survived. Ids that failed in canary are skipped
# regardless of OS — a bad kernel errata is held back exactly like a bad KB.
scripts/approve.sh promote canary pilot
ansible-playbook playbooks/patch_apply.yml -l ring_pilot -e ring=pilot

# Then production
scripts/approve.sh promote pilot prod
ansible-playbook playbooks/patch_apply.yml -l ring_prod -e ring=prod
```

Useful variations:

```bash
# Dry run
ansible-playbook playbooks/patch_apply.yml -l ring_prod -e ring=prod --check

# Download only during the day, install in the night window
ansible-playbook playbooks/patch_apply.yml -l ring_prod -e ring=prod -e patch_state=downloaded

# Block a bad patch permanently
scripts/approve.sh reject prod KB5033375 --note "breaks print spooler, INC-4471"

# Schedule an approval for a future date
scripts/approve.sh approve prod KB5034129 --not-before 2026-09-15
```

**Nothing installs unless it is explicitly approved.** `patch_apply.yml` asserts
that the accept list is non-empty and aborts otherwise. This is deliberate: a
misconfigured automation that installs everything it finds is how you take down
production on a Tuesday night.

---

## The dashboard

New in the multi-OS build: an **OS** filter beside Ring and Severity, an OS
column on the worklist and host tables, and the Patch column links each row to
its vendor advisory (MSRC for KBs, access.redhat.com / errata.rockylinux.org
for errata, Launchpad for packages) via the row's own URL — no more one-URL-
fits-nothing.


Six stat tiles across the top: hosts monitored, pending updates, critical
missing, awaiting reboot, total download size, and **stale scans**. That last one
matters more than it looks — a host that stopped reporting shows zero pending
updates, which is indistinguishable from "fully patched" unless you track scan
freshness explicitly.

Below that:

- **Available patches by KB** — the worklist. Severity-coloured, age-gradient
  (red past 60 days), KB numbers deep-link to the Microsoft support article, and
  the approval column shows per-ring status.
- **Host compliance** — per-server pending counts, OS build (UBR, which is the
  real patch level — `Get-HotFix` misses cumulative updates entirely), reboot
  state, last successful scan.
- **Pending updates over time** — should saw downward after each Patch Tuesday.
  A flat rising line means discovery is running but application is not.
- **Recent patch activity** — the audit trail, from `patch_events`.

---

## Vulnerability scanning

**Wazuh** (agent-based) answers: *which CVEs are exposed because a patch is
missing?* Deploy agents with:

```bash
ansible-playbook playbooks/deploy_wazuh_agent.yml -e wazuh_manager_ip=10.20.30.10
```

Then browse to **Vulnerability Detection** in the Wazuh dashboard. The first CVE
feed sync takes 10–30 minutes; before it finishes the module reports almost
nothing, which is easy to mistake for a clean bill of health.

**Greenbone** (network-based) answers: *what is exposed or misconfigured that no
agent would report?* — weak TLS, SMB signing disabled, stale service accounts,
default credentials. Configure a credentialed scan; uncredentialed scans of
Server 2022 find open ports and little else.

Run both. They find different classes of problem, and the overlap is smaller
than people expect.

---

## Things that will bite you

**Windows patching itself.** If Automatic Updates is left on auto-install,
Windows patches on its own schedule and your rings become decorative. With no
GPO to manage this centrally, `Bootstrap-WindowsTarget.ps1` pins the policy
registry key to `AUOptions=3` (auto-download, never auto-install) on every
host it touches. If a host drifts — someone reimages it, or a stray local
policy resets it — the symptom is patches appearing as installed that nobody
approved.

**Clock drift.** No Kerberos means no hard 5-minute wall, but certificate
validation still fails outside the cert's validity window, and every timestamp
in the dashboard, the audit trail, and Wazuh correlation depends on agreement.
`chrony` is installed on the control node; point the Windows VMs at the same
NTP source (`w32tm /config /manualpeerlist:<ntp> /syncfromflags:manual`).
VMware Workstation guests drift noticeably when the host sleeps — resuming a
paused lab and finding auth broken is usually this.

**Disk space.** A cumulative update that runs out of space mid-install can leave
the servicing stack in a state that needs `DISM /RestoreHealth` to recover.
`patch_apply.yml` pre-checks for 12 GB free and skips the host otherwise.

**Reboot-pending masking.** A host with a pending reboot reports subsequent
patches inconsistently. Treat "awaiting reboot" as an active problem, not a
cosmetic one.

**`Get-HotFix` lies.** It misses cumulative updates. The authoritative patch
level for Server 2022 is the UBR value in
`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` — build `10.0.20348.<UBR>`.
That is what the scanner records and what the dashboard shows.

**Domain controllers.** `ring_prod` sets `patch_reboot_allowed: false` for the DC
in the sample inventory. Never reboot DCs in parallel, and never let automation
do it unattended. Patch them by hand or in a tightly-scoped window.

---

**`needs-restarting` is the reboot oracle on RHEL, and it is not preinstalled
everywhere.** The bootstrap installs `yum-utils`/`dnf-utils`. Without it the
scanner falls back to comparing the running kernel against the newest
installed one — correct for kernels, blind to glibc/systemd.

**`--advisory=` silently skips advisories that don't apply.** Approving
`RHSA-2026:0123` ring-wide is safe: hosts without the affected packages do
nothing, exactly like a KB accept_list on a host that already has the KB. The
event log records `nothing to do` rather than pretending an install happened.

**apt `--only-upgrade` never installs absent packages** — approving `nginx`
for a ring upgrades the hosts that have it and no-ops the rest. That is the
semantics an approval should have, and it is why patch_id is the *binary*
package name, not the source package.

**A `dnf makecache`/`apt update` inside the scanner needs root**, which is why
the scan play runs the script with become. It installs nothing; repo metadata
freshness is the entire point of a scan.

## Lab first (VMware Workstation), then Nutanix AHV

The same repo runs in both; only sizing, snapshots, and networking differ.

**VMware Workstation (validation lab).**

- Put the patchmgr VM and the Windows VMs on the same NAT or host-only network
  and use static IPs — with no AD there is no DNS, which is why the inventory
  carries `ansible_host` per host. Certificate SANs must include the IP
  (`make_ca.sh host NAME --ip ...`).
- Sizing inside Workstation: patch stack only (Ansible + PostgreSQL + Grafana)
  runs happily in **2 vCPU / 4 GB**. Add Wazuh and it needs **12 GB** for the VM.
  Skip Greenbone in the lab unless the host has RAM to spare — it proves
  nothing there that it won't prove on Nutanix, and the 40 GB feed sync is slow
  on a laptop.
- **Snapshots are manual.** Workstation has no API reachable from inside a
  guest, so `snapshot_provider` stays `none`; snapshot the Windows VMs in the
  Workstation UI before an apply run. This is also the environment to
  deliberately break things: approve a patch, apply to canary, restore the
  snapshot, confirm the dashboard converges again.
- Lab shortcut: `ansible_winrm_server_cert_validation: ignore` in
  `group_vars/windows.yml` is acceptable *here* and nowhere else — though the
  full `make_ca.sh` flow works fine in the lab too, and rehearsing it there
  means production holds no surprises.

**Nutanix AHV (production).**

- Set in `group_vars/all.yml`:

  ```yaml
  snapshot_provider: nutanix
  nutanix_pe_host: <Prism Element VIP>
  ```

  and `vault_nutanix_password` in the vault. `patch_apply.yml` then takes a
  crash-consistent snapshot of each VM via the Prism v2 API before touching it,
  and refuses to continue for a host whose snapshot task does not report
  `Succeeded`. VM names in Prism must match inventory names (override per host
  with `nutanix_vm_name`).
- Use a dedicated Prism *Viewer+snapshot*-capable account rather than the
  cluster admin if your AOS release's RBAC allows it; the playbook only ever
  calls VM lookup, snapshot create, and task status.
- **Prune `prepatch-*` snapshots** after each successful ring. Snapshots hold
  vdisk deltas; a monthly cadence that never cleans up will quietly eat the
  storage container.
- Migrating the control node itself from the Workstation lab to an AHV VM:
  everything that matters lives in `/opt/patchmgr`, `/etc/patchmgr`, and the
  PostgreSQL database. `pg_dump patchmgr`, copy `/etc/patchmgr` (the CA
  especially — reissuing it means re-touching every Windows host), restore, and
  re-run `systemctl enable --now patchmgr-scan.timer`. Or simply rerun
  `bootstrap.sh` clean on the new VM and re-issue certs — at lab scale that is
  often less work than a migration.

## Layout

```
install/
  bootstrap.sh                  control node build (Ubuntu + RHEL)
  install_wazuh.sh              agent-based vuln detection
  install_greenbone.sh          network-based vuln scanning
  make_ca.sh                    private CA for WinRM certs (no AD CS needed)
  Bootstrap-WindowsTarget.ps1   run once per Windows host
ansible/
  inventory/hosts.yml           hosts, grouped into rings
  group_vars/all.yml            shared paths, patch source
  group_vars/windows.yml        connection (NTLM/HTTPS) + patch policy
  group_vars/windows_vault.yml.example  what to put in the encrypted vault
  files/Get-PendingUpdates.ps1  read-only WUA scanner
  templates/rings.json.j2       host to ring mapping
  playbooks/
    patch_scan.yml              discovery, safe to run hourly
    patch_apply.yml             approval-gated installation
    tasks/snapshot_nutanix.yml  pre-patch AHV snapshot (Prism v2 API)
    deploy_wazuh_agent.yml      agent rollout
sql/schema.sql                  tables, views, grafana_ro role
scripts/
  load_scan.py                  scan JSON to PostgreSQL
  record_events.py              win_updates results to audit trail
  approve.sh                    the approval gate CLI
grafana/patch-dashboard.json    auto-provisioned dashboard
systemd/                        scan timer + canary apply window
```

---

## Hardening checklist

- [ ] `svc_patchmgr` denied console/RDP logon (bootstrap script does this via secedit — verify with `whoami /priv` style audit or `secedit /export`)
- [ ] Password only in `windows_vault.yml` (encrypted) — never in plain group_vars; `/etc/patchmgr/vault_pass` mode 0600
- [ ] WinRM HTTP listener removed, Basic auth disabled, certs from `make_ca.sh`, validation ON (`ignore` is for the lab only)
- [ ] `/etc/patchmgr/ca/ca.key` mode 600 — whoever holds the CA key can mint a cert for any host name
- [ ] Windows firewall rule scoped to the control node IP only
- [ ] Grafana admin password changed from the default on first login
- [ ] `/etc/patchmgr/patchmgr.env` mode 0600
- [ ] Control node not internet-exposed; Grafana behind SSO or a reverse proxy with TLS
- [ ] PostgreSQL backed up — `patch_approvals` is your audit record of who
      approved what and when, and that is the artefact an auditor will ask for
