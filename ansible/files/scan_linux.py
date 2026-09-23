#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_linux.py - pending-update discovery for RHEL-family (7-10, incl. CentOS,
Rocky, Alma, Oracle) and Debian-family (Ubuntu, Debian) hosts.

Emits the SAME JSON contract as Get-PendingUpdates.ps1 so one loader and one
dashboard serve every OS. READ ONLY - installs nothing.

Patch identity differs per family and the whole pipeline keys off it:
  RHEL family   patch_id = errata advisory (RHSA-2026:1234, ALSA-..., RLSA-...)
                one advisory covers several packages -> listed in `components`.
                Severity comes straight from the errata metadata.
  Debian family patch_id = binary package name. apt has no advisory objects to
                key on; severity is 'Security' when the candidate version comes
                from a -security pocket or ESM, else 'Unspecified'.
  No-errata RPM updates (classic CentOS 7 base repos ship no updateinfo!)
                fall back to patch_id = package name, severity 'Unspecified'.

Python 3.6 compatible on purpose: that is what `yum install python3` gives you
on RHEL 7. Run as root (readonly, but repo metadata refresh needs it).
"""

import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import sys

SEC_SEVERITIES = ("Critical", "Important", "Moderate", "Low")


def sh(cmd, ok_codes=(0,), timeout=900):
    """Run a command, return (rc, stdout). Never raises on non-zero rc."""
    try:
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "", "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        p.kill()
        return 124, "", "timeout: %s" % " ".join(cmd)


def read_os_release():
    d = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    d[k] = v.strip().strip('"').strip("'")
    except IOError:
        pass
    return d


def detect_family(osr):
    ids = " ".join([osr.get("ID", ""), osr.get("ID_LIKE", "")]).lower()
    if any(t in ids for t in ("rhel", "centos", "fedora", "rocky", "almalinux", "ol")):
        return "rhel"
    if any(t in ids for t in ("debian", "ubuntu")):
        return "debian"
    return "unknown"


def boot_time_iso():
    try:
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
        bt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=up)
        return bt.replace(microsecond=0, tzinfo=None).isoformat() + "Z"
    except (IOError, ValueError):
        return None


def kernel():
    rc, out, _ = sh(["uname", "-r"])
    return out.strip() if rc == 0 else None


# ---------------------------------------------------------------------------
# RHEL family
# ---------------------------------------------------------------------------
LIST_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")
ADVISORY_RE = re.compile(r"^[A-Z]{2,6}-\d{4}:\d+$")   # RHSA-2026:0123, ALSA-, RLSA-, ELSA- (ELSA uses ELSA-2026-0123... tolerated below)
ADVISORY_LOOSE_RE = re.compile(r"^[A-Z]{2,6}[A-Z]?-\d{4}[:-]\d+")


def parse_updateinfo_list(text):
    """
    'updateinfo list' lines:  ADVISORY  CLASS  PKG-VER.ARCH
      RHSA-2026:0123  Important/Sec.  openssl-libs-1:3.0.7-27.el9.x86_64
      RHBA-2026:0456  bugfix          bash-5.1.8-9.el9.x86_64
    Returns {advisory: {"severity": .., "type": .., "packages": set()}}
    """
    advisories = {}
    for line in text.splitlines():
        line = line.strip()
        m = LIST_RE.match(line)
        if not m:
            continue
        adv, klass, pkg = m.groups()
        if not ADVISORY_LOOSE_RE.match(adv):
            continue  # header/noise
        sev, typ = "Unspecified", klass.lower()
        if "/Sec" in klass:
            sev = klass.split("/", 1)[0].capitalize()
            if sev not in SEC_SEVERITIES:
                sev = "Unspecified"
            typ = "security"
        entry = advisories.setdefault(adv, {"severity": sev, "type": typ, "packages": set()})
        entry["packages"].add(pkg)
        # A mixed listing keeps the highest severity seen for the advisory.
        order = {"Unspecified": 0, "Low": 1, "Moderate": 2, "Important": 3, "Critical": 4}
        if order.get(sev, 0) > order.get(entry["severity"], 0):
            entry["severity"] = sev
    return advisories


# dnf right-aligns keys: short ones like "CVEs" sit behind up to ~10 spaces.
INFO_KEY_RE = re.compile(r"^\s{0,12}([A-Za-z][A-Za-z ]{1,15}?)\s*:\s*(.*)$")
INFO_CONT_RE = re.compile(r"^\s+:\s*(.*)$")


def parse_updateinfo_info(text):
    """
    'updateinfo info' blocks:
      ===============================================
        Important: openssl security update
      ===============================================
        Update ID: RHSA-2026:0123
             Type: security
          Updated: 2026-08-12 00:00:00
             CVEs: CVE-2026-1111
                 : CVE-2026-2222
      Description: ...
    Returns {advisory: {"title":.., "cves":[..], "issued": iso-or-None}}
    """
    out = {}
    cur_id, cur_key = None, None
    expect_title = False
    just_titled = False     # the banner right under a title CLOSES it, not opens a block
    buf = {}

    def flush():
        nonlocal cur_id, buf
        if cur_id:
            out[cur_id] = {
                "title": buf.get("_title") or cur_id,
                "cves": buf.get("cves", []),
                "issued": buf.get("issued"),
            }
        cur_id, buf = None, {}

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if set(line.strip()) == {"="} and line.strip():
            if just_titled:
                just_titled = False        # closing banner: title already captured
            else:
                expect_title = True        # opening banner: next line is the title
            continue
        if expect_title and line.strip():
            flush()
            buf["_title"] = line.strip()
            expect_title = False
            just_titled = True
            cur_key = None
            continue

        m = INFO_KEY_RE.match(line)
        if m:
            just_titled = False   # keys have started; the next banner opens a new block
            key, val = m.group(1).strip().lower(), m.group(2).strip()
            cur_key = key
            if key == "update id":
                cur_id = val
            elif key == "cves" and val:
                buf.setdefault("cves", []).append(val)
            elif key in ("updated", "issued") and val:
                buf.setdefault("issued", val.split()[0])
            continue

        c = INFO_CONT_RE.match(line)
        if c and cur_key == "cves" and c.group(1).strip():
            buf.setdefault("cves", []).append(c.group(1).strip())

    flush()
    return out


def advisory_url(adv):
    if adv.startswith("RHSA") or adv.startswith("RHBA") or adv.startswith("RHEA"):
        return "https://access.redhat.com/errata/" + adv
    if adv.startswith("ALSA") or adv.startswith("ALBA") or adv.startswith("ALEA"):
        return "https://errata.almalinux.org/"
    if adv.startswith("RLSA") or adv.startswith("RLBA"):
        return "https://errata.rockylinux.org/" + adv
    return None


def scan_rhel(result):
    mgr = "dnf" if shutil.which("dnf") else "yum"
    result["notes"].append("package manager: %s" % mgr)

    # dnf: 'updateinfo list --all'; yum(7): 'updateinfo list all'. Try both.
    rc, listing, err = sh([mgr, "-q", "updateinfo", "list", "--all"])
    if rc != 0:
        rc, listing, err = sh([mgr, "-q", "updateinfo", "list", "all"])
    if rc != 0:
        result["notes"].append("updateinfo list failed rc=%d: %s" % (rc, err.strip()[:200]))
        listing = ""
    advisories = parse_updateinfo_list(listing)

    rc, info, _ = sh([mgr, "-q", "updateinfo", "info", "--all"])
    if rc != 0:
        rc, info, _ = sh([mgr, "-q", "updateinfo", "info", "all"])
    details = parse_updateinfo_info(info) if rc == 0 else {}

    covered_pkgs = set()
    for adv, meta in sorted(advisories.items()):
        det = details.get(adv, {})
        pkgs = sorted(meta["packages"])
        covered_pkgs.update(pkgs)
        result["updates"].append({
            "patch_id": adv,
            "title": det.get("title") or ("%s (%d packages)" % (adv, len(pkgs))),
            "severity": meta["severity"],
            "categories": [meta["type"]],
            "components": pkgs,
            "cve_ids": det.get("cves", []),
            "size_bytes": 0,          # updateinfo does not carry sizes; not worth N repoqueries
            "is_downloaded": False,
            "reboot_required": any(p.startswith(("kernel", "glibc", "systemd", "linux-firmware", "openssl-libs")) for p in pkgs),
            "support_url": advisory_url(adv),
            "release_date": det.get("issued"),
        })

    # Updates with NO errata coverage - the CentOS 7 base-repo situation, or any
    # third-party repo without updateinfo. Without this they would be invisible,
    # and invisible is worse than unrated.
    rc, chk, _ = sh([mgr, "-q", "check-update"], ok_codes=(0, 100))
    if rc in (0, 100):
        for line in chk.splitlines():
            parts = line.split()
            if len(parts) != 3 or "." not in parts[0]:
                continue
            pkg_arch, ver, repo = parts
            if repo.startswith("Obsoleting") or any(pkg_arch in c or c.startswith(pkg_arch.rsplit(".", 1)[0]) for c in covered_pkgs):
                continue
            name = pkg_arch.rsplit(".", 1)[0]
            result["updates"].append({
                "patch_id": name,
                "title": "%s -> %s (%s, no errata metadata)" % (name, ver, repo),
                "severity": "Unspecified",
                "categories": ["no-errata"],
                "components": [pkg_arch],
                "cve_ids": [],
                "size_bytes": 0,
                "is_downloaded": False,
                "reboot_required": name.startswith(("kernel", "glibc", "systemd")),
                "support_url": None,
                "release_date": None,
            })
        if rc == 100 and not advisories:
            result["notes"].append(
                "updates exist but no errata metadata in the enabled repos "
                "(classic CentOS base repos). Severity cannot be determined locally."
            )

    # Reboot needed? needs-restarting -r: rc 0 = no, 1 = yes (yum-utils / dnf-utils).
    reasons = []
    nr = shutil.which("needs-restarting")
    if nr:
        rc, out, _ = sh([nr, "-r"], ok_codes=(0, 1))
        if rc == 1:
            reasons = [l.strip("* ").strip() for l in out.splitlines() if l.strip().startswith("*")] or ["needs-restarting"]
    else:
        result["notes"].append("needs-restarting not installed (yum-utils/dnf-utils); using kernel comparison only")
        rc, latest, _ = sh(["rpm", "-q", "--last", "kernel"])
        if rc == 0 and latest:
            newest = latest.splitlines()[0].split()[0].replace("kernel-", "")
            if kernel() and newest not in kernel():
                reasons = ["kernel %s installed, running %s" % (newest, kernel())]
    result["reboot"] = {"pending": bool(reasons), "reasons": reasons}


# ---------------------------------------------------------------------------
# Debian family
# ---------------------------------------------------------------------------
def scan_debian(result):
    try:
        import apt  # python3-apt
    except ImportError:
        result["scan_error"] = "python3-apt is not installed (apt-get install python3-apt)"
        return

    cache = apt.Cache()
    try:
        cache.update()          # needs root; metadata freshness is the point
        cache.open(None)
    except Exception as e:      # noqa: BLE001 - stale metadata beats no scan
        result["notes"].append("apt cache update failed (%s); using existing metadata" % e)

    for pkg in cache:
        if not pkg.is_upgradable:
            continue
        cand = pkg.candidate
        cur = pkg.installed
        origins = cand.origins or []
        pockets = sorted({(o.archive or "") for o in origins if o.archive})
        labels = sorted({(o.origin or "") for o in origins if o.origin})
        is_sec = any(a.endswith("-security") for a in pockets) or \
                 any(o in ("UbuntuESM", "UbuntuESMApps") for o in labels)
        is_esm = any(o.startswith("UbuntuESM") for o in labels)

        cats = ["security" if is_sec else "updates"]
        if is_esm:
            cats.append("esm")
        result["updates"].append({
            "patch_id": pkg.name,
            "title": "%s %s -> %s [%s]" % (
                pkg.name,
                cur.version if cur else "?",
                cand.version,
                ",".join(pockets or labels) or "unknown",
            ),
            "severity": "Security" if is_sec else "Unspecified",
            "categories": cats,
            "components": [pkg.name + "=" + cand.version],
            "cve_ids": [],   # CVE mapping needs USN/OVAL data; Wazuh covers this side
            "size_bytes": int(cand.size or 0),
            "is_downloaded": False,
            "reboot_required": pkg.name.startswith(("linux-image", "linux-generic", "libc6", "systemd")),
            "support_url": "https://launchpad.net/ubuntu/+source/%s" % cand.source_name,
            "release_date": None,
        })

    reasons = []
    if os.path.exists("/var/run/reboot-required"):
        reasons = ["reboot-required"]
        try:
            with open("/var/run/reboot-required.pkgs") as f:
                reasons = sorted({l.strip() for l in f if l.strip()}) or reasons
        except IOError:
            pass
    result["reboot"] = {"pending": bool(reasons), "reasons": reasons}


# ---------------------------------------------------------------------------
def main():
    osr = read_os_release()
    family = detect_family(osr)

    result = {
        "hostname": socket.gethostname().split(".")[0],
        "fqdn": socket.getfqdn(),
        "scanned_at_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None).isoformat() + "Z",
        "source": "os-repos",
        "os_family": family,
        "scan_ok": False,
        "scan_error": None,
        "os": {
            "product_name": osr.get("PRETTY_NAME") or osr.get("NAME") or "unknown",
            "display_version": osr.get("VERSION_ID"),
            "build": kernel(),
            "ubr": None,
            "install_date": None,
            "last_boot": boot_time_iso(),
        },
        "reboot": {"pending": False, "reasons": []},
        "updates": [],
        "installed_kbs": [],
        "notes": [],
    }

    try:
        if family == "rhel":
            scan_rhel(result)
        elif family == "debian":
            scan_debian(result)
        else:
            result["scan_error"] = "unsupported distribution: %s" % osr.get("ID", "?")
        if result["scan_error"] is None:
            result["scan_ok"] = True
    except Exception as e:  # noqa: BLE001 - the stub must still reach the loader
        result["scan_error"] = "%s: %s" % (type(e).__name__, e)

    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if result["scan_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
