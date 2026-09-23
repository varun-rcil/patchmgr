#!/usr/bin/env bash
#
# bootstrap-linux-target.sh - one-time preparation of a RHEL-family (7-10) or
# Debian-family target for patchmgr. Run ON THE TARGET as root:
#
#   sudo ./bootstrap-linux-target.sh --pubkey "ssh-ed25519 AAAA... patchmgr"
#
# Creates the svc_patchmgr user (key-only, no password, full sudo - patching is
# root work; blast radius is limited by key custody, not by sudo rules that a
# package manager could not honour anyway), installs python3 where the distro
# does not guarantee it, and the reboot-detection tooling.

set -euo pipefail

PUBKEY=""
SVC_USER="svc_patchmgr"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --user)   SVC_USER="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n "$PUBKEY" ]] || { echo "--pubkey 'ssh-ed25519 ...' is required (control node: cat /etc/patchmgr/ssh/id_ed25519.pub)" >&2; exit 1; }

. /etc/os-release
LIKE="${ID} ${ID_LIKE:-}"

echo "==> $PRETTY_NAME"

case "$LIKE" in
  *rhel*|*centos*|*fedora*|*rocky*|*almalinux*|*ol*)
    PKG="yum"; command -v dnf >/dev/null && PKG="dnf"
    # ansible-core >= 2.17 cannot target python2; RHEL 7.7+ carries python3 in base.
    command -v python3 >/dev/null || $PKG install -y python3
    # needs-restarting lives in yum-utils (EL7) / dnf-utils (EL8+, provided by yum-utils too)
    command -v needs-restarting >/dev/null || $PKG install -y yum-utils || $PKG install -y dnf-utils
    if [[ "${VERSION_ID%%.*}" == "7" ]]; then
      echo "NOTE: RHEL/CentOS 7 is past end-of-maintenance."
      echo "      RHEL 7 receives new errata only with an ELS subscription;"
      echo "      CentOS 7 receives none at all, and its base repos never carried"
      echo "      updateinfo metadata - expect severity 'Unspecified' on that box."
    fi
    ;;
  *debian*|*ubuntu*)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # python3-apt is the scanner's data source; update-notifier-common writes
    # /var/run/reboot-required, which some minimal images lack.
    apt-get install -y -qq python3 python3-apt update-notifier-common
    ;;
  *)
    echo "unsupported distribution: $ID" >&2; exit 1 ;;
esac

echo "==> Creating $SVC_USER (no password, key-only)"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --comment "patchmgr automation" "$SVC_USER"
fi
passwd -l "$SVC_USER" >/dev/null 2>&1 || true

install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "/home/$SVC_USER/.ssh"
grep -qF "$PUBKEY" "/home/$SVC_USER/.ssh/authorized_keys" 2>/dev/null || \
  echo "$PUBKEY" >> "/home/$SVC_USER/.ssh/authorized_keys"
chmod 600 "/home/$SVC_USER/.ssh/authorized_keys"
chown "$SVC_USER:$SVC_USER" "/home/$SVC_USER/.ssh/authorized_keys"

echo "==> Sudo"
cat > "/etc/sudoers.d/90-$SVC_USER" <<SUDO
# patchmgr automation. NOPASSWD because runs are unattended; key custody on the
# control node is the actual control. Defaults preserved: no requiretty issues.
$SVC_USER ALL=(ALL) NOPASSWD:ALL
Defaults:$SVC_USER !requiretty
SUDO
chmod 440 "/etc/sudoers.d/90-$SVC_USER"
visudo -cf "/etc/sudoers.d/90-$SVC_USER" >/dev/null

echo
echo "Done. From the control node:"
echo "  ansible $(hostname -s) -m ansible.builtin.ping"
