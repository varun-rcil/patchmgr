#!/usr/bin/env bash
#
# bootstrap.sh - build the patchmgr control node on Ubuntu 24.04 or RHEL 9.
#
#   sudo ./bootstrap.sh --pg-password 'strong-secret'
#
# Installs: Ansible + pywinrm (NTLM for workgroup targets; add --realm REALM
# only if you have AD and want Kerberos), PostgreSQL, Grafana, and the patchmgr
# scripts/timers. Wazuh and Greenbone are separate scripts (install_wazuh.sh,
# install_greenbone.sh) because they are optional and heavy.

set -euo pipefail

PG_PASSWORD=""
GRAFANA_PASSWORD=""
KRB_REALM=""   # only set via --realm if you have AD; workgroup mode needs none
INSTALL_ROOT=/opt/patchmgr
DATA_ROOT=/var/lib/patchmgr

usage() { sed -n '2,12p' "$0"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pg-password)      PG_PASSWORD="$2"; shift 2 ;;
    --grafana-password) GRAFANA_PASSWORD="$2"; shift 2 ;;
    --realm)            KRB_REALM="$2"; shift 2 ;;
    -h|--help)          usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n "$PG_PASSWORD" ]] || { echo "--pg-password is required" >&2; exit 1; }
[[ -n "$GRAFANA_PASSWORD" ]] || GRAFANA_PASSWORD="$(openssl rand -base64 24)"

# --- Detect distro ----------------------------------------------------------
if [[ -f /etc/os-release ]]; then . /etc/os-release; else echo "no /etc/os-release" >&2; exit 1; fi
case "$ID" in
  ubuntu|debian) FAMILY=deb ;;
  rhel|rocky|almalinux|centos|fedora) FAMILY=rpm ;;
  *) echo "unsupported distro: $ID" >&2; exit 1 ;;
esac
echo "==> Detected $PRETTY_NAME (family: $FAMILY)"

# --- Packages ---------------------------------------------------------------
echo "==> Installing base packages"
if [[ $FAMILY == deb ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    python3 python3-venv python3-dev python3-pip \
    build-essential libkrb5-dev krb5-user libpq-dev \
    postgresql postgresql-contrib \
    git curl gnupg ca-certificates jq chrony ufw
else
  dnf install -y -q \
    python3 python3-devel python3-pip gcc \
    krb5-devel krb5-workstation libpq-devel \
    postgresql-server postgresql-contrib \
    git curl jq chrony firewalld
  [[ -f /var/lib/pgsql/data/PG_VERSION ]] || postgresql-setup --initdb
  systemctl enable --now postgresql firewalld
fi

# Kerberos against a Windows AD is time-sensitive: >5 min skew = auth failure.
systemctl enable --now chronyd 2>/dev/null || systemctl enable --now chrony

# --- Python venv ------------------------------------------------------------
echo "==> Creating Python environment at $INSTALL_ROOT/venv"
mkdir -p "$INSTALL_ROOT" "$DATA_ROOT/scans" /var/log/patchmgr /etc/patchmgr
python3 -m venv "$INSTALL_ROOT/venv"
"$INSTALL_ROOT/venv/bin/pip" install --quiet --upgrade pip wheel
"$INSTALL_ROOT/venv/bin/pip" install --quiet \
  "ansible-core>=2.16" \
  "pywinrm[kerberos]>=0.4.3" \
  "requests-credssp" \
  "psycopg2-binary>=2.9" \
  "pyyaml" "jmespath"

echo "==> Installing Ansible collections"
"$INSTALL_ROOT/venv/bin/ansible-galaxy" collection install -f \
  ansible.windows community.windows community.general community.postgresql chocolatey.chocolatey \
  -p "$INSTALL_ROOT/collections"

# --- PostgreSQL -------------------------------------------------------------
echo "==> Configuring PostgreSQL"
systemctl enable --now postgresql

sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='patchmgr'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE patchmgr LOGIN PASSWORD '${PG_PASSWORD}'"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='patchmgr'" | grep -q 1 || \
  sudo -u postgres createdb -O patchmgr patchmgr

sudo -u postgres psql -d patchmgr -f "$(dirname "$0")/../sql/schema.sql"
sudo -u postgres psql -d patchmgr -c \
  "ALTER ROLE grafana_ro PASSWORD '${GRAFANA_PASSWORD}'"

# --- Credentials file -------------------------------------------------------
cat > /etc/patchmgr/patchmgr.env <<EOF
# Sourced by systemd units and by operators. Root-readable only.
PATCHMGR_DSN=postgresql://patchmgr:${PG_PASSWORD}@localhost:5432/patchmgr
ANSIBLE_CONFIG=${INSTALL_ROOT}/ansible/ansible.cfg
ANSIBLE_COLLECTIONS_PATH=${INSTALL_ROOT}/collections
PATH=${INSTALL_ROOT}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF
chmod 0600 /etc/patchmgr/patchmgr.env

# Vault password file for unattended systemd runs (workgroup mode keeps the
# Windows local-admin password in an ansible-vault file; this decrypts it).
if [[ ! -s /etc/patchmgr/vault_pass ]]; then
  touch /etc/patchmgr/vault_pass
  chmod 0600 /etc/patchmgr/vault_pass
fi
echo "ANSIBLE_VAULT_PASSWORD_FILE=/etc/patchmgr/vault_pass" >> /etc/patchmgr/patchmgr.env

# SSH keypair for the Linux targets (bootstrap-linux-target.sh installs the pub half)
if [[ ! -f /etc/patchmgr/ssh/id_ed25519 ]]; then
  install -d -m 700 /etc/patchmgr/ssh
  ssh-keygen -t ed25519 -N "" -C "patchmgr@$(hostname -s)" -f /etc/patchmgr/ssh/id_ed25519 -q
  echo "==> SSH key generated: /etc/patchmgr/ssh/id_ed25519.pub (feed to bootstrap-linux-target.sh --pubkey)"
fi

# --- Kerberos (only with --realm, i.e. only if you have AD) ----------------
if [[ -n "$KRB_REALM" ]]; then
  echo "==> Writing /etc/krb5.conf for realm $KRB_REALM"
  REALM_LOWER="$(echo "$KRB_REALM" | tr '[:upper:]' '[:lower:]')"
  cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${KRB_REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
    ticket_lifetime = 24h
    forwardable = true

[domain_realm]
    .${REALM_LOWER} = ${KRB_REALM}
    ${REALM_LOWER} = ${KRB_REALM}
EOF
else
  echo "==> No --realm given: workgroup mode, NTLM over HTTPS. Skipping krb5.conf."
fi

# --- Grafana ----------------------------------------------------------------
echo "==> Installing Grafana"
if [[ $FAMILY == deb ]]; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
  echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
    > /etc/apt/sources.list.d/grafana.list
  apt-get update -qq && apt-get install -y -qq grafana
else
  cat > /etc/yum.repos.d/grafana.repo <<'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
EOF
  dnf install -y -q grafana
fi

echo "==> Provisioning Grafana datasource and dashboard"
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards

cat > /etc/grafana/provisioning/datasources/patchmgr.yml <<EOF
apiVersion: 1
datasources:
  - name: patchmgr
    type: postgres
    access: proxy
    url: localhost:5432
    database: patchmgr
    user: grafana_ro
    isDefault: true
    jsonData:
      sslmode: disable
      postgresVersion: 1500
      timescaledb: false
    secureJsonData:
      password: '${GRAFANA_PASSWORD}'
EOF
chmod 0640 /etc/grafana/provisioning/datasources/patchmgr.yml

cat > /etc/grafana/provisioning/dashboards/patchmgr.yml <<'EOF'
apiVersion: 1
providers:
  - name: patchmgr
    orgId: 1
    folder: 'Patch Management'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
EOF

cp "$(dirname "$0")/../grafana/patch-dashboard.json" /var/lib/grafana/dashboards/
chown -R grafana:grafana /var/lib/grafana/dashboards /etc/grafana/provisioning
systemctl enable --now grafana-server

# --- Deploy playbooks and scripts -------------------------------------------
echo "==> Installing playbooks and scripts"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
cp -r "$SRC/ansible" "$INSTALL_ROOT/"
cp -r "$SRC/scripts" "$INSTALL_ROOT/"
cp -r "$SRC/sql"     "$INSTALL_ROOT/"
chmod +x "$INSTALL_ROOT"/scripts/*.py "$INSTALL_ROOT"/scripts/*.sh 2>/dev/null || true

cat > "$INSTALL_ROOT/ansible/ansible.cfg" <<EOF
[defaults]
inventory = ${INSTALL_ROOT}/ansible/inventory/hosts.yml
collections_path = ${INSTALL_ROOT}/collections
host_key_checking = False
stdout_callback = yaml
callbacks_enabled = profile_tasks
forks = 25
timeout = 60
log_path = /var/log/patchmgr/ansible.log
retry_files_enabled = False
interpreter_python = auto_silent

[persistent_connection]
command_timeout = 900
connect_timeout = 120
EOF

cp "$SRC"/systemd/*.service "$SRC"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now patchmgr-scan.timer

# --- Firewall ---------------------------------------------------------------
echo "==> Firewall"
if [[ $FAMILY == deb ]]; then
  ufw allow 3000/tcp comment 'Grafana'  || true
else
  firewall-cmd --permanent --add-port=3000/tcp && firewall-cmd --reload || true
fi

cat <<EOF

============================================================
 patchmgr control node ready
============================================================
 Grafana      http://$(hostname -I | awk '{print $1}'):3000   (admin/admin on first login)
 Database     postgresql://patchmgr@localhost/patchmgr
 Credentials  /etc/patchmgr/patchmgr.env  (root only)
 Playbooks    ${INSTALL_ROOT}/ansible
 Scan timer   systemctl status patchmgr-scan.timer

 Next steps (workgroup / no-AD flow)
   1. Edit ${INSTALL_ROOT}/ansible/inventory/hosts.yml - names + ansible_host IPs
   2. ${INSTALL_ROOT}/../install/make_ca.sh init
      make_ca.sh host <NAME> --ip <addr>     # one per Windows target
      make_ca.sh trust
   3. On each Windows box (elevated PowerShell):
        Bootstrap-WindowsTarget.ps1 -ControlNodeIP <this-vm-ip> \
          -PfxPath .\<NAME>.pfx -PfxPassword <printed> \
          -CreateServiceAccount -ServiceAccountPassword '<pick-one>'
   4. Vault that password:
        ansible-vault create ${INSTALL_ROOT}/ansible/group_vars/windows_vault.yml
        echo '<vault-password>' > /etc/patchmgr/vault_pass
   5. cd ${INSTALL_ROOT}/ansible && source /etc/patchmgr/patchmgr.env
      ansible windows -m ansible.windows.win_ping
   6. ansible-playbook playbooks/patch_scan.yml
============================================================
EOF
