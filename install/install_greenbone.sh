#!/usr/bin/env bash
#
# install_greenbone.sh - Greenbone Community Edition (OpenVAS) via containers.
#
# This is the genuinely open-source, unlimited-target vulnerability scanner.
# It complements Wazuh rather than duplicating it:
#
#   Wazuh     agent-based, inside-out. Knows installed software and hotfixes.
#             Excellent CVE-to-missing-patch correlation. Blind to network
#             exposure and misconfiguration.
#
#   Greenbone network-based, outside-in. Authenticated SMB scan of Server 2022
#             finds weak TLS, exposed services, bad SMB signing, registry
#             misconfigurations, and default credentials that no agent reports.
#
# Run both. They find different classes of problem.
#
#   sudo ./install_greenbone.sh

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

DEST=/opt/greenbone
COMPOSE_VERSION="${COMPOSE_VERSION:-22.4}"   # check greenbone.github.io/docs for current

echo "==> Preflight"
MEM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
(( MEM_GB >= 8 )) || echo "WARNING: ${MEM_GB}GB RAM. Feed sync alone wants 8GB." >&2
FREE_GB=$(df -BG --output=avail /opt | tail -1 | tr -dc '0-9')
(( FREE_GB >= 40 )) || { echo "Need ~40GB free on /opt for the vulnerability feeds, have ${FREE_GB}GB" >&2; exit 1; }

echo "==> Installing Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

echo "==> Fetching the Greenbone compose file"
mkdir -p "$DEST"
curl -fsSL "https://greenbone.github.io/docs/latest/_static/docker-compose-${COMPOSE_VERSION}.yml" \
  -o "$DEST/docker-compose.yml"

cd "$DEST"
echo "==> Pulling images"
docker compose pull

echo "==> Starting the stack"
docker compose up -d

echo "==> Waiting for gvmd to come up"
for i in $(seq 1 60); do
  if docker compose exec -T gvmd gvmd --get-users >/dev/null 2>&1; then break; fi
  sleep 10
done

echo "==> Creating the admin user"
ADMIN_PW="$(openssl rand -base64 20)"
docker compose exec -T gvmd gvmd --create-user=admin --password="$ADMIN_PW" 2>/dev/null \
  || docker compose exec -T gvmd gvmd --user=admin --new-password="$ADMIN_PW"

IP=$(hostname -I | awk '{print $1}')
cat > "$DEST/CREDENTIALS.txt" <<CRED
Greenbone admin password: ${ADMIN_PW}
CRED
chmod 0600 "$DEST/CREDENTIALS.txt"

cat <<MSG

============================================================
 Greenbone Community Edition ready
============================================================
 Web UI     http://${IP}:9392
 User       admin
 Password   ${ADMIN_PW}     (also in ${DEST}/CREDENTIALS.txt)

 IMPORTANT: the initial feed sync takes 30-60+ minutes. Scans launched before
 it completes will report almost nothing and give false confidence. Watch it:
   docker compose -f ${DEST}/docker-compose.yml logs -f gvmd

 For a useful Windows scan you need CREDENTIALED scanning:
   1. Configuration > Credentials > New. Type "Username + Password",
      an account in the local Administrators group on the targets.
   2. Scans > Targets > New. Add your Windows hosts, attach the SMB credential.
   3. Scans > Tasks > New. Scan Config "Full and fast".

 Uncredentialed scans of Server 2022 detect open ports and little else. The
 patch-level findings all come from the authenticated SMB checks.
============================================================
MSG
