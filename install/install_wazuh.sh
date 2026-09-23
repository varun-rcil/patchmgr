#!/usr/bin/env bash
#
# install_wazuh.sh - Wazuh single-node (manager + indexer + dashboard) on the
# patchmgr VM. This is the agent-based vulnerability detection layer.
#
# Wazuh's Vulnerability Detection module pulls CVE feeds (NVD + Microsoft's
# security update feed) and correlates them against the software and hotfix
# inventory each agent reports. That answers the question a patch count cannot:
# "which CVEs are actually exposed because KB5034129 is missing?"
#
#   sudo ./install_wazuh.sh

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# Check https://documentation.wazuh.com for the current release before running.
WAZUH_BRANCH="${WAZUH_BRANCH:-4.14}"

echo "==> Preflight"
MEM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
CPUS=$(nproc)
if (( MEM_GB < 8 )); then
  echo "WARNING: ${MEM_GB}GB RAM. The indexer needs 8GB minimum and will OOM below that." >&2
  read -rp "Continue anyway? [y/N] " a; [[ "$a" == [yY] ]] || exit 1
fi
(( CPUS >= 4 )) || echo "WARNING: ${CPUS} vCPU. 4 is the practical minimum." >&2

# The indexer is Elasticsearch-derived and will refuse to start without this.
echo "==> Setting vm.max_map_count"
sysctl -w vm.max_map_count=262144
grep -q 'vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

echo "==> Downloading the Wazuh installer (branch ${WAZUH_BRANCH})"
curl -fsSL "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh" -o /tmp/wazuh-install.sh
curl -fsSL "https://packages.wazuh.com/${WAZUH_BRANCH}/config.yml" -o /tmp/config.yml 2>/dev/null || true
chmod +x /tmp/wazuh-install.sh

echo "==> Installing all-in-one (this takes 10-20 minutes)"
bash /tmp/wazuh-install.sh -a -i

echo "==> Enabling Vulnerability Detection"
OSSEC=/var/ossec/etc/ossec.conf
cp "$OSSEC" "${OSSEC}.bak.$(date +%s)"

if grep -q '<vulnerability-detection>' "$OSSEC"; then
  # 4.8+ syntax. Ensure it is on.
  sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' "$OSSEC"
else
  echo "NOTE: no <vulnerability-detection> block found. Your Wazuh version may use" >&2
  echo "      the older <vulnerability-detector> syntax. Check the docs for your release." >&2
fi

# Syscollector feeds the correlation engine. Without hotfix collection there is
# no way to know which Windows patches are already applied.
python3 - "$OSSEC" <<'PYEOF'
import re, sys
p = sys.argv[1]
s = open(p).read()
block = """  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes>
  </wodle>
"""
if 'name="syscollector"' in s:
    s = re.sub(r'  <wodle name="syscollector">.*?</wodle>\n', block, s, flags=re.S)
else:
    s = s.replace('</ossec_config>', block + '</ossec_config>', 1)
open(p, 'w').write(s)
print("syscollector configured with hotfix collection enabled")
PYEOF

echo "==> Creating the windows-servers agent group"
/var/ossec/bin/agent_groups -a -g windows-servers -q 2>/dev/null || true

systemctl restart wazuh-manager
systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard

IP=$(hostname -I | awk '{print $1}')
cat <<MSG

============================================================
 Wazuh ready
============================================================
 Dashboard  https://${IP}          (credentials printed above by the installer;
                                    they are also in wazuh-install-files.tar)
 Manager    ${IP}:1514/tcp (events)  ${IP}:1515/tcp (enrolment)

 Deploy agents:
   ansible-playbook playbooks/deploy_wazuh_agent.yml -e wazuh_manager_ip=${IP}

 Then browse to  Vulnerability Detection  in the dashboard. The first CVE feed
 sync takes 10-30 minutes; the module reports nothing useful until it finishes.
============================================================
MSG
