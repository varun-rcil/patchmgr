#!/usr/bin/env bash
#
# make_ca.sh - a small private CA for WinRM HTTPS certificates.
#
# No AD means no AD CS, but that is not a reason to run with certificate
# validation off. This creates a CA once, issues one cert per Windows host, and
# hands you the exact commands to import it. The control node then validates
# every WinRM connection against the CA - which is what makes NTLM tolerable.
#
#   sudo ./make_ca.sh init
#   sudo ./make_ca.sh host WIN2022-CANARY1 --ip 192.168.100.101
#   sudo ./make_ca.sh host WIN2022-SQL1 --ip 192.168.100.121 --dns win2022-sql1.lab.local
#   sudo ./make_ca.sh trust        # installs ca.pem where group_vars expects it
#
# The SAN must contain whatever ansible_host is set to. If you connect by IP,
# the IP must be in the cert; a DNS-only cert will fail validation.

set -euo pipefail

CA_DIR=/etc/patchmgr/ca
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.pem"
DAYS_CA=3650
DAYS_HOST=1095

usage() { sed -n '3,17p' "$0"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root (keys live under /etc/patchmgr)" >&2; exit 1; }
[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  init)
    if [[ -f "$CA_KEY" ]]; then
      echo "CA already exists at $CA_DIR - refusing to overwrite it." >&2
      echo "Reissuing a CA invalidates every host cert already deployed." >&2
      exit 1
    fi
    mkdir -p "$CA_DIR"
    chmod 700 "$CA_DIR"
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
    chmod 600 "$CA_KEY"
    openssl req -x509 -new -key "$CA_KEY" -sha256 -days "$DAYS_CA" \
      -subj "/CN=patchmgr WinRM CA/O=patchmgr" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$CA_CRT"
    echo "CA created: $CA_CRT (valid $((DAYS_CA/365)) years)"
    echo "Next: $0 host <NAME> --ip <addr>   for each Windows target"
    ;;

  host)
    [[ $# -ge 1 ]] || { echo "usage: $0 host <NAME> [--ip A.B.C.D]... [--dns fqdn]..." >&2; exit 1; }
    [[ -f "$CA_KEY" ]] || { echo "no CA yet - run: $0 init" >&2; exit 1; }
    name="$1"; shift
    sans=("DNS:$name")
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --ip)  sans+=("IP:$2");  shift 2 ;;
        --dns) sans+=("DNS:$2"); shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
      esac
    done
    san_line=$(IFS=,; echo "${sans[*]}")

    out="$CA_DIR/hosts/$name"
    mkdir -p "$out"

    openssl genrsa -out "$out/$name.key" 2048 2>/dev/null
    openssl req -new -key "$out/$name.key" -subj "/CN=$name" -out "$out/$name.csr"

    cat > "$out/$name.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san_line
EXT

    openssl x509 -req -in "$out/$name.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
      -CAcreateserial -days "$DAYS_HOST" -sha256 \
      -extfile "$out/$name.ext" -out "$out/$name.crt" 2>/dev/null

    pfx_pass="$(openssl rand -base64 15)"
    openssl pkcs12 -export \
      -inkey "$out/$name.key" -in "$out/$name.crt" -certfile "$CA_CRT" \
      -name "patchmgr WinRM $name" \
      -passout "pass:$pfx_pass" \
      -out "$out/$name.pfx"
    echo "$pfx_pass" > "$out/$name.pfx.pass"
    chmod 600 "$out/$name.key" "$out/$name.pfx" "$out/$name.pfx.pass"

    # Windows shows the SHA1 fingerprint, uppercase, no colons, as "thumbprint".
    thumb=$(openssl x509 -in "$out/$name.crt" -noout -fingerprint -sha1 \
            | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')

    cat <<MSG

Issued: $out/$name.pfx
  SAN:        $san_line
  Valid:      $((DAYS_HOST/365)) years
  PFX pass:   $pfx_pass    (also in $name.pfx.pass)
  Thumbprint: $thumb

Copy the .pfx to the Windows host, then in an elevated PowerShell:

  Import-PfxCertificate -FilePath .\\$name.pfx ``
      -CertStoreLocation Cert:\\LocalMachine\\My ``
      -Password (ConvertTo-SecureString '$pfx_pass' -AsPlainText -Force)

  .\\Bootstrap-WindowsTarget.ps1 -ControlNodeIP <patchmgr-ip> ``
      -CertThumbprint $thumb ``
      -CreateServiceAccount -ServiceAccountPassword '<local-admin-password>'

(Or pass -PfxPath/-PfxPassword to the bootstrap script and it imports for you.)
MSG
    ;;

  trust)
    [[ -f "$CA_CRT" ]] || { echo "no CA yet - run: $0 init" >&2; exit 1; }
    install -m 644 "$CA_CRT" /etc/patchmgr/winrm-ca.pem
    echo "Installed /etc/patchmgr/winrm-ca.pem"
    echo "group_vars/windows.yml already points ansible_winrm_ca_trust_path at it."
    ;;

  *) usage ;;
esac
