<#
.SYNOPSIS
  One-time preparation of a Windows Server 2022 target for Ansible patch management.

.DESCRIPTION
  Enables WinRM over HTTPS with a real certificate, opens the firewall to the
  control node only, and disables the plaintext HTTP listener.

  Deploy via GPO startup script, MDT/Packer image, or run once per host as admin.

.PARAMETER ControlNodeIP
  IP or CIDR of the patchmgr VM. The firewall rule is scoped to this only.

.PARAMETER CertThumbprint
  Thumbprint of an existing server-auth certificate. With make_ca.sh, this is
  printed when the host cert is issued. Alternatively pass -PfxPath and the
  script imports it for you.

.PARAMETER PfxPath
  Path to a .pfx from make_ca.sh (or any CA). Imported into LocalMachine\My and
  used for the listener. Overrides -CertThumbprint.

.PARAMETER CreateServiceAccount
  Workgroup mode: create a LOCAL administrator for Ansible (default name
  svc_patchmgr), enable remote admin for local accounts
  (LocalAccountTokenFilterPolicy), and deny it interactive + RDP logon so the
  credential is useful for WinRM and nothing else.

.EXAMPLE
  # Workgroup / no-AD deployment with a make_ca.sh certificate:
  Import-PfxCertificate -FilePath .\WIN2022-CANARY1.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString 'pfxpass' -AsPlainText -Force)
  .\Bootstrap-WindowsTarget.ps1 -ControlNodeIP 192.168.100.10 -CertThumbprint AB12... -CreateServiceAccount -ServiceAccountPassword 'S0me-L0ng-Passphrase!'

.EXAMPLE
  # Same, letting the script do the import:
  .\Bootstrap-WindowsTarget.ps1 -ControlNodeIP 192.168.100.10 -PfxPath .\WIN2022-CANARY1.pfx -PfxPassword 'pfxpass' -CreateServiceAccount -ServiceAccountPassword 'S0me-L0ng-Passphrase!'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ControlNodeIP,
    [string]$CertThumbprint,
    [string]$PfxPath,
    [string]$PfxPassword,
    [switch]$CreateServiceAccount,
    [string]$ServiceAccountName = 'svc_patchmgr',
    [string]$ServiceAccountPassword,
    [switch]$AllowSelfSigned
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell session.'
}

Write-Host '== Enabling WinRM ==' -ForegroundColor Cyan
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null

# --- Local service account (workgroup mode) --------------------------------
function Deny-InteractiveLogon {
    param([Parameter(Mandatory)][string]$AccountName)
    # No AD means no GPO, so user-rights assignments are done with secedit.
    $sid = (New-Object System.Security.Principal.NTAccount($AccountName)
           ).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $inf = Join-Path $env:TEMP 'patchmgr-ur.inf'
    $db  = Join-Path $env:TEMP 'patchmgr-ur.sdb'
    secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null

    $lines = [System.Collections.Generic.List[string]](Get-Content $inf)
    foreach ($right in 'SeDenyRemoteInteractiveLogonRight', 'SeDenyInteractiveLogonRight') {
        $idx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*$right\s*=") { $idx = $i; break }
        }
        if ($idx -ge 0) {
            if ($lines[$idx] -notmatch [regex]::Escape($sid)) {
                $lines[$idx] = $lines[$idx].TrimEnd() + ",*$sid"
            }
        }
        else {
            $sec = $lines.IndexOf('[Privilege Rights]')
            if ($sec -lt 0) { $lines.Add('[Privilege Rights]'); $sec = $lines.Count - 1 }
            $lines.Insert($sec + 1, "$right = *$sid")
        }
    }
    Set-Content -Path $inf -Value $lines -Encoding Unicode
    secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $inf, $db -ErrorAction SilentlyContinue
}

if ($CreateServiceAccount) {
    if (-not $ServiceAccountPassword) {
        throw '-ServiceAccountPassword is required with -CreateServiceAccount.'
    }
    Write-Host "== Creating local service account '$ServiceAccountName' ==" -ForegroundColor Cyan
    $secPw = ConvertTo-SecureString $ServiceAccountPassword -AsPlainText -Force

    if (Get-LocalUser -Name $ServiceAccountName -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $ServiceAccountName -Password $secPw
        Write-Host '   account exists, password updated'
    }
    else {
        New-LocalUser -Name $ServiceAccountName -Password $secPw `
            -PasswordNeverExpires -AccountNeverExpires `
            -Description 'patchmgr automation - WinRM only, no interactive logon' | Out-Null
    }

    if (-not (Get-LocalGroupMember -Group 'Administrators' -Member $ServiceAccountName -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group 'Administrators' -Member $ServiceAccountName
    }

    # Remote UAC filtering strips the admin token from LOCAL accounts connecting
    # over the network (built-in Administrator excepted). Without this, WinRM
    # auth succeeds but every privileged operation fails with Access Denied -
    # a genuinely confusing failure mode. It also gates authenticated SMB
    # scanning from Greenbone with the same account.
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force | Out-Null

    Deny-InteractiveLogon -AccountName $ServiceAccountName
    Write-Host '   admin over the network: yes; console/RDP logon: denied'
}

# --- Certificate -----------------------------------------------------------
if ($PfxPath) {
    Write-Host "== Importing certificate from $PfxPath ==" -ForegroundColor Cyan
    $pfxSec = if ($PfxPassword) { ConvertTo-SecureString $PfxPassword -AsPlainText -Force } else { $null }
    $imported = Import-PfxCertificate -FilePath $PfxPath `
        -CertStoreLocation Cert:\LocalMachine\My -Password $pfxSec
    $CertThumbprint = $imported.Thumbprint
    Write-Host "   thumbprint $CertThumbprint"
}

if (-not $CertThumbprint) {
    if (-not $AllowSelfSigned) {
        throw @'
No certificate supplied. Without AD CS, use install/make_ca.sh on the control
node: "make_ca.sh init" once, then "make_ca.sh host <NAME> --ip <addr>" per
target, and pass the printed thumbprint (or the .pfx via -PfxPath) to this
script. Self-signed certs mean the control node cannot verify the host, and
with NTLM that verification is the only server authentication you have.
Pass -AllowSelfSigned only for a throwaway lab.
'@
    }
    Write-Warning 'Generating a SELF-SIGNED certificate. Lab use only.'
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(3) `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    $CertThumbprint = $cert.Thumbprint
}

Write-Host "== Configuring HTTPS listener ($CertThumbprint) ==" -ForegroundColor Cyan
Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains 'Transport=HTTPS' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

New-Item -Path WSMan:\localhost\Listener `
    -Transport HTTPS -Address * -CertificateThumbPrint $CertThumbprint -Force | Out-Null

# --- Remove the plaintext listener ----------------------------------------
Write-Host '== Removing HTTP listener ==' -ForegroundColor Cyan
Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains 'Transport=HTTP' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- Auth: Kerberos on, Basic off -----------------------------------------
Write-Host '== Hardening authentication ==' -ForegroundColor Cyan
Set-Item WSMan:\localhost\Service\Auth\Basic       -Value $false
Set-Item WSMan:\localhost\Service\Auth\Kerberos    -Value $true
Set-Item WSMan:\localhost\Service\Auth\Negotiate   -Value $true
Set-Item WSMan:\localhost\Service\Auth\CredSSP     -Value $false   # not needed; we use runas SYSTEM
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

# Cumulative updates are memory-hungry to enumerate. The 150 MB default shell
# quota causes intermittent "out of memory" failures on WUA searches.
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 2048
Set-Item WSMan:\localhost\Plugin\microsoft.powershell\Quotas\MaxMemoryPerShellMB -Value 2048 -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Shell\MaxShellsPerUser -Value 30

# --- Firewall: control node only ------------------------------------------
Write-Host "== Firewall: allow 5986 from $ControlNodeIP only ==" -ForegroundColor Cyan
Get-NetFirewallRule -DisplayName 'patchmgr-WinRM-HTTPS' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule

New-NetFirewallRule -DisplayName 'patchmgr-WinRM-HTTPS' `
    -Direction Inbound -Protocol TCP -LocalPort 5986 `
    -RemoteAddress $ControlNodeIP -Action Allow -Profile Domain, Private | Out-Null

# Close the old HTTP rules if Enable-PSRemoting created them.
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue |
    Set-NetFirewallRule -Enabled False

# --- Windows Update service must be startable ------------------------------
Write-Host '== Checking Windows Update service ==' -ForegroundColor Cyan
$wuau = Get-Service -Name wuauserv
if ($wuau.StartType -eq 'Disabled') {
    Write-Warning 'wuauserv is Disabled. Setting to Manual so scans can run.'
    Set-Service -Name wuauserv -StartupType Manual
}

# Windows must not patch itself outside your windows, or the ring model and the
# dashboard both drift. With no AD there is no GPO, so set the policy registry
# key directly: AUOptions=3 (download automatically, never install on its own).
Write-Host '== Pinning Automatic Updates to download-only ==' -ForegroundColor Cyan
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if (-not (Test-Path $au)) { New-Item -Path $au -Force | Out-Null }
$existing = (Get-ItemProperty -Path $au -Name AUOptions -ErrorAction SilentlyContinue).AUOptions
if ($existing -in 4, 5) {
    Write-Warning "AUOptions was $existing (auto-install). Overriding to 3 so patchmgr owns the install schedule."
}
New-ItemProperty -Path $au -Name NoAutoUpdate  -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $au -Name AUOptions     -PropertyType DWord -Value 3 -Force | Out-Null
New-ItemProperty -Path $au -Name NoAutoRebootWithLoggedOnUsers -PropertyType DWord -Value 1 -Force | Out-Null

Write-Host ''
Write-Host 'Done. On the control node:' -ForegroundColor Green
Write-Host '  1. Put this host in ansible/inventory/hosts.yml with its ansible_host IP'
if ($CreateServiceAccount) {
    Write-Host "  2. Vault the password:  ansible-vault create group_vars/windows_vault.yml"
    Write-Host "     -> vault_patchmgr_password: <the -ServiceAccountPassword value>"
}
Write-Host "  3. ansible $env:COMPUTERNAME -m ansible.windows.win_ping"
Write-Host ''
Write-Host "Thumbprint: $CertThumbprint"
