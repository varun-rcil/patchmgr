<#
.SYNOPSIS
  Enumerates pending updates via the Windows Update Agent (WUA) COM API and emits JSON.

.DESCRIPTION
  ansible.windows.win_updates does not return MsrcSeverity, download size, or support URLs.
  This script talks to Microsoft.Update.Session directly so the dashboard can show severity
  and download footprint. It is READ ONLY - it never downloads or installs anything.

  Must run with an interactive/elevated token. Under Ansible use:
      become: true
      become_method: runas
      become_user: SYSTEM

.PARAMETER Source
  WindowsUpdate  - OS updates only (default WU service)
  MicrosoftUpdate- OS + other Microsoft products (Defender, Office, SQL...)
  WSUS           - use the configured managed server (Group Policy target)

.OUTPUTS
  Single JSON object on stdout.
#>
[CmdletBinding()]
param(
    [ValidateSet('WindowsUpdate', 'MicrosoftUpdate', 'WSUS')]
    [string]$Source = 'MicrosoftUpdate',

    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ssDefault=0 ssManagedServer=1 ssWindowsUpdate=2 ssOthers=3
$MICROSOFT_UPDATE_SERVICE_ID = '7971f918-a847-4430-9279-4a52d1efe18d'

function Get-OsPatchLevel {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $k = Get-ItemProperty -Path $cv
    # UBR is the authoritative patch level on Server 2022. Get-HotFix misses cumulative updates.
    [PSCustomObject]@{
        product_name    = $k.ProductName
        display_version = if ($k.PSObject.Properties.Name -contains 'DisplayVersion') { $k.DisplayVersion } else { $null }
        build           = "$($k.CurrentMajorVersionNumber).$($k.CurrentMinorVersionNumber).$($k.CurrentBuildNumber).$($k.UBR)"
        ubr             = $k.UBR
        install_date    = (Get-CimInstance Win32_OperatingSystem).InstallDate
        last_boot       = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
}

function Test-RebootPending {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'WindowsUpdate'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'ComponentBasedServicing'
    }
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pfro = Get-ItemProperty -Path $sm -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pfro) { $reasons += 'PendingFileRename' }
    $cn = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -ErrorAction SilentlyContinue
    if ($cn -and ($cn.PSObject.Properties.Name -contains 'JoinDomain')) { $reasons += 'DomainJoin' }

    [PSCustomObject]@{
        pending = ($reasons.Count -gt 0)
        reasons = $reasons
    }
}

function Get-InstalledHotfix {
    Get-CimInstance -ClassName Win32_QuickFixEngineering |
        Select-Object -Property @{n = 'kb'; e = { $_.HotFixID } },
                                @{n = 'description'; e = { $_.Description } },
                                @{n = 'installed_on'; e = { if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null } } }
}

$result = [ordered]@{
    hostname        = $env:COMPUTERNAME
    fqdn            = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    scanned_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
    source          = $Source
    scan_ok         = $false
    scan_error      = $null
    os              = $null
    reboot          = $null
    updates         = @()
    installed_kbs   = @()
    wua_version     = $null
}

try {
    $result.os = Get-OsPatchLevel
    $result.reboot = Test-RebootPending
    $result.installed_kbs = @(Get-InstalledHotfix)

    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'patchmgr-scanner'
    $result.wua_version = (New-Object -ComObject Microsoft.Update.AgentInfo).GetInfo('ProductVersionString')

    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $true

    switch ($Source) {
        'WindowsUpdate' { $searcher.ServerSelection = 2 }
        'WSUS'          { $searcher.ServerSelection = 1 }
        'MicrosoftUpdate' {
            $searcher.ServerSelection = 3
            $searcher.ServiceID = $MICROSOFT_UPDATE_SERVICE_ID
        }
    }

    # IsInstalled=0 -> not yet applied. IsHidden=0 -> not suppressed by an operator.
    $search = $searcher.Search('IsInstalled=0 and IsHidden=0 and Type=''Software''')

    foreach ($u in $search.Updates) {
        $kbs = @()
        foreach ($k in $u.KBArticleIDs) { $kbs += "KB$k" }

        $cats = @()
        foreach ($c in $u.Categories) { $cats += $c.Name }

        $cves = @()
        try { foreach ($c in $u.CveIDs) { $cves += $c } } catch { }

        $result.updates += [ordered]@{
            update_id       = $u.Identity.UpdateID
            revision        = $u.Identity.RevisionNumber
            title           = $u.Title
            kb              = $kbs
            msrc_severity   = if ($u.MsrcSeverity) { $u.MsrcSeverity } else { 'Unspecified' }
            categories      = $cats
            cve_ids         = $cves
            size_bytes      = [int64]$u.MaxDownloadSize
            is_downloaded   = [bool]$u.IsDownloaded
            is_mandatory    = [bool]$u.IsMandatory
            reboot_required = [bool]$u.RebootRequired
            support_url     = $u.SupportUrl
            release_date    = if ($u.LastDeploymentChangeTime) { $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } else { $null }
            eula_accepted   = [bool]$u.EulaAccepted
        }
    }

    $result.scan_ok = $true
}
catch {
    $result.scan_error = $_.Exception.Message
}
finally {
    # Release COM handles so repeated scans don't leak.
    foreach ($v in @('search', 'searcher', 'session')) {
        if (Get-Variable -Name $v -ErrorAction SilentlyContinue) {
            $obj = (Get-Variable -Name $v).Value
            if ($obj -is [__ComObject]) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($obj) }
        }
    }
}

# Depth 6 - Categories/KB arrays nest a few levels.
$result | ConvertTo-Json -Depth 6 -Compress
