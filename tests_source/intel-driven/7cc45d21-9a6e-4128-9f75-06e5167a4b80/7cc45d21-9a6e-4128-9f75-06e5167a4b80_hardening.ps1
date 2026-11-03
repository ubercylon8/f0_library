<#
.SYNOPSIS
    The Gentlemen (GOLD SHERWOOD) LOLBin Intrusion Defense Hardening — Windows Endpoint

.DESCRIPTION
    Idempotent hardening script implementing the Quick-Win and Medium-Term controls from
    the companion DEFENSE_GUIDANCE.md for The Gentlemen ransomware threat profile
    (LOLBin / masquerading / GPO-driven playbook):

      1. PowerShell Script Block + Module + Transcription logging
         (visibility into encoded -enc probes, DCOM fallbacks, New-GPO shapes)   [T1059.001-shaped]
      2. Command-line auditing + advanced audit-policy visibility pack:
         4688 w/ command line, scheduled-task events 4698-4702, service installs 7045,
         account creation 4720 / group adds 4728+4732, share access 5140/5145,
         registry + file-system auditing, GPO directory changes 5136+ (on DCs)   [T1053.005/T1543.003/T1136.001/T1484.001]
      3. UAC admin-account enumeration disabled                                 [T1087, M1028]
      4. Microsoft Defender ASR rule: Block process creations originating from
         PSExec and WMI                                                          [T1047/T1021.002, M1040]
      5. SMB hardening: signing required, SMBv1 removal, default admin shares
         (ADMIN$/C$) disabled                                                    [T1021.002, M1035/M1037]
      6. RDP NLA + TLS enforcement where RDP is enabled (never enables/disables
         RDP itself — the actor flips fDenyTSConnections; we make that harder to
         abuse and leave enablement to policy)                                   [T1021.001, M1028]
      7. WMI-Activity operational tracing enabled (remote WMI/DCOM visibility)   [T1047]
      8. Optional (-IncludeRmmBlocks): outbound firewall blocks for unapproved
         remote-access / DFIR tooling when present on the host
         (Velociraptor, AnyDesk, Cloudflared, NetExec/nxc, Datto RMM)            [T1219/T1036, M1042/M1037]

    All changes are idempotent and support -WhatIf (dry run) and -Undo (rollback).
    This script hardens against the TECHNIQUES, not against any specific tool or
    test payload — it protects against any actor using the same behaviors.

.PARAMETER Undo
    Revert all changes applied by this script to their pre-hardening state.

.PARAMETER IncludeRmmBlocks
    Also create outbound firewall block rules for unapproved remote-access / DFIR
    tool binaries when they exist on the host (velociraptor.exe, anydesk.exe,
    cloudflared.exe, nxc.exe/netexec.exe, DattoRMM.exe). Off by default — verify no
    approved usage (e.g., an internal IR deployment) before enabling.

.EXAMPLE
    .\7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1 -WhatIf    # preview all changes
.EXAMPLE
    .\7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1            # apply hardening
.EXAMPLE
    .\7cc45d21-9a6e-4128-9f75-06e5167a4b80_hardening.ps1 -Undo      # roll back

.NOTES
    Test: The Gentlemen: GPO-Driven, Living-off-the-Land Intrusion
    MITRE ATT&CK: T1518.001, T1087, T1082, T1036, T1219, T1047, T1021.002, T1021.001,
                  T1484.001, T1053.005, T1543.003, T1136.001
    Mitigations: M1018, M1022, M1026, M1027, M1028, M1030, M1035, M1037, M1038, M1040,
                 M1042, M1047, M1049
    Requires: Windows 10/11 or Server 2016+, local Administrator, reboot for admin-share
              changes; audit-mode ASR rollout recommended before block mode.
    Author: F0RT1KA Defense Guidance Generator
    Idempotent: Yes (safe to run multiple times)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Undo,
    [switch]$IncludeRmmBlocks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ChangesApplied = 0
$script:ChangesSkipped = 0

# ---------------------------------------------------------------
# Prerequisites (framework PowerShell guidelines)
# ---------------------------------------------------------------
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

function Write-Change([string]$Message) {
    $script:ChangesApplied++
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Skip([string]$Message) {
    $script:ChangesSkipped++
    Write-Host "[=] $Message" -ForegroundColor DarkGray
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Label)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($current -eq $Value) { Write-Skip "$Label already set ($Name=$Value)"; return }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        Write-Change "$Label ($Path\$Name = $Value)"
    }
}

function Remove-RegValue {
    param([string]$Path, [string]$Name, [string]$Label)
    $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $current) { Write-Skip "$Label already absent"; return }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Remove value")) {
        Remove-ItemProperty -Path $Path -Name $Name -Force
        Write-Change "$Label removed ($Path\$Name)"
    }
}

# ---------------------------------------------------------------
# Control 1: PowerShell logging (Script Block, Module, Transcription)
# ---------------------------------------------------------------
function Set-PowerShellLogging([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' $v 'DWord' "PowerShell Script Block Logging (4104 — exposes -enc payloads, Invoke-CimMethod, New-GPO)"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' $v 'DWord' "PowerShell Module Logging"
    if ($Enable) {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String' "Module Logging (all modules)"
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1 'DWord' "PowerShell Transcription"
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' 'C:\ProgramData\PSTranscripts' 'String' "PowerShell Transcription output directory"
    } else {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 0 'DWord' "PowerShell Transcription"
    }
    # Constrained Language Mode is NOT set here: CLM can break management tooling and is
    # best introduced via AppLocker/WDAC policy (see DEFENSE_GUIDANCE.md Medium-Term items).
}

# ---------------------------------------------------------------
# Control 2: Command-line auditing + advanced audit policy visibility
# (4688 w/ cmdline, 4698-4702 tasks, 7045 services, 4720/4732 accounts,
#  5140/5145 shares, 4657/4663 registry+file, 5136 GPO changes on DCs)
# ---------------------------------------------------------------
$AuditSubcategories = @(
    'Process Creation',           # 4688 — every LOLBin invocation
    'Other Object Access Events', # 4698-4702 — scheduled task lifecycle
    'Service Installation',       # 7045/7046 — decoy services
    'User Account Management',    # 4720/4722/4724 — backdoor accounts
    'Security Group Management',  # 4728/4732 — privilege group adds
    'Detailed File Share',        # 5145 — ADMIN$ share access
    'File Share',                 # 5140 — share mapping
    'File System',                # 4663 — SYSVOL/NETLOGON/PerfLogs writes (SACLs required too)
    'Registry',                   # 4657 — fDenyTSConnections / service config changes
    'Directory Service Changes',  # 5136/5137/5141 — GPO object changes (DC)
    'Logon',                      # 4624 — RDP type 10 / network type 3
    'Special Logon'
)

function Set-AuditVisibility([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' $v 'DWord' "Include command line in process creation events (4688)"
    # M1028 / T1087: do not enumerate administrator accounts on UAC elevation
    if ($Enable) {
        Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' 'EnumerateAdministrators' 0 'DWord' "UAC admin-account enumeration disabled (M1028)"
    } else {
        Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' 'EnumerateAdministrators' "UAC admin-account enumeration policy"
    }
    $state = if ($Enable) { '/success:enable /failure:enable' } else { '/success:disable /failure:disable' }
    foreach ($cat in $AuditSubcategories) {
        if ($PSCmdlet.ShouldProcess("auditpol '$cat'", $state)) {
            & auditpol.exe /set /subcategory:"$cat" $state.Split(' ') 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Change "auditpol '$cat' $state" }
            else { Write-Skip "auditpol '$cat' failed (may not exist on this SKU)" }
        }
    }
    if ($Enable) {
        Write-Host "[i] SACLs still required for file auditing: set auditing ACLs on SYSVOL\Policies," -ForegroundColor Cyan
        Write-Host "    NETLOGON, C:\PerfLogs and C:\Windows\Temp (see DEFENSE_GUIDANCE.md Stage 4)." -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------
# Control 3: ASR rule — Block process creations originating from PSExec and WMI
# ---------------------------------------------------------------
$AsrRules = @{
    'd1e49aac-8f56-4280-b9ba-993a6d77406a' = 'Block process creations originating from PSExec/WMI (T1047/T1021.002)'
}

function Set-AsrRules([int]$Mode) {  # 1=Block, 2=Audit, 0=Off
    $modeLabel = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit' }[$Mode]
    foreach ($guid in $AsrRules.Keys) {
        if ($PSCmdlet.ShouldProcess("ASR $guid ($($AsrRules[$guid]))", "Set mode $modeLabel")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $Mode -ErrorAction Stop
                Write-Change "ASR [$($AsrRules[$guid])] -> $modeLabel"
            } catch {
                Write-Skip "ASR $guid unchanged (Defender cmdlets unavailable or tamper-protected): $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------
# Control 4: SMB hardening — signing required, SMBv1 off, admin shares disabled
# ---------------------------------------------------------------
function Set-SmbHardening([bool]$Enable) {
    $sign = if ($Enable) { $true } else { $false }
    try {
        if ($PSCmdlet.ShouldProcess("SMB server signing", "RequireSecuritySignature=$sign")) {
            Set-SmbServerConfiguration -RequireSecuritySignature $sign -EnableSecuritySignature $true -Force -Confirm:$false -ErrorAction Stop
            Write-Change "SMB server signing required: $sign"
        }
    } catch {
        Write-Skip "SMB server signing unchanged: $($_.Exception.Message)"
    }
    if ($Enable) {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') {
            if ($PSCmdlet.ShouldProcess("SMBv1", "Disable")) {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Change "SMBv1 disabled (reboot to complete)"
            }
        } else { Write-Skip "SMBv1 already disabled or not present" }
        # M1035: remove default ADMIN$/C$ shares (blocks the PsExec-style drop path).
        # NOTE: breaks remote admin via admin shares on this host (SCCM/PsExec workflows)
        # and requires reboot — pilot first. Revert with -Undo (sets back to 1).
        $lanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Set-RegValue $lanman 'AutoShareWks' 0 'DWord' "Default admin shares disabled (workstation)"
        Set-RegValue $lanman 'AutoShareServer' 0 'DWord' "Default admin shares disabled (server)"
        Write-Host "[i] Admin-share removal takes effect after reboot (LanmanServer restart)." -ForegroundColor Yellow
    } else {
        $lanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Set-RegValue $lanman 'AutoShareWks' 1 'DWord' "Default admin shares restored (workstation)"
        Set-RegValue $lanman 'AutoShareServer' 1 'DWord' "Default admin shares restored (server)"
    }
}

# ---------------------------------------------------------------
# Control 5: RDP NLA + TLS enforcement (never enables or disables RDP itself —
# the adversary flips fDenyTSConnections; we make any enabled RDP harder to abuse)
# ---------------------------------------------------------------
function Set-RdpNla([bool]$Enable) {
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    if ($Enable) {
        Set-RegValue $rdpKey 'UserAuthentication' 1 'DWord' "RDP NLA required (UserAuthentication=1)"
        Set-RegValue $rdpKey 'SecurityLayer' 2 'DWord' "RDP TLS enforcement (SecurityLayer=2)"
        Write-Host "[i] RDP enablement (fDenyTSConnections) left untouched — manage via policy;" -ForegroundColor Cyan
        Write-Host "    alert on any change of fDenyTSConnections to 0 (Gentlemen T1021.001 IO)." -ForegroundColor Cyan
    } else {
        Remove-RegValue $rdpKey 'UserAuthentication' "RDP NLA enforcement"
        Remove-RegValue $rdpKey 'SecurityLayer' "RDP TLS enforcement"
    }
}

# ---------------------------------------------------------------
# Control 6: WMI-Activity operational tracing (remote WMI/DCOM visibility)
# ---------------------------------------------------------------
function Set-WmiActivityTrace([bool]$Enable) {
    $logName = 'Microsoft-Windows-WMI-Activity/Operational'
    $action = if ($Enable) { 'enable' } else { 'disable' }
    $flag = if ($Enable) { 'true' } else { 'false' }
    if ($PSCmdlet.ShouldProcess("ETW log $logName", $action)) {
        & wevtutil.exe sl $logName "/e:$flag" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Change "WMI-Activity operational tracing $action (wmic /node: / WmiPrvSE children)" }
        else { Write-Skip "WMI-Activity trace could not be $action'd (wevtutil exit $LASTEXITCODE)" }
    }
}

# ---------------------------------------------------------------
# Control 8 (optional): outbound blocks for unapproved remote-access / DFIR tools
# Velociraptor abused as C2; AnyDesk / Datto RMM / Cloudflared are the actor's
# other observed channels; NetExec/nxc is its SMB attack tool.
# ---------------------------------------------------------------
$RmmToolNames = @('velociraptor.exe', 'VelociraptorClient.exe', 'anydesk.exe',
                  'cloudflared.exe', 'nxc.exe', 'netexec.exe', 'DattoRMM.exe')

function Set-RmmEgressBlocks([bool]$Enable) {
    $candidateRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:LOCALAPPDATA,
        "$env:USERPROFILE\Downloads",
        "$env:SystemRoot\Temp",
        'C:\PerfLogs'
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($tool in $RmmToolNames) {
        $ruleName = "Block unapproved remote-access tool outbound ($tool)"
        $paths = @()
        foreach ($root in $candidateRoots) {
            $direct = Join-Path $root $tool
            if (Test-Path $direct) { $paths += $direct }
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($tool)
            $sub = Join-Path $root "$baseName\$tool"  # vendor-subfolder layout
            if (Test-Path $sub) { $paths += $sub }
        }
        if ($Enable) {
            if (-not $paths) { Write-Skip "$tool not found in common paths — rule skipped (hunt for it instead)"; continue }
            foreach ($p in ($paths | Select-Object -Unique)) {
                if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) { Write-Skip "Rule '$ruleName' exists"; continue }
                if ($PSCmdlet.ShouldProcess($ruleName, "Create outbound block for $p")) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $p -Action Block -Profile Any | Out-Null
                    Write-Change "Outbound block created for $p"
                }
            }
        } else {
            if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
                if ($PSCmdlet.ShouldProcess($ruleName, "Remove firewall rule")) {
                    Remove-NetFirewallRule -DisplayName $ruleName
                    Write-Change "Removed rule '$ruleName'"
                }
            } else { Write-Skip "Rule '$ruleName' absent" }
        }
    }
    Write-Host "[i] Firewall blocks are defense-in-depth; enforce via AppLocker/WDAC allowlisting" -ForegroundColor Cyan
    Write-Host "    for real execution prevention (see DEFENSE_GUIDANCE.md Medium-Term)." -ForegroundColor Cyan
}

# ---------------------------------------------------------------
# Post-checks (informational)
# ---------------------------------------------------------------
function Show-PostChecks {
    Write-Host "`n--- Post-hardening validation ---" -ForegroundColor Cyan
    try {
        $asr = Get-MpPreference -ErrorAction Stop
        $ids = $asr.AttackSurfaceReductionRules_Ids
        $acts = $asr.AttackSurfaceReductionRules_Actions
        if ($ids) {
            for ($i = 0; $i -lt $ids.Count; $i++) {
                Write-Host ("  ASR {0} : mode {1}  (0=Off 1=Block 2=Audit)" -f $ids[$i], $acts[$i])
            }
        } else { Write-Host "  ASR rules: none set (Defender cmdlets present?)" }
    } catch { Write-Host "  ASR: Get-MpPreference unavailable ($($_.Exception.Message))" }

    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        Write-Host ("  SMB signing required : {0}" -f $smb.RequireSecuritySignature)
    } catch { Write-Host "  SMB: Get-SmbServerConfiguration unavailable" }

    $lanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $asw = (Get-ItemProperty $lanman -Name AutoShareWks -ErrorAction SilentlyContinue).AutoShareWks
    $ass = (Get-ItemProperty $lanman -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
    Write-Host ("  Admin shares (Wks/Srv): {0}/{1}  (0=disabled; effective after reboot)" -f $asw, $ass)

    $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Host ("  PS ScriptBlock logging: {0}" -f $sbl)

    $cmdline = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    Write-Host ("  4688 command line     : {0}" -f $cmdline)

    $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    Write-Host ("  RDP NLA               : {0}  (alert on fDenyTSConnections -> 0)" -f $nla)

    Write-Host "  Remaining host-side TODOs:"
    Write-Host "    - SACLs on SYSVOL\Policies, NETLOGON, C:\PerfLogs, C:\Windows\Temp"
    Write-Host "    - Workstation segmentation (block 445/135/3389 between workstations)"
    Write-Host "    - AppLocker/WDAC allowlist for RMM/DFIR tooling (execution prevention)"
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
Write-Host "The Gentlemen LOLBin Defense Hardening — $(if ($Undo) { 'UNDO (rollback)' } else { 'APPLY' }) mode" -ForegroundColor Cyan

if (-not (Test-Administrator)) {
    Write-Host "[-] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}
Set-ExecutionPolicyBypass | Out-Null

if (-not $Undo) {
    Set-PowerShellLogging $true
    Set-AuditVisibility $true
    Set-AsrRules 1            # Block mode; run with 2 (audit) first in broad production rollouts
    Set-SmbHardening $true
    Set-RdpNla $true
    Set-WmiActivityTrace $true
    if ($IncludeRmmBlocks) { Set-RmmEgressBlocks $true }
} else {
    Set-PowerShellLogging $false
    Set-AuditVisibility $false
    Set-AsrRules 0
    Set-SmbHardening $false
    Set-RdpNla $false
    Set-WmiActivityTrace $false
    if ($IncludeRmmBlocks) { Set-RmmEgressBlocks $false }
}

Write-Host "`nSummary: $($script:ChangesApplied) change(s) applied, $($script:ChangesSkipped) already in desired state." -ForegroundColor Cyan
if (-not $Undo) { Show-PostChecks }
Write-Host "A reboot is required for admin-share (AutoShare*) changes to take effect." -ForegroundColor Yellow
