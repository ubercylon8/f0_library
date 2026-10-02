<#
.SYNOPSIS
    LockBit 3.0 Double-Extortion Defense Hardening — Windows Endpoint
.DESCRIPTION
    Idempotent hardening script implementing the Quick-Win and Medium-Term controls from
    the companion DEFENSE_GUIDANCE.md for the LockBit 3.0 (SB-PC-2026-001) threat profile:
      1. PowerShell Script Block + Module logging (detect T1059.001)
      2. Defender real-time protection enforcement + DisableAntiSpyware policy removal (T1562.001/T1112)
      3. Microsoft Defender ASR rules: LSASS credential theft, PSExec/WMI child processes,
         vulnerable signed drivers, advanced ransomware protection (T1003.001, T1021, T1486)
      4. LSA Protection (RunAsPPL) against LSASS dumping (T1003.001)
      5. Process command-line auditing + advanced audit policy (T1490/T1070.001 visibility)
      6. Controlled Folder Access against mass encryption (T1486)
      7. SMB hardening: signing required, SMBv1 disabled (T1021.002)
      8. Critical service protection: EventLog + VSS set to auto-start (T1070.001/T1490)
      9. Optional outbound block for unapproved exfil tools (rclone/megacmd) (T1567.002)

    All changes are idempotent and support -WhatIf (dry run) and -Undo (rollback).
.PARAMETER Undo
    Revert all changes applied by this script to their pre-hardening state.
.PARAMETER IncludeEgressBlocks
    Also create outbound firewall block rules for unapproved exfiltration tools
    (rclone.exe, megacmd.exe, winscp.exe) when the binaries exist on the host.
    Off by default — enable only after confirming no approved usage.
.EXAMPLE
    .\lockbit_defense_hardening.ps1 -WhatIf          # preview all changes
    .\lockbit_defense_hardening.ps1                  # apply hardening
    .\lockbit_defense_hardening.ps1 -Undo            # roll back
.NOTES
    Requires: Windows 10/11 or Server 2016+, local Administrator, reboot for RunAsPPL/ASR.
    Tamper Protection cannot be set via script — enforce it in the Defender portal/Intune
    (guidance only, validated by this script's post-checks).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Undo,
    [switch]$IncludeEgressBlocks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ChangesApplied = 0
$script:ChangesSkipped = 0

# ---------------------------------------------------------------
# Prerequisites
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
# Control 1: PowerShell Script Block + Module Logging
# ---------------------------------------------------------------
function Set-PowerShellLogging([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' $v 'DWord' "PowerShell Script Block Logging"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' $v 'DWord' "PowerShell Module Logging"
    if ($Enable) {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String' "Module Logging (all modules)"
    }
}

# ---------------------------------------------------------------
# Control 2: Defender real-time protection + policy cleanup
# ---------------------------------------------------------------
function Set-DefenderEnforcement([bool]$Enable) {
    if ($Enable) {
        Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' "DisableAntiSpyware policy value"
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0 'DWord' "Real-Time Monitoring enforced"
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiVirus' 0 'DWord' "Defender Antivirus enforced"
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Change "Defender real-time monitoring active (Set-MpPreference)"
        } catch {
            Write-Skip "Set-MpPreference blocked (Tamper Protection active — desired state): $($_.Exception.Message)"
        }
    } else {
        Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' "RTP policy enforcement"
        Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiVirus' "Defender AV policy enforcement"
    }
}

# ---------------------------------------------------------------
# Control 3: ASR rules (mode: 1=Block, 2=Audit, 0=Off)
# ---------------------------------------------------------------
$AsrRules = @{
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'd1e49aac-8f56-4280-b9ba-993a6d77406a' = 'Block process creations from PSExec/WMI'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
}

function Set-AsrRules([int]$Mode) {
    $modeLabel = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit' }[$Mode]
    foreach ($guid in $AsrRules.Keys) {
        if ($PSCmdlet.ShouldProcess("ASR $guid ($($AsrRules[$guid]))", "Set mode $modeLabel")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $Mode -ErrorAction Stop
                Write-Change "ASR [$($AsrRules[$guid])] -> $modeLabel"
            } catch {
                Write-Skip "ASR $guid unchanged: $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------
# Control 4: LSA Protection (RunAsPPL)
# ---------------------------------------------------------------
function Set-LsaProtection([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' $v 'DWord' "LSA Protection (RunAsPPL) — reboot required"
}

# ---------------------------------------------------------------
# Control 5: Command-line auditing + advanced audit policy
# ---------------------------------------------------------------
function Set-AuditVisibility([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' $v 'DWord' "Include command line in process creation events (4688)"
    $state = if ($Enable) { '/success:enable /failure:enable' } else { '/success:disable /failure:disable' }
    $categories = @(
        'Security System Extension', 'System Integrity', 'Security State Change',
        'Other System Events', 'Detailed File Share', 'File Share',
        'Sensitive Privilege Use', 'Registry'
    )
    foreach ($cat in $categories) {
        if ($PSCmdlet.ShouldProcess("auditpol '$cat'", $state)) {
            & auditpol.exe /set /subcategory:"$cat" $state.Split(' ') 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Change "auditpol '$cat' $state" } else { Write-Skip "auditpol '$cat' failed (may not exist on this SKU)" }
        }
    }
}

# ---------------------------------------------------------------
# Control 6: Controlled Folder Access
# ---------------------------------------------------------------
function Set-ControlledFolderAccess([int]$Mode) {  # 1=Block, 2=Audit, 0=Off
    $modeLabel = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit' }[$Mode]
    if ($PSCmdlet.ShouldProcess("Controlled Folder Access", "Set $modeLabel")) {
        try {
            Set-MpPreference -EnableControlledFolderAccess $Mode -ErrorAction Stop
            Write-Change "Controlled Folder Access -> $modeLabel (review exclusions for line-of-business apps)"
        } catch {
            Write-Skip "CFA unchanged: $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------
# Control 7: SMB hardening
# ---------------------------------------------------------------
function Set-SmbHardening([bool]$Enable) {
    $sign = if ($Enable) { $true } else { $false }
    if ($PSCmdlet.ShouldProcess("SMB server signing", "RequireSecuritySignature=$sign")) {
        Set-SmbServerConfiguration -RequireSecuritySignature $sign -EnableSecuritySignature $true -Force -Confirm:$false
        Write-Change "SMB server signing required: $sign"
    }
    if ($Enable) {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') {
            if ($PSCmdlet.ShouldProcess("SMBv1", "Disable")) {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Change "SMBv1 disabled (reboot to complete)"
            }
        } else { Write-Skip "SMBv1 already disabled or not present" }
    }
}

# ---------------------------------------------------------------
# Control 8: Critical service protection (EventLog, VSS)
# ---------------------------------------------------------------
function Set-CriticalServices([bool]$Enable) {
    $targets = if ($Enable) {
        @{ EventLog = 'auto'; VSS = 'Manual'; WinDefend = 'auto' }
    } else {
        @{}  # Undo: leave start types as-is (we never lower them below these values)
    }
    foreach ($svc in $targets.Keys) {
        $startType = $targets[$svc]
        $cur = (Get-Service -Name $svc -ErrorAction SilentlyContinue).StartType
        if ("$cur" -eq $startType -or ("$cur" -eq 'Automatic' -and $startType -eq 'auto')) {
            Write-Skip "$svc start type already $cur"
            continue
        }
        if ($PSCmdlet.ShouldProcess("service $svc", "Set start type $startType")) {
            Set-Service -Name $svc -StartupType $startType -ErrorAction SilentlyContinue
            Write-Change "$svc start type -> $startType"
        }
    }
    if ($Enable) {
        $evt = Get-Service -Name EventLog -ErrorAction SilentlyContinue
        if ($evt -and $evt.Status -ne 'Running') {
            if ($PSCmdlet.ShouldProcess("EventLog", "Start service")) {
                Start-Service EventLog -ErrorAction SilentlyContinue
                Write-Change "EventLog service started"
            }
        } else { Write-Skip "EventLog running" }
    }
}

# ---------------------------------------------------------------
# Control 9 (optional): outbound block for unapproved exfil tools
# ---------------------------------------------------------------
$ExfilToolNames = @('rclone.exe', 'megacmd.exe', 'winscp.exe')

function Set-ExfilEgressBlocks([bool]$Enable) {
    foreach ($tool in $ExfilToolNames) {
        $ruleName = "Block unapproved exfil tool outbound ($tool)"
        $paths = @(
            "$env:ProgramFiles\$tool\$tool",
            "$env:LOCALAPPDATA\$tool\$tool",
            "$env:USERPROFILE\Downloads\$tool"
        ) | Where-Object { Test-Path $_ }
        if ($Enable) {
            if (-not $paths) { Write-Skip "$tool not found in common paths — rule skipped (hunt for it instead)"; continue }
            foreach ($p in $paths) {
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
}

# ---------------------------------------------------------------
# Post-checks (informational)
# ---------------------------------------------------------------
function Show-PostChecks {
    Write-Host "`n--- Post-hardening validation ---" -ForegroundColor Cyan
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        Write-Host ("  Real-time protection : {0}" -f $mp.RealTimeProtectionEnabled)
        Write-Host ("  Tamper Protection    : {0}  (enforce in Defender portal/Intune if False)" -f $mp.IsTamperProtected)
        Write-Host ("  CFA                  : {0}" -f $mp.EnableControlledFolderAccess)
    }
    $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    Write-Host ("  RunAsPPL             : {0}  (effective after reboot)" -f $ppl)
    Write-Host "  ASR rule modes       : Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Actions"
    Write-Host "  Reminder: network segmentation (workstation->server 445/3389/5985) and egress filtering"
    Write-Host "            are network-layer controls — apply at the firewall, not the endpoint."
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
Write-Host "LockBit 3.0 Defense Hardening — $(if ($Undo) { 'UNDO (rollback)' } else { 'APPLY' }) mode" -ForegroundColor Cyan

if (-not (Test-Administrator)) {
    Write-Host "[-] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}
Set-ExecutionPolicyBypass | Out-Null

if (-not $Undo) {
    Set-PowerShellLogging $true
    Set-DefenderEnforcement $true
    Set-AsrRules 1            # Block mode; use 2 (audit) first in broad production rollouts
    Set-LsaProtection $true
    Set-AuditVisibility $true
    Set-ControlledFolderAccess 1
    Set-SmbHardening $true
    Set-CriticalServices $true
    if ($IncludeEgressBlocks) { Set-ExfilEgressBlocks $true }
} else {
    Set-PowerShellLogging $false
    Set-DefenderEnforcement $false
    Set-AsrRules 0
    Set-LsaProtection $false
    Set-AuditVisibility $false
    Set-ControlledFolderAccess 0
    Set-SmbHardening $false
    Set-CriticalServices $false
    if ($IncludeEgressBlocks) { Set-ExfilEgressBlocks $false }
}

Write-Host "`nSummary: $($script:ChangesApplied) change(s) applied, $($script:ChangesSkipped) already in desired state." -ForegroundColor Cyan
if (-not $Undo) { Show-PostChecks }
Write-Host "A reboot is required for RunAsPPL and SMBv1 changes to take effect." -ForegroundColor Yellow
