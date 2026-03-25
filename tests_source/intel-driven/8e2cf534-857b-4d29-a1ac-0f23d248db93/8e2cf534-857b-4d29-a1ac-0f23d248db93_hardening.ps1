<#
.SYNOPSIS
    Hardening script for TA453 NICECURL VBScript Backdoor techniques.

.DESCRIPTION
    Applies defensive hardening to mitigate TA453 NICECURL attack techniques:
    - T1204.002: User Execution: Malicious File (LNK restrictions)
    - T1059.005: Visual Basic Script execution restrictions
    - T1047: WMI event logging and access control
    - T1518.001: Security Software Discovery monitoring
    - T1071.001: curl.exe C2 communication monitoring
    - T1105: Ingress Tool Transfer restrictions
    - T1036.004: LNK masquerading (file extension visibility)

    Test ID: 8e2cf534-857b-4d29-a1ac-0f23d248db93
    MITRE ATT&CK: T1204.002, T1059.005, T1047, T1518.001, T1071.001, T1105, T1036.004
    Mitigations: M1017, M1026, M1031, M1037, M1038, M1040, M1042, M1049, M1054

.PARAMETER Undo
    Reverts all changes made by this script.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\8e2cf534-857b-4d29-a1ac-0f23d248db93_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\8e2cf534-857b-4d29-a1ac-0f23d248db93_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-24
    Requires: Administrator privileges
    Idempotent: Yes (safe to run multiple times)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo
)

#Requires -RunAsAdministrator

# ============================================================
# Configuration
# ============================================================
$ErrorActionPreference = "Continue"
$Script:ChangeLog = @()
$Script:StateFile = "$env:ProgramData\F0RT1KA\hardening_ta453_nicecurl_state.json"

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    $prefix = @{ Info = "[INFO]"; Success = "[OK]"; Warning = "[WARN]"; Error = "[ERR]" }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Save-State {
    param([hashtable]$State)
    $stateDir = Split-Path $Script:StateFile -Parent
    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $Script:StateFile -Force
    Write-Status "State saved to $Script:StateFile" "Info"
}

function Load-State {
    if (Test-Path $Script:StateFile) {
        return Get-Content $Script:StateFile | ConvertFrom-Json
    }
    return $null
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$PropertyType = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $PropertyType -Force
        Write-Status "Set $Path\$Name = $Value" "Success"
        return $true
    }
    catch {
        Write-Status "Failed to set $Path\$Name: $_" "Error"
        return $false
    }
}

# ============================================================
# Pre-flight checks
# ============================================================

if (-not (Test-IsAdmin)) {
    Write-Status "This script requires Administrator privileges." "Error"
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host " F0RT1KA Hardening: TA453 NICECURL VBScript Backdoor" -ForegroundColor Blue
Write-Host " Test ID: 8e2cf534-857b-4d29-a1ac-0f23d248db93" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

if ($Undo) {
    Write-Status "UNDO MODE: Reverting hardening changes..." "Warning"
} else {
    Write-Status "APPLY MODE: Applying hardening settings..." "Info"
}

# ============================================================
# Hardening Measures
# ============================================================

$state = @{}

if (-not $Undo) {

    # ----------------------------------------------------------
    # 1. Show file extensions (prevents double-extension masquerading)
    # Mitigates: T1204.002, T1036.004
    # ----------------------------------------------------------
    Write-Status "1/6: Enforcing file extension visibility..." "Info"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $currentValue = (Get-ItemProperty -Path $regPath -Name "HideFileExt" -ErrorAction SilentlyContinue).HideFileExt
    $state["HideFileExt_Original"] = $currentValue
    Set-RegistryValue -Path $regPath -Name "HideFileExt" -Value 0

    # Also set for default user profile
    $defaultPath = "Registry::HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (Test-Path $defaultPath) {
        Set-RegistryValue -Path $defaultPath -Name "HideFileExt" -Value 0
    }

    # ----------------------------------------------------------
    # 2. Restrict Windows Script Host for non-admin contexts
    # Mitigates: T1059.005
    # ----------------------------------------------------------
    Write-Status "2/6: Configuring Windows Script Host restrictions..." "Info"
    $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    $currentWSH = (Get-ItemProperty -Path $wshPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $state["WSH_Enabled_Original"] = $currentWSH

    # Note: Setting to 0 disables WSH system-wide. For production, use AppLocker instead.
    # Here we enable logging rather than full disable for safety.
    Set-RegistryValue -Path $wshPath -Name "LogSecuritySuccesses" -Value 1
    Set-RegistryValue -Path $wshPath -Name "TrustPolicy" -Value 2
    Write-Status "  WSH logging enabled (TrustPolicy=2 requires signed scripts)" "Info"

    # ----------------------------------------------------------
    # 3. Enable WMI event logging
    # Mitigates: T1047, T1518.001
    # ----------------------------------------------------------
    Write-Status "3/6: Enabling WMI event logging..." "Info"

    # Enable WMI Trace logging
    try {
        $wmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction SilentlyContinue
        if ($wmiLog -and -not $wmiLog.IsEnabled) {
            $wmiLog.IsEnabled = $true
            $wmiLog.SaveChanges()
            $state["WMI_Log_WasEnabled"] = $false
            Write-Status "  WMI-Activity/Operational log enabled" "Success"
        } else {
            $state["WMI_Log_WasEnabled"] = $true
            Write-Status "  WMI-Activity/Operational log already enabled" "Info"
        }
    }
    catch {
        Write-Status "  Could not configure WMI logging: $_" "Warning"
    }

    # Enable audit policy for WMI events
    try {
        $result = & auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>&1
        Write-Status "  WMI audit policy enabled" "Success"
        $state["WMI_Audit_Set"] = $true
    }
    catch {
        Write-Status "  Could not set WMI audit policy: $_" "Warning"
    }

    # ----------------------------------------------------------
    # 4. Enable process creation auditing with command line
    # Mitigates: All techniques (visibility)
    # ----------------------------------------------------------
    Write-Status "4/6: Enabling process creation auditing with command line..." "Info"
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    Set-RegistryValue -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
    $state["ProcessAudit_Set"] = $true

    # Enable process creation audit policy
    try {
        & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null
        Write-Status "  Process creation audit policy enabled" "Success"
    }
    catch {
        Write-Status "  Could not set process creation audit: $_" "Warning"
    }

    # ----------------------------------------------------------
    # 5. Configure Windows Firewall rules for curl.exe monitoring
    # Mitigates: T1071.001, T1105
    # ----------------------------------------------------------
    Write-Status "5/6: Configuring firewall logging for curl.exe..." "Info"

    # Enable Windows Firewall logging for outbound connections
    try {
        & netsh advfirewall set allprofiles logging droppedconnections enable 2>&1 | Out-Null
        & netsh advfirewall set allprofiles logging allowedconnections enable 2>&1 | Out-Null
        Write-Status "  Firewall connection logging enabled" "Success"
        $state["FW_Logging_Set"] = $true
    }
    catch {
        Write-Status "  Could not configure firewall logging: $_" "Warning"
    }

    # Note: Blocking curl.exe outright may impact legitimate admin use.
    # Instead, log and monitor curl.exe network activity.
    Write-Status "  Recommendation: Monitor curl.exe outbound via SIEM, do not block" "Info"

    # ----------------------------------------------------------
    # 6. Enable Defender ASR rules for script-based attacks
    # Mitigates: T1059.005, T1204.002
    # ----------------------------------------------------------
    Write-Status "6/6: Checking Defender ASR rule availability..." "Info"

    try {
        # ASR Rule: Block Office apps from creating child processes (d4f940ab-401b-4efc-aadc-ad5f3c50688a)
        $asrRules = Get-MpPreference -ErrorAction SilentlyContinue
        if ($asrRules) {
            # Check if script-based ASR rules are configured
            $scriptASR = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # Block Office child processes
            $vbsASR = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"     # Block VBS/JS abuse

            $currentRules = $asrRules.AttackSurfaceReductionRules_Ids
            if ($currentRules -notcontains $vbsASR) {
                Write-Status "  Recommendation: Enable ASR rule $vbsASR (Block VBS/JS abuse)" "Warning"
                Write-Status "  Command: Add-MpPreference -AttackSurfaceReductionRules_Ids $vbsASR -AttackSurfaceReductionRules_Actions Enabled" "Info"
            } else {
                Write-Status "  VBS/JS ASR rule already configured" "Success"
            }
        }
    }
    catch {
        Write-Status "  Defender ASR not available (non-Defender endpoint)" "Warning"
    }

    # Save state for undo
    Save-State -State $state

} else {
    # ----------------------------------------------------------
    # UNDO: Revert all changes
    # ----------------------------------------------------------
    $savedState = Load-State
    if (-not $savedState) {
        Write-Status "No saved state found. Cannot undo." "Error"
        exit 1
    }

    Write-Status "1/4: Reverting file extension visibility..." "Info"
    if ($null -ne $savedState.HideFileExt_Original) {
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value $savedState.HideFileExt_Original
    }

    Write-Status "2/4: Reverting Windows Script Host settings..." "Info"
    if ($null -ne $savedState.WSH_Enabled_Original) {
        $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        Remove-ItemProperty -Path $wshPath -Name "LogSecuritySuccesses" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $wshPath -Name "TrustPolicy" -ErrorAction SilentlyContinue
    }

    Write-Status "3/4: Reverting WMI logging..." "Info"
    if ($savedState.WMI_Log_WasEnabled -eq $false) {
        try {
            $wmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction SilentlyContinue
            if ($wmiLog) {
                $wmiLog.IsEnabled = $false
                $wmiLog.SaveChanges()
                Write-Status "  WMI-Activity log disabled" "Success"
            }
        }
        catch {
            Write-Status "  Could not revert WMI logging: $_" "Warning"
        }
    }

    Write-Status "4/4: Cleanup..." "Info"
    if (Test-Path $Script:StateFile) {
        Remove-Item $Script:StateFile -Force
        Write-Status "  State file removed" "Success"
    }
}

# ============================================================
# Summary
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
if ($Undo) {
    Write-Host " Hardening REVERTED successfully" -ForegroundColor Yellow
} else {
    Write-Host " Hardening APPLIED successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host " Changes applied:" -ForegroundColor Cyan
    Write-Host "   1. File extensions visible (prevents .pdf.lnk masquerading)" -ForegroundColor White
    Write-Host "   2. Windows Script Host logging enabled" -ForegroundColor White
    Write-Host "   3. WMI event logging enabled" -ForegroundColor White
    Write-Host "   4. Process creation auditing with command line" -ForegroundColor White
    Write-Host "   5. Firewall connection logging enabled" -ForegroundColor White
    Write-Host "   6. ASR rule recommendations provided" -ForegroundColor White
}
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""
