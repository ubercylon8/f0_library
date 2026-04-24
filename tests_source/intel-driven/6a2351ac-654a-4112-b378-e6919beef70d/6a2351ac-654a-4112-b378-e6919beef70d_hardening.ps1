# ============================================================================
# F0RT1KA Hardening Script — UnDefend Defender Update-DoS
# ============================================================================
# Test ID: 6a2351ac-654a-4112-b378-e6919beef70d
# MITRE ATT&CK: T1562.001, T1083
# Threat Actor: Nightmare-Eclipse (PoC author)
# Author: F0RT1KA sectest-builder
# ============================================================================
#
# This script applies preventive controls that raise the cost of UnDefend-class
# Defender signature/engine update DoS attacks. It is idempotent: re-running
# is safe.
#
# Controls applied:
#   1. Defender Tamper Protection (MDM-driven — cannot be fully enabled via registry)
#   2. Defender real-time protection + cloud protection + sample submission
#   3. ASR rules (stable set) in Block mode
#   4. Signature-update failure event-log forwarding hint
#   5. Audit for user-context autorun surfaces (not blocking — reporting only)
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File .\6a2351ac-654a-4112-b378-e6919beef70d_hardening.ps1
# ============================================================================

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Admin check + execution policy bypass
# ---------------------------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not set process execution policy: $($_.Exception.Message)"
    }
}

function Write-Step { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "[X] $msg" -ForegroundColor Red }

Ensure-ExecutionPolicyBypass

if (-not (Test-Admin)) {
    Write-Err "Administrator privileges required. Re-run from an elevated PowerShell session."
    exit 1
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Blue
Write-Host "  F0RT1KA Hardening: UnDefend Defender Update-DoS (T1562.001, T1083)" -ForegroundColor Blue
Write-Host "==========================================================================" -ForegroundColor Blue
Write-Host ""

# ---------------------------------------------------------------------------
# Control 1: Defender real-time + cloud + sample submission
# ---------------------------------------------------------------------------

Write-Step "Enabling Defender real-time protection, cloud-delivered protection, sample submission..."

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
    Set-MpPreference -CloudBlockLevel High -ErrorAction Stop
    Write-Ok "Real-time / cloud / sample settings applied"
} catch {
    Write-Warn "Could not fully apply Defender preferences (tamper protection may prevent changes): $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Control 2: Tamper Protection — reminder (must be set via MDM / Intune)
# ---------------------------------------------------------------------------

Write-Step "Checking Defender Tamper Protection status..."

try {
    $mp = Get-MpComputerStatus
    if ($mp.IsTamperProtected) {
        Write-Ok "Tamper Protection is ENABLED"
    } else {
        Write-Warn "Tamper Protection is DISABLED — enable via Microsoft 365 Defender portal or Intune"
        Write-Warn "  See: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection"
    }
} catch {
    Write-Warn "Could not query tamper protection state: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Control 3: ASR rules in Block mode
# ---------------------------------------------------------------------------

Write-Step "Configuring ASR rules relevant to UnDefend-class attacks..."

# Stable ASR rules — Block mode (1)
# GUIDs from https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
$asrRules = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet a prevalence/age/trusted-list criterion'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'
}

$guids = @($asrRules.Keys)
$actions = @()
for ($i = 0; $i -lt $guids.Count; $i++) { $actions += 1 }  # 1 = Block

try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $guids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
    foreach ($g in $asrRules.Keys) {
        Write-Ok "ASR enabled: $g ($($asrRules[$g]))"
    }
} catch {
    Write-Warn "Could not apply ASR rules: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Control 4: Signature-update failure event-log hint
# ---------------------------------------------------------------------------

Write-Step "Checking recent Defender signature-update failure events..."

try {
    $since = (Get-Date).AddDays(-7)
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id      = 2001, 2002, 2004
        StartTime = $since
    } -ErrorAction SilentlyContinue

    if ($null -eq $evts -or $evts.Count -eq 0) {
        Write-Ok "No signature-update failure events in the last 7 days"
    } else {
        Write-Warn "$($evts.Count) signature-update failure event(s) in the last 7 days:"
        $evts | Select-Object -First 5 | ForEach-Object {
            Write-Warn "  $($_.TimeCreated) [Id=$($_.Id)] $($_.Message.Split("`n")[0])"
        }
        Write-Warn "Investigate — 3+ failures in <6h is a strong UnDefend-class indicator."
    }
} catch {
    Write-Warn "Could not read Defender operational log: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Control 5: Audit user-context autorun surfaces (reporting only)
# ---------------------------------------------------------------------------

Write-Step "Auditing user-context autorun surfaces (UnDefend launch-persistence candidates)..."

$runKeys = @(
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($values) {
            $props = $values | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' }
            foreach ($p in $props) {
                $v = $values.$($p.Name)
                Write-Host "    [RUNKEY] $key\$($p.Name) => $v" -ForegroundColor DarkGray
            }
        }
    }
}

$startupDir = [Environment]::GetFolderPath('Startup')
if (Test-Path $startupDir) {
    Get-ChildItem -Path $startupDir -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "    [STARTUP] $($_.FullName)" -ForegroundColor DarkGray
    }
}

$userTasks = "$env:SystemRoot\System32\Tasks"
# User tasks live under %SystemRoot%\System32\Tasks\<users-tree> — admin-readable
$userTaskCount = 0
try {
    $userTaskCount = (Get-ChildItem -Path $userTasks -Recurse -ErrorAction SilentlyContinue -File).Count
} catch {}
Write-Host "    [TASKS] $userTaskCount scheduled-task files under $userTasks" -ForegroundColor DarkGray

Write-Ok "Autorun audit complete (review above output for unfamiliar entries)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Blue
Write-Host "  Hardening Complete" -ForegroundColor Blue
Write-Host "==========================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. If Tamper Protection was DISABLED, enable it via Microsoft 365 Defender / Intune."
Write-Host "  2. Deploy the companion detection rules (_detections.kql, _sigma_rules.yml,"
Write-Host "     _elastic_rules.ndjson, _dr_rules.yaml, _rules.yar)."
Write-Host "  3. Configure SOC alerts on Defender signature-update failure events"
Write-Host "     (EventIDs 2001 / 2002 / 2004, threshold 3 per 6h)."
Write-Host ""

exit 0
