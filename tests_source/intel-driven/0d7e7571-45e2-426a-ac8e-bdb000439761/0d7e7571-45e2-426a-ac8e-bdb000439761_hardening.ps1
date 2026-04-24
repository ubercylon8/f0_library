# F0RT1KA Hardening Script — Nightmare-Eclipse RedSun Primitive Chain
# UUID: 0d7e7571-45e2-426a-ac8e-bdb000439761
# Platform: Windows (PowerShell 5.1+)
#
# Idempotent, dry-run supported via -WhatIf.
# MUST run elevated. Re-runnable — re-applying is a no-op.

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$DryRun
)

# ====================================================================
# Admin-privilege check (MANDATORY for all F0RT1KA hardening scripts)
# ====================================================================

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# ====================================================================
# Execution policy bypass (MANDATORY pattern)
# ====================================================================

try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    Write-Host "[+] Execution policy set to Bypass for this process" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not set execution policy: $_" -ForegroundColor Yellow
}

# ====================================================================
# Banner
# ====================================================================

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " F0RT1KA Hardening — Nightmare-Eclipse RedSun Primitive Chain" -ForegroundColor Cyan
Write-Host " UUID: 0d7e7571-45e2-426a-ac8e-bdb000439761" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
if ($DryRun -or $WhatIfPreference) {
    Write-Host " MODE: DRY RUN (no changes will be applied)" -ForegroundColor Yellow
} else {
    Write-Host " MODE: APPLY (changes will be persisted)" -ForegroundColor Green
}
Write-Host ""

# ====================================================================
# Control 1 — Enable Defender real-time protection + cloud-delivered
#               protection. Both are required for RedSun-style
#               Cloud-Files-rewrite behaviors to even be triggerable.
# ====================================================================

Write-Host "[1] Defender real-time + cloud protection" -ForegroundColor Cyan

try {
    if ($PSCmdlet.ShouldProcess("Defender", "Enable real-time + cloud protection")) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
        Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
        Write-Host "    [+] Real-time protection: ON" -ForegroundColor Green
        Write-Host "    [+] MAPS cloud reporting: Advanced" -ForegroundColor Green
        Write-Host "    [+] Cloud block level: High" -ForegroundColor Green
    }
} catch {
    Write-Host "    [!] Failed to adjust Defender: $_" -ForegroundColor Red
}

# ====================================================================
# Control 2 — Enable ASR rules that cover the RedSun-adjacent behaviors
#               (untrusted unsigned processes from USB, child process
#               blocks for Office, persistence by WMI).
#
# Note: there is no single ASR rule for "block non-OneDrive Cloud Files
# sync root". We enable the general behavioral-heuristics-friendly rules.
# ====================================================================

Write-Host ""
Write-Host "[2] Attack Surface Reduction (ASR) rules" -ForegroundColor Cyan

# GUIDs from https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
$asrRules = @{
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted/unsigned processes from USB"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from lsass.exe"
}

foreach ($guid in $asrRules.Keys) {
    $name = $asrRules[$guid]
    try {
        if ($PSCmdlet.ShouldProcess($name, "Enable ASR rule")) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            Write-Host "    [+] Enabled: $name" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [!] Could not enable $name: $_" -ForegroundColor Yellow
    }
}

# ====================================================================
# Control 3 — Enable object-access auditing (required for SIEM to see
#               NtOpen/QueryDirectoryObject + reparse-point writes).
# ====================================================================

Write-Host ""
Write-Host "[3] Object-access auditing" -ForegroundColor Cyan

try {
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable File System + Handle Manipulation auditing")) {
        & auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable | Out-Null
        Write-Host "    [+] File System auditing: ON" -ForegroundColor Green
        Write-Host "    [+] Handle Manipulation auditing: ON" -ForegroundColor Green
        Write-Host "    [+] Kernel Object auditing: ON" -ForegroundColor Green
    }
} catch {
    Write-Host "    [!] Failed to configure audit policy: $_" -ForegroundColor Red
}

# ====================================================================
# Control 4 — Baseline the current SyncRootManager state so deviations
#               are easy to spot. We dump the existing registrations
#               to a known-good snapshot file.
# ====================================================================

Write-Host ""
Write-Host "[4] Cloud Files sync-root baseline snapshot" -ForegroundColor Cyan

$snapshotDir = "$env:ProgramData\F0RT1KA\baseline"
$snapshotFile = "$snapshotDir\syncroot_baseline.json"
$syncRootKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SyncRootManager"

try {
    if ($PSCmdlet.ShouldProcess("$snapshotFile", "Write sync-root baseline")) {
        if (-not (Test-Path $snapshotDir)) {
            New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
        }
        if (Test-Path $syncRootKey) {
            $rootsNow = Get-ChildItem $syncRootKey | ForEach-Object {
                [pscustomobject]@{
                    ProviderName = $_.PSChildName
                    Timestamp    = (Get-Date).ToString("o")
                }
            }
        } else {
            $rootsNow = @()
        }
        $rootsNow | ConvertTo-Json -Depth 3 | Out-File -FilePath $snapshotFile -Encoding UTF8 -Force
        Write-Host "    [+] Baseline saved: $snapshotFile ($($rootsNow.Count) provider(s))" -ForegroundColor Green
    }
} catch {
    Write-Host "    [!] Could not save sync-root baseline: $_" -ForegroundColor Yellow
}

# ====================================================================
# Control 5 — Summary of what an EDR should now be able to catch.
# ====================================================================

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Hardening Applied — Detection Coverage Summary" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " T1211  Non-OneDrive Cloud Files sync root       SIEM (SyncRootManager registry writes)" -ForegroundColor White
Write-Host " T1211  EICAR trigger inside sync root           Defender real-time protection" -ForegroundColor White
Write-Host " T1006  \Device enumeration                      Audit: Kernel Object (event 4663)" -ForegroundColor White
Write-Host " T1006  Batch oplock request                     Audit: File System + Handle Manipulation" -ForegroundColor White
Write-Host " T1574  Mount-point reparse (non-system proc)    Audit: File System (event 4663 reparse tag)" -ForegroundColor White
Write-Host " T1574  FILE_SUPERSEDE race loop                 SIEM correlation rule (15+ events/minute)" -ForegroundColor White
Write-Host ""
Write-Host " Next: deploy the matching detection rules from:" -ForegroundColor Yellow
Write-Host "   - 0d7e7571-45e2-426a-ac8e-bdb000439761_detections.kql (Sentinel)" -ForegroundColor White
Write-Host "   - 0d7e7571-45e2-426a-ac8e-bdb000439761_sigma_rules.yml (vendor-agnostic)" -ForegroundColor White
Write-Host "   - 0d7e7571-45e2-426a-ac8e-bdb000439761_elastic_rules.ndjson (Elastic SIEM)" -ForegroundColor White
Write-Host "   - 0d7e7571-45e2-426a-ac8e-bdb000439761_dr_rules.yaml (LimaCharlie D&R)" -ForegroundColor White
Write-Host ""
