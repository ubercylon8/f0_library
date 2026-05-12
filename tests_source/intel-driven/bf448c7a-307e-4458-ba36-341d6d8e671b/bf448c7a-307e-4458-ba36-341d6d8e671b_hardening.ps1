# =============================================================================
# TclBanker Brazilian Banking Trojan — Windows Hardening Script
# Source: https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan
# Test:   bf448c7a-307e-4458-ba36-341d6d8e671b
#
# Applies Defender ASR rules, audit-policy changes, and registry settings that
# block or detect TclBanker's exact tradecraft. Run as Administrator.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File bf448c7a-307e-4458-ba36-341d6d8e671b_hardening.ps1
# =============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Audit = $false,    # -Audit: enable detection-only (don't block)
    [switch]$DryRun = $false    # -DryRun: print intended changes without applying
)

$ErrorActionPreference = 'Continue'
$script:appliedCount = 0
$script:skippedCount = 0

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
        Write-Host "[+] Execution policy set to Bypass for this session" -ForegroundColor Green
    } catch {
        Write-Warning "Could not set execution policy: $_"
    }
}

function Write-Section($Title) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

if (-not (Test-AdminPrivileges)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

Set-ExecutionPolicyBypass

Write-Host ""
Write-Host "TclBanker Hardening Script" -ForegroundColor Yellow
Write-Host "  Mode: $(if ($DryRun) {'DRY-RUN'} elseif ($Audit) {'AUDIT (detect only)'} else {'BLOCK'})" -ForegroundColor Yellow

# =============================================================================
# 1. Defender ASR rules
# =============================================================================
Write-Section "Defender Attack Surface Reduction (ASR) Rules"

$asrAction = if ($Audit) { 2 } else { 1 }   # 1=Block, 2=Audit
$asrRules = @{
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office child processes'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS from launching downloaded content'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence via WMI event subscription'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block exploited vulnerable signed drivers'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Block Adobe Reader child processes'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office code injection into other processes'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables not meeting prevalence/age/trusted list'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
}

foreach ($id in $asrRules.Keys) {
    $name = $asrRules[$id]
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would set ASR rule '$name' to action=$asrAction" -ForegroundColor Gray
        continue
    }
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $asrAction -ErrorAction Stop
        Write-Host "[+] ASR rule applied: $name" -ForegroundColor Green
        $script:appliedCount++
    } catch {
        Write-Warning "ASR rule failed ($name): $_"
        $script:skippedCount++
    }
}

# =============================================================================
# 2. Block known TclBanker filename shape at AppLocker level (audit-only by default)
# =============================================================================
Write-Section "AppLocker Audit Policy (TclBanker Filename Shape)"

# Build a registry-based path rule for the renamed sideload host
$appLockerRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe'
if (-not $DryRun) {
    try {
        New-Item -Path $appLockerRegPath -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] AppLocker EXE policy hive available" -ForegroundColor Green
    } catch {
        Write-Warning "Could not create AppLocker policy key: $_"
    }
}
Write-Host "  -> Add an AppLocker EXE rule denying LogiAiPromptBuilder.exe outside \Program Files\Logi*\ via GPO/Intune" -ForegroundColor Yellow

# =============================================================================
# 3. Defender real-time + cloud submission
# =============================================================================
Write-Section "Defender Real-Time Protection"

if (-not $DryRun) {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
        Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
        Set-MpPreference -MAPSReporting 2 -ErrorAction Stop                       # Advanced
        Set-MpPreference -SubmitSamplesConsent 3 -ErrorAction Stop                # Send all samples automatically
        Set-MpPreference -CloudBlockLevel 4 -ErrorAction Stop                     # High+ block level
        Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction Stop
        Set-MpPreference -PUAProtection 1 -ErrorAction Stop                       # Block PUA
        Write-Host "[+] Defender real-time + cloud protection enforced" -ForegroundColor Green
        $script:appliedCount++
    } catch {
        Write-Warning "Defender configuration failed: $_"
        $script:skippedCount++
    }
} else {
    Write-Host "[DRY-RUN] Would enable Defender real-time + cloud + PUA protection" -ForegroundColor Gray
}

# =============================================================================
# 4. Scheduled Task auditing
# =============================================================================
Write-Section "Scheduled Task Auditing"

if (-not $DryRun) {
    try {
        # Enable detailed task scheduler logging
        $taskLog = 'Microsoft-Windows-TaskScheduler/Operational'
        wevtutil sl $taskLog /e:true 2>$null
        Write-Host "[+] Task Scheduler Operational log enabled" -ForegroundColor Green
        $script:appliedCount++
    } catch {
        Write-Warning "Could not enable Task Scheduler log: $_"
    }
}

# Detect any existing TclBanker task
$existingTask = Get-ScheduledTask -TaskName 'RuntimeOptimizeService' -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "[!] TclBanker persistence task FOUND: RuntimeOptimizeService" -ForegroundColor Red
    Write-Host "    Author: $($existingTask.Author)" -ForegroundColor Red
    Write-Host "    Action: $($existingTask.Actions.Execute) $($existingTask.Actions.Arguments)" -ForegroundColor Red
    Write-Host "    Run 'schtasks /delete /tn RuntimeOptimizeService /f' to remove (only after evidence collection!)" -ForegroundColor Yellow
} else {
    Write-Host "[+] No 'RuntimeOptimizeService' task present (good)" -ForegroundColor Green
}

# =============================================================================
# 5. DNS / Network egress recommendations (informational only — needs proxy/firewall)
# =============================================================================
Write-Section "Network Egress Recommendations"

Write-Host "  -> Block *.workers.dev at egress proxy except for business-justified allowlist" -ForegroundColor Yellow
Write-Host "  -> Wire DNS resolver to alert on:" -ForegroundColor Yellow
Write-Host "       *ef971a42*.workers.dev"
Write-Host "       *tcl-banker*.workers.dev"
Write-Host "       *tclbanker*.workers.dev"

# =============================================================================
# 6. Check for in-place TclBanker indicators
# =============================================================================
Write-Section "Indicator Check (current host)"

$indicators = @(
    @{Path='C:\temp\tcl-debug.txt'; Description='Debug artifact'},
    @{Path="$env:LocalAppData\LogiAI\screen_retriever_plugin.dll"; Description='Sideloaded DLL'},
    @{Path="$env:LocalAppData\LogiAI\LogiAiPromptBuilder.exe"; Description='Renamed host EXE'},
    @{Path="$env:LocalAppData\LogiAI\Tcl.Agent.dll"; Description='Tcl.Agent assembly'},
    @{Path="$env:LocalAppData\LogiAI\Tcl.WppBot.dll"; Description='Tcl.WppBot assembly'}
)

$found = 0
foreach ($ind in $indicators) {
    if (Test-Path $ind.Path) {
        Write-Host "[!] FOUND: $($ind.Path) ($($ind.Description))" -ForegroundColor Red
        $found++
    }
}
if ($found -eq 0) {
    Write-Host "[+] No on-disk TclBanker indicators found on this host" -ForegroundColor Green
} else {
    Write-Host "" -ForegroundColor Red
    Write-Host "[!!] $found TclBanker indicators present. Treat this host as compromised." -ForegroundColor Red
    Write-Host "     Follow the IR playbook in *_DEFENSE_GUIDANCE.md" -ForegroundColor Red
}

# =============================================================================
# Summary
# =============================================================================
Write-Section "Summary"
Write-Host "  Applied:  $script:appliedCount setting(s)" -ForegroundColor Green
Write-Host "  Skipped:  $script:skippedCount setting(s)" -ForegroundColor Yellow
Write-Host "  Mode:     $(if ($DryRun) {'DRY-RUN'} elseif ($Audit) {'AUDIT'} else {'BLOCK'})" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Verify with Get-MpPreference | Select-Object -Property AttackSurfaceReductionRules_*"
Write-Host "  2. Pilot in audit mode for 7 days before flipping to block mode"
Write-Host "  3. Wire SIEM/EDR rules from the test bundle (*.kql, *.yar, *.yml, *.ndjson, *.yaml)"
Write-Host ""

exit 0
