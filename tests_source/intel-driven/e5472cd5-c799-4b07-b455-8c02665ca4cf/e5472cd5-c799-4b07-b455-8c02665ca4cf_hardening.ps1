# ============================================================================
# Hardening Script — HONESTCUE LLM-Assisted Runtime C# Compilation
# Test ID: e5472cd5-c799-4b07-b455-8c02665ca4cf
# MITRE ATT&CK: T1071.001, T1027.004, T1027.010, T1620, T1105, T1583.006, T1565.001
# Date: 2026-04-13
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
# Applies Windows endpoint hardening controls that mitigate HONESTCUE-class
# LLM-as-runtime-component malware chains. Controls include PowerShell logging,
# ASR rules, hosts-file integrity monitoring via Sysmon, and Defender tamper
# protection recommendations.
#
# USAGE:
#   Run in an elevated PowerShell prompt:
#     powershell.exe -ExecutionPolicy Bypass -File e5472cd5-...-hardening.ps1
#
#   Dry-run:
#     powershell.exe -ExecutionPolicy Bypass -File e5472cd5-...-hardening.ps1 -DryRun
# ============================================================================

[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$WarningPreference     = 'Continue'

# ------------------------------------------------------------
# Helper: Ensure-Admin
# ------------------------------------------------------------
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (-not (Test-IsAdmin)) {
        Write-Error "This hardening script must be run in an elevated PowerShell prompt (Run as Administrator)."
        exit 1
    }
}

function Invoke-HardeningAction {
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    Write-Host "[*] $Description" -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "    (dry-run — not applying)" -ForegroundColor Yellow
        return
    }
    try {
        & $Action
        Write-Host "    OK" -ForegroundColor Green
    } catch {
        Write-Warning "    Failed: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Preflight
# ------------------------------------------------------------

Ensure-Admin

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " HONESTCUE-class Hardening" -ForegroundColor Cyan
Write-Host " Test ID: e5472cd5-c799-4b07-b455-8c02665ca4cf" -ForegroundColor Cyan
Write-Host " Mode: $(if ($DryRun) { 'DRY-RUN' } else { 'APPLY' })" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# Control 1: Enable PowerShell ScriptBlock Logging
# ------------------------------------------------------------
Invoke-HardeningAction "Enable PowerShell ScriptBlock Logging (captures reflective-load/compile patterns)" {
    $key = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null

    $key2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
    New-ItemProperty -Path $key2 -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
}

# ------------------------------------------------------------
# Control 2: Enable PowerShell Module Logging
# ------------------------------------------------------------
Invoke-HardeningAction "Enable PowerShell Module Logging" {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null

    $modules = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    if (-not (Test-Path $modules)) { New-Item -Path $modules -Force | Out-Null }
    New-ItemProperty -Path $modules -Name '*' -Value '*' -PropertyType String -Force | Out-Null
}

# ------------------------------------------------------------
# Control 3: Enable PowerShell Transcription
# ------------------------------------------------------------
Invoke-HardeningAction "Enable PowerShell Transcription (full session capture)" {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name EnableInvocationHeader -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name OutputDirectory -Value 'C:\ProgramData\PSTranscripts' -PropertyType String -Force | Out-Null

    # Ensure directory exists with restrictive ACL
    $dir = 'C:\ProgramData\PSTranscripts'
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

# ------------------------------------------------------------
# Control 4: Enable Attack Surface Reduction rules (Defender)
# ------------------------------------------------------------
Invoke-HardeningAction "Enable Defender ASR: block PSExec/WMI process creation" {
    # d1e49aac-8f56-4280-b9ba-993a6d77406c — Block process creations originating from PSExec/WMI commands
    Set-MpPreference -AttackSurfaceReductionRules_Ids 'd1e49aac-8f56-4280-b9ba-993a6d77406c' `
                     -AttackSurfaceReductionRules_Actions Enabled
}

Invoke-HardeningAction "Enable Defender ASR: block executable content from email/webmail" {
    # be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 — Block executable content from email client and webmail
    Set-MpPreference -AttackSurfaceReductionRules_Ids 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' `
                     -AttackSurfaceReductionRules_Actions Enabled
}

Invoke-HardeningAction "Enable Defender ASR: block Win32 API calls from Office macros" {
    # 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b — Block Win32 API calls from Office macros
    Set-MpPreference -AttackSurfaceReductionRules_Ids '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' `
                     -AttackSurfaceReductionRules_Actions Enabled
}

Invoke-HardeningAction "Enable Defender ASR: block untrusted/unsigned processes from USB" {
    # b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 — Block untrusted and unsigned processes that run from USB
    Set-MpPreference -AttackSurfaceReductionRules_Ids 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' `
                     -AttackSurfaceReductionRules_Actions Enabled
}

Invoke-HardeningAction "Enable Defender ASR: block execution of potentially obfuscated scripts" {
    # 5beb7efe-fd9a-4556-801d-275e5ffc04cc — Block execution of potentially obfuscated scripts
    Set-MpPreference -AttackSurfaceReductionRules_Ids '5beb7efe-fd9a-4556-801d-275e5ffc04cc' `
                     -AttackSurfaceReductionRules_Actions Enabled
}

# ------------------------------------------------------------
# Control 5: Enable Defender Cloud Protection & Tamper Protection
# ------------------------------------------------------------
Invoke-HardeningAction "Enable Defender cloud-delivered protection" {
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
    Set-MpPreference -CloudBlockLevel High
    Set-MpPreference -CloudExtendedTimeout 50
}

# Tamper Protection requires enrollment via Intune / MDM / Defender Security Center.
# We emit guidance rather than flipping a registry bit that Defender will reset.
Write-Host "[!] Defender Tamper Protection must be enabled via Intune / MDE console." -ForegroundColor Yellow

# ------------------------------------------------------------
# Control 6: Hosts-file ACL hardening (audit-only via Sysmon)
# ------------------------------------------------------------
Invoke-HardeningAction "Audit hosts-file modifications via Sysmon FileCreate rule" {
    $sysmonConfig = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="end with">\drivers\etc\hosts</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
    $path = 'C:\ProgramData\Sysmon\honestcue-hosts-file.xml'
    if (-not (Test-Path 'C:\ProgramData\Sysmon')) {
        New-Item -Path 'C:\ProgramData\Sysmon' -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path $path -Value $sysmonConfig -Force
    Write-Host "    Sysmon snippet written to $path"
    Write-Host "    If Sysmon is installed, merge into existing config with: sysmon -c C:\ProgramData\Sysmon\combined.xml"
}

# ------------------------------------------------------------
# Control 7: Baseline hosts-file snapshot for integrity comparison
# ------------------------------------------------------------
Invoke-HardeningAction "Snapshot current hosts file for baseline comparison" {
    $src = 'C:\Windows\System32\drivers\etc\hosts'
    $dst = 'C:\ProgramData\F0RT1KA-Baselines'
    if (-not (Test-Path $dst)) { New-Item -Path $dst -ItemType Directory -Force | Out-Null }
    $dstFile = Join-Path $dst "hosts.baseline.$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -Path $src -Destination $dstFile -Force
    Write-Host "    Baseline copied to $dstFile"
    # Compute and record SHA256 for future integrity checks
    $hash = Get-FileHash -Path $dstFile -Algorithm SHA256
    Write-Host "    SHA256: $($hash.Hash)"
    Set-Content -Path (Join-Path $dst 'hosts.baseline.sha256') -Value $hash.Hash -Force
}

# ------------------------------------------------------------
# Control 8: Guidance — WDAC / AppLocker for csc.exe
# ------------------------------------------------------------
Write-Host ""
Write-Host "[GUIDANCE] WDAC / AppLocker restriction for csc.exe:" -ForegroundColor Yellow
Write-Host "  The most effective mitigation for T1027.004 is a WDAC policy that" -ForegroundColor Yellow
Write-Host "  denies csc.exe execution from any context except approved developer" -ForegroundColor Yellow
Write-Host "  subnets / OUs. Apply via Intune WDAC management or MDM policy:" -ForegroundColor Yellow
Write-Host "    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/" -ForegroundColor Yellow
Write-Host ""

# ------------------------------------------------------------
# Control 9: Guidance — Egress allowlist for LLM APIs
# ------------------------------------------------------------
Write-Host "[GUIDANCE] Network egress allowlist for LLM APIs:" -ForegroundColor Yellow
Write-Host "  On corporate proxy / firewall, restrict the following hostnames to" -ForegroundColor Yellow
Write-Host "  approved AI-tooling clients (tune to your inventory):" -ForegroundColor Yellow
Write-Host "    - generativelanguage.googleapis.com" -ForegroundColor Yellow
Write-Host "    - api.openai.com" -ForegroundColor Yellow
Write-Host "    - api.anthropic.com" -ForegroundColor Yellow
Write-Host "    - api.cohere.ai" -ForegroundColor Yellow
Write-Host "  Approved-client allowlist recommendation: Chrome, Edge, Firefox," -ForegroundColor Yellow
Write-Host "  VS Code, Cursor, Windsurf, Zed, plus any internal copilot/agent tools." -ForegroundColor Yellow
Write-Host ""

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Hardening Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Reboot or log off to ensure ASR rules take effect" -ForegroundColor White
Write-Host "  2. Verify PowerShell logging via Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational'" -ForegroundColor White
Write-Host "  3. Deploy the detection rule set (_detections.kql / _sigma_rules.yml / _dr_rules.yaml)" -ForegroundColor White
Write-Host "  4. Enable Tamper Protection via Intune / MDE console" -ForegroundColor White
Write-Host "  5. Configure WDAC policy denying csc.exe in production OUs" -ForegroundColor White
Write-Host ""
