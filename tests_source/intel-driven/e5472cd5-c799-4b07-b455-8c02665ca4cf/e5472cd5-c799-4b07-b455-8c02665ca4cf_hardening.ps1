# ============================================================================
# Hardening Script — HONESTCUE v2 LLM-Assisted Runtime C# Compilation
# Test ID: e5472cd5-c799-4b07-b455-8c02665ca4cf
# Version: 2.1.0
# MITRE ATT&CK: T1071.001, T1027.004, T1027.010, T1620, T1105, T1204.002
# Date: 2026-04-13 (v2)
# Author: F0RT1KA Defense Guidance Builder
# ============================================================================
# Applies Windows endpoint hardening controls that mitigate HONESTCUE-class
# LLM-as-runtime-component malware chains. v2 controls focus on:
#   - PowerShell ScriptBlock logging (AMSI coverage for Assembly.Load)
#   - ASR rules (block untrusted file execution, block executable content
#     launched from email, etc.)
#   - Defender real-time + tamper protection
#   - AppLocker DLL rule for Microsoft.CodeAnalysis.CSharp.dll (optional)
#   - Sysmon configuration snippet for DNS logging (raw.githubusercontent.com)
#
# v1 hosts-file FIM logic removed — v2 no longer manipulates the hosts file.
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
    [switch]$DryRun = $false,
    [switch]$SkipASR = $false,
    [switch]$SkipAppLocker = $false
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-BypassExecutionPolicy {
    if ((Get-ExecutionPolicy) -ne 'Bypass') {
        try {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
            Write-Host "  [OK] ExecutionPolicy set to Bypass for this process" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not change ExecutionPolicy: $_" -ForegroundColor Yellow
        }
    }
}

function Write-Header($title) {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
}

function Write-Action($msg) { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info($msg)   { Write-Host "  [*] $msg" -ForegroundColor Gray }
function Write-Warn($msg)   { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)    { Write-Host "  [X] $msg" -ForegroundColor Red }

if (-not (Test-IsAdmin)) {
    Write-Err "Administrator privileges required. Re-run PowerShell as Administrator."
    exit 1
}

Invoke-BypassExecutionPolicy

Write-Header "HONESTCUE v2 Hardening Script"
Write-Host "  DryRun: $DryRun"
Write-Host "  SkipASR: $SkipASR"
Write-Host "  SkipAppLocker: $SkipAppLocker"

# ============================================================================
# 1. PowerShell ScriptBlock Logging (event 4104) + Module Logging
# ============================================================================
Write-Header "1. PowerShell Logging (covers Assembly.Load AMSI + Add-Type)"

$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psModulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$psTranscriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

if (-not $DryRun) {
    New-Item -Path $psLogPath -Force | Out-Null
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
    Write-Action "ScriptBlockLogging enabled"

    New-Item -Path $psModulePath -Force | Out-Null
    Set-ItemProperty -Path $psModulePath -Name "EnableModuleLogging" -Value 1 -Type DWord
    New-Item -Path "$psModulePath\ModuleNames" -Force | Out-Null
    Set-ItemProperty -Path "$psModulePath\ModuleNames" -Name "*" -Value "*"
    Write-Action "ModuleLogging enabled for all modules"

    $transcriptDir = "C:\PSTranscripts"
    New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
    New-Item -Path $psTranscriptionPath -Force | Out-Null
    Set-ItemProperty -Path $psTranscriptionPath -Name "EnableTranscripting" -Value 1 -Type DWord
    Set-ItemProperty -Path $psTranscriptionPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
    Set-ItemProperty -Path $psTranscriptionPath -Name "OutputDirectory" -Value $transcriptDir -Type String
    Write-Action "Transcription enabled -> $transcriptDir"
} else {
    Write-Info "[DRY-RUN] Would enable ScriptBlockLogging, ModuleLogging, Transcription"
}

# ============================================================================
# 2. Attack Surface Reduction (ASR) Rules
# ============================================================================
if (-not $SkipASR) {
    Write-Header "2. Defender Attack Surface Reduction (ASR) Rules"

    # ASR rule IDs relevant to HONESTCUE v2
    $asrRules = @(
        # Block executable files from running unless they meet a prevalence/age/trusted-list criterion
        @{ Id = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Name = "Block untrusted/unsigned processes from USB" }
        # Block Office communication applications from creating child processes
        @{ Id = "26190899-1602-49e8-8b27-eb1d0a1ce869"; Name = "Block Office comms from creating children" }
        # Block credential stealing from LSASS
        @{ Id = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Name = "Block LSASS credential stealing" }
        # Block process creations originating from PSExec/WMI commands
        @{ Id = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; Name = "Block PSExec/WMI-originated processes" }
        # Block executable content from email/webmail
        @{ Id = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"; Name = "Block exec content from email/webmail" }
        # Use advanced protection against ransomware
        @{ Id = "c1db55ab-c21a-4637-bb3f-a12568109d35"; Name = "Advanced ransomware protection" }
    )

    foreach ($rule in $asrRules) {
        if (-not $DryRun) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id `
                                 -AttackSurfaceReductionRules_Actions Enabled `
                                 -ErrorAction Stop
                Write-Action "ASR enabled: $($rule.Name) ($($rule.Id))"
            } catch {
                Write-Warn "Could not enable ASR $($rule.Id): $_"
            }
        } else {
            Write-Info "[DRY-RUN] Would enable ASR: $($rule.Name) ($($rule.Id))"
        }
    }
} else {
    Write-Header "2. ASR Rules (SKIPPED via -SkipASR)"
}

# ============================================================================
# 3. Defender Real-Time Protection + Tamper Protection
# ============================================================================
Write-Header "3. Defender Real-Time + Tamper Protection"

if (-not $DryRun) {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Action "Real-time monitoring enforced ON"
    } catch {
        Write-Warn "Could not set RealtimeMonitoring: $_"
    }

    try {
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
        Set-MpPreference -CloudBlockLevel High
        Set-MpPreference -CloudExtendedTimeout 50
        Write-Action "Defender hardening: BehaviorMonitoring ON, BlockAtFirstSeen ON, IOAV ON, ScriptScanning ON, Cloud High"
    } catch {
        Write-Warn "Could not apply Defender hardening: $_"
    }

    # Tamper Protection must typically be enabled via MDE / Intune — here we
    # only report state.
    $tamperState = (Get-MpComputerStatus).IsTamperProtected
    if ($tamperState) {
        Write-Action "Tamper Protection is already ENABLED"
    } else {
        Write-Warn "Tamper Protection NOT enabled — enable via MDE/Intune policy"
    }
} else {
    Write-Info "[DRY-RUN] Would enforce Defender real-time + report Tamper Protection state"
}

# ============================================================================
# 4. (Optional) AppLocker DLL rule for Microsoft.CodeAnalysis.CSharp.dll
# ============================================================================
if (-not $SkipAppLocker) {
    Write-Header "4. AppLocker DLL Rule for Roslyn (Microsoft.CodeAnalysis.CSharp.dll)"
    Write-Info "This is an ADVISORY recommendation — apply via Group Policy"
    Write-Info "to restrict Microsoft.CodeAnalysis.CSharp.dll to approved dev tools."
    Write-Info "Manual steps:"
    Write-Info "  1. Open 'Local Security Policy' -> 'Application Control Policies'"
    Write-Info "  2. Enable DLL rules collection"
    Write-Info "  3. Add Deny rule for Microsoft.CodeAnalysis.CSharp.dll"
    Write-Info "     with exceptions for devenv.exe, Code.exe, dotnet.exe, MSBuild.exe,"
    Write-Info "     csc.exe, rider64.exe."
    Write-Info "This blocks HONESTCUE v2 stage-2 Roslyn compile pipeline."
} else {
    Write-Header "4. AppLocker DLL rule (SKIPPED via -SkipAppLocker)"
}

# ============================================================================
# 5. Sysmon DNS logging snippet (for raw.githubusercontent.com monitoring)
# ============================================================================
Write-Header "5. Sysmon DNS Logging Recommendation (EventID 22)"

Write-Info "Add the following <DnsQuery> snippet to your Sysmon config to surface"
Write-Info "DNS queries for trusted-hosting CDNs from unexpected processes:"
Write-Host ""
Write-Host @"
  <DnsQuery onmatch="include">
    <QueryName condition="contains any">
      raw.githubusercontent.com;
      objects.githubusercontent.com;
      cdn.discordapp.com;
      media.discordapp.net;
      generativelanguage.googleapis.com;
      api.openai.com;
      api.anthropic.com
    </QueryName>
  </DnsQuery>
"@ -ForegroundColor DarkCyan

# ============================================================================
# 6. Auto-update Defender signatures
# ============================================================================
Write-Header "6. Update Defender Signatures"
if (-not $DryRun) {
    try {
        Update-MpSignature -UpdateSource MicrosoftUpdateServer
        Write-Action "Defender signatures updated"
    } catch {
        Write-Warn "Could not update signatures: $_"
    }
} else {
    Write-Info "[DRY-RUN] Would run Update-MpSignature"
}

# ============================================================================
# Summary
# ============================================================================
Write-Header "Hardening Complete"
Write-Host ""
Write-Host "  Applied controls:" -ForegroundColor Green
Write-Host "    - PowerShell ScriptBlock + Module + Transcription logging"
Write-Host "    - Defender Attack Surface Reduction rules (relevant subset)"
Write-Host "    - Defender Real-time Protection + Cloud High + MAPS Advanced"
Write-Host "    - Defender signature refresh"
Write-Host ""
Write-Host "  Recommended next steps:" -ForegroundColor Yellow
Write-Host "    - Enable Tamper Protection via Intune/MDE policy"
Write-Host "    - Deploy AppLocker DLL Deny rule for Microsoft.CodeAnalysis.CSharp.dll"
Write-Host "    - Apply Sysmon DNS-query include list snippet"
Write-Host "    - Ingest PSTranscripts (C:\PSTranscripts) into SIEM"
Write-Host "    - Deploy detection rules from this test package (KQL, YARA, Sigma, EQL, LC D&R)"
Write-Host ""
Write-Host "  Test validation:" -ForegroundColor Cyan
Write-Host "    - Re-run e5472cd5-c799-4b07-b455-8c02665ca4cf.exe after hardening"
Write-Host "    - Expect exit code 126 (blocked) when protections are fully deployed"
