<#
.SYNOPSIS
    Hardening against RoguePlanet-class Windows Defender remediation TOCTOU LPE.

.DESCRIPTION
    Defensive measures for the RoguePlanet local privilege escalation
    (MITRE ATT&CK T1068 / T1036.005 / T1053.005), which plants an attacker binary at
    C:\Windows\System32\wermgr.exe via a TOCTOU race against Defender's SYSTEM clean
    path and runs it as SYSTEM through the built-in WER QueueReporting task.

    Applies:
      1. Defender posture hardening (tamper protection, cloud + PUA protection).
         NOTE: real-time protection is intentionally NEVER disabled.
      2. ASR rules (Audit mode by default) that constrain unknown-executable launches.
      3. SACL audit ACE on System32\wermgr.exe (writes -> Event 4663).
      4. Process-creation auditing with command line.
      5. Guidance for restricting non-admin ISO/VHD mounting (the PoC prerequisite).

    Test ID: aa764293-94ed-4b25-a7fb-7d6fc14ac9a4
    MITRE ATT&CK: T1068, T1036.005, T1053.005
    Mitigations: M1051, M1038, M1028, M1040, M1047

.PARAMETER Enforce
    Switch ASR rules from Audit (default) to Block/Enforce.

.PARAMETER Undo
    Reverts changes made by this script (audit ACE, ASR rules -> Disabled).

.PARAMETER WhatIf
    Shows what would change without applying.

.EXAMPLE
    .\aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_hardening.ps1
    Applies hardening with ASR rules in Audit mode.

.EXAMPLE
    .\aa764293-94ed-4b25-a7fb-7d6fc14ac9a4_hardening.ps1 -Enforce
    Applies hardening with ASR rules in Block mode.

.NOTES
    Run as Administrator. Self-elevates and bypasses execution policy for this process.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Enforce,
    [switch]$Undo
)

# --- Execution policy bypass for this process ---
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch {}

# --- Admin check + self-elevation ---
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Warning "Administrator privileges required. Attempting to relaunch elevated..."
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    if ($Enforce) { $argList += '-Enforce' }
    if ($Undo)    { $argList += '-Undo' }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

$WermgrPath = "$env:WINDIR\System32\wermgr.exe"

# ASR rule GUIDs relevant to constraining unknown-executable launches / LPE staging.
$AsrRules = @{
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block untrusted/unknown executables'
    # Block process creations originating from PSExec and WMI commands
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block PSExec/WMI process creation'
    # Block credential stealing from LSASS
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
}

function Set-AsrRules {
    param([string]$Action) # 'AuditMode' | 'Enabled' | 'Disabled'
    foreach ($guid in $AsrRules.Keys) {
        $desc = $AsrRules[$guid]
        if ($PSCmdlet.ShouldProcess("ASR rule $desc ($guid)", "Set $Action")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $Action -ErrorAction Stop
                Write-Host "[OK]   ASR '$desc' -> $Action"
            } catch {
                Write-Warning "[WARN] Could not set ASR '$desc': $($_.Exception.Message)"
            }
        }
    }
}

function Set-DefenderPosture {
    if ($PSCmdlet.ShouldProcess("Windows Defender", "Harden posture (cloud/PUA/tamper)")) {
        try { Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue } catch {}
        try { Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue } catch {}
        try { Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue } catch {}
        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
        # Tamper protection is managed via security settings / Intune; report current state.
        try {
            $tp = (Get-MpComputerStatus).IsTamperProtected
            Write-Host "[INFO] Defender Tamper Protection currently: $tp (enable via Windows Security / Intune if false)"
        } catch {}
        Write-Host "[OK]   Defender posture hardened (real-time protection left ENABLED by design)."
    }
}

function Set-WermgrAuditAce {
    if (-not (Test-Path $WermgrPath)) { Write-Warning "[WARN] $WermgrPath not found."; return }
    if ($PSCmdlet.ShouldProcess($WermgrPath, "Add SACL audit ACE for write/delete")) {
        try {
            $acl = Get-Acl -Path $WermgrPath -Audit
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                "WriteData,AppendData,Delete,WriteAttributes,WriteExtendedAttributes",
                "Success,Failure")
            $acl.AddAuditRule($rule)
            Set-Acl -Path $WermgrPath -AclObject $acl
            Write-Host "[OK]   SACL audit ACE added to $WermgrPath (writes -> Event 4663)."
        } catch {
            Write-Warning "[WARN] Could not set SACL on $WermgrPath: $($_.Exception.Message)"
        }
    }
}

function Remove-WermgrAuditAce {
    if (-not (Test-Path $WermgrPath)) { return }
    if ($PSCmdlet.ShouldProcess($WermgrPath, "Remove SACL audit ACEs")) {
        try {
            $acl = Get-Acl -Path $WermgrPath -Audit
            $acl.GetAuditRules($true,$false,[System.Security.Principal.NTAccount]) | ForEach-Object {
                $acl.RemoveAuditRule($_) | Out-Null
            }
            Set-Acl -Path $WermgrPath -AclObject $acl
            Write-Host "[OK]   Removed SACL audit ACEs from $WermgrPath."
        } catch { Write-Warning "[WARN] $($_.Exception.Message)" }
    }
}

function Set-ProcessAuditing {
    if ($PSCmdlet.ShouldProcess("Audit policy", "Enable process creation auditing + command line")) {
        try {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
            # Include command line in 4688 events
            $k = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
            New-ItemProperty -Path $k -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
            Write-Host "[OK]   Process creation auditing enabled (with command line)."
        } catch { Write-Warning "[WARN] $($_.Exception.Message)" }
    }
}

# ============================== MAIN ==============================
Write-Host "==============================================================="
Write-Host " RoguePlanet LPE Hardening (T1068 / T1036.005 / T1053.005)"
Write-Host "==============================================================="

if ($Undo) {
    Write-Host "[*] Reverting hardening changes..."
    Set-AsrRules -Action 'Disabled'
    Remove-WermgrAuditAce
    Write-Host "[*] Undo complete. (Defender posture/auditpol left as-is intentionally.)"
    return
}

Set-DefenderPosture
$asrAction = if ($Enforce) { 'Enabled' } else { 'AuditMode' }
Write-Host "[*] Applying ASR rules in mode: $asrAction"
Set-AsrRules -Action $asrAction
Set-WermgrAuditAce
Set-ProcessAuditing

Write-Host ""
Write-Host "[*] Reminder (manual): restrict non-admin ISO/VHD mounting — RoguePlanet"
Write-Host "    requires a standard user to mount an ISO. Monitor 'Microsoft-Windows-VHDMP'"
Write-Host "    Operational log for AttachVirtualDisk by non-elevated processes, and consider"
Write-Host "    a WDAC/AppLocker policy constraining unknown-executable launches."
Write-Host ""
Write-Host "[*] Patch state matters most: ensure Windows + Defender platform are current."
Write-Host "[OK] Hardening complete."
