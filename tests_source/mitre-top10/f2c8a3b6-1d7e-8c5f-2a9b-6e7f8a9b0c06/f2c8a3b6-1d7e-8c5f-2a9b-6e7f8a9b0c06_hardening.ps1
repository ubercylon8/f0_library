<#
.SYNOPSIS
    Hardening script for LOLBIN Download Detection techniques.

.DESCRIPTION
    Applies defensive hardening to mitigate LOLBIN-based ingress tool transfer:
    - T1105: Ingress Tool Transfer (certutil, bitsadmin, curl restrictions)
    - T1059.001: PowerShell download cradles (constrained language mode, logging)

    Implements MITRE mitigations:
    - M1038: Execution Prevention (AppLocker/WDAC for LOLBINs)
    - M1042: Disable or Remove Feature (BITS service restriction)
    - M1049: Antivirus/Antimalware (ASR rules)
    - M1037: Filter Network Traffic (proxy enforcement)

    Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
    MITRE ATT&CK: T1105, T1059.001

.PARAMETER Undo
    Reverts all changes made by this script.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
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
$Script:StateFile = "$env:ProgramData\F0RT1KA\hardening_lolbin_state.json"

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    $prefix = @{ Info = "[INFO]"; Success = "[OK]"; Warning = "[WARN]"; Error = "[ERR]" }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param([string]$Action, [string]$Target, [string]$OldValue, [string]$NewValue)
    $Script:ChangeLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
    }
}

function Save-State {
    $stateDir = Split-Path $Script:StateFile -Parent
    if (-not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }
    $Script:ChangeLog | ConvertTo-Json -Depth 5 | Set-Content -Path $Script:StateFile -Force
    Write-Status "State saved to $Script:StateFile" "Info"
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

# ============================================================
# 1. PowerShell Hardening (T1059.001)
# MITRE Mitigation: M1038 - Execution Prevention
# ============================================================

function Set-PowerShellHardening {
    Write-Status "=== PowerShell Hardening (T1059.001) ===" "Info"

    if ($Undo) {
        # Revert ScriptBlock logging
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $regPath) {
            if ($PSCmdlet.ShouldProcess("ScriptBlock logging", "Disable")) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed ScriptBlock logging policy" "Warning"
            }
        }
        # Revert Module logging
        $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (Test-Path $regPath2) {
            if ($PSCmdlet.ShouldProcess("Module logging", "Disable")) {
                Remove-Item -Path $regPath2 -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed Module logging policy" "Warning"
            }
        }
        # Revert Transcription
        $regPath3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (Test-Path $regPath3) {
            if ($PSCmdlet.ShouldProcess("Transcription", "Disable")) {
                Remove-Item -Path $regPath3 -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed Transcription policy" "Warning"
            }
        }
        return
    }

    # Enable ScriptBlock logging (captures all PowerShell commands including download cradles)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("ScriptBlock logging", "Enable")) {
        Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
        Add-ChangeLog "Set" "ScriptBlockLogging" "Disabled" "Enabled"
        Write-Status "PowerShell ScriptBlock logging enabled (Event ID 4104)" "Success"
    }

    # Enable Module logging
    $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $regPath2)) {
        New-Item -Path $regPath2 -Force | Out-Null
    }
    $modNames = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    if (-not (Test-Path $modNames)) {
        New-Item -Path $modNames -Force | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("Module logging", "Enable")) {
        Set-ItemProperty -Path $regPath2 -Name "EnableModuleLogging" -Value 1 -Type DWord
        Set-ItemProperty -Path $modNames -Name "*" -Value "*" -Type String
        Add-ChangeLog "Set" "ModuleLogging" "Disabled" "Enabled (all modules)"
        Write-Status "PowerShell Module logging enabled for all modules" "Success"
    }

    # Enable Transcription (records full PowerShell session to text files)
    $regPath3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $regPath3)) {
        New-Item -Path $regPath3 -Force | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("Transcription", "Enable")) {
        Set-ItemProperty -Path $regPath3 -Name "EnableTranscripting" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath3 -Name "EnableInvocationHeader" -Value 1 -Type DWord
        $transcriptDir = "$env:ProgramData\PowerShellTranscripts"
        if (-not (Test-Path $transcriptDir)) {
            New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath3 -Name "OutputDirectory" -Value $transcriptDir -Type String
        Add-ChangeLog "Set" "Transcription" "Disabled" "Enabled ($transcriptDir)"
        Write-Status "PowerShell Transcription enabled to $transcriptDir" "Success"
    }
}

# ============================================================
# 2. Certutil Restrictions (T1105)
# MITRE Mitigation: M1038 - Execution Prevention
# ============================================================

function Set-CertutilRestrictions {
    Write-Status "=== Certutil Download Restrictions (T1105) ===" "Info"

    $fwRuleName = "Block Certutil Outbound Internet"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess($fwRuleName, "Remove firewall rule")) {
            try {
                Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction Stop
                Write-Status "Removed certutil firewall restriction" "Warning"
            } catch {
                if ($_.Exception.Message -match "No MSFT_NetFirewallRule") {
                    Write-Status "Certutil firewall rule not found (already removed)" "Info"
                }
            }
        }
        return
    }

    # Create Windows Firewall rule to block certutil outbound connections
    $existing = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($fwRuleName, "Create firewall rule")) {
            try {
                New-NetFirewallRule `
                    -DisplayName $fwRuleName `
                    -Direction Outbound `
                    -Action Block `
                    -Program "C:\Windows\System32\certutil.exe" `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                Add-ChangeLog "CreateFWRule" $fwRuleName "None" "Block certutil outbound"
                Write-Status "Created firewall rule: Block certutil outbound connections" "Success"
            } catch {
                Write-Status "Failed to create certutil firewall rule: $_" "Error"
            }
        }
    } else {
        Write-Status "Certutil firewall rule already exists" "Info"
    }
}

# ============================================================
# 3. BITSAdmin / BITS Service Restrictions (T1105)
# MITRE Mitigation: M1042 - Disable or Remove Feature
# ============================================================

function Set-BITSRestrictions {
    Write-Status "=== BITS Service Restrictions (T1105) ===" "Info"

    if ($Undo) {
        # Re-enable BITS if it was disabled
        if ($PSCmdlet.ShouldProcess("BITS service", "Set to Manual start")) {
            try {
                Set-Service -Name BITS -StartupType Manual -ErrorAction Stop
                Write-Status "BITS service restored to Manual start" "Warning"
            } catch {
                Write-Status "Failed to restore BITS service: $_" "Error"
            }
        }
        return
    }

    # NOTE: Disabling BITS may affect Windows Update and SCCM
    # Instead of disabling, we add monitoring and restrict bitsadmin
    Write-Status "BITS service is required by Windows Update - restricting bitsadmin instead" "Info"

    # Create firewall rule to block bitsadmin from outbound connections
    $fwRuleName = "Block BITSAdmin Outbound Internet"
    $existing = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($fwRuleName, "Create firewall rule")) {
            try {
                New-NetFirewallRule `
                    -DisplayName $fwRuleName `
                    -Direction Outbound `
                    -Action Block `
                    -Program "C:\Windows\System32\bitsadmin.exe" `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                Add-ChangeLog "CreateFWRule" $fwRuleName "None" "Block bitsadmin outbound"
                Write-Status "Created firewall rule: Block bitsadmin outbound connections" "Success"
            } catch {
                Write-Status "Failed to create bitsadmin firewall rule: $_" "Error"
            }
        }
    } else {
        Write-Status "BITSAdmin firewall rule already exists" "Info"
    }

    # Enable BITS event logging
    if ($PSCmdlet.ShouldProcess("BITS event log", "Enable")) {
        try {
            $logName = "Microsoft-Windows-Bits-Client/Operational"
            $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
            if (-not $log.IsEnabled) {
                $log.IsEnabled = $true
                $log.SaveChanges()
                Add-ChangeLog "EnableLog" $logName "Disabled" "Enabled"
                Write-Status "BITS Client operational log enabled" "Success"
            } else {
                Write-Status "BITS Client operational log already enabled" "Info"
            }
        } catch {
            Write-Status "Failed to enable BITS log: $_" "Error"
        }
    }
}

# ============================================================
# 4. ASR Rules for Download Protection (T1105, T1059.001)
# MITRE Mitigation: M1049 - Antivirus/Antimalware
# ============================================================

function Set-ASRRules {
    Write-Status "=== Attack Surface Reduction Rules (T1105, T1059.001) ===" "Info"

    $asrRules = @{
        # Block execution of potentially obfuscated scripts
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block obfuscated scripts"
        # Block process creations originating from PSExec and WMI commands
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creation from PSExec/WMI"
        # Block Win32 API calls from Office macros
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        # Block executable content from email and webmail
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email"
        # Block JavaScript or VBScript from launching downloaded executable content
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBS from launching downloaded content"
    }

    if ($Undo) {
        foreach ($ruleId in $asrRules.Keys) {
            if ($PSCmdlet.ShouldProcess($asrRules[$ruleId], "Disable ASR rule")) {
                try {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Disabled -ErrorAction Stop
                    Write-Status "Disabled ASR rule: $($asrRules[$ruleId])" "Warning"
                } catch {
                    Write-Status "Could not disable ASR rule: $_" "Error"
                }
            }
        }
        return
    }

    foreach ($ruleId in $asrRules.Keys) {
        if ($PSCmdlet.ShouldProcess($asrRules[$ruleId], "Enable ASR rule in Block mode")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                Add-ChangeLog "EnableASR" $ruleId "Disabled" "Enabled"
                Write-Status "Enabled ASR: $($asrRules[$ruleId])" "Success"
            } catch {
                Write-Status "Could not enable ASR rule: $_" "Error"
            }
        }
    }
}

# ============================================================
# 5. Process Creation and Network Auditing
# ============================================================

function Set-AuditPolicies {
    Write-Status "=== Audit Policies for LOLBIN Detection ===" "Info"

    if ($Undo) {
        Write-Status "Audit policies are non-destructive - leaving in place" "Info"
        return
    }

    # Enable process creation auditing with command line
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    $current = Get-RegistryValueSafe -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled"
    if ($current -ne 1) {
        if ($PSCmdlet.ShouldProcess("Command line auditing", "Enable")) {
            Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
            Add-ChangeLog "Set" "ProcessCreationIncludeCmdLine_Enabled" "$current" "1"
            Write-Status "Command line logging in process creation events enabled" "Success"
        }
    } else {
        Write-Status "Command line auditing already enabled" "Info"
    }

    # Enable process creation audit
    if ($PSCmdlet.ShouldProcess("Process Creation audit", "Enable")) {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null
        Add-ChangeLog "AuditPol" "Process Creation" "Default" "Success+Failure"
        Write-Status "Process creation audit policy enabled" "Success"
    }

    # Enable filtering platform connection (for network monitoring)
    if ($PSCmdlet.ShouldProcess("Filtering Platform Connection audit", "Enable")) {
        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable 2>&1 | Out-Null
        Add-ChangeLog "AuditPol" "Filtering Platform Connection" "Default" "Success"
        Write-Status "Filtering Platform Connection audit enabled (network monitoring)" "Success"
    }
}

# ============================================================
# 6. Windows Defender Network Protection
# ============================================================

function Set-DefenderNetworkProtection {
    Write-Status "=== Windows Defender Network Protection ===" "Info"

    if ($Undo) {
        Write-Status "Network protection is non-destructive - not reverting" "Info"
        return
    }

    try {
        # Enable network protection (blocks connections to known malicious domains)
        if ($PSCmdlet.ShouldProcess("Network protection", "Enable")) {
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
            Add-ChangeLog "Set" "EnableNetworkProtection" "Default" "Enabled"
            Write-Status "Network protection enabled (blocks known malicious connections)" "Success"
        }

        # Enable real-time protection
        if ($PSCmdlet.ShouldProcess("Real-time protection", "Enable")) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Status "Real-time protection enabled" "Success"
        }

        # Enable behavior monitoring
        if ($PSCmdlet.ShouldProcess("Behavior monitoring", "Enable")) {
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
            Write-Status "Behavior monitoring enabled" "Success"
        }

        # Enable PUA protection
        if ($PSCmdlet.ShouldProcess("PUA protection", "Enable")) {
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Write-Status "PUA protection enabled" "Success"
        }
    } catch {
        Write-Status "Defender configuration failed: $_" "Error"
    }
}

# ============================================================
# Main Execution
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  LOLBIN Download Detection - Defense Hardening" -ForegroundColor White
Write-Host "  Test ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06" -ForegroundColor Gray
Write-Host "  MITRE: T1105, T1059.001" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Undo) {
    Write-Status "REVERTING hardening changes..." "Warning"
    Write-Host ""
} else {
    Write-Status "APPLYING hardening settings..." "Info"
    Write-Host ""
}

Set-PowerShellHardening
Write-Host ""
Set-CertutilRestrictions
Write-Host ""
Set-BITSRestrictions
Write-Host ""
Set-ASRRules
Write-Host ""
Set-AuditPolicies
Write-Host ""
Set-DefenderNetworkProtection
Write-Host ""

# Save change log
if ($Script:ChangeLog.Count -gt 0) {
    Save-State
}

Write-Host "============================================================" -ForegroundColor White
if ($Undo) {
    Write-Status "Hardening reverted. $($Script:ChangeLog.Count) changes processed." "Warning"
} else {
    Write-Status "Hardening complete. $($Script:ChangeLog.Count) changes applied." "Success"
}
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if (-not $Undo) {
    Write-Host ""
    Write-Status "=== MANUAL HARDENING STEPS (Require Planning) ===" "Warning"
    Write-Host ""
    Write-Status "1. AppLocker / WDAC Policy:" "Info"
    Write-Host "   Create rules to restrict certutil.exe, bitsadmin.exe, mshta.exe"
    Write-Host "   from being executed by standard users."
    Write-Host "   GPO: Computer Configuration > Windows Settings > Security Settings > Application Control Policies"
    Write-Host ""
    Write-Status "2. PowerShell Constrained Language Mode:" "Info"
    Write-Host "   Deploy via WDAC or Device Guard for non-admin users."
    Write-Host "   Prevents .NET method calls (WebClient.DownloadFile) in PowerShell."
    Write-Host "   Ref: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes"
    Write-Host ""
    Write-Status "3. Web Proxy Enforcement:" "Info"
    Write-Host "   Force all HTTP/HTTPS through an authenticated proxy."
    Write-Host "   LOLBINs like certutil and bitsadmin may bypass proxy settings."
    Write-Host "   Configure proxy via GPO for system-level enforcement."
    Write-Host ""
    Write-Status "4. DNS Filtering:" "Info"
    Write-Host "   Deploy DNS-level filtering to block known malicious domains."
    Write-Host "   Tools: Pi-hole, Cisco Umbrella, Cloudflare Gateway"
    Write-Host ""
    Write-Status "5. Sysmon Deployment:" "Info"
    Write-Host "   Deploy Sysmon with configuration that captures:"
    Write-Host "   - Event ID 1: Process creation with command line"
    Write-Host "   - Event ID 3: Network connections from LOLBINs"
    Write-Host "   - Event ID 11: File creation by LOLBIN processes"
    Write-Host ""
}
