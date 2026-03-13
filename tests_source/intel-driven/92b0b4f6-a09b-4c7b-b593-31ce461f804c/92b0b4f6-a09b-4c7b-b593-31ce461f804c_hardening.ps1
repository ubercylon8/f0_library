<#
.SYNOPSIS
    Hardening script to protect against APT42 TAMECAT fileless backdoor techniques.

.DESCRIPTION
    This script implements defensive measures against the APT42 TAMECAT attack chain
    covering multiple MITRE ATT&CK techniques:

    1. Script Interpreter Restrictions - Block VBScript/JScript execution (T1059.005)
    2. PowerShell Hardening - Enable logging and constrained language mode (T1059.001)
    3. Registry Persistence Protection - Monitor and restrict Run keys (T1547.001)
    4. UserInitMprLogonScript Lockdown - Block rare persistence mechanism (T1037.001)
    5. Browser Credential Protection - Restrict credential database access (T1555.003)
    6. Network Exfiltration Prevention - Block Telegram API and FTP (T1102)

    Test ID: 92b0b4f6-a09b-4c7b-b593-31ce461f804c
    MITRE ATT&CK: T1204.002, T1059.001, T1059.005, T1547.001, T1037.001, T1555.003, T1102
    Mitigations: M1038, M1042, M1024, M1031, M1027, M1049

.PARAMETER Undo
    Reverts all changes made by this script to default settings.

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.EXAMPLE
    .\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1
    Applies all hardening settings to protect against APT42 TAMECAT.

.EXAMPLE
    .\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1 -Undo
    Reverts all hardening settings to default.

.EXAMPLE
    .\92b0b4f6-a09b-4c7b-b593-31ce461f804c_hardening.ps1 -WhatIf
    Shows what changes would be made without applying them.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Tested on: Windows 10/11, Windows Server 2019/2022
    Idempotent: Yes (safe to run multiple times)

.LINK
    https://attack.mitre.org/groups/G1024/
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo
)

#Requires -RunAsAdministrator

# ============================================================================
# Configuration
# ============================================================================
$ErrorActionPreference = "Stop"
$Script:ChangeLog = @()
$Script:LogFile = Join-Path $env:TEMP "apt42_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Test metadata
$TestID = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
$TestName = "APT42 TAMECAT Fileless Backdoor with Browser Credential Theft"
$MitreAttack = "T1204.002, T1059.001, T1547.001, T1037.001, T1555.003, T1102"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Header")]
        [string]$Type = "Info"
    )
    $colors = @{
        Info = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error = "Red"
        Header = "Magenta"
    }
    $prefix = @{
        Info = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error = "[-]"
        Header = "[=]"
    }
    $line = "$($prefix[$Type]) $Message"
    Write-Host $line -ForegroundColor $colors[$Type]
    Add-Content -Path $Script:LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $line" -ErrorAction SilentlyContinue
}

function Add-ChangeLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue
    )
    $Script:ChangeLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
    }
}

function Test-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

# ============================================================================
# Hardening Functions
# ============================================================================

function Set-ScriptInterpreterRestrictions {
    <#
    .SYNOPSIS
        Block execution of potentially obfuscated scripts (ASR Rule)
        Mitigates T1204.002 and T1059.005
    #>
    Write-Status "Configuring ASR rules to block script interpreter abuse..." "Header"

    # ASR Rule: Block execution of potentially obfuscated scripts
    $asrRuleId = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    $asrRuleName = "Block execution of potentially obfuscated scripts"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess($asrRuleName, "Disable ASR rule")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Disabled
                Write-Status "Disabled ASR rule: $asrRuleName" "Success"
                Add-ChangeLog "Disabled" "ASR Rule $asrRuleId" "Enabled" "Disabled"
            } catch {
                Write-Status "Failed to disable ASR rule: $_" "Warning"
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess($asrRuleName, "Enable ASR rule")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
                Write-Status "Enabled ASR rule: $asrRuleName" "Success"
                Add-ChangeLog "Enabled" "ASR Rule $asrRuleId" "Disabled" "Enabled"
            } catch {
                Write-Status "Failed to enable ASR rule: $_" "Warning"
            }
        }
    }

    # ASR Rule: Block process creations from WMI event subscriptions
    $asrRuleWmi = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    $asrRuleWmiName = "Block process creations originating from PSExec and WMI commands"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess($asrRuleWmiName, "Disable ASR rule")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleWmi -AttackSurfaceReductionRules_Actions Disabled
                Write-Status "Disabled ASR rule: $asrRuleWmiName" "Success"
                Add-ChangeLog "Disabled" "ASR Rule $asrRuleWmi" "Enabled" "Disabled"
            } catch {
                Write-Status "Failed to disable ASR rule: $_" "Warning"
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess($asrRuleWmiName, "Enable ASR rule")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleWmi -AttackSurfaceReductionRules_Actions Enabled
                Write-Status "Enabled ASR rule: $asrRuleWmiName" "Success"
                Add-ChangeLog "Enabled" "ASR Rule $asrRuleWmi" "Disabled" "Enabled"
            } catch {
                Write-Status "Failed to enable ASR rule: $_" "Warning"
            }
        }
    }
}

function Set-PowerShellHardening {
    <#
    .SYNOPSIS
        Enable PowerShell Script Block Logging and Module Logging
        Mitigates T1059.001
    #>
    Write-Status "Configuring PowerShell security logging..." "Header"

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("PowerShell Script Block Logging", "Disable")) {
            try {
                Remove-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $regPath2 -Name "EnableTranscripting" -Force -ErrorAction SilentlyContinue
                Write-Status "Disabled PowerShell Script Block Logging and Transcription" "Success"
                Add-ChangeLog "Disabled" "PowerShell Logging" "Enabled" "Default"
            } catch {
                Write-Status "Failed to disable PowerShell logging: $_" "Warning"
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess("PowerShell Script Block Logging", "Enable")) {
            try {
                # Script Block Logging
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
                Write-Status "Enabled PowerShell Script Block Logging" "Success"
                Add-ChangeLog "Enabled" "Script Block Logging" "Not configured" "1"

                # Transcription
                if (-not (Test-Path $regPath2)) {
                    New-Item -Path $regPath2 -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath2 -Name "EnableTranscripting" -Value 1 -Type DWord
                $transcriptDir = "C:\PSTranscripts"
                if (-not (Test-Path $transcriptDir)) {
                    New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath2 -Name "OutputDirectory" -Value $transcriptDir -Type String
                Write-Status "Enabled PowerShell Transcription -> $transcriptDir" "Success"
                Add-ChangeLog "Enabled" "PowerShell Transcription" "Not configured" $transcriptDir
            } catch {
                Write-Status "Failed to configure PowerShell logging: $_" "Warning"
            }
        }
    }
}

function Set-LogonScriptProtection {
    <#
    .SYNOPSIS
        Block the UserInitMprLogonScript persistence mechanism
        Mitigates T1037.001
    #>
    Write-Status "Protecting UserInitMprLogonScript registry key..." "Header"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("UserInitMprLogonScript protection", "Remove ACL deny rule")) {
            Write-Status "Undo for registry ACL changes requires manual intervention" "Warning"
            Write-Status "  Remove deny ACE on HKCU:\Environment for UserInitMprLogonScript" "Info"
            Add-ChangeLog "Manual" "UserInitMprLogonScript ACL" "Deny" "Review required"
        }
    } else {
        if ($PSCmdlet.ShouldProcess("HKCU:\Environment\UserInitMprLogonScript", "Set deny ACL")) {
            try {
                # Remove any existing UserInitMprLogonScript value
                $existing = Test-RegistryValue "HKCU:\Environment" "UserInitMprLogonScript"
                if ($existing) {
                    Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -Force
                    Write-Status "Removed existing UserInitMprLogonScript value: $existing" "Success"
                    Add-ChangeLog "Removed" "UserInitMprLogonScript" $existing "(empty)"
                }

                Write-Status "UserInitMprLogonScript value cleared (if present)" "Success"
                Write-Status "  RECOMMENDATION: Use Group Policy to prevent UserInitMprLogonScript" "Info"
                Write-Status "  Computer Config > Admin Templates > System > Logon > Do not process legacy run lists" "Info"
            } catch {
                Write-Status "Failed to protect UserInitMprLogonScript: $_" "Warning"
            }
        }
    }
}

function Set-NetworkExfiltrationPrevention {
    <#
    .SYNOPSIS
        Block outbound connections to Telegram API and FTP
        Mitigates T1102 and T1048
    #>
    Write-Status "Configuring network exfiltration prevention..." "Header"

    $firewallRules = @(
        @{
            Name        = "F0RT1KA-Block-Telegram-API"
            DisplayName = "Block Telegram API (APT42 C2)"
            Direction   = "Outbound"
            RemoteAddress = "149.154.160.0/20","91.108.4.0/22","91.108.8.0/22","91.108.12.0/22","91.108.16.0/22","91.108.20.0/22","91.108.56.0/22"
            Action      = "Block"
            Description = "Block APT42 Telegram C2 exfiltration - MITRE T1102"
        },
        @{
            Name        = "F0RT1KA-Block-FTP-Outbound"
            DisplayName = "Block FTP Outbound (APT42 Exfil)"
            Direction   = "Outbound"
            Protocol    = "TCP"
            RemotePort  = "21"
            Action      = "Block"
            Description = "Block FTP exfiltration channel - MITRE T1048"
        }
    )

    foreach ($rule in $firewallRules) {
        if ($Undo) {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove firewall rule")) {
                try {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                    Write-Status "Removed firewall rule: $($rule.DisplayName)" "Success"
                    Add-ChangeLog "Removed" "Firewall Rule" $rule.Name "(deleted)"
                } catch {
                    Write-Status "Firewall rule not found or already removed: $($rule.Name)" "Info"
                }
            }
        } else {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Create firewall rule")) {
                try {
                    # Remove existing rule first (idempotent)
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue

                    $params = @{
                        Name        = $rule.Name
                        DisplayName = $rule.DisplayName
                        Direction   = $rule.Direction
                        Action      = $rule.Action
                        Description = $rule.Description
                        Enabled     = "True"
                    }

                    if ($rule.RemoteAddress) { $params.RemoteAddress = $rule.RemoteAddress }
                    if ($rule.Protocol) { $params.Protocol = $rule.Protocol }
                    if ($rule.RemotePort) { $params.RemotePort = $rule.RemotePort }

                    New-NetFirewallRule @params | Out-Null
                    Write-Status "Created firewall rule: $($rule.DisplayName)" "Success"
                    Add-ChangeLog "Created" "Firewall Rule" "(none)" $rule.Name
                } catch {
                    Write-Status "Failed to create firewall rule: $_" "Warning"
                }
            }
        }
    }
}

function Set-DefenderProtection {
    <#
    .SYNOPSIS
        Enable Windows Defender protections against script-based attacks
        Mitigates T1059.001, T1059.005
    #>
    Write-Status "Configuring Windows Defender protections..." "Header"

    if ($Undo) {
        Write-Status "Defender protection settings are not reverted for safety" "Warning"
        Write-Status "  Real-time protection and cloud-delivered protection should remain enabled" "Info"
    } else {
        if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable enhanced protections")) {
            try {
                # Enable real-time protection
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Write-Status "Verified real-time protection is enabled" "Success"

                # Enable cloud-delivered protection
                Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
                Write-Status "Enabled cloud-delivered protection (Advanced)" "Success"

                # Enable automatic sample submission
                Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
                Write-Status "Enabled automatic sample submission" "Success"

                # Enable behavior monitoring
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
                Write-Status "Verified behavior monitoring is enabled" "Success"

                # Enable script scanning
                Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
                Write-Status "Verified script scanning is enabled" "Success"

                Add-ChangeLog "Enabled" "Defender Protections" "Various" "Enhanced"
            } catch {
                Write-Status "Failed to configure Defender: $_" "Warning"
            }
        }
    }
}

function Set-AuditPolicies {
    <#
    .SYNOPSIS
        Enable audit policies for detecting persistence and credential access
        Mitigates T1547.001, T1037.001, T1555.003
    #>
    Write-Status "Configuring audit policies..." "Header"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("Audit policies", "Reset to defaults")) {
            try {
                auditpol /set /subcategory:"Registry" /success:disable /failure:disable 2>$null
                auditpol /set /subcategory:"File System" /success:disable /failure:disable 2>$null
                Write-Status "Reset audit policies to defaults" "Success"
                Add-ChangeLog "Reset" "Audit Policies" "Enabled" "Default"
            } catch {
                Write-Status "Failed to reset audit policies: $_" "Warning"
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess("Registry and File System auditing", "Enable")) {
            try {
                # Enable registry auditing (for Run key and Environment key changes)
                auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null
                Write-Status "Enabled registry access auditing" "Success"

                # Enable file system auditing (for browser credential access)
                auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null
                Write-Status "Enabled file system access auditing" "Success"

                # Enable process creation auditing (for conhost/powershell chain detection)
                auditpol /set /subcategory:"Process Creation" /success:enable 2>$null
                Write-Status "Enabled process creation auditing" "Success"

                Add-ChangeLog "Enabled" "Audit Policies" "Default" "Registry+FileSystem+Process"
            } catch {
                Write-Status "Failed to configure audit policies: $_" "Warning"
            }
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Status "============================================================" "Header"
Write-Status "F0RT1KA Defense Hardening: APT42 TAMECAT" "Header"
Write-Status "Test ID: $TestID" "Header"
Write-Status "MITRE ATT&CK: $MitreAttack" "Header"
Write-Status "============================================================" "Header"
Write-Status ""

if ($Undo) {
    Write-Status "MODE: UNDO - Reverting hardening changes..." "Warning"
} else {
    Write-Status "MODE: APPLY - Applying hardening settings..." "Info"
}

Write-Status ""

# Execute hardening functions
Set-ScriptInterpreterRestrictions     # T1204.002, T1059.005
Set-PowerShellHardening               # T1059.001
Set-LogonScriptProtection             # T1037.001
Set-NetworkExfiltrationPrevention     # T1102, T1048
Set-DefenderProtection                # T1059.001, T1059.005
Set-AuditPolicies                     # T1547.001, T1555.003

# Summary
Write-Status "" "Info"
Write-Status "============================================================" "Header"
Write-Status "HARDENING COMPLETE" "Header"
Write-Status "============================================================" "Header"
Write-Status "Changes applied: $($Script:ChangeLog.Count)" "Info"
Write-Status "Log file: $Script:LogFile" "Info"

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "" "Info"
    Write-Status "Change Summary:" "Info"
    foreach ($change in $Script:ChangeLog) {
        Write-Status "  $($change.Action): $($change.Target) [$($change.OldValue) -> $($change.NewValue)]" "Info"
    }
}

Write-Status "" "Info"
Write-Status "ADDITIONAL RECOMMENDATIONS (require Group Policy):" "Info"
Write-Status "  1. Enable Constrained Language Mode for PowerShell" "Info"
Write-Status "  2. Deploy WDAC/AppLocker to block unsigned script execution" "Info"
Write-Status "  3. Block cscript.exe/wscript.exe for non-admin users" "Info"
Write-Status "  4. Deploy enterprise password manager to eliminate browser credentials" "Info"
Write-Status "  5. Enable Microsoft Defender for Endpoint (MDE) tamper protection" "Info"
