<#
.SYNOPSIS
    Hardening script for APT33 Tickler Backdoor DLL Sideloading techniques.

.DESCRIPTION
    Applies defensive hardening to mitigate APT33 Tickler attack techniques:
    - T1566.001: Spearphishing Attachment (ASR rules, attachment blocking)
    - T1574.002: DLL Side-Loading (SafeDllSearchMode, CWDIllegalInDllSearch)
    - T1547.001: Registry Run Keys (audit policy, Run key restrictions)
    - T1053.005: Scheduled Task (audit policy, task creation restrictions)
    - T1036: Masquerading (process creation auditing, AppLocker guidance)
    - T1071.001: Web Protocols C2 (firewall rules for ports 808/880)

    Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9
    MITRE ATT&CK: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001
    Mitigations: M1049, M1038, M1054, M1031, M1036, M1037

.PARAMETER Undo
    Reverts all changes made by this script.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\13c2d073-8e33-4fca-ab27-68f20c408ce9_hardening.ps1 -Undo
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
$Script:StateFile = "$env:ProgramData\F0RT1KA\hardening_apt33_state.json"

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
# 1. DLL Sideloading Hardening (T1574.002)
# MITRE Mitigation: M1038 - Execution Prevention
# ============================================================

function Set-DllSideloadingProtection {
    Write-Status "=== DLL Sideloading Protection (T1574.002) ===" "Info"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

    if ($Undo) {
        # Restore SafeDllSearchMode to default (1 = enabled, which is default)
        Write-Status "SafeDllSearchMode is enabled by default - no revert needed" "Info"

        # Remove CWDIllegalInDllSearch if it was added
        $val = Get-RegistryValueSafe -Path $regPath -Name "CWDIllegalInDllSearch"
        if ($null -ne $val) {
            if ($PSCmdlet.ShouldProcess("CWDIllegalInDllSearch", "Remove registry value")) {
                Remove-ItemProperty -Path $regPath -Name "CWDIllegalInDllSearch" -ErrorAction SilentlyContinue
                Write-Status "Removed CWDIllegalInDllSearch registry value" "Success"
            }
        }
        return
    }

    # Enable SafeDllSearchMode (ensures System32 DLLs are loaded before CWD)
    $currentSafe = Get-RegistryValueSafe -Path $regPath -Name "SafeDllSearchMode"
    if ($currentSafe -ne 1) {
        if ($PSCmdlet.ShouldProcess("SafeDllSearchMode", "Set to 1")) {
            Set-ItemProperty -Path $regPath -Name "SafeDllSearchMode" -Value 1 -Type DWord
            Add-ChangeLog "Set" "SafeDllSearchMode" "$currentSafe" "1"
            Write-Status "SafeDllSearchMode enabled (System32 DLLs loaded first)" "Success"
        }
    } else {
        Write-Status "SafeDllSearchMode already enabled" "Info"
    }

    # Set CWDIllegalInDllSearch to block CWD DLL loading for remote paths
    # Value 2 = Block CWD from DLL search for UNC/WebDAV paths
    $currentCWD = Get-RegistryValueSafe -Path $regPath -Name "CWDIllegalInDllSearch"
    if ($currentCWD -ne 2) {
        if ($PSCmdlet.ShouldProcess("CWDIllegalInDllSearch", "Set to 2")) {
            Set-ItemProperty -Path $regPath -Name "CWDIllegalInDllSearch" -Value 2 -Type DWord
            Add-ChangeLog "Set" "CWDIllegalInDllSearch" "$currentCWD" "2"
            Write-Status "CWDIllegalInDllSearch set to block remote CWD DLL loading" "Success"
        }
    } else {
        Write-Status "CWDIllegalInDllSearch already configured" "Info"
    }
}

# ============================================================
# 2. ASR Rules for Spearphishing / DLL Sideloading (T1566.001, T1574.002)
# MITRE Mitigation: M1049 - Antivirus/Antimalware
# ============================================================

function Set-ASRRules {
    Write-Status "=== Attack Surface Reduction Rules (T1566.001, T1574.002) ===" "Info"

    # ASR Rule GUIDs
    $asrRules = @{
        # Block executable content from email and webmail
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email"
        # Block all Office applications from creating child processes
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office child processes"
        # Block Office applications from creating executable content
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office executable content creation"
        # Block Win32 API calls from Office macros
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        # Block execution of potentially obfuscated scripts
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block obfuscated scripts"
        # Block untrusted and unsigned processes from USB
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted USB processes"
    }

    if ($Undo) {
        foreach ($ruleId in $asrRules.Keys) {
            if ($PSCmdlet.ShouldProcess($asrRules[$ruleId], "Disable ASR rule")) {
                try {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Disabled -ErrorAction Stop
                    Write-Status "Disabled ASR rule: $($asrRules[$ruleId])" "Warning"
                } catch {
                    Write-Status "Could not disable ASR rule $ruleId : $_" "Error"
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
                Write-Status "Could not enable ASR rule $ruleId : $_" "Error"
            }
        }
    }
}

# ============================================================
# 3. Registry Run Key Auditing (T1547.001)
# MITRE Mitigation: M1054 - Software Configuration
# ============================================================

function Set-RegistryAuditing {
    Write-Status "=== Registry Run Key Auditing (T1547.001) ===" "Info"

    if ($Undo) {
        Write-Status "Registry auditing is non-destructive - leaving audit policies in place" "Info"
        return
    }

    # Enable auditing on registry Run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            try {
                $acl = Get-Acl -Path $key
                $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                    "Everyone",
                    "SetValue,CreateSubKey,Delete",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Success,Failure"
                )
                $acl.AddAuditRule($auditRule)
                if ($PSCmdlet.ShouldProcess($key, "Add audit rule")) {
                    Set-Acl -Path $key -AclObject $acl
                    Add-ChangeLog "AddAudit" $key "None" "SetValue,CreateSubKey,Delete"
                    Write-Status "Audit rule added for: $key" "Success"
                }
            } catch {
                Write-Status "Failed to set audit on $key : $_" "Error"
            }
        }
    }

    # Enable advanced audit policy for registry changes
    if ($PSCmdlet.ShouldProcess("Registry audit policy", "Enable")) {
        try {
            auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>&1 | Out-Null
            Add-ChangeLog "AuditPol" "Registry" "Default" "Success+Failure"
            Write-Status "Registry audit subcategory enabled (success + failure)" "Success"
        } catch {
            Write-Status "Failed to set audit policy: $_" "Error"
        }
    }
}

# ============================================================
# 4. Scheduled Task Auditing and Restrictions (T1053.005)
# MITRE Mitigation: M1054 - Software Configuration
# ============================================================

function Set-ScheduledTaskHardening {
    Write-Status "=== Scheduled Task Hardening (T1053.005) ===" "Info"

    if ($Undo) {
        # Revert task creation audit policy
        if ($PSCmdlet.ShouldProcess("Task Scheduler audit", "Revert to default")) {
            auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable 2>&1 | Out-Null
            Write-Status "Reverted scheduled task audit policy to default" "Warning"
        }
        return
    }

    # Enable auditing for scheduled task creation (Event ID 4698)
    if ($PSCmdlet.ShouldProcess("Task creation auditing", "Enable")) {
        try {
            auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>&1 | Out-Null
            Add-ChangeLog "AuditPol" "Other Object Access Events" "Default" "Success+Failure"
            Write-Status "Scheduled task creation auditing enabled (Event ID 4698)" "Success"
        } catch {
            Write-Status "Failed to enable task auditing: $_" "Error"
        }
    }

    # Enable Task Scheduler operational log
    $logName = "Microsoft-Windows-TaskScheduler/Operational"
    if ($PSCmdlet.ShouldProcess($logName, "Enable event log")) {
        try {
            $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
            if (-not $log.IsEnabled) {
                $log.IsEnabled = $true
                $log.SaveChanges()
                Add-ChangeLog "EnableLog" $logName "Disabled" "Enabled"
                Write-Status "Task Scheduler operational log enabled" "Success"
            } else {
                Write-Status "Task Scheduler operational log already enabled" "Info"
            }
        } catch {
            Write-Status "Failed to enable Task Scheduler log: $_" "Error"
        }
    }
}

# ============================================================
# 5. Firewall Rules for C2 Ports (T1071.001)
# MITRE Mitigation: M1031 - Network Intrusion Prevention
# ============================================================

function Set-C2FirewallRules {
    Write-Status "=== C2 Port Blocking Firewall Rules (T1071.001) ===" "Info"

    $firewallRules = @(
        @{ Name = "Block Outbound TCP 808 - APT33 C2"; Port = 808; Direction = "Outbound"; Protocol = "TCP" },
        @{ Name = "Block Outbound TCP 880 - APT33 C2"; Port = 880; Direction = "Outbound"; Protocol = "TCP" }
    )

    if ($Undo) {
        foreach ($rule in $firewallRules) {
            if ($PSCmdlet.ShouldProcess($rule.Name, "Remove firewall rule")) {
                try {
                    Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction Stop
                    Write-Status "Removed firewall rule: $($rule.Name)" "Warning"
                } catch {
                    if ($_.Exception.Message -match "No MSFT_NetFirewallRule") {
                        Write-Status "Firewall rule not found: $($rule.Name)" "Info"
                    } else {
                        Write-Status "Failed to remove rule: $_" "Error"
                    }
                }
            }
        }
        return
    }

    foreach ($rule in $firewallRules) {
        # Check if rule already exists
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Status "Firewall rule already exists: $($rule.Name)" "Info"
            continue
        }

        if ($PSCmdlet.ShouldProcess($rule.Name, "Create firewall rule")) {
            try {
                New-NetFirewallRule `
                    -DisplayName $rule.Name `
                    -Direction Outbound `
                    -Action Block `
                    -Protocol TCP `
                    -RemotePort $rule.Port `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                Add-ChangeLog "CreateFWRule" $rule.Name "None" "Block Outbound TCP $($rule.Port)"
                Write-Status "Created firewall rule: $($rule.Name)" "Success"
            } catch {
                Write-Status "Failed to create rule: $_" "Error"
            }
        }
    }
}

# ============================================================
# 6. Process Creation Auditing (T1036)
# MITRE Mitigation: M1036 - Account Use Policies
# ============================================================

function Set-ProcessCreationAuditing {
    Write-Status "=== Process Creation Auditing (T1036) ===" "Info"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("Command line auditing", "Revert to default")) {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            $val = Get-RegistryValueSafe -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled"
            if ($null -ne $val) {
                Remove-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
                Write-Status "Removed command line auditing registry key" "Warning"
            }
        }
        return
    }

    # Enable command line in process creation events (Event ID 4688)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $current = Get-RegistryValueSafe -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled"
    if ($current -ne 1) {
        if ($PSCmdlet.ShouldProcess("ProcessCreationIncludeCmdLine_Enabled", "Set to 1")) {
            Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
            Add-ChangeLog "Set" "ProcessCreationIncludeCmdLine_Enabled" "$current" "1"
            Write-Status "Command line logging in process creation events enabled" "Success"
        }
    } else {
        Write-Status "Command line auditing already enabled" "Info"
    }

    # Enable process creation audit policy
    if ($PSCmdlet.ShouldProcess("Process Creation audit policy", "Enable")) {
        try {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null
            Add-ChangeLog "AuditPol" "Process Creation" "Default" "Success+Failure"
            Write-Status "Process creation audit policy enabled" "Success"
        } catch {
            Write-Status "Failed to set process creation audit: $_" "Error"
        }
    }
}

# ============================================================
# 7. Windows Defender Configuration
# ============================================================

function Set-DefenderHardening {
    Write-Status "=== Windows Defender Configuration ===" "Info"

    if ($Undo) {
        Write-Status "Defender hardening is protective - not reverting" "Warning"
        Write-Status "To revert, use Set-MpPreference with default values manually" "Info"
        return
    }

    try {
        # Enable real-time protection
        if ($PSCmdlet.ShouldProcess("Real-time protection", "Enable")) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Status "Real-time protection enabled" "Success"
        }

        # Enable cloud-delivered protection
        if ($PSCmdlet.ShouldProcess("Cloud protection", "Enable")) {
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
            Write-Status "Cloud-delivered protection set to Advanced" "Success"
        }

        # Enable network protection (blocks C2 connections)
        if ($PSCmdlet.ShouldProcess("Network protection", "Enable")) {
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
            Add-ChangeLog "Set" "EnableNetworkProtection" "Default" "Enabled"
            Write-Status "Network protection enabled (blocks known malicious connections)" "Success"
        }

        # Enable PUA (Potentially Unwanted Application) protection
        if ($PSCmdlet.ShouldProcess("PUA protection", "Enable")) {
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Write-Status "PUA protection enabled" "Success"
        }

    } catch {
        Write-Status "Defender configuration failed (may not be available): $_" "Error"
    }
}

# ============================================================
# Main Execution
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  APT33 Tickler Backdoor - Defense Hardening" -ForegroundColor White
Write-Host "  Test ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9" -ForegroundColor Gray
Write-Host "  MITRE: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Undo) {
    Write-Status "REVERTING hardening changes..." "Warning"
    Write-Host ""
} else {
    Write-Status "APPLYING hardening settings..." "Info"
    Write-Host ""
}

Set-DllSideloadingProtection
Write-Host ""
Set-ASRRules
Write-Host ""
Set-RegistryAuditing
Write-Host ""
Set-ScheduledTaskHardening
Write-Host ""
Set-C2FirewallRules
Write-Host ""
Set-ProcessCreationAuditing
Write-Host ""
Set-DefenderHardening
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

# Display complex hardening that requires manual steps
if (-not $Undo) {
    Write-Host ""
    Write-Status "=== MANUAL HARDENING STEPS (Require Planning) ===" "Warning"
    Write-Host ""
    Write-Status "1. AppLocker / WDAC Policy:" "Info"
    Write-Host "   Block execution of binaries from user-writable directories"
    Write-Host "   that are not signed by trusted publishers."
    Write-Host "   GPO: Computer Configuration > Windows Settings > Security Settings > Application Control Policies"
    Write-Host ""
    Write-Status "2. Email Gateway Configuration:" "Info"
    Write-Host "   Block ZIP archives containing executable files (.exe, .dll, .scr)"
    Write-Host "   Strip or quarantine attachments with double extensions (.pdf.zip)"
    Write-Host ""
    Write-Status "3. Web Proxy / Firewall:" "Info"
    Write-Host "   Block outbound HTTP traffic on non-standard ports (808, 880)"
    Write-Host "   Monitor for SharePoint User-Agent strings from non-Microsoft processes"
    Write-Host ""
    Write-Status "4. Sysmon Deployment:" "Info"
    Write-Host "   Deploy Sysmon with configuration that logs:"
    Write-Host "   - Event ID 7: Image loaded (for DLL sideloading detection)"
    Write-Host "   - Event ID 12/13/14: Registry events (for Run key monitoring)"
    Write-Host "   - Event ID 1: Process creation with command line"
    Write-Host ""
}
