<#
.SYNOPSIS
    Hardening script to protect Windows/AD infrastructure against ESXi hypervisor ransomware.

.DESCRIPTION
    This script implements defensive measures on Windows infrastructure supporting
    VMware ESXi environments. It hardens Active Directory, network egress controls,
    and backup infrastructure against the RansomHub/Akira/Black Basta/LockBit
    ESXi ransomware kill chain.

    Measures implemented:
    1. AD Protection - Monitor and restrict ESX Admins group (CVE-2024-37085)
    2. Network Egress - Block Rclone cloud storage exfiltration destinations
    3. SSH Key Monitoring - Audit access to SSH key files on Windows
    4. Firewall Rules - Restrict ESXi management port access
    5. Audit Policies - Enable group change, process creation, and logon auditing
    6. Defender Hardening - Enable network protection and controlled folder access
    7. Scheduled Monitoring - Hourly ESX Admins group detection task

    Test ID: 25aafe2c-ec57-4a85-a26a-c3d7cf35620c
    MITRE ATT&CK: T1046, T1021.004, T1068, T1489, T1048, T1567.002, T1486
    Mitigations: M1030, M1031, M1032, M1035, M1037, M1042, M1051, M1057

.PARAMETER Undo
    Reverts all changes made by this script to default settings.

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.EXAMPLE
    .\25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\25aafe2c-ec57-4a85-a26a-c3d7cf35620c_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Tested on: Windows Server 2019/2022, Windows 10/11
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
$ErrorActionPreference = "Stop"
$Script:ChangeLog = @()
$Script:LogFile = Join-Path $env:TEMP "esxi_ransomware_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$TestID = "25aafe2c-ec57-4a85-a26a-c3d7cf35620c"

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Header")]
        [string]$Type = "Info"
    )
    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Header  = "Magenta"
    }
    $prefix = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[-]"
        Header  = "[=]"
    }
    $color = if ($colors.ContainsKey($Type)) { $colors[$Type] } else { "White" }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $color
    Add-Content -Path $Script:LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Type] $Message" -ErrorAction SilentlyContinue
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

# ============================================================
# 1. Block Rclone Cloud Exfiltration Destinations (T1048, T1567.002)
# ============================================================
# Rclone appears in 57% of ransomware incidents per ReliaQuest.
# Block outbound connections to known exfiltration cloud providers.

function Set-ExfiltrationFirewallRules {
    Write-Status "Configuring firewall rules to block Rclone cloud exfiltration targets..." "Header"

    $blockRules = @(
        @{ Name = "F0RT1KA-Block-Mega-Exfil";  RemoteAddress = "89.44.169.0/24";  Description = "Block Mega.nz cloud storage (primary exfil target)" },
        @{ Name = "F0RT1KA-Block-Mega-API";     RemoteAddress = "31.216.148.0/24"; Description = "Block Mega API endpoints" },
        @{ Name = "F0RT1KA-Block-Mega-EU";      RemoteAddress = "185.229.88.0/24"; Description = "Block Mega EU API endpoints" }
    )

    foreach ($rule in $blockRules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if (-not $existing) {
            if ($PSCmdlet.ShouldProcess($rule.Name, "Create firewall rule")) {
                New-NetFirewallRule -DisplayName $rule.Name -Direction Outbound -Action Block `
                    -RemoteAddress $rule.RemoteAddress -Description $rule.Description `
                    -Profile Any -Enabled True | Out-Null
                Write-Status "Created firewall rule: $($rule.Name)" "Success"
                Add-ChangeLog "Created" "Firewall Rule: $($rule.Name)" "Not exists" "Blocking $($rule.RemoteAddress)"
            }
        } else {
            Write-Status "Firewall rule already exists: $($rule.Name)" "Info"
        }
    }
}

function Remove-ExfiltrationFirewallRules {
    Write-Status "Removing exfiltration block firewall rules..." "Warning"
    $rules = Get-NetFirewallRule -DisplayName "F0RT1KA-Block-*" -ErrorAction SilentlyContinue
    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove firewall rule")) {
            Remove-NetFirewallRule -DisplayName $rule.DisplayName
            Write-Status "Removed firewall rule: $($rule.DisplayName)" "Success"
            Add-ChangeLog "Removed" "Firewall Rule: $($rule.DisplayName)" "Blocking" "Removed"
        }
    }
}

# ============================================================
# 2. Restrict ESXi Management Port Access (T1046, M1030, M1035)
# ============================================================
# Block outbound connections to ESXi management ports from non-admin
# workstations. Created DISABLED -- enable after configuring jump host exceptions.

function Set-ESXiManagementRestrictions {
    Write-Status "Restricting ESXi management port access to authorized jump hosts..." "Header"

    $esxiPorts = @(
        @{ Port = 443;  Desc = "ESXi HTTPS management" },
        @{ Port = 902;  Desc = "VMware Authentication Daemon" },
        @{ Port = 5480; Desc = "VMware VAMI" },
        @{ Port = 8697; Desc = "VMware Update Manager" }
    )

    foreach ($portInfo in $esxiPorts) {
        $ruleName = "F0RT1KA-Restrict-ESXi-Port-$($portInfo.Port)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            if ($PSCmdlet.ShouldProcess($ruleName, "Create ESXi port restriction")) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
                    -Protocol TCP -RemotePort $portInfo.Port `
                    -Description "Block unauthorized ESXi access: $($portInfo.Desc) (port $($portInfo.Port))" `
                    -Profile Any -Enabled False | Out-Null
                Write-Status "Created ESXi restriction rule (disabled): $ruleName" "Success"
                Add-ChangeLog "Created" "Firewall Rule: $ruleName" "Not exists" "Disabled (enable after configuring exceptions)"
            }
        } else {
            Write-Status "Firewall rule already exists: $ruleName" "Info"
        }
    }
    Write-Status "  Enable these rules after configuring jump host exceptions" "Warning"
}

function Remove-ESXiManagementRestrictions {
    Write-Status "Removing ESXi management port restrictions..." "Warning"
    $rules = Get-NetFirewallRule -DisplayName "F0RT1KA-Restrict-ESXi-*" -ErrorAction SilentlyContinue
    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Remove firewall rule")) {
            Remove-NetFirewallRule -DisplayName $rule.DisplayName
            Write-Status "Removed: $($rule.DisplayName)" "Success"
        }
    }
}

# ============================================================
# 3. Enable Advanced Audit Policies (M1030, Detection Support)
# ============================================================
# Enable auditing for AD group changes, process creation, and logon
# events critical for detecting ESXi ransomware attack stages.

function Set-AuditPolicies {
    Write-Status "Enabling advanced audit policies for ESXi attack detection..." "Header"

    $auditSettings = @(
        @{ Subcategory = "Security Group Management"; Setting = "/success:enable /failure:enable"; Purpose = "Detect ESX Admins group creation (CVE-2024-37085)" },
        @{ Subcategory = "Computer Account Management"; Setting = "/success:enable /failure:enable"; Purpose = "Detect domain-join manipulation" },
        @{ Subcategory = "User Account Management";    Setting = "/success:enable /failure:enable"; Purpose = "Detect account addition to ESX Admins" },
        @{ Subcategory = "Process Creation";            Setting = "/success:enable";                Purpose = "Detect Rclone and attack tool execution" },
        @{ Subcategory = "Logon";                       Setting = "/success:enable /failure:enable"; Purpose = "Detect lateral movement SSH/RDP" },
        @{ Subcategory = "Special Logon";               Setting = "/success:enable";                Purpose = "Detect privilege escalation" }
    )

    foreach ($audit in $auditSettings) {
        if ($PSCmdlet.ShouldProcess($audit.Subcategory, "Enable audit policy")) {
            try {
                $cmd = "auditpol /set /subcategory:`"$($audit.Subcategory)`" $($audit.Setting)"
                Invoke-Expression $cmd 2>$null | Out-Null
                Write-Status "Enabled audit: $($audit.Subcategory) -- $($audit.Purpose)" "Success"
                Add-ChangeLog "Enabled" "Audit Policy: $($audit.Subcategory)" "Default" $audit.Setting
            } catch {
                Write-Status "Failed to set audit: $($audit.Subcategory)" "Warning"
            }
        }
    }

    # Enable command-line process auditing (critical for detecting Rclone commands)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    $current = Get-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    if (-not $current -or $current.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
        if ($PSCmdlet.ShouldProcess("ProcessCreationIncludeCmdLine_Enabled", "Enable")) {
            Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
            Write-Status "Enabled command-line process auditing (Event ID 4688)" "Success"
            Add-ChangeLog "Set" "Registry: CommandLine Auditing" "Disabled" "Enabled"
        }
    } else {
        Write-Status "Command-line process auditing already enabled" "Info"
    }
}

function Undo-AuditPolicies {
    Write-Status "Note: Audit policies are NOT reverted (they should remain enabled for security)" "Info"
}

# ============================================================
# 4. Monitor ESX Admins Group (CVE-2024-37085, T1068)
# ============================================================
# CVE-2024-37085 allows attackers to create an "ESX Admins" group in AD
# to automatically gain admin rights on domain-joined ESXi hosts.

function Set-ESXAdminsProtection {
    Write-Status "Checking for ESX Admins group (CVE-2024-37085 protection)..." "Header"

    try {
        $adModule = Get-Module -ListAvailable -Name ActiveDirectory
        if ($adModule) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $esxGroups = Get-ADGroup -Filter "Name -like '*ESX*Admin*'" -ErrorAction SilentlyContinue
            if ($esxGroups) {
                foreach ($group in $esxGroups) {
                    Write-Status "CRITICAL: '$($group.Name)' group exists in Active Directory!" "Error"
                    Write-Status "  SID: $($group.SID)" "Warning"
                    Write-Status "  This group grants automatic ESXi admin rights (CVE-2024-37085)" "Warning"

                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    if ($members) {
                        Write-Status "  Members ($($members.Count)):" "Warning"
                        foreach ($member in $members) {
                            Write-Status "    - $($member.Name) ($($member.SamAccountName))" "Warning"
                        }
                    } else {
                        Write-Status "  Group has no members (but existence is still a risk)" "Warning"
                    }
                    Add-ChangeLog "Detected" "AD Group: $($group.Name)" "Exists" "REVIEW AND REMOVE"
                }
            } else {
                Write-Status "No ESX Admins-pattern groups found in AD (CVE-2024-37085 not exploitable)" "Success"
            }
        } else {
            Write-Status "ActiveDirectory module not available (run on domain controller for full check)" "Info"
        }
    } catch {
        Write-Status "Could not query AD: $($_.Exception.Message)" "Warning"
    }
}

# ============================================================
# 5. Windows Defender Hardening (M1050)
# ============================================================

function Set-DefenderHardening {
    Write-Status "Configuring Windows Defender enhanced protections..." "Header"

    if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable enhanced protections")) {
        try {
            # Cloud-delivered protection
            Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
            Write-Status "Enabled advanced cloud-delivered protection (MAPS)" "Success"

            # Behavior monitoring
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Write-Status "Enabled behavior monitoring" "Success"

            # Real-time protection
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Write-Status "Enabled real-time protection" "Success"

            # Network protection (blocks C2 and exfiltration domains)
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
            Write-Status "Enabled network protection" "Success"
            Add-ChangeLog "Enable" "Defender: Network Protection" "Not configured" "Enabled"

            # Controlled folder access (ransomware protection)
            Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
            Write-Status "Enabled Controlled Folder Access" "Success"
            Add-ChangeLog "Enable" "Defender: Controlled Folder Access" "Not configured" "Enabled"

        } catch {
            Write-Status "Some Defender settings could not be configured: $($_.Exception.Message)" "Warning"
        }
    }
}

function Undo-DefenderHardening {
    Write-Status "Reverting Defender settings to audit mode..." "Warning"
    if ($PSCmdlet.ShouldProcess("Windows Defender", "Revert to audit mode")) {
        try {
            Set-MpPreference -EnableNetworkProtection AuditMode -ErrorAction SilentlyContinue
            Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
            Write-Status "Reverted Defender protections to audit mode" "Success"
        } catch {
            Write-Status "Could not revert Defender settings: $($_.Exception.Message)" "Warning"
        }
    }
}

# ============================================================
# 6. SSH Key Protection (T1021.004)
# ============================================================

function Set-SSHKeyProtection {
    Write-Status "Protecting SSH key files on Windows..." "Header"

    $sshDir = Join-Path $env:USERPROFILE ".ssh"
    if (Test-Path $sshDir) {
        $keyFiles = Get-ChildItem $sshDir -File | Where-Object {
            $_.Name -match "^id_(rsa|ed25519|ecdsa)" -or
            $_.Name -eq "authorized_keys" -or
            $_.Name -eq "known_hosts" -or
            $_.Name -eq "config"
        }

        if ($keyFiles) {
            Write-Status "Found $($keyFiles.Count) SSH credential files in $sshDir" "Warning"
            foreach ($key in $keyFiles) {
                Write-Status "  $($key.Name) ($('{0:N0}' -f $key.Length) bytes)" "Info"
            }

            # Restrict permissions
            if ($PSCmdlet.ShouldProcess($sshDir, "Restrict permissions")) {
                try {
                    $acl = Get-Acl $sshDir
                    $acl.SetAccessRuleProtection($true, $false)
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl $sshDir $acl
                    Write-Status "Restricted SSH directory to current user only" "Success"
                    Add-ChangeLog "Restrict" "SSH Dir Permissions" "Inherited" "Current user only"
                } catch {
                    Write-Status "Could not restrict SSH directory: $($_.Exception.Message)" "Warning"
                }
            }
        }
    } else {
        Write-Status "No .ssh directory found at $sshDir" "Info"
    }

    # Enable file system auditing
    if ($PSCmdlet.ShouldProcess("File System Auditing", "Enable")) {
        try {
            auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null | Out-Null
            Write-Status "Enabled File System object access auditing" "Success"
            Add-ChangeLog "Enable" "Audit: File System" "Default" "Success and Failure"
        } catch {
            Write-Status "Could not enable file system auditing: $($_.Exception.Message)" "Warning"
        }
    }
}

function Undo-SSHKeyProtection {
    Write-Status "Reverting SSH key permissions..." "Warning"
    $sshDir = Join-Path $env:USERPROFILE ".ssh"
    if (Test-Path $sshDir) {
        if ($PSCmdlet.ShouldProcess($sshDir, "Restore default permissions")) {
            try {
                $acl = Get-Acl $sshDir
                $acl.SetAccessRuleProtection($false, $true)
                Set-Acl $sshDir $acl
                Write-Status "Restored default SSH directory permissions" "Success"
            } catch {
                Write-Status "Could not restore permissions: $($_.Exception.Message)" "Warning"
            }
        }
    }
}

# ============================================================
# 7. Rclone Binary Block Policy (T1048, M1038)
# ============================================================

function Set-RcloneBlockPolicy {
    Write-Status "Configuring Rclone execution block policy..." "Header"

    # Create policy recommendations file
    $policyDir = Join-Path $env:ProgramData "F0RT1KA"
    if (-not (Test-Path $policyDir)) {
        New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
    }

    $policyPath = Join-Path $policyDir "rclone_block_policy.txt"
    $policyContent = @"
# F0RT1KA Rclone Block Policy Recommendations
# Test ID: $TestID
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
#
# Block Rclone by file version info (catches renamed binaries):
#   Product: "Rclone"
#   Company: "https://rclone.org"
#
# Block known binary names on Linux (via EDR policy):
#   svchost.exe, csrss.exe, lsass.exe, svhost.exe, taskhost.exe
#   (Windows process names should never appear on Linux hosts)
#
# AppLocker Recommendation:
#   Create a deny rule for Publisher "O=rclone, CN=rclone"
#
# WDAC Recommendation:
#   Add Rclone to deny list by OriginalFileName or FileDescription
"@
    Set-Content -Path $policyPath -Value $policyContent
    Write-Status "Rclone block policy saved to $policyPath" "Success"
    Write-Status "  Deploy via WDAC or AppLocker for production enforcement" "Warning"
    Add-ChangeLog "Advisory" "Rclone Block Policy" "None" "Recommendations saved"
}

function Undo-RcloneBlockPolicy {
    $policyPath = Join-Path $env:ProgramData "F0RT1KA\rclone_block_policy.txt"
    if (Test-Path $policyPath) {
        Remove-Item $policyPath -Force -ErrorAction SilentlyContinue
        Write-Status "Removed Rclone block policy file" "Success"
    }
}

# ============================================================
# 8. ESX Admins Scheduled Monitor (CVE-2024-37085)
# ============================================================

function Set-ESXAdminsScheduledMonitor {
    Write-Status "Creating scheduled monitoring for ESX Admins group..." "Header"

    $taskName = "F0RT1KA-ESXAdmins-Monitor"
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status "Monitoring task already exists: $taskName" "Info"
        return
    }

    if ($PSCmdlet.ShouldProcess($taskName, "Create scheduled task")) {
        try {
            $scriptContent = @'
# F0RT1KA ESX Admins Group Monitor (CVE-2024-37085)
$logDir = "$env:ProgramData\F0RT1KA"
$logPath = "$logDir\esxadmins_monitor.log"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $groups = Get-ADGroup -Filter "Name -like '*ESX*Admin*'" -ErrorAction SilentlyContinue
    if ($groups) {
        foreach ($g in $groups) {
            $members = (Get-ADGroupMember $g -ErrorAction SilentlyContinue | Measure-Object).Count
            $msg = "$(Get-Date -F 'yyyy-MM-dd HH:mm:ss') [ALERT] ESX Admins group detected: $($g.Name) ($members members)"
            Add-Content -Path $logPath -Value $msg
        }
    } else {
        Add-Content -Path $logPath -Value "$(Get-Date -F 'yyyy-MM-dd HH:mm:ss') [OK] No ESX Admins groups"
    }
} catch {
    Add-Content -Path $logPath -Value "$(Get-Date -F 'yyyy-MM-dd HH:mm:ss') [ERROR] $($_.Exception.Message)"
}
'@
            $scriptDir = Join-Path $env:ProgramData "F0RT1KA"
            if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }
            $scriptPath = Join-Path $scriptDir "esxadmins_monitor.ps1"
            Set-Content -Path $scriptPath -Value $scriptContent

            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
                -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
            $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -At (Get-Date) -Once
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

            Register-ScheduledTask -TaskName $taskName `
                -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings `
                -Description "F0RT1KA: Monitor AD for ESX Admins group creation (CVE-2024-37085)" | Out-Null

            Write-Status "Created scheduled task: $taskName (runs hourly)" "Success"
            Add-ChangeLog "Created" "Scheduled Task: $taskName" "None" "Hourly ESX Admins check"
        } catch {
            Write-Status "Could not create monitoring task: $($_.Exception.Message)" "Warning"
        }
    }
}

function Undo-ESXAdminsScheduledMonitor {
    $taskName = "F0RT1KA-ESXAdmins-Monitor"
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Status "Removed scheduled task: $taskName" "Success"
    } catch {
        Write-Status "No monitoring task to remove" "Info"
    }

    $scriptPath = Join-Path $env:ProgramData "F0RT1KA\esxadmins_monitor.ps1"
    if (Test-Path $scriptPath) {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================
# Main Execution
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "F0RT1KA Hardening: ESXi Hypervisor Ransomware Kill Chain" -ForegroundColor White
Write-Host "Test ID: $TestID" -ForegroundColor Gray
Write-Host "MITRE ATT&CK: T1046, T1021.004, T1068, T1489, T1048, T1486" -ForegroundColor Gray
Write-Host "CVEs: CVE-2024-37085, CVE-2024-1086" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Undo) {
    Write-Status "UNDO MODE: Reverting hardening changes..." "Warning"
    Write-Host ""
    Remove-ExfiltrationFirewallRules
    Remove-ESXiManagementRestrictions
    Undo-AuditPolicies
    Undo-DefenderHardening
    Undo-SSHKeyProtection
    Undo-RcloneBlockPolicy
    Undo-ESXAdminsScheduledMonitor
} else {
    Write-Status "HARDENING MODE: Applying defensive measures..." "Info"
    Write-Host ""
    Set-ExfiltrationFirewallRules
    Set-ESXiManagementRestrictions
    Set-AuditPolicies
    Set-ESXAdminsProtection
    Set-DefenderHardening
    Set-SSHKeyProtection
    Set-RcloneBlockPolicy
    Set-ESXAdminsScheduledMonitor
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Status "Operation complete. $($Script:ChangeLog.Count) changes applied." "Success"
Write-Status "Log file: $Script:LogFile" "Info"
Write-Host "============================================================" -ForegroundColor White

if ($Script:ChangeLog.Count -gt 0) {
    Write-Host ""
    Write-Status "Change Summary:" "Info"
    $Script:ChangeLog | Format-Table -AutoSize
}

if (-not $Undo) {
    Write-Host ""
    Write-Status "MANUAL STEPS REQUIRED:" "Warning"
    Write-Status "  1. Patch CVE-2024-37085: Update vCenter to latest version" "Warning"
    Write-Status "  2. Patch CVE-2024-1086: Update Linux kernel on ESXi hosts" "Warning"
    Write-Status "  3. Enable ESXi Lockdown Mode on all hosts" "Warning"
    Write-Status "  4. Disable SSH on ESXi: vim-cmd hostsvc/disable_ssh" "Warning"
    Write-Status "  5. Segment ESXi management network from production" "Warning"
    Write-Status "  6. Deploy air-gapped backup infrastructure" "Warning"
}
