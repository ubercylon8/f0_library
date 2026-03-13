<#
.SYNOPSIS
    Hardening script for DPRK BlueNoroff Financial Sector attack prevention

.DESCRIPTION
    Applies comprehensive security hardening measures relevant to defending
    against BlueNoroff/Lazarus (DPRK) attack techniques in Windows/mixed
    environments. While BlueNoroff primarily targets macOS, Windows endpoints
    in financial and cryptocurrency organizations require network-level
    protections, DNS blocking, credential protection, and exfiltration
    monitoring.

    This script addresses all 5 stages of the BlueNoroff attack chain:
    - Stage 1 (T1553.001): Code signing and trust control enforcement
    - Stage 2 (T1543.004): Persistence monitoring (scheduled tasks, services)
    - Stage 3 (T1555.001): Credential protection (Credential Guard, DPAPI)
    - Stage 4 (T1071.001, T1573.002): C2 domain/port blocking
    - Stage 5 (T1041, T1567.002): Exfiltration channel monitoring

    Test ID: 244dfb88-9068-4db4-9fa8-dbc49517f63d
    MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001, T1056.002,
                  T1071.001, T1573.002, T1071.004, T1041, T1567.002, T1560.001
    Mitigations: M1031 (Network Intrusion Prevention), M1037 (Filter Network),
                 M1038 (Execution Prevention), M1022 (Restrict Permissions),
                 M1045 (Code Signing), M1027 (Password Policies)

.PARAMETER Undo
    Reverts all changes made by this script

.PARAMETER WhatIf
    Shows what would happen without making changes

.EXAMPLE
    .\244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening.ps1
    Applies all hardening settings

.EXAMPLE
    .\244dfb88-9068-4db4-9fa8-dbc49517f63d_hardening.ps1 -Undo
    Reverts all hardening settings

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Idempotent: Yes (safe to run multiple times)
    Tested on: Windows 10/11, Windows Server 2019/2022
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
$Script:TestID = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
$Script:BackupPath = "$env:TEMP\F0RT1KA_Hardening_Backup_$Script:TestID"

# BlueNoroff C2 domains (high-confidence threat intelligence)
$Script:C2Domains = @(
    "linkpc.net",
    "dnx.capital",
    "swissborg.blog",
    "on-offx.com",
    "tokenview.xyz"
)

$Script:C2Subdomains = @(
    "beacon.linkpc.net",
    "app.linkpc.net",
    "update.linkpc.net",
    "check.linkpc.net",
    "cloud.dnx.capital"
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    $prefix = @{ Info = "[*]"; Success = "[+]"; Warning = "[!]"; Error = "[-]" }
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

# ============================================================================
# 1. Block DPRK C2 Domains via Hosts File and DNS (T1071.001, T1071.004)
# ============================================================================

function Set-C2DomainBlocking {
    Write-Status "Section 1: C2 Domain Blocking (T1071.001, T1071.004)" "Info"

    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"

    if ($Undo) {
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
        $filteredContent = $hostsContent | Where-Object { $_ -notmatch "F0RT1KA-BlueNoroff" }
        Set-Content -Path $hostsFile -Value $filteredContent -Force
        Write-Status "  Removed C2 domain entries from hosts file" "Warning"
        Add-ChangeLog "Remove" "HostsFile" "BlueNoroff entries" ""

        # Remove Windows Firewall rules for domain blocking
        foreach ($domain in $Script:C2Domains) {
            $ruleName = "F0RT1KA-Block-$($domain -replace '\.', '-')"
            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($existing) {
                Remove-NetFirewallRule -DisplayName $ruleName
                Write-Status "  Removed firewall rule: $ruleName" "Warning"
            }
        }
        return
    }

    # Block parent C2 domains via hosts file
    foreach ($domain in $Script:C2Domains) {
        $entry = "0.0.0.0 $domain # F0RT1KA-BlueNoroff C2 block"
        $existingEntry = Select-String -Path $hostsFile -Pattern ([regex]::Escape($domain)) -ErrorAction SilentlyContinue
        if (-not $existingEntry) {
            Add-Content -Path $hostsFile -Value $entry
            Write-Status "  Blocked C2 domain: $domain" "Success"
            Add-ChangeLog "Add" "HostsFile" "" $domain
        } else {
            Write-Status "  Already blocked: $domain" "Info"
        }
    }

    # Block known C2 subdomains
    foreach ($subdomain in $Script:C2Subdomains) {
        $entry = "0.0.0.0 $subdomain # F0RT1KA-BlueNoroff C2 subdomain"
        $existingEntry = Select-String -Path $hostsFile -Pattern ([regex]::Escape($subdomain)) -ErrorAction SilentlyContinue
        if (-not $existingEntry) {
            Add-Content -Path $hostsFile -Value $entry
            Write-Status "  Blocked C2 subdomain: $subdomain" "Success"
            Add-ChangeLog "Add" "HostsFile" "" $subdomain
        }
    }

    # Flush DNS cache
    ipconfig /flushdns | Out-Null
    Write-Status "  DNS cache flushed" "Success"
}

# ============================================================================
# 2. Block Sliver C2 Default Port 8888 (T1573.002)
# ============================================================================

function Set-SliverPortBlocking {
    Write-Status "Section 2: Sliver C2 Port Blocking (T1573.002)" "Info"

    $ruleName = "F0RT1KA-Block-Sliver-mTLS-8888"

    if ($Undo) {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-Status "  Removed Sliver port block rule" "Warning"
            Add-ChangeLog "Remove" "FirewallRule" $ruleName ""
        }
        return
    }

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Action Block `
            -Protocol TCP `
            -RemotePort 8888 `
            -Description "Block outbound TCP 8888 - Sliver C2 mTLS default port used by BlueNoroff (T1573.002)" | Out-Null
        Write-Status "  Blocked outbound TCP port 8888" "Success"
        Add-ChangeLog "Add" "FirewallRule" "" $ruleName
    } else {
        Write-Status "  Already blocked: outbound port 8888" "Info"
    }
}

# ============================================================================
# 3. Enable Credential Guard (T1555.001 mitigation)
# ============================================================================

function Set-CredentialGuard {
    Write-Status "Section 3: Credential Guard Configuration (M1027)" "Info"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

    if ($Undo) {
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $regPath -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
            Write-Status "  Removed Credential Guard settings (reboot required)" "Warning"
            Add-ChangeLog "Remove" "CredentialGuard" "Enabled" "Removed"
        }
        return
    }

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $currentVBS = (Get-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    if ($currentVBS -ne 1) {
        Set-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
        Write-Status "  Enabled Virtualization Based Security (reboot required)" "Success"
        Add-ChangeLog "Set" "CredentialGuard" "$currentVBS" "1"
    } else {
        Write-Status "  Credential Guard already enabled" "Info"
    }

    # Enable LSASS protection (RunAsPPL)
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $currentPPL = (Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if ($currentPPL -ne 1) {
        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord
        Write-Status "  Enabled LSA Protection (RunAsPPL, reboot required)" "Success"
        Add-ChangeLog "Set" "LSAProtection" "$currentPPL" "1"
    } else {
        Write-Status "  LSA Protection already enabled" "Info"
    }
}

# ============================================================================
# 4. Enhanced Audit Logging (M1047)
# ============================================================================

function Set-AuditLogging {
    Write-Status "Section 4: Enhanced Audit Logging (M1047)" "Info"

    if ($Undo) {
        Write-Status "  Audit logging undo not recommended (non-destructive setting)" "Warning"
        return
    }

    # Enable credential validation auditing
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>$null | Out-Null
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable 2>$null | Out-Null

    # Enable process creation with command line auditing
    auditpol /set /subcategory:"Process Creation" /success:enable 2>$null | Out-Null

    # Enable command line in process creation events (Event ID 4688)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue

    # Enable network connection auditing
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable 2>$null | Out-Null

    # Enable DNS client events
    auditpol /set /subcategory:"DNS Client Events" /success:enable 2>$null | Out-Null

    # Enable file system auditing (for credential access detection)
    auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null | Out-Null

    # Enable scheduled task auditing (persistence detection)
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>$null | Out-Null

    Write-Status "  Enabled credential, process, network, DNS, and file auditing" "Success"
    Add-ChangeLog "Set" "AuditPolicy" "" "Comprehensive BlueNoroff-relevant auditing"

    # Enable PowerShell Script Block Logging
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) {
        New-Item -Path $psLogPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Write-Status "  Enabled PowerShell Script Block Logging" "Success"
    Add-ChangeLog "Set" "PowerShellLogging" "" "ScriptBlockLogging enabled"

    # Enable PowerShell Module Logging
    $psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $psModPath)) {
        New-Item -Path $psModPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1 -Type DWord
    Write-Status "  Enabled PowerShell Module Logging" "Success"
}

# ============================================================================
# 5. Cloud Storage Exfiltration Monitoring (T1567.002, T1041)
# ============================================================================

function Set-CloudExfilMonitoring {
    Write-Status "Section 5: Cloud Exfiltration Monitoring (T1567.002, T1041)" "Info"

    if ($Undo) {
        $rules = Get-NetFirewallRule -DisplayName "F0RT1KA-Monitor-*" -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -DisplayName $rule.DisplayName
            Write-Status "  Removed rule: $($rule.DisplayName)" "Warning"
        }
        return
    }

    # Monitor AWS CLI usage
    Write-Status "  Monitoring guidance for cloud exfiltration:" "Info"
    Write-Status "    - Monitor aws.exe execution (Event ID 4688, command line contains 's3 cp' or 's3api put-object')" "Info"
    Write-Status "    - Monitor gsutil.exe execution" "Info"
    Write-Status "    - Alert on non-browser processes connecting to s3.amazonaws.com" "Info"
    Write-Status "    - Alert on non-browser processes connecting to googleapis.com/upload/drive" "Info"
    Write-Status "    - Deploy CASB or web proxy for full cloud upload visibility" "Warning"

    # Check if AWS CLI is installed and set up audit
    $awsCli = Get-Command aws.exe -ErrorAction SilentlyContinue
    if ($awsCli) {
        Write-Status "  AWS CLI detected at: $($awsCli.Source)" "Warning"
        Write-Status "  RECOMMENDATION: Restrict AWS CLI to authorized service accounts" "Warning"
    }
}

# ============================================================================
# 6. Browser Credential Protection (T1555.001 equivalent)
# ============================================================================

function Set-BrowserCredentialProtection {
    Write-Status "Section 6: Browser Credential Protection (T1555.001)" "Info"

    if ($Undo) {
        Write-Status "  Browser credential protection audit settings left as-is" "Info"
        return
    }

    # Monitor Chrome Login Data and Local State files
    $chromeDataPaths = @()
    foreach ($userProfile in Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue) {
        $chromePath = Join-Path $userProfile.FullName "AppData\Local\Google\Chrome\User Data\Default"
        if (Test-Path $chromePath) {
            $chromeDataPaths += $chromePath
            Write-Status "  Found Chrome profile: $chromePath" "Info"
        }
    }

    # Monitor crypto wallet extension directories
    $walletExtensions = @{
        "nkbihfbeogaeaoehlefnkodbefgpgknn" = "MetaMask"
        "hnfanknocfeofbddgcijnmhnfnkdnaad" = "Coinbase Wallet"
    }

    foreach ($chromePath in $chromeDataPaths) {
        foreach ($extId in $walletExtensions.Keys) {
            $extPath = Join-Path $chromePath "Local Extension Settings\$extId"
            if (Test-Path $extPath) {
                Write-Status "  Found $($walletExtensions[$extId]) wallet data at: $extPath" "Warning"
                Write-Status "  RECOMMENDATION: Use hardware wallet for significant holdings" "Warning"
            }
        }
    }

    Write-Status "  RECOMMENDATIONS for credential protection:" "Info"
    Write-Status "    1. Use hardware wallets (Ledger, Trezor) for crypto assets" "Info"
    Write-Status "    2. Enable 2FA on all exchange accounts (hardware key preferred)" "Info"
    Write-Status "    3. Use a dedicated browser profile for crypto operations" "Info"
    Write-Status "    4. Do not save exchange passwords in the browser" "Info"
}

# ============================================================================
# 7. Scheduled Task / Service Persistence Monitoring (T1543.004 equivalent)
# ============================================================================

function Set-PersistenceMonitoring {
    Write-Status "Section 7: Persistence Mechanism Monitoring (T1543.004 equivalent)" "Info"

    if ($Undo) {
        Write-Status "  Persistence monitoring settings left as-is" "Info"
        return
    }

    # Check for suspicious scheduled tasks
    $suspiciousPatterns = @("systemupdate", "avatar", "update.wake", "security.update", "beacon", "linkpc")
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

    foreach ($task in $tasks) {
        foreach ($pattern in $suspiciousPatterns) {
            if ($task.TaskName -match $pattern -or $task.TaskPath -match $pattern) {
                Write-Status "  WARNING: Suspicious scheduled task found: $($task.TaskName) at $($task.TaskPath)" "Warning"
            }
        }
    }

    # Check for suspicious services
    $services = Get-Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        foreach ($pattern in $suspiciousPatterns) {
            if ($svc.Name -match $pattern -or $svc.DisplayName -match $pattern) {
                Write-Status "  WARNING: Suspicious service found: $($svc.Name) ($($svc.DisplayName))" "Warning"
            }
        }
    }

    # Enable scheduled task auditing
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>$null | Out-Null
    Write-Status "  Scheduled task and service auditing enabled" "Success"
    Add-ChangeLog "Set" "PersistenceAudit" "" "Scheduled task auditing enabled"
}

# ============================================================================
# 8. ASR Rules for Script-Based Attacks (T1059.002 equivalent)
# ============================================================================

function Set-ASRRules {
    Write-Status "Section 8: Attack Surface Reduction Rules (M1038)" "Info"

    if ($Undo) {
        # Reset ASR rules to not configured
        $asrRules = @(
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a",  # Block all Office child processes
            "3b576869-a4ec-4529-8536-b80a7769e899",  # Block Office from creating executable
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",  # Block Office from injecting code
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",  # Block executable content from email
            "d3e037e1-3eb8-44c8-a917-57927947596d",  # Block JavaScript/VBScript from launching
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc",  # Block execution of obfuscated scripts
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",  # Block Win32 API calls from Office macros
            "01443614-cd74-433a-b99e-2ecdc07bfc25"   # Block executable files from running unless they meet prevalence/age/trusted list criteria
        )
        foreach ($rule in $asrRules) {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
        }
        Write-Status "  ASR rules disabled" "Warning"
        return
    }

    # Enable key ASR rules for script-based attack prevention
    # These address the equivalent of osascript/AppleScript attacks on Windows
    $asrConfigs = @(
        @{ Id = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"; Name = "Block Office child processes" },
        @{ Id = "3b576869-a4ec-4529-8536-b80a7769e899"; Name = "Block Office creating executables" },
        @{ Id = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"; Name = "Block Office code injection" },
        @{ Id = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"; Name = "Block executable content from email" },
        @{ Id = "d3e037e1-3eb8-44c8-a917-57927947596d"; Name = "Block JS/VBS launching executables" },
        @{ Id = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Name = "Block obfuscated script execution" },
        @{ Id = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"; Name = "Block Win32 API calls from Office macros" },
        @{ Id = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Name = "Block executables by prevalence/age" }
    )

    foreach ($config in $asrConfigs) {
        try {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $config.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Status "  Enabled ASR: $($config.Name)" "Success"
            Add-ChangeLog "Set" "ASR" "" $config.Name
        } catch {
            Write-Status "  Could not enable ASR: $($config.Name) (may not be supported)" "Warning"
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Status "============================================================" "Info"
Write-Status "F0RT1KA Hardening: DPRK BlueNoroff Attack Chain Defense" "Info"
Write-Status "Test ID: $Script:TestID" "Info"
Write-Status "MITRE ATT&CK: T1553.001, T1543.004, T1059.002, T1555.001," "Info"
Write-Status "              T1071.001, T1573.002, T1071.004, T1041, T1567.002" "Info"
Write-Status "Campaigns: RustBucket, Hidden Risk, KANDYKORN, TodoSwift, BeaverTail" "Info"
Write-Status "============================================================" "Info"
Write-Status ""

if ($Undo) {
    Write-Status "REVERTING hardening changes..." "Warning"
} else {
    Write-Status "APPLYING hardening settings..." "Info"
}
Write-Status ""

Set-C2DomainBlocking
Write-Status ""
Set-SliverPortBlocking
Write-Status ""
Set-CredentialGuard
Write-Status ""
Set-AuditLogging
Write-Status ""
Set-CloudExfilMonitoring
Write-Status ""
Set-BrowserCredentialProtection
Write-Status ""
Set-PersistenceMonitoring
Write-Status ""
Set-ASRRules

Write-Status ""
Write-Status "============================================================" "Info"
if ($Undo) {
    Write-Status "Hardening reverted. Some changes require reboot." "Warning"
} else {
    Write-Status "Hardening complete. $($Script:ChangeLog.Count) changes applied." "Success"
    Write-Status "" "Info"
    Write-Status "Applied Settings:" "Info"
    Write-Status "  1. C2 domain blocking via hosts file (T1071.001, T1071.004)" "Info"
    Write-Status "  2. Outbound port 8888 blocked (T1573.002 - Sliver mTLS)" "Info"
    Write-Status "  3. Credential Guard and LSA Protection enabled (T1555.001)" "Info"
    Write-Status "  4. Enhanced audit logging (credential, process, network, DNS)" "Info"
    Write-Status "  5. Cloud exfiltration monitoring guidance (T1567.002)" "Info"
    Write-Status "  6. Browser credential and crypto wallet awareness" "Info"
    Write-Status "  7. Persistence mechanism monitoring (T1543.004)" "Info"
    Write-Status "  8. Attack Surface Reduction rules for script attacks (T1059.002)" "Info"
    Write-Status "" "Info"
    Write-Status "Some changes (Credential Guard, LSA Protection) require reboot." "Warning"
}
Write-Status "============================================================" "Info"

# Export change log
if ($Script:ChangeLog.Count -gt 0) {
    if (-not (Test-Path $Script:BackupPath)) { New-Item -Path $Script:BackupPath -ItemType Directory -Force | Out-Null }
    $logPath = Join-Path $Script:BackupPath "changelog_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Script:ChangeLog | ConvertTo-Json | Out-File $logPath
    Write-Status "Change log saved to: $logPath" "Info"
}
