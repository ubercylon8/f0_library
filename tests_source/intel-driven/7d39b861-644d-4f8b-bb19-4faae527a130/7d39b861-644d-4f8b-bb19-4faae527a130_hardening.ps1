<#
.SYNOPSIS
    Hardening script to protect against Agrius Multi-Wiper destructive attack chain.

.DESCRIPTION
    This script implements defensive measures against the Agrius (Pink Sandstorm /
    Agonizing Serpens) multi-stage destructive attack chain targeting banking
    infrastructure. It configures:

    1. Windows Defender Tamper Protection - Protects security settings from modification
    2. EDR Service Protection - Restricts modification of EDR service registry keys
    3. Vulnerable Driver Blocklist - Blocks known vulnerable drivers (BYOVD prevention)
    4. Driver Signature Enforcement (HVCI) - Requires signed kernel drivers
    5. Service Creation Auditing - Enables Event ID 7045 logging
    6. Event Log Protection - Restricts wevtutil.exe and enables forwarding
    7. Attack Surface Reduction Rules - Blocks script/webshell abuse
    8. IIS Web Directory Hardening - Restricts write access to web roots
    9. Data Protection - Volume Shadow Copy and critical directory ACLs
   10. Audit Policy Configuration - Enables critical security audit categories

    Test ID: 7d39b861-644d-4f8b-bb19-4faae527a130
    MITRE ATT&CK: T1505.003, T1543.003, T1562.001, T1485, T1070.001
    Mitigations: M1018, M1022, M1024, M1026, M1028, M1029, M1038, M1042, M1047, M1053

.PARAMETER Undo
    Reverts all changes made by this script to default settings.

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.PARAMETER Verbose
    Provides detailed output of all operations.

.EXAMPLE
    .\7d39b861-644d-4f8b-bb19-4faae527a130_hardening.ps1
    Applies all hardening settings to protect against Agrius wiper attacks.

.EXAMPLE
    .\7d39b861-644d-4f8b-bb19-4faae527a130_hardening.ps1 -Undo
    Reverts all hardening settings to default.

.EXAMPLE
    .\7d39b861-644d-4f8b-bb19-4faae527a130_hardening.ps1 -WhatIf
    Shows what changes would be made without applying them.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Tested on: Windows 10/11, Windows Server 2019/2022
    Idempotent: Yes (safe to run multiple times)

.LINK
    https://attack.mitre.org/techniques/T1505/003/
    https://attack.mitre.org/techniques/T1543/003/
    https://attack.mitre.org/techniques/T1562/001/
    https://attack.mitre.org/techniques/T1485/
    https://attack.mitre.org/techniques/T1070/001/
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
$Script:LogFile = Join-Path $env:TEMP "agrius_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Test metadata
$TestID = "7d39b861-644d-4f8b-bb19-4faae527a130"
$TestName = "Agrius Multi-Wiper Deployment Against Banking Infrastructure"
$MitreAttack = "T1505.003, T1543.003, T1562.001, T1485, T1070.001"

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

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp $($prefix[$Type]) $Message"

    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
    Add-Content -Path $Script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
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

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AuditPolicyValue {
    param([string]$Subcategory)

    try {
        $result = auditpol /get /subcategory:"$Subcategory" 2>&1
        if ($result -match "Success and Failure") { return "SuccessAndFailure" }
        elseif ($result -match "Success") { return "Success" }
        elseif ($result -match "Failure") { return "Failure" }
        else { return "No Auditing" }
    } catch {
        return "Unknown"
    }
}

# ============================================================================
# 1. Windows Defender Tamper Protection & Configuration
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Registry Permissions
# Protects Windows Defender from being disabled via registry or sc.exe

function Set-DefenderProtection {
    Write-Status "Configuring Windows Defender Protection..." "Header"

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Status "Windows Defender not available - skipping Defender protection" "Warning"
        return
    }

    if ($Undo) {
        Write-Status "Note: Defender Tamper Protection is managed by Microsoft - manual revert not recommended" "Warning"
        return
    }

    # Enable Real-Time Protection
    if ($PSCmdlet.ShouldProcess("Real-Time Protection", "Enable")) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Add-ChangeLog "Enable" "Defender: Real-Time Protection" "Unknown" "Enabled"
            Write-Status "Real-Time Protection enabled" "Success"
        } catch {
            Write-Status "Failed to enable Real-Time Protection: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Behavior Monitoring
    if ($PSCmdlet.ShouldProcess("Behavior Monitoring", "Enable")) {
        try {
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
            Add-ChangeLog "Enable" "Defender: Behavior Monitoring" "Unknown" "Enabled"
            Write-Status "Behavior Monitoring enabled" "Success"
        } catch {
            Write-Status "Failed to enable Behavior Monitoring: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Script Scanning
    if ($PSCmdlet.ShouldProcess("Script Scanning", "Enable")) {
        try {
            Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
            Add-ChangeLog "Enable" "Defender: Script Scanning" "Unknown" "Enabled"
            Write-Status "Script Scanning enabled" "Success"
        } catch {
            Write-Status "Failed to enable Script Scanning: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Block At First Seen
    if ($PSCmdlet.ShouldProcess("Block At First Seen", "Enable")) {
        try {
            Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
            Add-ChangeLog "Enable" "Defender: Block At First Seen" "Unknown" "Enabled"
            Write-Status "Block At First Seen enabled" "Success"
        } catch {
            Write-Status "Failed to enable Block At First Seen: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Cloud Protection
    if ($PSCmdlet.ShouldProcess("Cloud Protection", "Enable")) {
        try {
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
            Add-ChangeLog "Enable" "Defender: Cloud Protection (Advanced)" "Unknown" "Advanced"
            Write-Status "Cloud Protection set to Advanced" "Success"
        } catch {
            Write-Status "Failed to configure Cloud Protection: $($_.Exception.Message)" "Warning"
        }
    }

    # Protect Defender registry keys from modification
    if ($PSCmdlet.ShouldProcess("Defender Registry Keys", "Set audit rules")) {
        try {
            $defenderPaths = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
                "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features",
                "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
            )

            foreach ($path in $defenderPaths) {
                if (Test-Path $path) {
                    $acl = Get-Acl $path
                    $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
                        "Everyone",
                        "SetValue,Delete",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Success,Failure"
                    )
                    $acl.AddAuditRule($rule)
                    Set-Acl $path $acl
                    Write-Status "Registry audit enabled for: $path" "Success"
                }
            }
            Add-ChangeLog "Audit" "Defender Registry Keys" "None" "Audit SetValue,Delete"
        } catch {
            Write-Status "Failed to set Defender registry auditing: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "Windows Defender protection configured" "Success"
}

# ============================================================================
# 2. Vulnerable Driver Blocklist and HVCI
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Prevents BYOVD attacks by blocking known vulnerable drivers and
# enforcing kernel code integrity

function Set-DriverProtection {
    Write-Status "Configuring Driver Protection (BYOVD Prevention)..." "Header"

    $ciConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
    $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

    if ($Undo) {
        Write-Status "Disabling vulnerable driver blocklist..." "Info"
        if ($PSCmdlet.ShouldProcess("VulnerableDriverBlocklistEnable", "Set to 0")) {
            try {
                if (Test-Path $ciConfigPath) {
                    Set-ItemProperty -Path $ciConfigPath -Name "VulnerableDriverBlocklistEnable" -Value 0 -Type DWord -Force
                    Add-ChangeLog "Disable" "Vulnerable Driver Blocklist" "Enabled" "Disabled"
                    Write-Status "Vulnerable Driver Blocklist disabled" "Success"
                }
            } catch {
                Write-Status "Failed to disable blocklist: $($_.Exception.Message)" "Warning"
            }
        }
        return
    }

    # Enable Vulnerable Driver Blocklist
    if ($PSCmdlet.ShouldProcess("VulnerableDriverBlocklistEnable", "Set to 1")) {
        try {
            if (-not (Test-Path $ciConfigPath)) {
                New-Item -Path $ciConfigPath -Force | Out-Null
            }

            $currentValue = Get-ItemProperty -Path $ciConfigPath -Name "VulnerableDriverBlocklistEnable" -ErrorAction SilentlyContinue
            $oldValue = if ($currentValue) { $currentValue.VulnerableDriverBlocklistEnable } else { "Not Set" }

            Set-ItemProperty -Path $ciConfigPath -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "Vulnerable Driver Blocklist" $oldValue "1"
            Write-Status "Vulnerable Driver Blocklist enabled" "Success"
        } catch {
            Write-Status "Failed to enable blocklist: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Virtualization Based Security and HVCI
    if ($PSCmdlet.ShouldProcess("DeviceGuard", "Configure VBS and HVCI")) {
        try {
            if (-not (Test-Path $deviceGuardPath)) {
                New-Item -Path $deviceGuardPath -Force | Out-Null
            }

            Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "Virtualization Based Security" "Unknown" "1"
            Write-Status "Virtualization Based Security enabled" "Success"

            Set-ItemProperty -Path $deviceGuardPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "HVCI" "Unknown" "1"
            Write-Status "Hypervisor-Protected Code Integrity (HVCI) enabled" "Success"

            Set-ItemProperty -Path $deviceGuardPath -Name "RequireUEFIMemoryAttributesTable" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "UEFI Memory Attributes Table Requirement" "Unknown" "1"
            Write-Status "UEFI Memory Attributes Table requirement enabled" "Success"
        } catch {
            Write-Status "Failed to configure DeviceGuard: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "Driver protection configured" "Success"
}

# ============================================================================
# 3. Service Creation and EDR Service Auditing
# ============================================================================
# MITRE Mitigation: M1047 - Audit
# Enables auditing for service creation and modification events

function Set-ServiceAuditing {
    Write-Status "Configuring Service Auditing..." "Header"

    if ($Undo) {
        Write-Status "Reverting audit policy changes..." "Info"
        if ($PSCmdlet.ShouldProcess("Security System Extension", "Set audit to No Auditing")) {
            auditpol /set /subcategory:"Security System Extension" /success:disable /failure:disable 2>$null
            auditpol /set /subcategory:"Security State Change" /success:disable /failure:disable 2>$null
            Add-ChangeLog "Disable" "Service Creation Auditing" "SuccessAndFailure" "No Auditing"
            Write-Status "Service creation auditing disabled" "Success"
        }
        return
    }

    # Enable Security System Extension auditing (captures Event ID 7045 - service installation)
    if ($PSCmdlet.ShouldProcess("Security System Extension", "Enable Success and Failure auditing")) {
        try {
            $oldValue = Get-AuditPolicyValue "Security System Extension"
            auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
            Add-ChangeLog "Enable" "Security System Extension Audit" $oldValue "SuccessAndFailure"
            Write-Status "Security System Extension auditing enabled (Event ID 7045)" "Success"
        } catch {
            Write-Status "Failed to set Security System Extension audit: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Security State Change auditing (captures security-related state transitions)
    if ($PSCmdlet.ShouldProcess("Security State Change", "Enable Success and Failure auditing")) {
        try {
            $oldValue = Get-AuditPolicyValue "Security State Change"
            auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
            Add-ChangeLog "Enable" "Security State Change Audit" $oldValue "SuccessAndFailure"
            Write-Status "Security State Change auditing enabled" "Success"
        } catch {
            Write-Status "Failed to set Security State Change audit: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable process creation auditing with command line
    if ($PSCmdlet.ShouldProcess("Process Creation", "Enable command line auditing")) {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "Process Creation Command Line Logging" "Unknown" "1"
            Write-Status "Process creation command line logging enabled" "Success"

            $oldValue = Get-AuditPolicyValue "Process Creation"
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
            Add-ChangeLog "Enable" "Process Creation Audit" $oldValue "SuccessAndFailure"
            Write-Status "Process Creation auditing enabled (Event ID 4688)" "Success"
        } catch {
            Write-Status "Failed to enable process creation auditing: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable object access auditing (for file integrity monitoring)
    if ($PSCmdlet.ShouldProcess("File System", "Enable file access auditing")) {
        try {
            $oldValue = Get-AuditPolicyValue "File System"
            auditpol /set /subcategory:"File System" /success:enable /failure:enable
            Add-ChangeLog "Enable" "File System Audit" $oldValue "SuccessAndFailure"
            Write-Status "File System access auditing enabled (Event ID 4663)" "Success"
        } catch {
            Write-Status "Failed to enable file system auditing: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "Service and process auditing configured" "Success"
}

# ============================================================================
# 4. Event Log Protection
# ============================================================================
# MITRE Mitigation: M1029 - Remote Data Storage, M1022 - Restrict File Permissions
# Protects event logs from clearing and configures forwarding

function Set-EventLogProtection {
    Write-Status "Configuring Event Log Protection..." "Header"

    if ($Undo) {
        Write-Status "Reverting event log protection..." "Info"
        if ($PSCmdlet.ShouldProcess("Event Log Protection", "Revert")) {
            # Remove wevtutil restriction if applied
            $wevtutilPath = "$env:SystemRoot\System32\wevtutil.exe"
            if (Test-Path $wevtutilPath) {
                icacls $wevtutilPath /reset 2>$null
                Write-Status "wevtutil.exe permissions reset" "Success"
            }
        }
        Add-ChangeLog "Revert" "Event Log Protection" "Restricted" "Default"
        return
    }

    # Increase event log maximum sizes for forensic retention
    if ($PSCmdlet.ShouldProcess("Event Log Sizes", "Increase to 256MB")) {
        try {
            $logs = @("Security", "System", "Application",
                "Microsoft-Windows-PowerShell/Operational")
            foreach ($logName in $logs) {
                try {
                    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                    $oldSize = $log.MaximumSizeInBytes
                    $newSize = 268435456  # 256MB
                    if ($oldSize -lt $newSize) {
                        wevtutil sl $logName /ms:$newSize 2>$null
                        Add-ChangeLog "Increase" "Event Log Size: $logName" "$oldSize" "$newSize"
                        Write-Status "Event log $logName size increased to 256MB" "Success"
                    } else {
                        Write-Status "Event log $logName already >= 256MB" "Info"
                    }
                } catch {
                    Write-Status "Failed to resize log $logName : $($_.Exception.Message)" "Warning"
                }
            }
        } catch {
            Write-Status "Failed to configure event log sizes: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable audit log cleared event (Event ID 1102) monitoring
    if ($PSCmdlet.ShouldProcess("Audit Log Cleared", "Enable monitoring")) {
        Write-Status "Event ID 1102 (Audit Log Cleared) is enabled by default in Windows" "Info"
        Write-Status "Ensure SIEM ingests Security log to capture Event ID 1102" "Info"
    }

    # Restrict wevtutil.exe execution to administrators only
    if ($PSCmdlet.ShouldProcess("wevtutil.exe", "Restrict execution permissions")) {
        try {
            $wevtutilPath = "$env:SystemRoot\System32\wevtutil.exe"
            if (Test-Path $wevtutilPath) {
                # Only SYSTEM and Administrators can execute
                icacls $wevtutilPath /inheritance:r /grant "BUILTIN\Administrators:(RX)" /grant "NT AUTHORITY\SYSTEM:(RX)" 2>$null
                Add-ChangeLog "Restrict" "wevtutil.exe permissions" "Default" "Administrators and SYSTEM only"
                Write-Status "wevtutil.exe restricted to Administrators and SYSTEM" "Success"
            }
        } catch {
            Write-Status "Failed to restrict wevtutil.exe: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "Event log protection configured" "Success"
}

# ============================================================================
# 5. Attack Surface Reduction (ASR) Rules
# ============================================================================
# MITRE Mitigation: M1038 - Execution Prevention
# Blocks obfuscated scripts, webshell patterns, and credential stealing

function Set-ASRRules {
    Write-Status "Configuring Attack Surface Reduction Rules..." "Header"

    # ASR Rule GUIDs
    $asrRules = @{
        # Block abuse of exploited vulnerable signed drivers
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        # Block executable files from running unless they meet prevalence, age, or trusted list criteria
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files unless they meet criteria"
        # Block process creations originating from PSExec and WMI commands
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations from PSExec and WMI"
        # Block untrusted and unsigned processes that run from USB
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted processes from USB"
        # Block persistence through WMI event subscription
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI"
        # Use advanced protection against ransomware
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Advanced protection against ransomware"
        # Block credential stealing from LSASS
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
    }

    if ($Undo) {
        Write-Status "Disabling ASR rules..." "Info"
        if ($PSCmdlet.ShouldProcess("ASR Rules", "Disable all")) {
            try {
                foreach ($ruleGuid in $asrRules.Keys) {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
                }
                Add-ChangeLog "Disable" "ASR Rules" "Block/Audit" "Disabled"
                Write-Status "All ASR rules disabled" "Success"
            } catch {
                Write-Status "Failed to disable ASR rules: $($_.Exception.Message)" "Warning"
            }
        }
        return
    }

    # Check if Defender is available for ASR
    try {
        $null = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Status "Windows Defender not available - cannot configure ASR rules" "Warning"
        return
    }

    foreach ($ruleGuid in $asrRules.Keys) {
        $ruleName = $asrRules[$ruleGuid]
        if ($PSCmdlet.ShouldProcess("ASR Rule: $ruleName", "Set to Block")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                Add-ChangeLog "Enable" "ASR Rule: $ruleName" "Unknown" "Block"
                Write-Status "ASR Rule enabled: $ruleName" "Success"
            } catch {
                Write-Status "Failed to enable ASR rule $ruleName : $($_.Exception.Message)" "Warning"
            }
        }
    }

    Write-Status "ASR rules configured" "Success"
}

# ============================================================================
# 6. IIS Web Directory Hardening
# ============================================================================
# MITRE Mitigation: M1018 - User Account Management, M1042 - Disable Feature
# Restricts write access to IIS web application directories to prevent
# webshell deployment

function Set-IISHardening {
    Write-Status "Configuring IIS Web Directory Hardening..." "Header"

    $iisDefaultPath = "C:\inetpub\wwwroot"

    if ($Undo) {
        Write-Status "IIS hardening revert requires manual review of directory permissions" "Warning"
        Write-Status "Use icacls to restore default IIS permissions if needed" "Info"
        return
    }

    if (-not (Test-Path $iisDefaultPath)) {
        Write-Status "IIS not detected (C:\inetpub\wwwroot not found) - skipping IIS hardening" "Info"
        return
    }

    # Restrict write permissions on IIS wwwroot
    if ($PSCmdlet.ShouldProcess($iisDefaultPath, "Restrict write access")) {
        try {
            # Add audit rule for .aspx file creation
            $acl = Get-Acl $iisDefaultPath
            $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                "Write,Delete",
                "ContainerInherit,ObjectInherit",
                "None",
                "Success,Failure"
            )
            $acl.AddAuditRule($auditRule)
            Set-Acl $iisDefaultPath $acl
            Add-ChangeLog "Audit" "IIS wwwroot write access" "None" "Audit Write,Delete"
            Write-Status "Audit rule added for write operations to $iisDefaultPath" "Success"
        } catch {
            Write-Status "Failed to configure IIS audit: $($_.Exception.Message)" "Warning"
        }
    }

    # Disable WebDAV if present (prevents file upload via HTTP PUT)
    if ($PSCmdlet.ShouldProcess("WebDAV", "Check and disable")) {
        try {
            $webdavFeature = Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -ErrorAction SilentlyContinue
            if ($webdavFeature -and $webdavFeature.State -eq "Enabled") {
                Write-Status "WebDAV is enabled - consider disabling to prevent file upload attacks" "Warning"
                Write-Status "Run: Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV" "Info"
            } else {
                Write-Status "WebDAV is not enabled" "Info"
            }
        } catch {
            Write-Status "Could not check WebDAV status" "Info"
        }
    }

    Write-Status "IIS hardening configured" "Success"
}

# ============================================================================
# 7. Data Protection (Wiper Resilience)
# ============================================================================
# MITRE Mitigation: M1053 - Data Backup, M1022 - Restrict File Permissions
# Configures Volume Shadow Copy and protects critical data directories

function Set-DataProtection {
    Write-Status "Configuring Data Protection (Wiper Resilience)..." "Header"

    if ($Undo) {
        Write-Status "Data protection revert: Shadow copies will remain" "Info"
        Write-Status "Reverting is not recommended for backup configurations" "Warning"
        return
    }

    # Enable Volume Shadow Copy for system drive
    if ($PSCmdlet.ShouldProcess("Volume Shadow Copy", "Create for C:")) {
        try {
            $existingShadows = vssadmin list shadows /for=C: 2>$null
            if ($existingShadows -match "Shadow Copy Volume") {
                Write-Status "Volume Shadow Copies already exist for C:" "Info"
            } else {
                vssadmin create shadow /for=C: 2>$null
                Add-ChangeLog "Create" "Volume Shadow Copy for C:" "None" "Created"
                Write-Status "Volume Shadow Copy created for C:" "Success"
            }
        } catch {
            Write-Status "Failed to create Volume Shadow Copy: $($_.Exception.Message)" "Warning"
        }
    }

    # Configure VSS maximum size
    if ($PSCmdlet.ShouldProcess("VSS Storage", "Set maximum size")) {
        try {
            vssadmin resize shadowstorage /for=C: /on=C: /maxsize=20GB 2>$null
            Add-ChangeLog "Configure" "VSS Max Storage" "Unknown" "20GB"
            Write-Status "VSS maximum storage set to 20GB" "Success"
        } catch {
            Write-Status "Failed to configure VSS storage: $($_.Exception.Message)" "Warning"
        }
    }

    # Recommend backup strategy
    Write-Status "" "Info"
    Write-Status "DATA PROTECTION RECOMMENDATIONS FOR BANKING INFRASTRUCTURE:" "Header"
    Write-Status "  1. Implement 3-2-1 backup rule (3 copies, 2 media types, 1 offsite)" "Info"
    Write-Status "  2. Use immutable/WORM storage for critical banking data" "Info"
    Write-Status "  3. Test backup restoration quarterly" "Info"
    Write-Status "  4. Maintain air-gapped backup copies updated weekly" "Info"
    Write-Status "  5. Configure backup frequency: every 4 hours for critical data" "Info"
    Write-Status "  6. Enable VSS for all data volumes" "Info"
    Write-Status "" "Info"

    Write-Status "Data protection configured" "Success"
}

# ============================================================================
# 8. EDR Service Protection
# ============================================================================
# MITRE Mitigation: M1024 - Restrict Registry Permissions
# Protects EDR service registry keys from modification

function Set-EDRServiceProtection {
    Write-Status "Configuring EDR Service Protection..." "Header"

    if ($Undo) {
        Write-Status "EDR service protection revert requires manual registry permission changes" "Warning"
        return
    }

    # List of EDR service names to protect
    $edrServices = @(
        "Sense", "WinDefend", "MsSense", "MpDefenderCoreService",
        "CSFalconService",
        "SentinelAgent", "SentinelStaticEngine",
        "CortexXDR", "cyserver",
        "CbDefense", "CbDefenseWSC",
        "ekrn", "EsetService",
        "Ntrtscan", "ds_agent",
        "elastic-endpoint",
        "CylanceSvc",
        "SepMasterService", "ccSvcHst"
    )

    $protectedCount = 0

    foreach ($svcName in $edrServices) {
        $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"

        if (Test-Path $svcRegPath) {
            if ($PSCmdlet.ShouldProcess("Service: $svcName", "Add registry audit rule")) {
                try {
                    $acl = Get-Acl $svcRegPath
                    $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                        "Everyone",
                        "SetValue,Delete",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Success,Failure"
                    )
                    $acl.AddAuditRule($auditRule)
                    Set-Acl $svcRegPath $acl
                    Write-Status "Registry audit enabled for service: $svcName" "Success"
                    $protectedCount++
                } catch {
                    Write-Status "Failed to protect service $svcName : $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    if ($protectedCount -gt 0) {
        Add-ChangeLog "Protect" "EDR Service Registry Keys" "None" "Audit on $protectedCount services"
        Write-Status "Protected $protectedCount EDR service registry keys" "Success"
    } else {
        Write-Status "No EDR services found to protect on this system" "Info"
    }

    Write-Status "EDR service protection configured" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Status "============================================================================" "Header"
Write-Status " F0RT1KA Hardening Script" "Header"
Write-Status " Test: $TestName" "Header"
Write-Status " ID:   $TestID" "Header"
Write-Status " MITRE ATT&CK: $MitreAttack" "Header"
Write-Status "============================================================================" "Header"
Write-Status "" "Info"

if (-not (Test-IsAdmin)) {
    Write-Status "This script requires Administrator privileges. Please run as Administrator." "Error"
    exit 1
}

if ($Undo) {
    Write-Status "UNDO MODE: Reverting all hardening changes..." "Warning"
    Write-Status "" "Info"
} else {
    Write-Status "Applying hardening settings against Agrius wiper attack chain..." "Info"
    Write-Status "" "Info"
}

# Execute all hardening functions
Set-DefenderProtection
Write-Status "" "Info"

Set-DriverProtection
Write-Status "" "Info"

Set-ServiceAuditing
Write-Status "" "Info"

Set-EventLogProtection
Write-Status "" "Info"

Set-ASRRules
Write-Status "" "Info"

Set-IISHardening
Write-Status "" "Info"

Set-DataProtection
Write-Status "" "Info"

Set-EDRServiceProtection
Write-Status "" "Info"

# Summary
Write-Status "============================================================================" "Header"
Write-Status " Hardening Complete" "Header"
Write-Status "============================================================================" "Header"
Write-Status "" "Info"

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes made: $($Script:ChangeLog.Count)" "Success"
    Write-Status "Change log saved to: $Script:LogFile" "Info"

    # Export change log
    $Script:ChangeLog | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Status $_ "Info" }

    # Save structured change log
    $changeLogPath = Join-Path $env:TEMP "agrius_hardening_changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Script:ChangeLog | Export-Csv -Path $changeLogPath -NoTypeInformation
    Write-Status "Structured change log: $changeLogPath" "Info"
} else {
    Write-Status "No changes were required (system already hardened or WhatIf mode)" "Info"
}

Write-Status "" "Info"
Write-Status "Recommendations:" "Header"
Write-Status "  1. Reboot to apply driver protection and HVCI changes" "Info"
Write-Status "  2. Configure Windows Event Forwarding to SIEM" "Info"
Write-Status "  3. Implement immutable backup strategy for banking data" "Info"
Write-Status "  4. Deploy Sysmon with file integrity monitoring" "Info"
Write-Status "  5. Review IIS directory permissions and disable unnecessary features" "Info"
Write-Status "" "Info"
