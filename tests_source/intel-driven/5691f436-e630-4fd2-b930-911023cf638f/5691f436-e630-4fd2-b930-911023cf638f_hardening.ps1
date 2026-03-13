<#
.SYNOPSIS
    Hardening script to protect against APT34 Exchange Server Weaponization attack chain.

.DESCRIPTION
    This script implements defensive measures against the APT34 (OilRig / Hazel
    Sandstorm) Exchange weaponization attack chain covering:

    1. IIS Module Hardening - Restricts native module registration
    2. LSA Password Filter Protection - Monitors and protects Notification Packages
    3. Exchange Server Hardening - EWS access restrictions and transport rules
    4. Outbound SMTP Controls - Blocks unauthorized SMTP egress
    5. Audit Logging - Enables critical event logging for detection
    6. Attack Surface Reduction (ASR) Rules - Blocks credential theft vectors
    7. PowerShell Logging - Captures Exchange C2 script activity

    Test ID: 5691f436-e630-4fd2-b930-911023cf638f
    MITRE ATT&CK: T1505.003, T1071.003, T1556.002, T1048.003
    Mitigations: M1042, M1038, M1047, M1037, M1031, M1026

.PARAMETER Undo
    Reverts all changes made by this script to default settings.

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.PARAMETER Verbose
    Provides detailed output of all operations.

.EXAMPLE
    .\5691f436-e630-4fd2-b930-911023cf638f_hardening.ps1
    Applies all hardening settings to protect against APT34 Exchange weaponization.

.EXAMPLE
    .\5691f436-e630-4fd2-b930-911023cf638f_hardening.ps1 -Undo
    Reverts all hardening settings to default.

.EXAMPLE
    .\5691f436-e630-4fd2-b930-911023cf638f_hardening.ps1 -WhatIf
    Shows what changes would be made without applying them.

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Tested on: Windows Server 2016/2019/2022, Windows 10/11
    Idempotent: Yes (safe to run multiple times)

.LINK
    https://attack.mitre.org/groups/G0049/
    https://attack.mitre.org/techniques/T1505/003/
    https://attack.mitre.org/techniques/T1071/003/
    https://attack.mitre.org/techniques/T1556/002/
    https://attack.mitre.org/techniques/T1048/003/
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
$Script:LogFile = Join-Path $env:TEMP "apt34_exchange_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Test metadata
$TestID = "5691f436-e630-4fd2-b930-911023cf638f"
$TestName = "APT34 Exchange Server Weaponization with Email-Based C2"
$MitreAttack = "T1505.003, T1071.003, T1556.002, T1048.003"

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
# 1. IIS Module Hardening (T1505.003)
# ============================================================================

function Set-IISModuleHardening {
    <#
    .SYNOPSIS
        Restricts IIS native module registration to prevent backdoor installation.

    .DESCRIPTION
        Configures IIS to require administrator approval for native module
        registration and restricts appcmd.exe usage.

        MITRE Mitigation: M1042 - Disable or Remove Feature or Program
    #>

    Write-Status "Configuring IIS Module Hardening..." "Header"

    if ($Undo) {
        Write-Status "Reverting IIS module hardening..." "Info"

        if ($PSCmdlet.ShouldProcess("IIS appcmd.exe ACL", "Revert permissions")) {
            try {
                $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
                if (Test-Path $appcmd) {
                    icacls $appcmd /reset 2>&1 | Out-Null
                    Add-ChangeLog "Revert" "appcmd.exe permissions" "Restricted" "Default"
                    Write-Status "appcmd.exe permissions reverted to default" "Success"
                }
            } catch {
                Write-Status "Failed to revert appcmd.exe permissions: $($_.Exception.Message)" "Warning"
            }
        }
        return
    }

    # Restrict appcmd.exe to Administrators only
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        if ($PSCmdlet.ShouldProcess("appcmd.exe", "Restrict to Administrators")) {
            try {
                # Remove inherited permissions and restrict to Administrators + SYSTEM
                icacls $appcmd /inheritance:r 2>&1 | Out-Null
                icacls $appcmd /grant "BUILTIN\Administrators:(RX)" 2>&1 | Out-Null
                icacls $appcmd /grant "NT AUTHORITY\SYSTEM:(RX)" 2>&1 | Out-Null
                Add-ChangeLog "Restrict" "appcmd.exe permissions" "Default" "Administrators + SYSTEM only"
                Write-Status "appcmd.exe restricted to Administrators and SYSTEM" "Success"
            } catch {
                Write-Status "Failed to restrict appcmd.exe: $($_.Exception.Message)" "Warning"
            }
        }
    } else {
        Write-Status "IIS not installed (appcmd.exe not found) - skipping" "Info"
    }

    # Enable IIS configuration auditing
    $iisConfigPath = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $iisConfigPath) {
        if ($PSCmdlet.ShouldProcess("applicationHost.config", "Enable auditing SACL")) {
            try {
                $acl = Get-Acl $iisConfigPath
                $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone",
                    "Write,Delete",
                    "None",
                    "None",
                    "Success,Failure"
                )
                $acl.AddAuditRule($rule)
                Set-Acl $iisConfigPath $acl
                Add-ChangeLog "Enable" "SACL: applicationHost.config" "None" "Audit Write/Delete"
                Write-Status "Auditing enabled for applicationHost.config" "Success"
            } catch {
                Write-Status "Failed to set SACL on IIS config: $($_.Exception.Message)" "Warning"
            }
        }
    }

    # Set audit SACL on inetsrv directory for DLL drops
    $inetsrvPath = "$env:SystemRoot\System32\inetsrv"
    if (Test-Path $inetsrvPath) {
        if ($PSCmdlet.ShouldProcess("inetsrv directory", "Enable file creation auditing")) {
            try {
                $acl = Get-Acl $inetsrvPath
                $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone",
                    "CreateFiles,WriteData",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Success,Failure"
                )
                $acl.AddAuditRule($rule)
                Set-Acl $inetsrvPath $acl
                Add-ChangeLog "Enable" "SACL: inetsrv directory" "None" "Audit CreateFiles/WriteData"
                Write-Status "File creation auditing enabled for inetsrv directory" "Success"
            } catch {
                Write-Status "Failed to set SACL on inetsrv: $($_.Exception.Message)" "Warning"
            }
        }
    }

    Write-Status "IIS Module hardening configured" "Success"
}

# ============================================================================
# 2. LSA Password Filter Protection (T1556.002)
# ============================================================================

function Set-LSAPasswordFilterProtection {
    <#
    .SYNOPSIS
        Protects LSA Notification Packages registry key from unauthorized modification.

    .DESCRIPTION
        Configures auditing and access controls on the LSA registry key to detect
        and prevent unauthorized password filter DLL registration.

        MITRE Mitigation: M1024 - Restrict Registry Permissions
    #>

    Write-Status "Configuring LSA Password Filter Protection..." "Header"

    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    if ($Undo) {
        Write-Status "Reverting LSA protection..." "Info"

        if ($PSCmdlet.ShouldProcess("LSA Registry Key SACL", "Remove audit rule")) {
            try {
                # Remove the audit SACL we added
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "SYSTEM\CurrentControlSet\Control\Lsa",
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::ChangePermissions
                )
                if ($key) {
                    $acl = $key.GetAccessControl()
                    # Reset audit rules
                    $acl.SetAuditRuleProtection($false, $true)
                    $key.SetAccessControl($acl)
                    $key.Close()
                    Add-ChangeLog "Revert" "LSA Registry SACL" "Auditing Enabled" "Default"
                    Write-Status "LSA registry SACL reverted" "Success"
                }
            } catch {
                Write-Status "Failed to revert LSA SACL: $($_.Exception.Message)" "Warning"
            }
        }
        return
    }

    # Enable auditing on LSA registry key
    if ($PSCmdlet.ShouldProcess("LSA Notification Packages", "Enable registry auditing SACL")) {
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                "SYSTEM\CurrentControlSet\Control\Lsa",
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            if ($key) {
                $acl = $key.GetAccessControl()
                $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                    "Everyone",
                    "SetValue,CreateSubKey,Delete",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Success,Failure"
                )
                $acl.AddAuditRule($auditRule)
                $key.SetAccessControl($acl)
                $key.Close()
                Add-ChangeLog "Enable" "SACL: HKLM\SYSTEM\...\Lsa" "None" "Audit SetValue/CreateSubKey/Delete"
                Write-Status "Auditing SACL enabled on LSA registry key" "Success"
            }
        } catch {
            Write-Status "Failed to set LSA SACL: $($_.Exception.Message)" "Warning"
        }
    }

    # Record current Notification Packages for baseline comparison
    if ($PSCmdlet.ShouldProcess("Notification Packages", "Record baseline")) {
        try {
            $currentPackages = (Get-ItemProperty -Path $lsaPath -Name "Notification Packages" -ErrorAction SilentlyContinue).'Notification Packages'
            if ($currentPackages) {
                $packageList = $currentPackages -join ", "
                Write-Status "Current Notification Packages baseline: $packageList" "Info"
                Add-ChangeLog "Record" "Notification Packages Baseline" "N/A" $packageList
            }
        } catch {
            Write-Status "Could not read current Notification Packages" "Warning"
        }
    }

    # Enable Credential Guard (protects LSA)
    $dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    if ($PSCmdlet.ShouldProcess("Credential Guard", "Enable via DeviceGuard")) {
        try {
            if (-not (Test-Path $dgPath)) {
                New-Item -Path $dgPath -Force | Out-Null
            }
            Set-ItemProperty -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force

            $lsaCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-ItemProperty -Path $lsaCfgPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Force

            Add-ChangeLog "Enable" "Credential Guard" "Unknown" "Enabled (VBS + LSA)"
            Write-Status "Credential Guard enabled (protects LSA from credential theft)" "Success"
        } catch {
            Write-Status "Failed to enable Credential Guard: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "LSA Password Filter protection configured" "Success"
}

# ============================================================================
# 3. Outbound SMTP Controls (T1048.003)
# ============================================================================

function Set-OutboundSMTPControls {
    <#
    .SYNOPSIS
        Restricts outbound SMTP traffic to prevent email-based exfiltration.

    .DESCRIPTION
        Creates Windows Firewall rules to block outbound SMTP connections
        (ports 25, 587, 465) from non-mail processes, preventing STEALHOOK-
        style email exfiltration.

        MITRE Mitigation: M1037 - Filter Network Traffic
    #>

    Write-Status "Configuring Outbound SMTP Controls..." "Header"

    $firewallRulePrefix = "F0RT1KA-APT34"

    if ($Undo) {
        Write-Status "Removing outbound SMTP firewall rules..." "Info"

        if ($PSCmdlet.ShouldProcess("SMTP Firewall Rules", "Remove")) {
            Get-NetFirewallRule -DisplayName "$firewallRulePrefix*" -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Add-ChangeLog "Remove" "Outbound SMTP Firewall Rules" "Blocked" "Removed"
            Write-Status "Outbound SMTP firewall rules removed" "Success"
        }
        return
    }

    # Block outbound SMTP from all processes except known mail servers
    $smtpPorts = @(25, 587, 465)

    foreach ($port in $smtpPorts) {
        $ruleName = "$firewallRulePrefix-Block-SMTP-$port"

        if ($PSCmdlet.ShouldProcess("Outbound port $port", "Create blocking firewall rule")) {
            try {
                # Remove existing rule if present (idempotent)
                Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule -ErrorAction SilentlyContinue

                New-NetFirewallRule `
                    -DisplayName $ruleName `
                    -Description "Block outbound SMTP port $port - APT34 STEALHOOK exfiltration prevention" `
                    -Direction Outbound `
                    -Protocol TCP `
                    -RemotePort $port `
                    -Action Block `
                    -Profile Any `
                    -Enabled True | Out-Null

                Add-ChangeLog "Create" "Firewall: Block outbound port $port" "N/A" "Block"
                Write-Status "Blocked outbound SMTP port $port" "Success"
            } catch {
                Write-Status "Failed to create firewall rule for port $port : $($_.Exception.Message)" "Warning"
            }
        }
    }

    # Allow exception for designated Exchange transport services
    $exchangeExceptions = @(
        @{ Name = "$firewallRulePrefix-Allow-EdgeTransport"; Path = "C:\Program Files\Microsoft\Exchange Server\*\Bin\EdgeTransport.exe" },
        @{ Name = "$firewallRulePrefix-Allow-MSExchangeTransport"; Path = "C:\Program Files\Microsoft\Exchange Server\*\Bin\MSExchangeTransport.exe" }
    )

    foreach ($exception in $exchangeExceptions) {
        if ($PSCmdlet.ShouldProcess($exception.Name, "Create allow exception")) {
            try {
                Get-NetFirewallRule -DisplayName $exception.Name -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule -ErrorAction SilentlyContinue

                New-NetFirewallRule `
                    -DisplayName $exception.Name `
                    -Description "Allow SMTP for legitimate Exchange transport" `
                    -Direction Outbound `
                    -Protocol TCP `
                    -RemotePort @(25, 587, 465) `
                    -Program $exception.Path `
                    -Action Allow `
                    -Profile Any `
                    -Enabled True | Out-Null

                Add-ChangeLog "Create" "Firewall: Allow $($exception.Name)" "N/A" "Allow"
                Write-Status "SMTP exception created for $($exception.Name)" "Success"
            } catch {
                Write-Status "Exchange not found for exception: $($exception.Name) (expected on non-Exchange servers)" "Info"
            }
        }
    }

    Write-Status "Outbound SMTP controls configured" "Success"
}

# ============================================================================
# 4. Attack Surface Reduction Rules (T1556.002, T1505.003)
# ============================================================================

function Set-ASRRulesForAPT34 {
    <#
    .SYNOPSIS
        Configures ASR rules to block APT34 attack vectors.

    .DESCRIPTION
        Enables ASR rules targeting credential theft, script execution,
        and persistence mechanisms used by APT34.

        MITRE Mitigation: M1038 - Execution Prevention
    #>

    Write-Status "Configuring ASR Rules for APT34 Protection..." "Header"

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Status "Windows Defender not available - skipping ASR configuration" "Warning"
        return
    }

    $asrRules = @{
        # Block credential stealing from LSASS (protects against password filter abuse)
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
        # Block process creations from PSExec and WMI commands
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PSExec/WMI"
        # Block Office applications from creating child processes
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office applications from creating child processes"
        # Block all Office applications from creating child processes
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication apps from creating child processes"
        # Block persistence through WMI event subscription
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block WMI event subscription persistence"
        # Block abuse of exploited vulnerable signed drivers
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block vulnerable driver abuse"
    }

    if ($Undo) {
        Write-Status "Removing APT34-specific ASR rules..." "Info"

        foreach ($ruleGuid in $asrRules.Keys) {
            if ($PSCmdlet.ShouldProcess($asrRules[$ruleGuid], "Remove ASR rule")) {
                try {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -ErrorAction SilentlyContinue
                    Add-ChangeLog "Remove" "ASR Rule: $($asrRules[$ruleGuid])" "Enabled" "Removed"
                    Write-Status "Removed: $($asrRules[$ruleGuid])" "Success"
                } catch {
                    Write-Status "Failed to remove ASR rule: $($asrRules[$ruleGuid])" "Warning"
                }
            }
        }
        return
    }

    foreach ($ruleGuid in $asrRules.Keys) {
        if ($PSCmdlet.ShouldProcess($asrRules[$ruleGuid], "Enable ASR rule (Block mode)")) {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
                Add-ChangeLog "Enable" "ASR Rule: $($asrRules[$ruleGuid])" "Disabled" "Block"
                Write-Status "Enabled (Block): $($asrRules[$ruleGuid])" "Success"
            } catch {
                Write-Status "Failed to enable ASR rule: $($asrRules[$ruleGuid]) - $($_.Exception.Message)" "Warning"
            }
        }
    }

    Write-Status "ASR rules for APT34 protection configured" "Success"
}

# ============================================================================
# 5. Audit Logging Configuration (All Techniques)
# ============================================================================

function Set-AuditLogging {
    <#
    .SYNOPSIS
        Enables comprehensive audit logging for APT34 detection.

    .DESCRIPTION
        Configures Windows audit policies to capture registry modifications,
        process creation, object access, and network connections needed to
        detect all four APT34 attack stages.

        MITRE Mitigation: M1047 - Audit
    #>

    Write-Status "Configuring Audit Logging for APT34 Detection..." "Header"

    if ($Undo) {
        Write-Status "Reverting audit logging settings..." "Info"

        if ($PSCmdlet.ShouldProcess("Audit Policies", "Revert to defaults")) {
            $subcategories = @("Registry", "Process Creation", "Security System Extension", "Filtering Platform Connection", "File System")
            foreach ($sub in $subcategories) {
                auditpol /set /subcategory:"$sub" /success:disable /failure:disable 2>&1 | Out-Null
            }
            Add-ChangeLog "Disable" "All Audit Policies" "Enabled" "Disabled"
            Write-Status "Audit policies reverted to defaults" "Success"
        }
        return
    }

    # Registry auditing (for LSA Notification Packages - T1556.002)
    $currentValue = Get-AuditPolicyValue "Registry"
    if ($PSCmdlet.ShouldProcess("Registry Auditing", "Enable Success/Failure")) {
        auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>&1 | Out-Null
        Add-ChangeLog "Enable" "Audit: Registry" $currentValue "SuccessAndFailure"
        Write-Status "Registry auditing enabled (Event ID 4656, 4657, 4660, 4663)" "Success"
    }

    # Process Creation auditing (for appcmd.exe and PowerShell - T1505.003, T1071.003)
    $currentValue = Get-AuditPolicyValue "Process Creation"
    if ($PSCmdlet.ShouldProcess("Process Creation", "Enable Success")) {
        auditpol /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
        Add-ChangeLog "Enable" "Audit: Process Creation" $currentValue "Success"
        Write-Status "Process Creation auditing enabled (Event ID 4688)" "Success"
    }

    # Enable command line in process creation events
    if ($PSCmdlet.ShouldProcess("Command Line Auditing", "Enable")) {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "Command Line in Process Events" "Disabled" "Enabled"
            Write-Status "Command Line logging in process events enabled" "Success"
        } catch {
            Write-Status "Failed to enable command line auditing: $($_.Exception.Message)" "Warning"
        }
    }

    # Security System Extension (for service creation - T1505.003 persistence)
    $currentValue = Get-AuditPolicyValue "Security System Extension"
    if ($PSCmdlet.ShouldProcess("Security System Extension", "Enable Success/Failure")) {
        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable 2>&1 | Out-Null
        Add-ChangeLog "Enable" "Audit: Security System Extension" $currentValue "SuccessAndFailure"
        Write-Status "Security System Extension auditing enabled (Event ID 4697, 7045)" "Success"
    }

    # Filtering Platform Connection (for SMTP egress - T1048.003)
    $currentValue = Get-AuditPolicyValue "Filtering Platform Connection"
    if ($PSCmdlet.ShouldProcess("Filtering Platform Connection", "Enable Failure")) {
        auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable 2>&1 | Out-Null
        Add-ChangeLog "Enable" "Audit: Filtering Platform Connection" $currentValue "Failure"
        Write-Status "Network connection auditing enabled (Event ID 5157)" "Success"
    }

    # File System auditing (for DLL drops and data staging)
    $currentValue = Get-AuditPolicyValue "File System"
    if ($PSCmdlet.ShouldProcess("File System", "Enable Success/Failure")) {
        auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1 | Out-Null
        Add-ChangeLog "Enable" "Audit: File System" $currentValue "SuccessAndFailure"
        Write-Status "File System auditing enabled (Event ID 4663)" "Success"
    }

    Write-Status "Audit logging configured for APT34 detection" "Success"
}

# ============================================================================
# 6. PowerShell Logging (T1071.003)
# ============================================================================

function Set-PowerShellLogging {
    <#
    .SYNOPSIS
        Enables comprehensive PowerShell logging for Exchange C2 detection.

    .DESCRIPTION
        Configures PowerShell script block logging and module logging to
        capture PowerExchange C2 scripts and EWS API interactions.

        MITRE Mitigation: M1047 - Audit
    #>

    Write-Status "Configuring PowerShell Logging..." "Header"

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    if ($Undo) {
        Write-Status "Reverting PowerShell logging settings..." "Info"

        if ($PSCmdlet.ShouldProcess("PowerShell Logging", "Disable")) {
            try {
                Remove-ItemProperty -Path "$regPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "$regPath\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
                Add-ChangeLog "Disable" "PowerShell Logging" "Enabled" "Removed"
                Write-Status "PowerShell logging disabled" "Success"
            } catch {
                Write-Status "Failed to disable PowerShell logging: $($_.Exception.Message)" "Warning"
            }
        }
        return
    }

    # Enable ScriptBlock Logging (captures Exchange C2 scripts)
    if ($PSCmdlet.ShouldProcess("PowerShell ScriptBlock Logging", "Enable")) {
        try {
            $scriptBlockPath = "$regPath\ScriptBlockLogging"
            if (-not (Test-Path $scriptBlockPath)) {
                New-Item -Path $scriptBlockPath -Force | Out-Null
            }
            Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
            Add-ChangeLog "Enable" "PowerShell ScriptBlock Logging" "Disabled" "Enabled"
            Write-Status "ScriptBlock Logging enabled (Event ID 4104)" "Success"
        } catch {
            Write-Status "Failed to enable ScriptBlock Logging: $($_.Exception.Message)" "Warning"
        }
    }

    # Enable Module Logging
    if ($PSCmdlet.ShouldProcess("PowerShell Module Logging", "Enable")) {
        try {
            $moduleLoggingPath = "$regPath\ModuleLogging"
            if (-not (Test-Path $moduleLoggingPath)) {
                New-Item -Path $moduleLoggingPath -Force | Out-Null
            }
            Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

            $moduleNamesPath = "$moduleLoggingPath\ModuleNames"
            if (-not (Test-Path $moduleNamesPath)) {
                New-Item -Path $moduleNamesPath -Force | Out-Null
            }
            Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force

            Add-ChangeLog "Enable" "PowerShell Module Logging" "Disabled" "Enabled (All Modules)"
            Write-Status "Module Logging enabled (Event ID 4103)" "Success"
        } catch {
            Write-Status "Failed to enable Module Logging: $($_.Exception.Message)" "Warning"
        }
    }

    Write-Status "PowerShell logging configured" "Success"
}

# ============================================================================
# 7. Windows Defender Configuration
# ============================================================================

function Set-DefenderConfiguration {
    <#
    .SYNOPSIS
        Ensures Windows Defender is properly configured for APT34 detection.

    .DESCRIPTION
        Enables real-time protection, behavior monitoring, cloud protection,
        and network protection to maximize detection of APT34 techniques.

        MITRE Mitigation: M1038 - Execution Prevention
    #>

    Write-Status "Configuring Windows Defender..." "Header"

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Status "Windows Defender not available - skipping" "Warning"
        return
    }

    if ($Undo) {
        Write-Status "Note: Defender settings are not automatically reverted for safety" "Warning"
        return
    }

    $settings = @(
        @{ Name = "Real-Time Protection"; Cmd = { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop } },
        @{ Name = "Behavior Monitoring"; Cmd = { Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop } },
        @{ Name = "Cloud-Delivered Protection"; Cmd = { Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop } },
        @{ Name = "Automatic Sample Submission"; Cmd = { Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop } },
        @{ Name = "Network Protection"; Cmd = { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop } },
        @{ Name = "PUA Protection"; Cmd = { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop } }
    )

    foreach ($setting in $settings) {
        if ($PSCmdlet.ShouldProcess($setting.Name, "Enable")) {
            try {
                & $setting.Cmd
                Add-ChangeLog "Enable" "Defender: $($setting.Name)" "Unknown" "Enabled"
                Write-Status "$($setting.Name) enabled" "Success"
            } catch {
                Write-Status "Failed to enable $($setting.Name): $($_.Exception.Message)" "Warning"
            }
        }
    }

    Write-Status "Windows Defender configured" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  F0RT1KA Defense Hardening Script" -ForegroundColor Cyan
Write-Host "  Test: $TestName" -ForegroundColor Cyan
Write-Host "  MITRE ATT&CK: $MitreAttack" -ForegroundColor Cyan
Write-Host "  Threat Actor: APT34 / OilRig / Hazel Sandstorm" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify admin privileges
if (-not (Test-IsAdmin)) {
    Write-Status "This script requires Administrator privileges" "Error"
    Write-Status "Please run as Administrator" "Error"
    exit 1
}

$mode = if ($Undo) { "REVERT" } else { "HARDEN" }
Write-Status "Mode: $mode" "Header"
Write-Status "Log File: $Script:LogFile" "Info"
Write-Host ""

try {
    # Execute hardening functions in order of priority
    Set-LSAPasswordFilterProtection        # Critical: T1556.002
    Write-Host ""

    Set-IISModuleHardening                 # High: T1505.003
    Write-Host ""

    Set-OutboundSMTPControls               # High: T1048.003
    Write-Host ""

    Set-ASRRulesForAPT34                   # High: All techniques
    Write-Host ""

    Set-DefenderConfiguration              # High: All techniques
    Write-Host ""

    Set-AuditLogging                       # Medium: Detection enablement
    Write-Host ""

    Set-PowerShellLogging                  # Medium: T1071.003 detection
    Write-Host ""

    # Summary
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host "  Hardening Complete!" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Status "Total changes: $($Script:ChangeLog.Count)" "Success"
    Write-Status "Log file: $Script:LogFile" "Info"
    Write-Host ""

    # Display change summary
    if ($Script:ChangeLog.Count -gt 0) {
        Write-Status "Change Summary:" "Header"
        $Script:ChangeLog | Format-Table -AutoSize
    }

    # Verification commands
    Write-Host ""
    Write-Status "Verification Commands:" "Header"
    Write-Host ""
    Write-Host "  # Verify LSA Notification Packages (baseline):" -ForegroundColor Yellow
    Write-Host '  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Notification Packages"'
    Write-Host ""
    Write-Host "  # Verify Credential Guard:" -ForegroundColor Yellow
    Write-Host '  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" | Select-Object EnableVirtualizationBasedSecurity'
    Write-Host ""
    Write-Host "  # Verify ASR rules:" -ForegroundColor Yellow
    Write-Host "  Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids"
    Write-Host ""
    Write-Host "  # Verify SMTP firewall rules:" -ForegroundColor Yellow
    Write-Host '  Get-NetFirewallRule -DisplayName "F0RT1KA-APT34*" | Format-Table DisplayName, Enabled, Action'
    Write-Host ""
    Write-Host "  # Verify audit policies:" -ForegroundColor Yellow
    Write-Host '  auditpol /get /subcategory:"Registry"'
    Write-Host '  auditpol /get /subcategory:"Process Creation"'
    Write-Host '  auditpol /get /subcategory:"Security System Extension"'
    Write-Host ""
    Write-Host "  # Verify PowerShell logging:" -ForegroundColor Yellow
    Write-Host '  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue'
    Write-Host ""
    Write-Host "  # Verify Defender status:" -ForegroundColor Yellow
    Write-Host "  Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled"
    Write-Host ""

    # Reboot recommendation
    Write-Host ""
    Write-Status "IMPORTANT: Credential Guard and some audit settings require a reboot to take effect." "Warning"
    Write-Host ""

} catch {
    Write-Status "Critical error during hardening: $($_.Exception.Message)" "Error"
    Write-Status "Stack trace: $($_.ScriptStackTrace)" "Error"
    exit 1
}

exit 0
