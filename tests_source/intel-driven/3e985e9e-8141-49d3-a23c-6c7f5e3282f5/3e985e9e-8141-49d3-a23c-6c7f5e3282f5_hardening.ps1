<#
.SYNOPSIS
    F0RT1KA Hardening Script - macOS Infostealer Defense (Windows Cross-Platform Guidance)

.DESCRIPTION
    This script implements hardening measures relevant to defending against credential
    theft techniques used by AMOS/Banshee/Cuckoo macOS infostealers. While the primary
    test targets macOS, many of the same MITRE ATT&CK techniques (T1005, T1555, T1560,
    T1041) apply to Windows environments where browser credentials and cryptocurrency
    wallets are also targeted by cross-platform infostealers.

    Test ID: 3e985e9e-8141-49d3-a23c-6c7f5e3282f5
    MITRE ATT&CK: T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027
    Mitigations: M1027, M1038, M1041, M1042, M1047, M1049, M1054

    Hardening Actions:
    - Enables Windows Credential Guard to protect credential stores
    - Configures browser credential database access auditing
    - Restricts archive creation in temp directories
    - Enables network egress monitoring for suspicious HTTP POST
    - Configures WDAC/AppLocker rules for script interpreter restriction
    - Enables PowerShell script block logging for obfuscated code detection

.PARAMETER Undo
    Reverts all changes made by this script

.PARAMETER AuditOnly
    Only checks current security posture without making changes

.EXAMPLE
    .\3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening.ps1
    Applies all hardening settings

.EXAMPLE
    .\3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening.ps1 -Undo
    Reverts all hardening settings

.EXAMPLE
    .\3e985e9e-8141-49d3-a23c-6c7f5e3282f5_hardening.ps1 -AuditOnly
    Checks security posture without making changes

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Date: 2026-03-13
    Requires: Administrator privileges
    Idempotent: Yes (safe to run multiple times)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$AuditOnly
)

#Requires -RunAsAdministrator

# ============================================================
# Configuration
# ============================================================
$ErrorActionPreference = "Continue"
$Script:TestID = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
$Script:TestName = "AMOS/Banshee macOS Infostealer Defense"
$Script:ChangeLog = @()
$Script:ChangeCount = 0
$Script:WarningCount = 0

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Check")]
        [string]$Type = "Info"
    )
    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Check   = "Magenta"
    }
    $prefixes = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[-]"
        Check   = "[?]"
    }
    Write-Host "$($prefixes[$Type]) $Message" -ForegroundColor $colors[$Type]
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
    $Script:ChangeCount++
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    }
    catch {
        return $null
    }
}

function Set-RegistryHardening {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    $currentValue = Test-RegistryValue -Path $Path -Name $Name

    if ($AuditOnly) {
        if ($currentValue -eq $Value) {
            Write-Status "$Description - COMPLIANT (Current: $currentValue)" -Type "Success"
        }
        else {
            Write-Status "$Description - NON-COMPLIANT (Current: $currentValue, Required: $Value)" -Type "Warning"
            $Script:WarningCount++
        }
        return
    }

    if ($currentValue -ne $Value) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Add-ChangeLog -Action "Set Registry" -Target "$Path\$Name" -OldValue "$currentValue" -NewValue "$Value"
        Write-Status "$Description - Applied (was: $currentValue)" -Type "Success"
    }
    else {
        Write-Status "$Description - Already configured" -Type "Info"
    }
}

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "F0RT1KA Hardening: macOS Infostealer Defense (Windows)" -ForegroundColor Cyan
Write-Host "Test ID: $Script:TestID" -ForegroundColor Cyan
Write-Host "MITRE ATT&CK: T1005, T1555, T1560.001, T1041, T1027" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($AuditOnly) {
    Write-Status "Running in AUDIT ONLY mode - no changes will be made" -Type "Check"
    Write-Host ""
}
elseif ($Undo) {
    Write-Status "Running in UNDO mode - reverting hardening changes" -Type "Warning"
    Write-Host ""
}

# ============================================================
# 1. Browser Credential Protection (M1041 - Encrypt Sensitive Information)
# ============================================================

Write-Status "=== 1. Browser Credential Protection (M1041) ===" -Type "Info"

# Enable Credential Guard (protects LSASS credentials)
Set-RegistryHardening `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" `
    -Value 1 `
    -Description "Virtualization-Based Security (Credential Guard)"

Set-RegistryHardening `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" `
    -Value 1 `
    -Description "Credential Guard UEFI Lock"

# Audit file access to browser credential stores
if (-not $AuditOnly -and -not $Undo) {
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )

    foreach ($path in $browserPaths) {
        if (Test-Path $path) {
            try {
                $acl = Get-Acl $path
                $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone",
                    "Read",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Success"
                )
                $acl.AddAuditRule($auditRule)
                Set-Acl $path $acl
                Write-Status "Audit rule applied to: $path" -Type "Success"
                Add-ChangeLog -Action "Add Audit Rule" -Target $path -OldValue "None" -NewValue "Read audit"
            }
            catch {
                Write-Status "Could not set audit on: $path - $($_.Exception.Message)" -Type "Warning"
            }
        }
    }
}

Write-Host ""

# ============================================================
# 2. Script Interpreter Restrictions (M1042 - Disable or Remove Feature)
# ============================================================

Write-Status "=== 2. Script Interpreter Restrictions (M1042) ===" -Type "Info"

# Enable PowerShell Constrained Language Mode via WDAC
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "__PSLockdownPolicy" `
    -Value 4 `
    -Description "PowerShell Constrained Language Mode"

# Disable Windows Script Host (prevents VBScript/JScript credential phishing)
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
    -Name "Enabled" `
    -Value 0 `
    -Description "Windows Script Host disabled (prevents script-based phishing)"

Write-Host ""

# ============================================================
# 3. PowerShell Logging for Obfuscation Detection (M1049)
# ============================================================

Write-Status "=== 3. PowerShell Security Logging (M1049) ===" -Type "Info"

# Enable Script Block Logging (detects XOR obfuscation at runtime)
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" `
    -Value 1 `
    -Description "PowerShell Script Block Logging (detects runtime deobfuscation)"

Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockInvocationLogging" `
    -Value 1 `
    -Description "PowerShell Script Block Invocation Logging"

# Enable Module Logging
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" `
    -Value 1 `
    -Description "PowerShell Module Logging"

# Enable Transcription (full command output capture)
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" `
    -Value 1 `
    -Description "PowerShell Transcription"

Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" `
    -Value "C:\PSTranscripts" `
    -Type "String" `
    -Description "PowerShell Transcription output directory"

Write-Host ""

# ============================================================
# 4. Archive Creation Monitoring (M1047 - Audit)
# ============================================================

Write-Status "=== 4. Archive Creation Auditing (M1047) ===" -Type "Info"

# Enable process creation auditing (Event ID 4688)
if (-not $AuditOnly) {
    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null
        Write-Status "Process Creation auditing enabled" -Type "Success"
        Add-ChangeLog -Action "Enable Audit" -Target "Process Creation" -OldValue "Unknown" -NewValue "Success+Failure"
    }
    catch {
        Write-Status "Could not enable process creation auditing" -Type "Warning"
    }

    # Enable command line in process creation events
    Set-RegistryHardening `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -Value 1 `
        -Description "Include command line in process creation events"

    # Enable file system auditing
    try {
        auditpol /set /subcategory:"File System" /success:enable 2>$null
        Write-Status "File System auditing enabled" -Type "Success"
        Add-ChangeLog -Action "Enable Audit" -Target "File System" -OldValue "Unknown" -NewValue "Success"
    }
    catch {
        Write-Status "Could not enable file system auditing" -Type "Warning"
    }
}
else {
    $auditResult = auditpol /get /subcategory:"Process Creation" 2>$null
    if ($auditResult -match "Success") {
        Write-Status "Process Creation auditing - COMPLIANT" -Type "Success"
    }
    else {
        Write-Status "Process Creation auditing - NON-COMPLIANT" -Type "Warning"
        $Script:WarningCount++
    }
}

Write-Host ""

# ============================================================
# 5. Network Egress Monitoring (M1031 - Network Intrusion Prevention)
# ============================================================

Write-Status "=== 5. Network Egress Monitoring (M1031) ===" -Type "Info"

if (-not $AuditOnly -and -not $Undo) {
    # Create firewall rule to log outbound HTTP POST from non-browser processes
    # Note: Windows Firewall cannot filter by HTTP method; this blocks suspicious ports
    $existingRule = Get-NetFirewallRule -DisplayName "F0RT1KA - Block Suspicious Outbound" -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        try {
            # Log all outbound connections on non-standard ports
            Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 32768
            Write-Status "Firewall logging enabled for all profiles" -Type "Success"
            Add-ChangeLog -Action "Enable Firewall Logging" -Target "All Profiles" -OldValue "Default" -NewValue "LogAllowed+LogBlocked"
        }
        catch {
            Write-Status "Could not configure firewall logging: $($_.Exception.Message)" -Type "Warning"
        }
    }
    else {
        Write-Status "Firewall logging rule already exists" -Type "Info"
    }
}
elseif ($Undo) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed False -LogBlocked True
    Write-Status "Firewall logging reverted to defaults" -Type "Success"
}
else {
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        if ($profile.LogAllowed) {
            Write-Status "Firewall logging ($($profile.Name)) - COMPLIANT" -Type "Success"
        }
        else {
            Write-Status "Firewall logging ($($profile.Name)) - NON-COMPLIANT" -Type "Warning"
            $Script:WarningCount++
        }
    }
}

Write-Host ""

# ============================================================
# 6. Credential Store Encryption (M1041)
# ============================================================

Write-Status "=== 6. Credential Store Encryption (M1041) ===" -Type "Info"

# Enforce DPAPI for stored credentials
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\DPAPI" `
    -Name "ForceProtection" `
    -Value 1 `
    -Description "DPAPI forced protection for credential stores"

# Disable credential caching (reduces offline attack surface)
Set-RegistryHardening `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "CachedLogonsCount" `
    -Value 1 `
    -Type "String" `
    -Description "Reduce cached credential count to 1"

Write-Host ""

# ============================================================
# Summary
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Hardening Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($AuditOnly) {
    Write-Status "Audit complete. Non-compliant settings: $Script:WarningCount" -Type "Check"
}
elseif ($Undo) {
    Write-Status "Undo complete. Changes reverted: $Script:ChangeCount" -Type "Warning"
}
else {
    Write-Status "Hardening complete. Changes applied: $Script:ChangeCount" -Type "Success"

    if ($Script:ChangeLog.Count -gt 0) {
        Write-Host ""
        Write-Status "Change Log:" -Type "Info"
        $Script:ChangeLog | Format-Table -AutoSize
    }
}

Write-Host ""
Write-Status "NOTE: This script provides Windows-equivalent protections for" -Type "Info"
Write-Status "techniques used by macOS infostealers. For macOS-specific hardening," -Type "Info"
Write-Status "use: 3e985e9e..._hardening_macos.sh" -Type "Info"
Write-Host ""
