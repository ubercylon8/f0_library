<#
.SYNOPSIS
    F0RT1KA Windows Hardening Script - LD_PRELOAD Hijacking Defense Equivalents

.DESCRIPTION
    While the Perfctl/Symbiote LD_PRELOAD attack chain targets Linux endpoints,
    Windows has equivalent attack surfaces: DLL search order hijacking (T1574.001),
    AppInit_DLLs injection (T1546.010), credential harvesting via SAM/LSASS, and
    SUID-equivalent privilege escalation via service misconfigurations.

    This script hardens Windows endpoints against the equivalent classes of attacks:
    - DLL hijacking prevention (equivalent to LD_PRELOAD)
    - Credential dumping protection (equivalent to /etc/shadow access)
    - Privilege escalation prevention (equivalent to SUID abuse)
    - Persistence mechanism hardening

    Test ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97
    MITRE ATT&CK: T1574.001, T1574.002, T1546.010, T1003.001, T1003.002, T1548.002
    Mitigations: M1038, M1025, M1028, M1043

.PARAMETER Undo
    Reverts all changes made by this script

.PARAMETER WhatIf
    Shows what would happen without making changes

.EXAMPLE
    .\54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening.ps1
    Applies all hardening settings

.EXAMPLE
    .\54a0bd24-d75a-4d89-8dce-c381d932ca97_hardening.ps1 -Undo
    Reverts all hardening settings

.NOTES
    Author: F0RT1KA Defense Guidance Builder
    Requires: Administrator privileges
    Idempotent: Yes (safe to run multiple times)
    Platform: Windows Server 2016+, Windows 10/11
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
$Script:BackupDir = "$env:ProgramData\F0RT1KA\HardeningBackups\54a0bd24"

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
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

function Ensure-BackupDir {
    if (-not (Test-Path $Script:BackupDir)) {
        New-Item -Path $Script:BackupDir -ItemType Directory -Force | Out-Null
    }
}

function Backup-RegistryKey {
    param([string]$Path, [string]$Name)
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($value) {
            $backupFile = Join-Path $Script:BackupDir "$(($Path -replace '[:\\]','_'))_$Name.txt"
            "$($value.$Name)" | Out-File -FilePath $backupFile -Force
        }
    } catch { }
}

# ============================================================
# 1. Disable AppInit_DLLs (Windows equivalent of LD_PRELOAD)
# ============================================================
# AppInit_DLLs is the closest Windows equivalent to LD_PRELOAD.
# Any DLL listed here is loaded into every user-mode process.
# MITRE: T1546.010 - AppInit DLLs

function Set-AppInitDLLsProtection {
    Write-Status "Configuring AppInit_DLLs protection..." "Info"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    $regPath32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"

    foreach ($path in @($regPath, $regPath32)) {
        if (Test-Path $path) {
            Backup-RegistryKey -Path $path -Name "LoadAppInit_DLLs"
            Backup-RegistryKey -Path $path -Name "AppInit_DLLs"

            if ($Undo) {
                Set-ItemProperty -Path $path -Name "LoadAppInit_DLLs" -Value 0 -Type DWord
                Set-ItemProperty -Path $path -Name "RequireSignedAppInit_DLLs" -Value 0 -Type DWord
                Write-Status "  Reverted AppInit_DLLs settings at $path" "Warning"
            } else {
                # Disable AppInit_DLLs loading entirely
                Set-ItemProperty -Path $path -Name "LoadAppInit_DLLs" -Value 0 -Type DWord
                # If enabled, require signed DLLs
                Set-ItemProperty -Path $path -Name "RequireSignedAppInit_DLLs" -Value 1 -Type DWord
                # Clear any existing AppInit_DLLs entries
                Set-ItemProperty -Path $path -Name "AppInit_DLLs" -Value "" -Type String
                Add-ChangeLog "Hardened" $path "Various" "LoadAppInit_DLLs=0, RequireSignedAppInit_DLLs=1"
                Write-Status "  Disabled AppInit_DLLs at $path" "Success"
            }
        }
    }
}

# ============================================================
# 2. Enable Credential Guard / LSASS Protection
# ============================================================
# Equivalent to protecting /etc/shadow from unauthorized reads.
# MITRE: T1003.001 - LSASS Memory, T1003.002 - SAM

function Set-CredentialProtection {
    Write-Status "Configuring credential dumping protections..." "Info"

    # Enable LSASS as PPL (Protected Process Light)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Backup-RegistryKey -Path $regPath -Name "RunAsPPL"

    if ($Undo) {
        Remove-ItemProperty -Path $regPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
        Write-Status "  Reverted LSASS PPL protection" "Warning"
    } else {
        Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1 -Type DWord
        Add-ChangeLog "Hardened" "$regPath\RunAsPPL" "0 or not set" "1"
        Write-Status "  Enabled LSASS Protected Process Light (PPL)" "Success"
    }

    # Disable WDigest credential caching
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigestPath)) {
        New-Item -Path $wdigestPath -Force | Out-Null
    }
    Backup-RegistryKey -Path $wdigestPath -Name "UseLogonCredential"

    if ($Undo) {
        Remove-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        Write-Status "  Reverted WDigest credential caching setting" "Warning"
    } else {
        Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWord
        Add-ChangeLog "Hardened" "$wdigestPath\UseLogonCredential" "1 or not set" "0"
        Write-Status "  Disabled WDigest plaintext credential storage" "Success"
    }

    # Restrict SAM remote access (equivalent to /etc/shadow permission hardening)
    $samPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Backup-RegistryKey -Path $samPath -Name "RestrictRemoteSAM"

    if (-not $Undo) {
        $restrictSAM = "O:BAG:BAD:(A;;RC;;;BA)"  # Only Administrators
        Set-ItemProperty -Path $samPath -Name "RestrictRemoteSAM" -Value $restrictSAM -Type String
        Add-ChangeLog "Hardened" "$samPath\RestrictRemoteSAM" "Not set" "Administrators only"
        Write-Status "  Restricted remote SAM access to Administrators only" "Success"
    } else {
        Remove-ItemProperty -Path $samPath -Name "RestrictRemoteSAM" -ErrorAction SilentlyContinue
        Write-Status "  Reverted remote SAM restriction" "Warning"
    }
}

# ============================================================
# 3. DLL Search Order Hardening
# ============================================================
# Equivalent to preventing .so loading from untrusted paths.
# MITRE: T1574.001 - DLL Search Order Hijacking

function Set-DLLSearchOrderProtection {
    Write-Status "Configuring DLL search order hardening..." "Info"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    Backup-RegistryKey -Path $regPath -Name "SafeDllSearchMode"
    Backup-RegistryKey -Path $regPath -Name "CWDIllegalInDllSearch"

    if ($Undo) {
        Set-ItemProperty -Path $regPath -Name "SafeDllSearchMode" -Value 1 -Type DWord
        Remove-ItemProperty -Path $regPath -Name "CWDIllegalInDllSearch" -ErrorAction SilentlyContinue
        Write-Status "  Reverted DLL search order settings" "Warning"
    } else {
        # Enable safe DLL search mode (search system dirs before CWD)
        Set-ItemProperty -Path $regPath -Name "SafeDllSearchMode" -Value 1 -Type DWord
        # Block DLL loading from CWD for remote paths
        Set-ItemProperty -Path $regPath -Name "CWDIllegalInDllSearch" -Value 2 -Type DWord
        Add-ChangeLog "Hardened" $regPath "Default" "SafeDllSearchMode=1, CWDIllegalInDllSearch=2"
        Write-Status "  Enabled safe DLL search mode" "Success"
        Write-Status "  Blocked CWD DLL loading from remote paths" "Success"
    }
}

# ============================================================
# 4. Service Account Hardening (Equivalent to SUID protection)
# ============================================================
# Equivalent to auditing and removing unnecessary SUID bits.
# MITRE: T1548.002 - Bypass User Account Control

function Set-ServiceAccountHardening {
    Write-Status "Configuring service privilege hardening..." "Info"

    # Enable UAC (equivalent to requiring explicit privilege escalation)
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if ($Undo) {
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        Write-Status "  Reverted UAC to defaults" "Warning"
    } else {
        # Ensure UAC is enabled
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
        # Prompt for consent on secure desktop for administrators
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
        # Prompt for credentials for standard users
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord
        # Always use secure desktop for UAC prompts
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        # Detect application installations and elevate
        Set-ItemProperty -Path $uacPath -Name "EnableInstallerDetection" -Value 1 -Type DWord
        Add-ChangeLog "Hardened" $uacPath "Default" "Maximum UAC enforcement"
        Write-Status "  Enforced maximum UAC protection" "Success"
    }
}

# ============================================================
# 5. Audit Policy Configuration (Detection Enhancement)
# ============================================================
# Enable auditing equivalent to auditd rules for LD_PRELOAD monitoring.

function Set-AuditPolicies {
    Write-Status "Configuring advanced audit policies..." "Info"

    if ($Undo) {
        # Reset to defaults
        auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable 2>$null
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
        Write-Status "  Reverted audit policies to defaults" "Warning"
    } else {
        # Enable process creation auditing (detect suspicious process trees)
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null
        # Enable detailed tracking for privilege use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable 2>$null
        # Enable logon event auditing
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
        # Enable object access for file monitoring
        auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null
        # Enable registry access auditing
        auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null

        # Enable command line in process creation events (Event ID 4688)
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

        Add-ChangeLog "Hardened" "AuditPolicy" "Default" "Enhanced process, privilege, and file auditing"
        Write-Status "  Enabled process creation auditing with command line logging" "Success"
        Write-Status "  Enabled sensitive privilege use auditing" "Success"
        Write-Status "  Enabled file system and registry access auditing" "Success"
    }
}

# ============================================================
# 6. Windows Defender Configuration
# ============================================================

function Set-DefenderProtection {
    Write-Status "Configuring Windows Defender protections..." "Info"

    if ($Undo) {
        Write-Status "  Defender settings should be managed via Group Policy" "Warning"
        return
    }

    try {
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        # Enable behavior monitoring
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        # Enable IOAV protection (download scanning)
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        # Enable PUA protection
        Set-MpPreference -PUAProtection 1 -ErrorAction SilentlyContinue
        # Enable cloud-delivered protection
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        # Enable automatic sample submission
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
        # Enable network protection
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue

        Add-ChangeLog "Hardened" "WindowsDefender" "Various" "Full protection enabled"
        Write-Status "  Enabled real-time, behavior, IOAV, PUA, cloud, and network protection" "Success"
    } catch {
        Write-Status "  Windows Defender configuration failed (may not be available): $_" "Warning"
    }
}

# ============================================================
# 7. Attack Surface Reduction Rules
# ============================================================

function Set-ASRRules {
    Write-Status "Configuring Attack Surface Reduction rules..." "Info"

    if ($Undo) {
        Write-Status "  ASR rules should be managed via Group Policy or Intune" "Warning"
        return
    }

    try {
        $asrRules = @{
            # Block all Office applications from creating child processes
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1
            # Block Office applications from creating executable content
            "3b576869-a4ec-4529-8536-b80a7769e899" = 1
            # Block credential stealing from Windows LSASS
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1
            # Block process creations from PSExec and WMI
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 1
            # Block untrusted/unsigned processes from USB
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1
            # Block persistence through WMI event subscription
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1
        }

        foreach ($rule in $asrRules.GetEnumerator()) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value -ErrorAction SilentlyContinue
        }

        Add-ChangeLog "Hardened" "ASR Rules" "Not set" "6 ASR rules enabled in block mode"
        Write-Status "  Enabled 6 Attack Surface Reduction rules including LSASS protection" "Success"
    } catch {
        Write-Status "  ASR rule configuration failed (requires Defender): $_" "Warning"
    }
}

# ============================================================
# Main Execution
# ============================================================

Write-Status "============================================================" "Info"
Write-Status "F0RT1KA Hardening Script" "Info"
Write-Status "Test: Perfctl/Symbiote LD_PRELOAD - Windows Equivalents" "Info"
Write-Status "ID: 54a0bd24-d75a-4d89-8dce-c381d932ca97" "Info"
Write-Status "============================================================" "Info"
Write-Status "" "Info"

Ensure-BackupDir

if ($Undo) {
    Write-Status "MODE: UNDO - Reverting hardening changes..." "Warning"
    Write-Status "" "Info"
} else {
    Write-Status "MODE: APPLY - Applying hardening settings..." "Info"
    Write-Status "" "Info"
}

# Execute all hardening functions
Set-AppInitDLLsProtection
Set-CredentialProtection
Set-DLLSearchOrderProtection
Set-ServiceAccountHardening
Set-AuditPolicies
Set-DefenderProtection
Set-ASRRules

Write-Status "" "Info"
Write-Status "============================================================" "Info"
if ($Undo) {
    Write-Status "Hardening REVERTED. Review system security posture." "Warning"
} else {
    Write-Status "Hardening COMPLETE. $($Script:ChangeLog.Count) changes applied." "Success"
    Write-Status "Backups saved to: $Script:BackupDir" "Info"
    Write-Status "Reboot recommended to apply all changes." "Info"
}
Write-Status "============================================================" "Info"

# Export change log
if ($Script:ChangeLog.Count -gt 0) {
    $logPath = Join-Path $Script:BackupDir "changelog_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Script:ChangeLog | Export-Csv -Path $logPath -NoTypeInformation
    Write-Status "Change log exported: $logPath" "Info"
}
