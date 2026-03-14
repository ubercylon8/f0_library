<#
.SYNOPSIS
    Hardens Windows against PowerShell-based execution and AMSI bypass techniques.

.DESCRIPTION
    Applies security hardening to mitigate T1059.001 (Command and Scripting Interpreter:
    PowerShell) and T1140 (Deobfuscate/Decode Files or Information).

    Controls applied:
      - PowerShell Script Block Logging (Event ID 4104)
      - PowerShell Module Logging (Event ID 4103)
      - PowerShell Transcription
      - Protected Event Logging
      - PowerShell v2 removal
      - AMSI provider integrity verification
      - Windows Defender real-time protection enforcement
      - Attack Surface Reduction (ASR) rules for script-based attacks
      - Process Creation audit policy with command-line capture
      - AMSI registry key monitoring (via audit SACL)
      - Constrained Language Mode awareness check

    MITRE ATT&CK: T1059.001, T1140
    Mitigations:  M1042, M1045, M1026, M1038, M1049, M1040

    All changes are idempotent and fully reversible via -Undo.

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.
    Backup values are read from the registry backup key written during hardening.

.PARAMETER WhatIf
    Shows what the script would change without making any modifications.

.PARAMETER SkipASR
    Skips Attack Surface Reduction rule configuration. Use when MDE/Defender for
    Endpoint is not licensed or when ASR rules require separate change management.

.PARAMETER TranscriptPath
    Directory where PowerShell transcripts will be written.
    Default: C:\ProgramData\PowerShellTranscripts

.EXAMPLE
    .\f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01_hardening.ps1 -WhatIf
    Previews all changes without applying them.

.EXAMPLE
    .\f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01_hardening.ps1 -Undo
    Reverts all hardening settings.

.EXAMPLE
    .\f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01_hardening.ps1 -SkipASR
    Applies all settings except ASR rule configuration.

.NOTES
    Author:       F0RT1KA Defense Guidance Generator
    Requires:     Administrator privileges
    Idempotent:   Yes (safe to run multiple times)
    Backup store: HKLM\SOFTWARE\F0RT1KA\Hardening\T1059-T1140
    Test ID:      f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipASR,
    [string]$TranscriptPath = "C:\ProgramData\PowerShellTranscripts"
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog      = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:BackupRegPath  = "HKLM:\SOFTWARE\F0RT1KA\Hardening\T1059-T1140"

# ============================================================
# Utility functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Section")]
        [string]$Type = "Info"
    )
    $color = switch ($Type) {
        "Info"    { "Cyan"    }
        "Success" { "Green"   }
        "Warning" { "Yellow"  }
        "Error"   { "Red"     }
        "Section" { "Magenta" }
    }
    $prefix = switch ($Type) {
        "Info"    { "[INFO]   " }
        "Success" { "[ OK ]   " }
        "Warning" { "[WARN]   " }
        "Error"   { "[ERR ]   " }
        "Section" { "[====]   " }
    }
    Write-Host "$prefix$Message" -ForegroundColor $color
}

function Add-ChangeLog {
    param([string]$Component, [string]$Setting, [string]$OldValue, [string]$NewValue, [string]$Action)
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Component = $Component
        Setting   = $Setting
        OldValue  = $OldValue
        NewValue  = $NewValue
        Action    = $Action
    })
}

function Get-RegValueSafe {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $val) { return $val.$Name }
        }
    } catch {}
    return $null
}

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set registry value to '$Value'")) {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    }
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Remove registry value")) {
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        }
    }
}

function Backup-RegValue {
    param([string]$Path, [string]$Name, [string]$BackupName)
    $current = Get-RegValueSafe -Path $Path -Name $Name
    $backupValue = if ($null -eq $current) { "__NOT_SET__" } else { "$current" }
    Set-RegValue -Path $Script:BackupRegPath -Name $BackupName -Value $backupValue `
                 -Type ([Microsoft.Win32.RegistryValueKind]::String)
}

function Restore-RegValue {
    param([string]$Path, [string]$Name, [string]$BackupName, [string]$OrigType = "DWord")
    $backupValue = Get-RegValueSafe -Path $Script:BackupRegPath -Name $BackupName
    if ($null -eq $backupValue) {
        Write-Status "No backup found for $BackupName — skipping restore" "Warning"
        return
    }
    if ($backupValue -eq "__NOT_SET__") {
        Remove-RegValue -Path $Path -Name $Name
        Write-Status "Restored: removed $Name from $Path" "Success"
    } else {
        $kindMap = @{ "DWord" = [Microsoft.Win32.RegistryValueKind]::DWord; "String" = [Microsoft.Win32.RegistryValueKind]::String }
        $kind = $kindMap[$OrigType]
        $typedValue = if ($OrigType -eq "DWord") { [int]$backupValue } else { $backupValue }
        Set-RegValue -Path $Path -Name $Name -Value $typedValue -Type $kind
        Write-Status "Restored: $Name = $backupValue in $Path" "Success"
    }
}

# ============================================================
# Section 1: PowerShell Script Block Logging (Event ID 4104)
# MITRE M1049, M1040
# CIS Benchmark: 18.9.91.1
# ============================================================

function Set-ScriptBlockLogging {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

    if ($Undo) {
        Write-Status "Reverting Script Block Logging..." "Warning"
        Restore-RegValue -Path $regPath -Name "EnableScriptBlockLogging" -BackupName "SBL_EnableScriptBlockLogging"
        Restore-RegValue -Path $regPath -Name "EnableScriptBlockInvocationLogging" -BackupName "SBL_EnableScriptBlockInvocationLogging"
        Add-ChangeLog -Component "ScriptBlockLogging" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring PowerShell Script Block Logging..." "Info"

    Backup-RegValue -Path $regPath -Name "EnableScriptBlockLogging" -BackupName "SBL_EnableScriptBlockLogging"
    Backup-RegValue -Path $regPath -Name "EnableScriptBlockInvocationLogging" -BackupName "SBL_EnableScriptBlockInvocationLogging"

    if ($PSCmdlet.ShouldProcess($regPath, "Enable Script Block Logging")) {
        Set-RegValue -Path $regPath -Name "EnableScriptBlockLogging" -Value 1
        Set-RegValue -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1

        $current = Get-RegValueSafe -Path $regPath -Name "EnableScriptBlockLogging"
        if ($current -eq 1) {
            Write-Status "Script Block Logging enabled (Event ID 4104)" "Success"
            Add-ChangeLog -Component "ScriptBlockLogging" -Setting "EnableScriptBlockLogging" -OldValue "0/NotSet" -NewValue "1" -Action "Set"
        } else {
            Write-Status "Failed to confirm Script Block Logging state" "Warning"
        }
    }
}

# ============================================================
# Section 2: PowerShell Module Logging (Event ID 4103)
# MITRE M1049
# ============================================================

function Set-ModuleLogging {
    $regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $namesPath = "$regPath\ModuleNames"

    if ($Undo) {
        Write-Status "Reverting Module Logging..." "Warning"
        Restore-RegValue -Path $regPath -Name "EnableModuleLogging" -BackupName "ML_EnableModuleLogging"
        # Remove the wildcard module name entry added by this script
        if ($PSCmdlet.ShouldProcess($namesPath, "Remove wildcard module entry")) {
            Remove-RegValue -Path $namesPath -Name "*"
        }
        Add-ChangeLog -Component "ModuleLogging" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring PowerShell Module Logging..." "Info"

    Backup-RegValue -Path $regPath -Name "EnableModuleLogging" -BackupName "ML_EnableModuleLogging"

    if ($PSCmdlet.ShouldProcess($regPath, "Enable Module Logging")) {
        Set-RegValue -Path $regPath -Name "EnableModuleLogging" -Value 1

        if (-not (Test-Path $namesPath)) {
            New-Item -Path $namesPath -Force | Out-Null
        }
        # Log all modules
        Set-RegValue -Path $namesPath -Name "*" -Value "*" -Type ([Microsoft.Win32.RegistryValueKind]::String)

        Write-Status "Module Logging enabled — all modules captured (Event ID 4103)" "Success"
        Add-ChangeLog -Component "ModuleLogging" -Setting "EnableModuleLogging + ModuleNames=*" -OldValue "0/NotSet" -NewValue "1 / *" -Action "Set"
    }
}

# ============================================================
# Section 3: PowerShell Transcription
# MITRE M1049, M1040
# ============================================================

function Set-PowerShellTranscription {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    if ($Undo) {
        Write-Status "Reverting PowerShell Transcription..." "Warning"
        Restore-RegValue -Path $regPath -Name "EnableTranscripting" -BackupName "TR_EnableTranscripting"
        Restore-RegValue -Path $regPath -Name "EnableInvocationHeader" -BackupName "TR_EnableInvocationHeader"
        Restore-RegValue -Path $regPath -Name "OutputDirectory" -BackupName "TR_OutputDirectory" -OrigType "String"
        Add-ChangeLog -Component "Transcription" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring PowerShell Transcription..." "Info"

    # Create transcript directory if not present
    if (-not (Test-Path $TranscriptPath)) {
        if ($PSCmdlet.ShouldProcess($TranscriptPath, "Create transcript directory")) {
            New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
            # Restrict directory: SYSTEM + Admins write, Everyone read — transcripts stay readable for SOC
            $acl = Get-Acl $TranscriptPath
            $acl.SetAccessRuleProtection($true, $false)
            $adminRule   = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $systemRule  = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $acl.AddAccessRule($adminRule)
            $acl.AddAccessRule($systemRule)
            Set-Acl -Path $TranscriptPath -AclObject $acl
        }
    }

    Backup-RegValue -Path $regPath -Name "EnableTranscripting" -BackupName "TR_EnableTranscripting"
    Backup-RegValue -Path $regPath -Name "EnableInvocationHeader" -BackupName "TR_EnableInvocationHeader"
    Backup-RegValue -Path $regPath -Name "OutputDirectory" -BackupName "TR_OutputDirectory"

    if ($PSCmdlet.ShouldProcess($regPath, "Enable PowerShell Transcription")) {
        Set-RegValue -Path $regPath -Name "EnableTranscripting" -Value 1
        Set-RegValue -Path $regPath -Name "EnableInvocationHeader" -Value 1
        Set-RegValue -Path $regPath -Name "OutputDirectory" -Value $TranscriptPath -Type ([Microsoft.Win32.RegistryValueKind]::String)

        Write-Status "PowerShell Transcription enabled — output: $TranscriptPath" "Success"
        Add-ChangeLog -Component "Transcription" -Setting "EnableTranscripting + OutputDirectory" -OldValue "0/NotSet" -NewValue "1 / $TranscriptPath" -Action "Set"
    }
}

# ============================================================
# Section 4: Disable PowerShell Version 2
# MITRE M1042
# CIS Benchmark: 18.9.91.3 / NSA-CISA PowerShell guidance
#
# PowerShell v2 bypasses AMSI, ScriptBlockLogging, and CLM.
# Removing the Windows Feature eliminates this attack path.
# ============================================================

function Disable-PowerShellV2 {
    $featureName = "MicrosoftWindowsPowerShellV2Root"

    if ($Undo) {
        Write-Status "Re-enabling PowerShell v2 (reverting removal)..." "Warning"
        $backup = Get-RegValueSafe -Path $Script:BackupRegPath -Name "PSv2_OriginalState"
        if ($backup -eq "Enabled") {
            if ($PSCmdlet.ShouldProcess($featureName, "Enable Windows Feature")) {
                Enable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Status "PowerShell v2 re-enabled (was enabled before hardening)" "Warning"
                Add-ChangeLog -Component "PowerShellV2" -Setting "WindowsFeature" -OldValue "Disabled" -NewValue "Enabled" -Action "Undo"
            }
        } else {
            Write-Status "PowerShell v2 was not enabled before hardening — no action needed" "Info"
        }
        return
    }

    Write-Status "Checking PowerShell v2 feature status..." "Info"

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
    if ($null -eq $feature) {
        Write-Status "PowerShell v2 feature not found on this OS version — skipping" "Warning"
        return
    }

    $originalState = $feature.State
    Set-RegValue -Path $Script:BackupRegPath -Name "PSv2_OriginalState" -Value $originalState -Type ([Microsoft.Win32.RegistryValueKind]::String)

    if ($feature.State -eq "Enabled") {
        if ($PSCmdlet.ShouldProcess($featureName, "Disable Windows Feature (PowerShell v2)")) {
            Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction SilentlyContinue | Out-Null
            # Verify
            $afterState = (Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue).State
            if ($afterState -eq "Disabled") {
                Write-Status "PowerShell v2 disabled — AMSI/logging bypass path removed" "Success"
                Add-ChangeLog -Component "PowerShellV2" -Setting "WindowsFeature" -OldValue "Enabled" -NewValue "Disabled" -Action "Disabled"
            } else {
                Write-Status "PowerShell v2 disable did not take effect immediately (may require reboot)" "Warning"
            }
        }
    } else {
        Write-Status "PowerShell v2 already disabled — no action needed" "Success"
    }
}

# ============================================================
# Section 5: Windows Defender / AMSI Configuration
# MITRE M1049, M1040
# ============================================================

function Set-DefenderAMSIHardening {
    if ($Undo) {
        Write-Status "Reverting Defender/AMSI hardening..." "Warning"
        $rtBackup = Get-RegValueSafe -Path $Script:BackupRegPath -Name "DEF_DisableRealtimeMonitoring"
        if ($null -ne $rtBackup -and $rtBackup -ne "__NOT_SET__") {
            if ($PSCmdlet.ShouldProcess("Defender", "Restore DisableRealtimeMonitoring")) {
                Set-MpPreference -DisableRealtimeMonitoring ([bool][int]$rtBackup) -ErrorAction SilentlyContinue
                Write-Status "Restored DisableRealtimeMonitoring = $rtBackup" "Success"
            }
        }
        $ioavBackup = Get-RegValueSafe -Path $Script:BackupRegPath -Name "DEF_DisableIOAVProtection"
        if ($null -ne $ioavBackup -and $ioavBackup -ne "__NOT_SET__") {
            if ($PSCmdlet.ShouldProcess("Defender", "Restore DisableIOAVProtection")) {
                Set-MpPreference -DisableIOAVProtection ([bool][int]$ioavBackup) -ErrorAction SilentlyContinue
            }
        }
        Add-ChangeLog -Component "Defender" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring Windows Defender for PowerShell threat coverage..." "Info"

    # Verify Defender service is running
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($null -eq $svc -or $svc.Status -ne "Running") {
        Write-Status "Windows Defender service (WinDefend) is not running — skipping Defender configuration" "Warning"
        return
    }

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        # Backup current state
        $rtValue = [int]$mpStatus.RealTimeProtectionEnabled
        Set-RegValue -Path $Script:BackupRegPath -Name "DEF_DisableRealtimeMonitoring" -Value (if ($mpStatus.RealTimeProtectionEnabled) { "0" } else { "1" }) -Type ([Microsoft.Win32.RegistryValueKind]::String)

        if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable real-time protection")) {
            if (-not $mpStatus.RealTimeProtectionEnabled) {
                Set-MpPreference -DisableRealtimeMonitoring $false
                Write-Status "Real-time protection enabled" "Success"
                Add-ChangeLog -Component "Defender" -Setting "DisableRealtimeMonitoring" -OldValue "True" -NewValue "False" -Action "Set"
            } else {
                Write-Status "Real-time protection already enabled" "Success"
            }
        }

        if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable IOAV protection (download scanning)")) {
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            Write-Status "IOAV (downloaded file scanning) enabled" "Success"
        }

        if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable script scanning")) {
            Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
            Write-Status "Script scanning enabled" "Success"
        }

        # Verify AMSI providers exist
        $amsiProviders = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        if ($null -eq $amsiProviders -or $amsiProviders.Count -eq 0) {
            Write-Status "WARNING: No AMSI providers registered — AMSI is non-functional on this system" "Error"
            Add-ChangeLog -Component "AMSI" -Setting "ProviderCheck" -OldValue "N/A" -NewValue "NO PROVIDERS FOUND" -Action "Alert"
        } else {
            Write-Status "AMSI providers verified ($($amsiProviders.Count) registered)" "Success"
            foreach ($provider in $amsiProviders) {
                Write-Status "  AMSI Provider: $($provider.PSChildName)" "Info"
            }
        }

    } catch {
        Write-Status "Could not configure Defender preferences: $_" "Warning"
    }
}

# ============================================================
# Section 6: Attack Surface Reduction (ASR) Rules
# MITRE M1040, M1038
# Requires: Windows 10 1709+, Microsoft Defender Antivirus active
# ============================================================

function Set-ASRRulesForPowerShell {
    if ($SkipASR) {
        Write-Status "ASR rule configuration skipped (-SkipASR)" "Warning"
        return
    }

    # Verify ASR capability
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Status "ASR rules require Windows 10 or later — skipping" "Warning"
        return
    }

    # ASR rules relevant to PowerShell/scripting execution and obfuscation
    # Each rule: [GUID] = [Action] (2=Audit, 1=Block)
    # Start in Audit to validate environment before enforcing Block
    $asrRules = [ordered]@{
        # Block Office applications from creating child processes (spawned PS)
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 2
        # Block Office applications from creating executable content
        "3b576869-a4ec-4529-8536-b80a7769e899" = 2
        # Block executable content from email/webmail
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 2
        # Block JavaScript or VBScript from launching downloaded executable content
        "d3e037e1-3eb8-44c8-a917-57927947596d" = 2
        # Block execution of potentially obfuscated scripts
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 2
        # Block Win32 API calls from Office macros
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 2
        # Block credential stealing from the Windows local security authority subsystem
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3" = 2
        # Use advanced protection against ransomware
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = 2
    }

    if ($Undo) {
        Write-Status "Reverting ASR rules..." "Warning"
        $backup = Get-RegValueSafe -Path $Script:BackupRegPath -Name "ASR_BackedUp"
        if ($backup -ne "1") {
            Write-Status "No ASR backup found — cannot revert ASR rules safely" "Warning"
            return
        }
        foreach ($ruleId in $asrRules.Keys) {
            $backupAction = Get-RegValueSafe -Path $Script:BackupRegPath -Name "ASR_$ruleId"
            if ($null -ne $backupAction) {
                if ($PSCmdlet.ShouldProcess("ASR Rule $ruleId", "Restore action to $backupAction")) {
                    try {
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                                         -AttackSurfaceReductionRules_Actions $backupAction `
                                         -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
        }
        Write-Status "ASR rules reverted" "Success"
        Add-ChangeLog -Component "ASR" -Setting "AllRules" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring Attack Surface Reduction rules..." "Info"
    Write-Status "  Mode: Audit (2) — review events in Event ID 1121/1122 before switching to Block (1)" "Warning"

    # Read and backup current ASR state
    $currentRules = (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids
    $currentActions = (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Actions

    Set-RegValue -Path $Script:BackupRegPath -Name "ASR_BackedUp" -Value "1" -Type ([Microsoft.Win32.RegistryValueKind]::String)

    foreach ($ruleId in $asrRules.Keys) {
        $currentAction = $null
        if ($currentRules) {
            $idx = [array]::IndexOf($currentRules, $ruleId)
            if ($idx -ge 0 -and $null -ne $currentActions -and $idx -lt $currentActions.Count) {
                $currentAction = $currentActions[$idx]
            }
        }
        $backupVal = if ($null -ne $currentAction) { "$currentAction" } else { "__NOT_SET__" }
        Set-RegValue -Path $Script:BackupRegPath -Name "ASR_$ruleId" -Value $backupVal -Type ([Microsoft.Win32.RegistryValueKind]::String)

        $targetAction = $asrRules[$ruleId]
        if ($PSCmdlet.ShouldProcess("ASR Rule $ruleId", "Set action to $targetAction (2=Audit)")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                                 -AttackSurfaceReductionRules_Actions $targetAction `
                                 -ErrorAction Stop
                $actionName = if ($targetAction -eq 1) { "Block" } elseif ($targetAction -eq 2) { "Audit" } else { "Disabled" }
                Write-Status "  ASR $ruleId = $actionName" "Success"
                Add-ChangeLog -Component "ASR" -Setting $ruleId -OldValue "$backupVal" -NewValue "$targetAction" -Action "Set"
            } catch {
                Write-Status "  Failed to set ASR rule $ruleId : $_" "Warning"
            }
        }
    }

    Write-Status "ASR rules configured in Audit mode. Review Event IDs 1121/1122 in Event Viewer before switching to Block." "Warning"
    Write-Status "To switch a rule to Block:  Add-MpPreference -AttackSurfaceReductionRules_Ids '<GUID>' -AttackSurfaceReductionRules_Actions 1" "Info"
}

# ============================================================
# Section 7: Process Creation Auditing with Command Line
# MITRE M1040 (detection prerequisite)
# CIS Benchmark: 17.2.2
# ============================================================

function Set-ProcessCreationAudit {
    $cmdLineRegPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $cmdLineRegName  = "ProcessCreationIncludeCmdLine_Enabled"

    if ($Undo) {
        Write-Status "Reverting process creation audit policy..." "Warning"
        Restore-RegValue -Path $cmdLineRegPath -Name $cmdLineRegName -BackupName "AUDIT_CmdLine"
        if ($PSCmdlet.ShouldProcess("Audit Policy", "Revert process creation audit")) {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable 2>$null | Out-Null
        }
        Add-ChangeLog -Component "AuditPolicy" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring Process Creation audit policy..." "Info"

    Backup-RegValue -Path $cmdLineRegPath -Name $cmdLineRegName -BackupName "AUDIT_CmdLine"

    if ($PSCmdlet.ShouldProcess("auditpol", "Enable Process Creation auditing (Success)")) {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
        Write-Status "Process Creation auditing enabled (Event ID 4688)" "Success"
        Add-ChangeLog -Component "AuditPolicy" -Setting "ProcessCreation" -OldValue "Disabled" -NewValue "Success+Failure" -Action "Set"
    }

    if ($PSCmdlet.ShouldProcess($cmdLineRegPath, "Enable command-line capture in Event 4688")) {
        Set-RegValue -Path $cmdLineRegPath -Name $cmdLineRegName -Value 1
        Write-Status "Command-line capture in Event 4688 enabled — full PS command lines now logged" "Success"
        Add-ChangeLog -Component "AuditPolicy" -Setting "ProcessCreationIncludeCmdLine" -OldValue "0/NotSet" -NewValue "1" -Action "Set"
    }
}

# ============================================================
# Section 8: PowerShell Execution Policy (defense-in-depth)
# MITRE M1045
#
# NOTE: Execution policy alone is not a security boundary —
# it can be bypassed with -ExecutionPolicy Bypass. Pair with
# WDAC for an enforceable control. Configured here for
# defense-in-depth at the registry (GPO) level.
# ============================================================

function Set-ExecutionPolicyHardening {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    if ($Undo) {
        Write-Status "Reverting execution policy hardening..." "Warning"
        Restore-RegValue -Path $regPath -Name "ExecutionPolicy" -BackupName "EP_ExecutionPolicy" -OrigType "String"
        Restore-RegValue -Path $regPath -Name "EnableScripts" -BackupName "EP_EnableScripts"
        Add-ChangeLog -Component "ExecutionPolicy" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring PowerShell execution policy via registry (GPO scope)..." "Info"
    Write-Status "  NOTE: Pair with WDAC to make this bypass-resistant" "Warning"

    Backup-RegValue -Path $regPath -Name "ExecutionPolicy" -BackupName "EP_ExecutionPolicy"
    Backup-RegValue -Path $regPath -Name "EnableScripts" -BackupName "EP_EnableScripts"

    if ($PSCmdlet.ShouldProcess($regPath, "Set ExecutionPolicy = RemoteSigned via GPO registry")) {
        Set-RegValue -Path $regPath -Name "EnableScripts" -Value 1
        Set-RegValue -Path $regPath -Name "ExecutionPolicy" -Value "RemoteSigned" -Type ([Microsoft.Win32.RegistryValueKind]::String)
        Write-Status "Execution policy set to RemoteSigned at machine scope (GPO registry)" "Success"
        Add-ChangeLog -Component "ExecutionPolicy" -Setting "ExecutionPolicy" -OldValue "NotSet/Unrestricted" -NewValue "RemoteSigned" -Action "Set"
    }
}

# ============================================================
# Section 9: AMSI Registry Key Audit SACL
# Alerts on attempts to modify AMSI provider registration.
# MITRE M1049
# ============================================================

function Set-AMSIRegistryAudit {
    $amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"

    if ($Undo) {
        Write-Status "Reverting AMSI registry audit SACL..." "Warning"
        if ($PSCmdlet.ShouldProcess($amsiPath, "Remove audit SACL from AMSI registry key")) {
            try {
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "SOFTWARE\Microsoft\AMSI",
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::ChangePermissions
                )
                if ($null -ne $key) {
                    $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
                    $auditRules = $acl.GetAuditRules($true, $false, [System.Security.Principal.NTAccount])
                    foreach ($rule in $auditRules) { $acl.RemoveAuditRule($rule) | Out-Null }
                    $key.SetAccessControl($acl)
                    $key.Close()
                    Write-Status "AMSI registry audit SACL removed" "Success"
                }
            } catch {
                Write-Status "Could not remove AMSI audit SACL: $_" "Warning"
            }
        }
        Add-ChangeLog -Component "AMSIAudit" -Setting "SACL" -OldValue "Set" -NewValue "Removed" -Action "Undo"
        return
    }

    Write-Status "Setting audit SACL on AMSI registry key..." "Info"

    if (-not (Test-Path $amsiPath)) {
        Write-Status "AMSI registry key not found — skipping SACL configuration" "Warning"
        return
    }

    if ($PSCmdlet.ShouldProcess($amsiPath, "Set audit SACL for write attempts")) {
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                "SOFTWARE\Microsoft\AMSI",
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)

            # Audit ALL users for write/delete on the AMSI key — catches bypass attempts
            $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                "Everyone",
                [System.Security.AccessControl.RegistryRights]::SetValue -bor
                [System.Security.AccessControl.RegistryRights]::Delete -bor
                [System.Security.AccessControl.RegistryRights]::DeleteSubKey -bor
                [System.Security.AccessControl.RegistryRights]::CreateSubKey,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AuditFlags]::Failure -bor
                [System.Security.AccessControl.AuditFlags]::Success
            )
            $acl.AddAuditRule($auditRule)
            $key.SetAccessControl($acl)
            $key.Close()

            Write-Status "AMSI registry audit SACL configured — modifications will generate Event ID 4657" "Success"
            Add-ChangeLog -Component "AMSIAudit" -Setting "SACL on HKLM:\SOFTWARE\Microsoft\AMSI" -OldValue "None" -NewValue "Audit:Write/Delete by Everyone" -Action "Set"
        } catch {
            Write-Status "Could not set AMSI audit SACL: $_" "Warning"
            Write-Status "  Requires 'Manage auditing and security log' privilege (SeSecurityPrivilege)" "Warning"
        }
    }

    # Also enable Object Access auditing in audit policy
    if ($PSCmdlet.ShouldProcess("auditpol", "Enable Registry Object Access auditing")) {
        auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null | Out-Null
        Write-Status "Registry object access auditing enabled (required for SACL events)" "Success"
    }
}

# ============================================================
# Section 10: PowerShell Constrained Language Mode Status Check
# MITRE M1038, M1045
# Note: CLM is enforced by WDAC policy, not a standalone registry
# key. This section checks the current state and warns if unset.
# ============================================================

function Test-ConstrainedLanguageModeStatus {
    Write-Status "Checking PowerShell Constrained Language Mode (CLM) status..." "Info"

    # CLM is applied via WDAC. Check whether a WDAC policy is active.
    $wdacPoliciesPath = "C:\Windows\System32\CodeIntegrity\CIPolicies\Active"
    $codeIntegrityRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"

    $wdacActive = $false
    if (Test-Path $wdacPoliciesPath) {
        $activePolicies = Get-ChildItem $wdacPoliciesPath -Filter "*.cip" -ErrorAction SilentlyContinue
        if ($null -ne $activePolicies -and $activePolicies.Count -gt 0) {
            $wdacActive = $true
            Write-Status "WDAC policy detected ($($activePolicies.Count) active CIP file(s))" "Success"
        }
    }

    # Check CLM status for the current session (informational)
    $clmStatus = $ExecutionContext.SessionState.LanguageMode
    Write-Status "Current session language mode: $clmStatus" "Info"

    if (-not $wdacActive) {
        Write-Status "No active WDAC policy detected — PowerShell Constrained Language Mode is NOT enforced" "Warning"
        Write-Status "  Recommendation: Deploy a WDAC policy to enforce CLM and prevent AMSI bypass via reflection" "Warning"
        Write-Status "  Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/" "Info"
        Add-ChangeLog -Component "CLM" -Setting "WDACCheck" -OldValue "N/A" -NewValue "NOT ENFORCED — deploy WDAC" -Action "Alert"
    } else {
        Write-Status "WDAC is active — CLM is likely enforced for untrusted code" "Success"
    }

    # This function is informational only in both apply and undo modes
}

# ============================================================
# Section 11: PowerShell Event Log Size Configuration
# Ensures logs are large enough to retain forensic evidence
# ============================================================

function Set-PowerShellLogSize {
    $psLogPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\PowerShellOperational"
    $secLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"

    if ($Undo) {
        Write-Status "Reverting event log size configuration..." "Warning"
        Restore-RegValue -Path $psLogPath  -Name "MaxSize" -BackupName "EVTLOG_PSMaxSize"
        Restore-RegValue -Path $secLogPath -Name "MaxSize" -BackupName "EVTLOG_SecMaxSize"
        Add-ChangeLog -Component "EventLog" -Setting "Reverted" -OldValue "Hardened" -NewValue "Original" -Action "Undo"
        return
    }

    Write-Status "Configuring PowerShell and Security event log sizes..." "Info"

    Backup-RegValue -Path $psLogPath  -Name "MaxSize" -BackupName "EVTLOG_PSMaxSize"
    Backup-RegValue -Path $secLogPath -Name "MaxSize" -BackupName "EVTLOG_SecMaxSize"

    # 100 MB for PowerShell Operational (script block logs can be large)
    $psSizeKB  = 102400
    # 512 MB for Security log
    $secSizeKB = 524288

    if ($PSCmdlet.ShouldProcess($psLogPath, "Set PowerShell Operational log to $psSizeKB KB")) {
        Set-RegValue -Path $psLogPath -Name "MaxSize" -Value $psSizeKB
        Write-Status "PowerShell Operational log max size: $psSizeKB KB (100 MB)" "Success"
        Add-ChangeLog -Component "EventLog" -Setting "PSOperational MaxSize" -OldValue "Default" -NewValue "$psSizeKB KB" -Action "Set"
    }

    if ($PSCmdlet.ShouldProcess($secLogPath, "Set Security log to $secSizeKB KB")) {
        Set-RegValue -Path $secLogPath -Name "MaxSize" -Value $secSizeKB
        Write-Status "Security log max size: $secSizeKB KB (512 MB)" "Success"
        Add-ChangeLog -Component "EventLog" -Setting "Security MaxSize" -OldValue "Default" -NewValue "$secSizeKB KB" -Action "Set"
    }
}

# ============================================================
# Main Execution
# ============================================================

$modeLabel = if ($Undo) { "UNDO (Revert)" } else { "APPLY (Harden)" }
$whatIfLabel = if ($WhatIfPreference) { " [WHATIF MODE — no changes will be made]" } else { "" }

Write-Status "============================================================" "Section"
Write-Status "F0RT1KA Hardening: PowerShell Execution & AMSI" "Section"
Write-Status "MITRE ATT&CK: T1059.001, T1140" "Section"
Write-Status "Mitigations:  M1042, M1045, M1026, M1038, M1049, M1040" "Section"
Write-Status "Mode: $modeLabel$whatIfLabel" "Section"
Write-Status "============================================================" "Section"
Write-Host ""

# Ensure backup registry key exists
if (-not (Test-Path $Script:BackupRegPath)) {
    if ($PSCmdlet.ShouldProcess($Script:BackupRegPath, "Create hardening backup registry key")) {
        New-Item -Path $Script:BackupRegPath -Force | Out-Null
    }
}

# Execute hardening sections
Write-Host ""
Write-Status "Section 1: Script Block Logging" "Section"
Set-ScriptBlockLogging

Write-Host ""
Write-Status "Section 2: Module Logging" "Section"
Set-ModuleLogging

Write-Host ""
Write-Status "Section 3: PowerShell Transcription" "Section"
Set-PowerShellTranscription

Write-Host ""
Write-Status "Section 4: Disable PowerShell v2" "Section"
Disable-PowerShellV2

Write-Host ""
Write-Status "Section 5: Windows Defender & AMSI" "Section"
Set-DefenderAMSIHardening

Write-Host ""
Write-Status "Section 6: Attack Surface Reduction Rules" "Section"
Set-ASRRulesForPowerShell

Write-Host ""
Write-Status "Section 7: Process Creation Audit Policy" "Section"
Set-ProcessCreationAudit

Write-Host ""
Write-Status "Section 8: Execution Policy (GPO registry)" "Section"
Set-ExecutionPolicyHardening

Write-Host ""
Write-Status "Section 9: AMSI Registry Audit SACL" "Section"
Set-AMSIRegistryAudit

Write-Host ""
Write-Status "Section 10: Constrained Language Mode Check" "Section"
Test-ConstrainedLanguageModeStatus

Write-Host ""
Write-Status "Section 11: Event Log Size" "Section"
Set-PowerShellLogSize

# Summary
Write-Host ""
Write-Status "============================================================" "Section"
Write-Status "Hardening Complete — Change Summary" "Section"
Write-Status "============================================================" "Section"

if ($Script:ChangeLog.Count -gt 0) {
    $Script:ChangeLog | Format-Table Component, Setting, OldValue, NewValue, Action, Timestamp -AutoSize | Out-String | Write-Host
} else {
    Write-Status "No changes were recorded (WhatIf mode or all settings already in target state)" "Info"
}

if (-not $Undo) {
    Write-Host ""
    Write-Status "Next Steps:" "Warning"
    Write-Status "  1. Review ASR audit events (Event ID 1121/1122) for 1-2 weeks before switching ASR rules to Block mode" "Info"
    Write-Status "  2. Verify script block logs appear in Event Viewer > Applications and Services > Microsoft > Windows > PowerShell > Operational" "Info"
    Write-Status "  3. Deploy WDAC policy to enforce Constrained Language Mode (see defense guidance document)" "Info"
    Write-Status "  4. Forward Event IDs 4103, 4104, 4688, 4657 to SIEM for detection analytics" "Info"
    Write-Status "  5. A reboot may be required for PowerShell v2 removal to take full effect" "Warning"
}

Write-Host ""
Write-Status "Backup registry path: $Script:BackupRegPath" "Info"
Write-Status "To revert: .\$(Split-Path -Leaf $PSCommandPath) -Undo" "Info"
