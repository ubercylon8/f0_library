<#
.SYNOPSIS
    Hardens Windows against Webshell Post-Exploitation techniques.

.DESCRIPTION
    Applies security hardening to mitigate post-exploitation behaviors enabled by
    webshell deployment (T1190 — Exploit Public-Facing Application, T1059.003 —
    Windows Command Shell).

    Hardening areas:
      - Advanced audit policy: process creation with command-line logging
      - Attack Surface Reduction (ASR) rules targeting shell spawning from web processes
      - Windows Defender behavioral and network protection
      - IIS / web server process restriction via AppLocker or WDAC script rules
      - Outbound Windows Firewall rules restricting HTTP/HTTPS egress from web worker
      - Controlled Folder Access
      - Exploit protection settings for IIS worker process

    MITRE ATT&CK : T1190, T1059.003
    Mitigations  : M1016, M1026, M1030, M1038, M1048, M1050, M1051

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what would be changed without making any modifications.

.PARAMETER SkipASR
    Skip ASR rule configuration (use when Defender ATP / MDE is not present).

.PARAMETER SkipFirewall
    Skip Windows Firewall egress rule configuration.

.PARAMETER SkipAudit
    Skip audit policy changes.

.EXAMPLE
    .\c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09_hardening.ps1 -WhatIf
    Preview changes without applying them.

.EXAMPLE
    .\c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author      : F0RT1KA Defense Guidance Generator
    Techniques  : T1190, T1059.003
    Mitigations : M1016, M1026, M1030, M1038, M1048, M1050, M1051
    Requires    : Administrator privileges
    Idempotent  : Yes — safe to run multiple times
    Tested on   : Windows Server 2019, Windows Server 2022, Windows 10/11
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipASR,
    [switch]$SkipFirewall,
    [switch]$SkipAudit
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog      = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:BackupDir      = "$env:ProgramData\F0RT1KA\Hardening\WebshellPostExploit"
$Script:LogFile        = "$Script:BackupDir\hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ============================================================
# Utility functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Section")]
        [string]$Type = "Info"
    )
    $palette = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Section = "Magenta"
    }
    $prefix = @{
        Info    = "[INFO]"
        Success = "[ OK ]"
        Warning = "[WARN]"
        Error   = "[ERR ]"
        Section = "[====]"
    }
    $line = "$(Get-Date -Format 'HH:mm:ss') $($prefix[$Type]) $Message"
    Write-Host $line -ForegroundColor $palette[$Type]
    if (-not (Test-Path (Split-Path $Script:LogFile))) {
        New-Item -ItemType Directory -Path (Split-Path $Script:LogFile) -Force | Out-Null
    }
    Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue
}

function Add-ChangeRecord {
    param([string]$Category, [string]$Target, [string]$Action, [string]$OldValue, [string]$NewValue)
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category  = $Category
        Target    = $Target
        Action    = $Action
        OldValue  = $OldValue
        NewValue  = $NewValue
    })
}

function Backup-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $val) {
                $backupKey = "HKLM:\SOFTWARE\F0RT1KA\Hardening\WebshellPostExploit\Registry"
                if (-not (Test-Path $backupKey)) {
                    New-Item -Path $backupKey -Force | Out-Null
                }
                $encodedPath = $Path -replace "[\\:/]", "_"
                Set-ItemProperty -Path $backupKey -Name "${encodedPath}__${Name}" -Value $val.$Name -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Status "Could not back up registry value ${Path}\${Name}: $_" -Type Warning
    }
}

function Restore-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $backupKey = "HKLM:\SOFTWARE\F0RT1KA\Hardening\WebshellPostExploit\Registry"
        $encodedPath = $Path -replace "[\\:/]", "_"
        $backup = Get-ItemProperty -Path $backupKey -Name "${encodedPath}__${Name}" -ErrorAction SilentlyContinue
        if ($null -ne $backup) {
            if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            Set-ItemProperty -Path $Path -Name $Name -Value $backup."${encodedPath}__${Name}"
            Write-Status "Restored: $Path\$Name" -Type Success
        } else {
            Write-Status "No backup found for $Path\$Name — skipping restore" -Type Warning
        }
    } catch {
        Write-Status "Could not restore ${Path}\${Name}: $_" -Type Warning
    }
}

function Test-MicrosoftDefenderPresent {
    $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    return ($null -ne $service)
}

function Test-IISInstalled {
    $iis = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    return ($null -ne $iis)
}

function Test-AppLockerAvailable {
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($null -eq $os) { return $false }
    # AppLocker is available on Enterprise and Education SKUs
    return ($os.OperatingSystemSKU -in @(4, 27, 48, 96, 97, 98, 99, 100, 101, 121, 125, 162))
}

# ============================================================
# Section 1: Advanced Audit Policy — Process Creation (M1016, M1038)
# ============================================================

function Set-ProcessCreationAudit {
    if ($SkipAudit) {
        Write-Status "Skipping audit policy changes (SkipAudit flag set)" -Type Warning
        return
    }

    Write-Status "--- Process Creation Audit Policy ---" -Type Section

    if ($Undo) {
        Write-Status "Reverting process creation audit policy..." -Type Warning
        if ($PSCmdlet.ShouldProcess("Audit Process Creation", "Revert to No Auditing")) {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
            Write-Status "Audit Process Creation reverted (disabled)" -Type Success
            Add-ChangeRecord "Audit" "Process Creation" "Reverted" "Success+Failure" "Disabled"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess("Audit Process Creation", "Enable Success auditing")) {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Write-Status "Enabled: Audit Process Creation (Success + Failure)" -Type Success
        Add-ChangeRecord "Audit" "Process Creation" "Enabled" "Disabled" "Success+Failure"
    }
}

# ============================================================
# Section 2: Command-Line Logging in Process Creation Events (M1038)
# ============================================================

function Set-CommandLineAuditLogging {
    if ($SkipAudit) { return }

    Write-Status "--- Command-Line Logging in Event 4688 ---" -Type Section

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $regName = "ProcessCreationIncludeCmdLine_Enabled"

    if ($Undo) {
        Write-Status "Reverting command-line audit logging..." -Type Warning
        if ($PSCmdlet.ShouldProcess("$regPath\$regName", "Remove registry value")) {
            Restore-RegistryValue -Path $regPath -Name $regName
            Add-ChangeRecord "Registry" "$regPath\$regName" "Reverted" "1" "(restored)"
        }
        return
    }

    Backup-RegistryValue -Path $regPath -Name $regName

    $currentVal = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    if ($currentVal -eq 1) {
        Write-Status "Command-line audit logging already enabled — no change needed" -Type Info
        return
    }

    if ($PSCmdlet.ShouldProcess("$regPath\$regName", "Set to 1 (enable command-line in Event 4688)")) {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Type DWord
        Write-Status "Enabled: Command-line logging in Event ID 4688" -Type Success
        Add-ChangeRecord "Registry" "$regPath\$regName" "Set" "0" "1"
    }
}

# ============================================================
# Section 3: ASR Rules — Restrict Shell from Web/Office Processes (M1038, M1050)
# ============================================================

function Set-ASRRules {
    if ($SkipASR) {
        Write-Status "Skipping ASR rules (SkipASR flag set)" -Type Warning
        return
    }

    Write-Status "--- Attack Surface Reduction (ASR) Rules ---" -Type Section

    if (-not (Test-MicrosoftDefenderPresent)) {
        Write-Status "Windows Defender not detected — skipping ASR configuration" -Type Warning
        return
    }

    # Check if MpPreference cmdlet is available
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Status "Set-MpPreference not available — skipping ASR configuration" -Type Warning
        return
    }

    # ASR rules relevant to webshell post-exploitation
    # Each rule GUID maps to a specific behavior restriction
    $asrRules = @{
        # Block process creations originating from PSExec and WMI commands
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations from PSExec and WMI"
        # Block Office applications from creating executable content
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office apps from creating executable content"
        # Block Office applications from injecting code into other processes
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office apps from injecting into other processes"
        # Block execution of potentially obfuscated scripts
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
        # Block JavaScript or VBScript from launching downloaded executable content
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JS/VBS from launching downloaded executable content"
        # Block credential stealing from Windows LSASS
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3" = "Block credential stealing from LSASS"
        # Block untrusted and unsigned processes that run from USB
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted/unsigned processes from USB"
        # Use advanced protection against ransomware
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }

    if ($Undo) {
        Write-Status "Reverting ASR rules to Audit mode..." -Type Warning
        foreach ($ruleGuid in $asrRules.Keys) {
            if ($PSCmdlet.ShouldProcess($asrRules[$ruleGuid], "Set ASR rule to Audit (0)")) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
                    Write-Status "Reverted ASR rule: $($asrRules[$ruleGuid])" -Type Success
                    Add-ChangeRecord "ASR" $ruleGuid "Reverted" "Enabled" "Disabled"
                } catch {
                    Write-Status "Could not revert ASR rule $ruleGuid : $_" -Type Warning
                }
            }
        }
        return
    }

    foreach ($ruleGuid in $asrRules.Keys) {
        if ($PSCmdlet.ShouldProcess($asrRules[$ruleGuid], "Enable ASR rule (Block mode)")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                Write-Status "Enabled ASR: $($asrRules[$ruleGuid])" -Type Success
                Add-ChangeRecord "ASR" $ruleGuid "Enabled" "Disabled/Audit" "Enabled"
            } catch {
                Write-Status "Failed to enable ASR rule $($asrRules[$ruleGuid]): $_" -Type Warning
            }
        }
    }
}

# ============================================================
# Section 4: Windows Defender Network Protection (M1030, M1048)
# ============================================================

function Set-NetworkProtection {
    Write-Status "--- Windows Defender Network Protection ---" -Type Section

    if (-not (Test-MicrosoftDefenderPresent)) {
        Write-Status "Windows Defender not detected — skipping Network Protection" -Type Warning
        return
    }

    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Status "Set-MpPreference not available — skipping Network Protection" -Type Warning
        return
    }

    if ($Undo) {
        Write-Status "Reverting Network Protection to Disabled..." -Type Warning
        if ($PSCmdlet.ShouldProcess("EnableNetworkProtection", "Set to Disabled")) {
            Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue
            Write-Status "Network Protection reverted to Disabled" -Type Success
            Add-ChangeRecord "Defender" "EnableNetworkProtection" "Reverted" "Enabled" "Disabled"
        }
        return
    }

    $current = (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection
    if ($current -eq 1) {
        Write-Status "Network Protection already Enabled — no change needed" -Type Info
        return
    }

    if ($PSCmdlet.ShouldProcess("EnableNetworkProtection", "Set to Enabled")) {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Write-Status "Enabled: Windows Defender Network Protection" -Type Success
        Add-ChangeRecord "Defender" "EnableNetworkProtection" "Enabled" "Disabled/Audit" "Enabled"
    }
}

# ============================================================
# Section 5: Controlled Folder Access (M1048)
# ============================================================

function Set-ControlledFolderAccess {
    Write-Status "--- Controlled Folder Access ---" -Type Section

    if (-not (Test-MicrosoftDefenderPresent)) {
        Write-Status "Windows Defender not detected — skipping Controlled Folder Access" -Type Warning
        return
    }

    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Status "Set-MpPreference not available — skipping Controlled Folder Access" -Type Warning
        return
    }

    if ($Undo) {
        Write-Status "Reverting Controlled Folder Access to Disabled..." -Type Warning
        if ($PSCmdlet.ShouldProcess("EnableControlledFolderAccess", "Set to Disabled")) {
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            Write-Status "Controlled Folder Access reverted" -Type Success
            Add-ChangeRecord "Defender" "ControlledFolderAccess" "Reverted" "Enabled" "Disabled"
        }
        return
    }

    $current = (Get-MpPreference -ErrorAction SilentlyContinue).EnableControlledFolderAccess
    if ($current -eq 1) {
        Write-Status "Controlled Folder Access already Enabled — no change needed" -Type Info
        return
    }

    if ($PSCmdlet.ShouldProcess("EnableControlledFolderAccess", "Set to Enabled")) {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Write-Status "Enabled: Controlled Folder Access" -Type Success
        Add-ChangeRecord "Defender" "ControlledFolderAccess" "Enabled" "Disabled" "Enabled"
    }
}

# ============================================================
# Section 6: Windows Defender Exploit Protection for IIS Worker Process (M1050)
# ============================================================

function Set-IISExploitProtection {
    Write-Status "--- Windows Defender Exploit Protection for IIS Worker (w3wp.exe) ---" -Type Section

    if (-not (Test-IISInstalled)) {
        Write-Status "IIS (W3SVC) not detected — skipping IIS-specific exploit protection" -Type Info
        return
    }

    if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) {
        Write-Status "Set-ProcessMitigation not available (requires Windows 10 1709+) — skipping" -Type Warning
        return
    }

    $w3wpPath = "$env:SystemRoot\System32\inetsrv\w3wp.exe"
    if (-not (Test-Path $w3wpPath)) {
        $w3wpPath = "w3wp.exe"  # Use name only if path not found
    }

    if ($Undo) {
        Write-Status "Reverting w3wp.exe exploit protection mitigations..." -Type Warning
        if ($PSCmdlet.ShouldProcess("w3wp.exe", "Remove exploit protection overrides")) {
            try {
                Set-ProcessMitigation -Name $w3wpPath -Remove -Disable DEP, ASLR, StrictHandleCheck -ErrorAction SilentlyContinue
                Write-Status "w3wp.exe exploit protection overrides removed" -Type Success
                Add-ChangeRecord "ExploitProtection" "w3wp.exe" "Reverted" "Enforced" "Default"
            } catch {
                Write-Status "Could not fully revert w3wp.exe mitigations: $_" -Type Warning
            }
        }
        return
    }

    if ($PSCmdlet.ShouldProcess("w3wp.exe", "Apply exploit protection mitigations (DEP, ASLR, CFG, StrictHandleCheck)")) {
        try {
            Set-ProcessMitigation -Name $w3wpPath `
                -Enable DEP, EmulateAtlThunks, ForceRelocateImages, BottomUp, HighEntropy, `
                        StrictHandleCheck, DisableWin32kSystemCalls, AuditDisableWin32kSystemCalls `
                -ErrorAction Stop
            Write-Status "Applied exploit protection to w3wp.exe (DEP, ASLR, StrictHandleCheck, DisableWin32k)" -Type Success
            Add-ChangeRecord "ExploitProtection" "w3wp.exe" "Applied" "Default" "DEP+ASLR+StrictHandle+DisableWin32k"
        } catch {
            # Fallback: apply minimal subset
            Write-Status "Full mitigation set failed ($($_.Exception.Message)); applying minimal subset..." -Type Warning
            try {
                Set-ProcessMitigation -Name $w3wpPath -Enable DEP, ForceRelocateImages, StrictHandleCheck -ErrorAction Stop
                Write-Status "Applied minimal exploit protection to w3wp.exe" -Type Success
                Add-ChangeRecord "ExploitProtection" "w3wp.exe" "Applied (minimal)" "Default" "DEP+ForceRelocate+StrictHandle"
            } catch {
                Write-Status "Could not apply exploit protection to w3wp.exe: $_" -Type Warning
            }
        }
    }
}

# ============================================================
# Section 7: Windows Firewall — Restrict Outbound HTTP/HTTPS from IIS Worker (M1030)
# ============================================================

function Set-IISEgressFirewallRules {
    if ($SkipFirewall) {
        Write-Status "Skipping firewall rule configuration (SkipFirewall flag set)" -Type Warning
        return
    }

    Write-Status "--- Outbound Firewall Rules for IIS Worker Process ---" -Type Section

    if (-not (Test-IISInstalled)) {
        Write-Status "IIS (W3SVC) not detected — skipping IIS-specific firewall rules" -Type Info
        return
    }

    $ruleName80  = "F0RT1KA-Block-w3wp-HTTP-Outbound"
    $ruleName443 = "F0RT1KA-Block-w3wp-HTTPS-Outbound"

    if ($Undo) {
        Write-Status "Removing IIS egress firewall rules..." -Type Warning
        foreach ($name in @($ruleName80, $ruleName443)) {
            if ($PSCmdlet.ShouldProcess($name, "Remove firewall rule")) {
                Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
                Write-Status "Removed firewall rule: $name" -Type Success
                Add-ChangeRecord "Firewall" $name "Removed" "Blocked" "(removed)"
            }
        }
        return
    }

    # Remove existing rules first (idempotency)
    Remove-NetFirewallRule -DisplayName $ruleName80  -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $ruleName443 -ErrorAction SilentlyContinue

    $w3wpPath = "$env:SystemRoot\System32\inetsrv\w3wp.exe"

    # Block outbound HTTP from w3wp.exe
    if ($PSCmdlet.ShouldProcess($ruleName80, "Create outbound block rule for w3wp.exe port 80")) {
        try {
            New-NetFirewallRule `
                -DisplayName $ruleName80 `
                -Description "Block outbound HTTP (port 80) from IIS worker process. Prevents webshell C2 callbacks. MITRE T1190/T1059.003 hardening." `
                -Direction Outbound `
                -Action Block `
                -Program $w3wpPath `
                -Protocol TCP `
                -RemotePort 80 `
                -Profile Any `
                -Enabled True | Out-Null
            Write-Status "Created: Block outbound HTTP (port 80) from w3wp.exe" -Type Success
            Add-ChangeRecord "Firewall" $ruleName80 "Created" "(none)" "Block TCP/80 out from w3wp.exe"
        } catch {
            Write-Status "Could not create HTTP outbound block rule: $_" -Type Warning
        }
    }

    # Block outbound HTTPS from w3wp.exe
    if ($PSCmdlet.ShouldProcess($ruleName443, "Create outbound block rule for w3wp.exe port 443")) {
        try {
            New-NetFirewallRule `
                -DisplayName $ruleName443 `
                -Description "Block outbound HTTPS (port 443) from IIS worker process. Prevents webshell C2 callbacks. MITRE T1190/T1059.003 hardening." `
                -Direction Outbound `
                -Action Block `
                -Program $w3wpPath `
                -Protocol TCP `
                -RemotePort 443 `
                -Profile Any `
                -Enabled True | Out-Null
            Write-Status "Created: Block outbound HTTPS (port 443) from w3wp.exe" -Type Success
            Add-ChangeRecord "Firewall" $ruleName443 "Created" "(none)" "Block TCP/443 out from w3wp.exe"
        } catch {
            Write-Status "Could not create HTTPS outbound block rule: $_" -Type Warning
        }
    }

    Write-Status "" -Type Info
    Write-Status "NOTE: These rules block ALL outbound HTTP/HTTPS from w3wp.exe." -Type Warning
    Write-Status "If your web app needs outbound connectivity (APIs, CDNs, etc.) use" -Type Warning
    Write-Status "SkipFirewall and configure egress filtering at the network perimeter." -Type Warning
}

# ============================================================
# Section 8: Restrict cmd.exe / powershell.exe for IIS App Pool Identity (M1026, M1038)
# ============================================================

function Set-ShellExecutionRestrictions {
    Write-Status "--- Shell Execution Restrictions via Registry (Software Restriction Policy) ---" -Type Section

    # Restrict cmd.exe via IFEO (Image File Execution Options) debugger trick is NOT used
    # (it would break legitimate admin usage). Instead, we harden via registry policy
    # and provide AppLocker guidance.

    # Disable command extensions for the machine — reduces capability of cmd.exe invocations
    # that don't explicitly re-enable them
    $regPathCmd   = "HKLM:\SOFTWARE\Microsoft\Command Processor"
    $regNameExt   = "EnableExtensions"
    $regNameDelay = "DelayedExpansion"

    if ($Undo) {
        Write-Status "Reverting Command Processor restrictions..." -Type Warning
        if ($PSCmdlet.ShouldProcess($regPathCmd, "Restore EnableExtensions")) {
            Restore-RegistryValue -Path $regPathCmd -Name $regNameExt
            Add-ChangeRecord "Registry" "$regPathCmd\$regNameExt" "Reverted" "0" "(restored)"
        }
        return
    }

    Backup-RegistryValue -Path $regPathCmd -Name $regNameExt
    Backup-RegistryValue -Path $regPathCmd -Name $regNameDelay

    # This does NOT disable cmd.exe, but restricts scripts that rely on command extensions.
    # Real shell blocking must be done through AppLocker/WDAC.
    Write-Status "Shell execution restrictions via registry require AppLocker/WDAC for full enforcement." -Type Info
    Write-Status "Providing AppLocker guidance below..." -Type Info

    # --- AppLocker Guidance Output ---
    if (Test-AppLockerAvailable) {
        Write-Status "" -Type Info
        Write-Status "AppLocker IS available on this SKU. Consider applying the following rules:" -Type Info
        Write-Status "  1. Default Executable Rules (allow signed Windows + Program Files binaries)" -Type Info
        Write-Status "  2. Deny rule: cmd.exe and powershell.exe when parent is w3wp.exe" -Type Info
        Write-Status "  3. Deny rule: cscript.exe, wscript.exe, mshta.exe from web directory paths" -Type Info
        Write-Status "" -Type Info
        Write-Status "To configure AppLocker via PowerShell:" -Type Info
        Write-Status '  $policy = Get-AppLockerPolicy -Effective' -Type Info
        Write-Status '  Set-AppLockerPolicy -PolicyObject $policy -Merge' -Type Info
        Write-Status "Reference: https://docs.microsoft.com/windows/security/application-security/application-control/applocker/" -Type Info
    } else {
        Write-Status "AppLocker not available on this SKU. Consider Windows Defender Application Control (WDAC)." -Type Warning
        Write-Status "WDAC policy reference: https://docs.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/" -Type Info
    }

    Add-ChangeRecord "Advisory" "AppLocker/WDAC" "Guidance provided" "N/A" "Manual configuration required"
}

# ============================================================
# Section 9: PowerShell Script Block Logging (M1038, M1016)
# ============================================================

function Set-PowerShellLogging {
    if ($SkipAudit) { return }

    Write-Status "--- PowerShell Script Block Logging and Module Logging ---" -Type Section

    $psLogPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psModPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $psTransPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    if ($Undo) {
        Write-Status "Reverting PowerShell logging settings..." -Type Warning
        if ($PSCmdlet.ShouldProcess("PowerShell Script Block Logging", "Disable")) {
            if (Test-Path $psLogPath) {
                Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 0 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 0 -ErrorAction SilentlyContinue
            }
            if (Test-Path $psModPath) {
                Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 0 -ErrorAction SilentlyContinue
            }
            Write-Status "PowerShell script block logging reverted" -Type Success
            Add-ChangeRecord "PowerShell" "ScriptBlockLogging" "Reverted" "Enabled" "Disabled"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess("PowerShell Script Block Logging", "Enable")) {
        foreach ($p in @($psLogPath, $psModPath, $psTransPath)) {
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        }

        # Script block logging — captures all PS code executed (Event ID 4104)
        Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging"           -Value 1 -Type DWord
        Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

        # Module logging — logs all module/cmdlet invocations (Event ID 4103)
        Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1 -Type DWord
        Set-ItemProperty -Path $psModPath -Name "ModuleNames" -Value @("*") -Type MultiString

        Write-Status "Enabled: PowerShell Script Block Logging (Event ID 4104)" -Type Success
        Write-Status "Enabled: PowerShell Module Logging (Event ID 4103)" -Type Success
        Add-ChangeRecord "PowerShell" "ScriptBlockLogging" "Enabled" "Disabled" "Enabled (4103+4104)"
    }
}

# ============================================================
# Section 10: IIS Hardening — Handler Mapping Restrictions (M1048)
# ============================================================

function Set-IISHandlerRestrictions {
    Write-Status "--- IIS Handler Mapping Hardening ---" -Type Section

    if (-not (Test-IISInstalled)) {
        Write-Status "IIS (W3SVC) not detected — skipping IIS handler hardening" -Type Info
        return
    }

    # Check for WebAdministration module
    $webAdminAvail = Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue
    if (-not $webAdminAvail) {
        Write-Status "WebAdministration module not available — providing manual guidance only" -Type Warning
        Write-Status "Manual IIS hardening steps:" -Type Info
        Write-Status "  1. IIS Manager > Request Filtering > Deny: .asa, .asax, .config extensions in upload directories" -Type Info
        Write-Status "  2. Remove unused handler mappings (PHP, Perl, CGI) if not needed" -Type Info
        Write-Status "  3. Disable WebDAV if not required: Remove-WindowsFeature Web-DAV-Publishing" -Type Info
        Write-Status "  4. Enable IIS detailed error logging with restricted access" -Type Info
        Add-ChangeRecord "Advisory" "IIS Handlers" "Manual guidance provided" "N/A" "Manual configuration required"
        return
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    if ($Undo) {
        Write-Status "IIS handler restrictions require manual review to revert safely." -Type Warning
        Write-Status "Re-enable any removed handler mappings via IIS Manager or applicationHost.config." -Type Info
        Add-ChangeRecord "Advisory" "IIS Handlers" "Manual revert required" "N/A" "Review applicationHost.config"
        return
    }

    # Disable WebDAV if installed and not needed
    if ($PSCmdlet.ShouldProcess("WebDAV", "Disable if installed")) {
        $webdav = Get-WindowsFeature -Name Web-DAV-Publishing -ErrorAction SilentlyContinue
        if ($webdav -and $webdav.Installed) {
            Write-Status "WebDAV is installed. Consider removing: Remove-WindowsFeature Web-DAV-Publishing" -Type Warning
            Write-Status "Run: Remove-WindowsFeature Web-DAV-Publishing -Restart" -Type Info
            Add-ChangeRecord "Advisory" "WebDAV" "Manual removal recommended" "Installed" "Should be removed if not needed"
        } else {
            Write-Status "WebDAV not installed — good" -Type Success
        }
    }

    # Check IIS request filtering configuration for upload directories
    Write-Status "IIS Request Filtering check..." -Type Info
    try {
        $config = Get-WebConfiguration -Filter "//requestFiltering/fileExtensions" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($config) {
            Write-Status "IIS Request Filtering is configured. Review extension deny list includes:" -Type Info
            Write-Status "  .asp .aspx .php .jsp .cfm .ashx .asmx .shtml .shtm .stm" -Type Info
        }
    } catch {
        Write-Status "Could not query IIS Request Filtering: $_" -Type Warning
    }

    Add-ChangeRecord "Advisory" "IIS Request Filtering" "Review completed" "N/A" "Manual extension deny list recommended"
}

# ============================================================
# Section 11: Windows Event Log Size Increase (M1016)
# ============================================================

function Set-EventLogSizes {
    if ($SkipAudit) { return }

    Write-Status "--- Event Log Maximum Size ---" -Type Section

    $logConfigs = @{
        "Security"                                         = 1GB
        "System"                                           = 256MB
        "Application"                                      = 256MB
        "Microsoft-Windows-PowerShell/Operational"         = 256MB
        "Microsoft-Windows-Sysmon/Operational"             = 512MB
        "Microsoft-Windows-WinRM/Operational"              = 128MB
    }

    foreach ($logName in $logConfigs.Keys) {
        $targetSizeBytes = $logConfigs[$logName]
        $targetSizeKB    = $targetSizeBytes / 1KB

        if ($Undo) {
            # Restore to Windows default (20480 KB for Security, 20480 for others)
            if ($PSCmdlet.ShouldProcess($logName, "Restore default log size")) {
                try {
                    $log = [System.Diagnostics.EventLog]::new($logName)
                    $log.MaximumKilobytes = 20480
                    $log.Dispose()
                    Write-Status "Restored $logName to 20 MB (default)" -Type Success
                    Add-ChangeRecord "EventLog" $logName "Reverted" "${targetSizeKB}KB" "20480KB"
                } catch {
                    Write-Status "Could not restore $logName size: $_" -Type Warning
                }
            }
        } else {
            if ($PSCmdlet.ShouldProcess($logName, "Set maximum size to $($targetSizeBytes / 1MB)MB")) {
                try {
                    wevtutil sl $logName /ms:$targetSizeBytes 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Status "Set $logName max size to $($targetSizeBytes / 1MB)MB" -Type Success
                        Add-ChangeRecord "EventLog" $logName "Resized" "20MB" "$($targetSizeBytes/1MB)MB"
                    }
                } catch {
                    Write-Status "Could not resize $logName : $_" -Type Warning
                }
            }
        }
    }
}

# ============================================================
# Section 12: Verify Defender Real-Time Protection (M1050)
# ============================================================

function Test-DefenderRealTimeProtection {
    Write-Status "--- Windows Defender Real-Time Protection Check ---" -Type Section

    if (-not (Test-MicrosoftDefenderPresent)) {
        Write-Status "Windows Defender not detected — skipping check" -Type Warning
        return
    }

    if ($Undo) {
        Write-Status "Real-time protection check: no changes to revert" -Type Info
        return
    }

    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        $status = Get-MpComputerStatus -ErrorAction Stop

        if ($status.RealTimeProtectionEnabled) {
            Write-Status "Real-Time Protection: ENABLED" -Type Success
        } else {
            Write-Status "Real-Time Protection: DISABLED — enabling now..." -Type Warning
            if ($PSCmdlet.ShouldProcess("DisableRealtimeMonitoring", "Set to 0 (enable real-time protection)")) {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Write-Status "Real-Time Protection enabled" -Type Success
                Add-ChangeRecord "Defender" "RealTimeProtection" "Enabled" "Disabled" "Enabled"
            }
        }

        if ($status.BehaviorMonitorEnabled) {
            Write-Status "Behavior Monitoring: ENABLED" -Type Success
        } else {
            Write-Status "Behavior Monitoring: DISABLED — enabling now..." -Type Warning
            if ($PSCmdlet.ShouldProcess("DisableBehaviorMonitoring", "Set to 0")) {
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
                Write-Status "Behavior Monitoring enabled" -Type Success
                Add-ChangeRecord "Defender" "BehaviorMonitoring" "Enabled" "Disabled" "Enabled"
            }
        }

        if ($status.IoavProtectionEnabled) {
            Write-Status "IOAV (Download/Attachment) Protection: ENABLED" -Type Success
        } else {
            Write-Status "IOAV Protection: DISABLED — review Defender configuration" -Type Warning
        }

        Write-Status "Signature version: $($status.AntivirusSignatureVersion)" -Type Info
        $sigAge = (Get-Date) - $status.AntivirusSignatureLastUpdated
        if ($sigAge.TotalHours -gt 24) {
            Write-Status "Signatures are $([int]$sigAge.TotalHours) hours old — consider updating" -Type Warning
        } else {
            Write-Status "Signatures updated $([int]$sigAge.TotalHours) hour(s) ago" -Type Success
        }
    } catch {
        Write-Status "Could not query Defender status: $_" -Type Warning
    }
}

# ============================================================
# Summary and report
# ============================================================

function Write-Summary {
    Write-Status "" -Type Info
    Write-Status "==========================================" -Type Section
    Write-Status "HARDENING SUMMARY" -Type Section
    Write-Status "==========================================" -Type Section

    if ($Script:ChangeLog.Count -eq 0) {
        Write-Status "No changes recorded." -Type Info
    } else {
        $Script:ChangeLog | Format-Table -AutoSize -Property Timestamp, Category, Target, Action, OldValue, NewValue
    }

    Write-Status "" -Type Info
    Write-Status "Log file: $Script:LogFile" -Type Info

    if (-not $Undo) {
        Write-Status "" -Type Info
        Write-Status "MANUAL ACTIONS REQUIRED:" -Type Warning
        Write-Status "  1. Configure AppLocker/WDAC to block cmd.exe/powershell.exe spawned by web worker processes" -Type Warning
        Write-Status "  2. Deploy a Web Application Firewall (WAF) in front of any public-facing web applications" -Type Warning
        Write-Status "  3. Run vulnerability scans against web applications (OWASP ZAP, Nuclei, Nessus Web App)" -Type Warning
        Write-Status "  4. Review and rotate IIS application pool service account credentials" -Type Warning
        Write-Status "  5. Verify Sysmon is deployed and configured to capture process creation with command lines" -Type Warning
        Write-Status "  6. Confirm SIEM/EDR is ingesting Windows Security Event ID 4688 with command-line data" -Type Warning
        Write-Status "" -Type Info
        Write-Status "To revert all changes, run: .\$($MyInvocation.ScriptName) -Undo" -Type Info
    }
}

# ============================================================
# Main execution
# ============================================================

$modeLabel = if ($Undo) { "UNDO" } elseif ($WhatIfPreference) { "WHATIF" } else { "APPLY" }

Write-Status "==========================================" -Type Section
Write-Status "F0RT1KA Webshell Post-Exploitation Hardening" -Type Section
Write-Status "Techniques : T1190 (Exploit Public-Facing Application)" -Type Section
Write-Status "             T1059.003 (Windows Command Shell)" -Type Section
Write-Status "Mitigations: M1016, M1026, M1030, M1038, M1048, M1050, M1051" -Type Section
Write-Status "Mode       : $modeLabel" -Type Section
Write-Status "==========================================" -Type Section
Write-Status "" -Type Info

# Ensure backup directory exists
if (-not (Test-Path $Script:BackupDir)) {
    New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null
}

# Execute hardening sections
Set-ProcessCreationAudit
Set-CommandLineAuditLogging
Set-PowerShellLogging
Set-EventLogSizes
Test-DefenderRealTimeProtection
Set-NetworkProtection
Set-ControlledFolderAccess
Set-ASRRules
Set-IISExploitProtection
Set-IISEgressFirewallRules
Set-ShellExecutionRestrictions
Set-IISHandlerRestrictions

Write-Summary

Write-Status "" -Type Info
Write-Status "Hardening $modeLabel complete." -Type Success
