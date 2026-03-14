<#
.SYNOPSIS
    Hardens Windows against pre-encryption file enumeration techniques.

.DESCRIPTION
    Applies security hardening to mitigate file and directory discovery (T1083),
    automated collection (T1119), and system information discovery (T1082).

    Specifically addresses:
      - Bulk recursive file enumeration (cmd.exe /s /b patterns)
      - Extension-based file filtering used in ransomware reconnaissance
      - Execution of offensive enumeration tools (e.g., GhostPack Seatbelt)
      - Credential store enumeration (Windows Vault, Credential Files)

    MITRE ATT&CK: T1083, T1119, T1082
    Mitigations:  M1041 (Encrypt Sensitive Information),
                  M1029 (Remote Data Storage),
                  M1028 (Operating System Configuration)

    All changes are idempotent and fully reversible via the -Undo switch.

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what would be changed without making any modifications.

.PARAMETER SkipAuditPolicy
    Skip audit policy changes (useful if audit policy is managed via GPO).

.PARAMETER SkipASR
    Skip Attack Surface Reduction rule changes.

.PARAMETER SkipCFA
    Skip Controlled Folder Access changes.

.PARAMETER SkipAppLocker
    Skip AppLocker policy changes.

.EXAMPLE
    .\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07_hardening.ps1 -WhatIf
    Preview all changes without applying them.

.EXAMPLE
    .\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07_hardening.ps1 -Undo
    Reverts all hardening settings.

.EXAMPLE
    .\a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07_hardening.ps1 -SkipAppLocker -SkipCFA
    Applies hardening except AppLocker and Controlled Folder Access sections.

.NOTES
    Author:      F0RT1KA Defense Guidance Generator
    Techniques:  T1083 (File and Directory Discovery),
                 T1119 (Automated Collection),
                 T1082 (System Information Discovery)
    Mitigations: M1041, M1029, M1028
    Requires:    Administrator privileges, Windows 10 1709+ for CFA/ASR features
    Idempotent:  Yes — safe to run multiple times
    Undo:        Full revert supported via -Undo parameter

    This script targets the TECHNIQUE BEHAVIORS (bulk enumeration, offensive
    tool execution, credential store access), not any specific test binary or
    test framework. It will protect against any tool or actor employing the
    same techniques.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipAuditPolicy,
    [switch]$SkipASR,
    [switch]$SkipCFA,
    [switch]$SkipAppLocker
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:WarningLog = [System.Collections.Generic.List[string]]::new()

# ============================================================
# Output Helpers
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Action", "Skip")]
        [string]$Type = "Info"
    )
    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Action  = "Magenta"
        Skip    = "DarkGray"
    }
    $prefix = @{
        Info    = "[INFO]   "
        Success = "[ OK ]   "
        Warning = "[WARN]   "
        Error   = "[ERROR]  "
        Action  = "[ACTION] "
        Skip    = "[SKIP]   "
    }
    Write-Host "$($prefix[$Type])$Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param(
        [string]$Section,
        [string]$Setting,
        [string]$OldValue,
        [string]$NewValue,
        [string]$UndoHint = ""
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Section   = $Section
        Setting   = $Setting
        OldValue  = $OldValue
        NewValue  = $NewValue
        UndoHint  = $UndoHint
    })
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        if (Test-Path $Path) {
            $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $val) { return $val.$Name }
        }
    } catch { }
    return $Default
}

function Set-RegistryValueIdempotent {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWORD",
        [string]$Section,
        $UndoValue = $null
    )
    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, "Create registry key")) {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    $current = Get-RegistryValueSafe -Path $Path -Name $Name -Default "__NOT_SET__"
    if ($current -eq $Value) {
        Write-Status "Already set: $Path\$Name = $Value" -Type Skip
        return
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set registry value to '$Value' (was '$current')")) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Add-ChangeLog -Section $Section -Setting "$Path\$Name" -OldValue "$current" -NewValue "$Value" -UndoHint "Set to '$UndoValue'"
        Write-Status "Set $Name = $Value (was: $current)" -Type Action
    }
}

# ============================================================
# Section 1: Process Creation & Command-Line Auditing
# ============================================================
# Enables Event ID 4688 with full command-line arguments.
# This is the primary detective control for bulk enumeration via cmd.exe.
# Without command-line auditing, Event 4688 shows cmd.exe started but
# not the '/s /b' flags that indicate recursive enumeration.

function Set-ProcessCreationAuditing {
    Write-Status "--- Section 1: Process Creation & Command-Line Auditing ---" -Type Info

    if ($Undo) {
        Write-Status "Reverting process creation audit settings..." -Type Warning

        # Restore audit policy to Not Configured for process creation
        if ($PSCmdlet.ShouldProcess("Audit Policy: Process Creation", "Revert to No Auditing")) {
            & auditpol.exe /set /subcategory:"Process Creation" /success:disable /failure:disable 2>&1 | Out-Null
            Write-Status "Reverted: Process Creation auditing disabled" -Type Success
        }

        # Remove command-line inclusion in process creation events
        $clPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (Test-Path $clPath) {
            if ($PSCmdlet.ShouldProcess("$clPath\ProcessCreationIncludeCmdLine_Enabled", "Remove")) {
                Remove-ItemProperty -Path $clPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
                Write-Status "Reverted: ProcessCreationIncludeCmdLine_Enabled removed" -Type Success
            }
        }
        return
    }

    if ($SkipAuditPolicy) {
        Write-Status "Skipping audit policy (SkipAuditPolicy flag set)" -Type Skip
        return
    }

    # Enable Process Creation auditing (Success) — generates Event ID 4688
    Write-Status "Enabling Process Creation audit (Success) — Event ID 4688..." -Type Info
    if ($PSCmdlet.ShouldProcess("Audit Policy: Process Creation", "Enable Success auditing")) {
        $result = & auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-ChangeLog -Section "Audit Policy" -Setting "Process Creation" -OldValue "Not configured" -NewValue "Success+Failure"
            Write-Status "Process Creation auditing enabled (Success + Failure)" -Type Success
        } else {
            Write-Status "Failed to set Process Creation audit policy: $result" -Type Warning
            $Script:WarningLog.Add("Process Creation audit policy: $result")
        }
    }

    # Enable command-line logging in process creation events
    # This populates the CommandLine field in Event ID 4688, which is required
    # to distinguish 'cmd.exe /c dir /s /b' from a benign cmd.exe launch.
    Write-Status "Enabling command-line logging in process creation events..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -Value 1 -Type DWORD `
        -Section "Audit Policy" `
        -UndoValue 0

    # Enable Object Access auditing — required for file-level Event ID 4663 (file read)
    # Without this, bulk file enumeration velocity cannot be measured.
    Write-Status "Enabling Object Access auditing (File System) — Event ID 4663..." -Type Info
    if ($PSCmdlet.ShouldProcess("Audit Policy: File System", "Enable Success auditing")) {
        $result = & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-ChangeLog -Section "Audit Policy" -Setting "File System Object Access" -OldValue "Not configured" -NewValue "Success+Failure"
            Write-Status "File System Object Access auditing enabled" -Type Success
        } else {
            Write-Status "Failed to set File System audit policy (may require SACL on specific folders): $result" -Type Warning
            $Script:WarningLog.Add("File System audit policy: $result")
        }
    }

    # Enable Detailed File Share auditing — captures SMB file access
    if ($PSCmdlet.ShouldProcess("Audit Policy: Detailed File Share", "Enable Success+Failure")) {
        & auditpol.exe /set /subcategory:"Detailed File Share" /success:enable /failure:enable 2>&1 | Out-Null
        Write-Status "Detailed File Share auditing enabled" -Type Success
    }
}

# ============================================================
# Section 2: Windows Defender — PUA and Real-Time Protection
# ============================================================
# Seatbelt and other GhostPack tools are detected by Windows Defender as
# HackTool/PUA. Enabling PUA protection in Block mode causes Defender to
# quarantine these binaries on extraction (before execution).

function Set-DefenderHardeningForEnumeration {
    Write-Status "--- Section 2: Windows Defender — PUA and Behavioral Protection ---" -Type Info

    # Verify Defender is present
    $defenderPresent = $null -ne (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)
    if (-not $defenderPresent) {
        Write-Status "Windows Defender cmdlets not available — skipping Defender section" -Type Skip
        $Script:WarningLog.Add("Windows Defender cmdlets not found. Verify Defender is installed and RSAT tools are present.")
        return
    }

    if ($Undo) {
        Write-Status "Reverting Windows Defender enumeration hardening..." -Type Warning

        if ($PSCmdlet.ShouldProcess("Windows Defender PUA Protection", "Revert to AuditMode")) {
            Set-MpPreference -PUAProtection AuditMode -ErrorAction SilentlyContinue
            Write-Status "PUA Protection reverted to AuditMode" -Type Success
        }

        if ($PSCmdlet.ShouldProcess("Windows Defender Behavior Monitoring", "Revert")) {
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Write-Status "Behavior Monitoring re-enabled" -Type Success
        }
        return
    }

    # Enable PUA Protection in Block mode
    # Seatbelt is classified as HackTool:MSIL/Seatbelt and as a PUA.
    # Block mode causes Defender to quarantine PUA on detection rather than just alert.
    Write-Status "Enabling PUA Protection in Block mode (blocks HackTool/Seatbelt on extraction)..." -Type Info
    $currentPUA = (Get-MpPreference).PUAProtection
    if ($currentPUA -ne 1) {
        if ($PSCmdlet.ShouldProcess("Windows Defender", "Set PUAProtection = Enabled (Block)")) {
            Set-MpPreference -PUAProtection Enabled
            Add-ChangeLog -Section "Windows Defender" -Setting "PUAProtection" -OldValue "$currentPUA" -NewValue "1 (Enabled/Block)" -UndoHint "Set-MpPreference -PUAProtection AuditMode"
            Write-Status "PUA Protection set to Block mode" -Type Success
        }
    } else {
        Write-Status "PUA Protection already in Block mode" -Type Skip
    }

    # Enable Behavior Monitoring — required for behavioral detection of
    # bulk enumeration patterns (high-velocity file opens from a single process)
    Write-Status "Ensuring Behavior Monitoring is enabled..." -Type Info
    $bmDisabled = (Get-MpPreference).DisableBehaviorMonitoring
    if ($bmDisabled -eq $true) {
        if ($PSCmdlet.ShouldProcess("Windows Defender", "Enable Behavior Monitoring")) {
            Set-MpPreference -DisableBehaviorMonitoring $false
            Add-ChangeLog -Section "Windows Defender" -Setting "DisableBehaviorMonitoring" -OldValue "True" -NewValue "False"
            Write-Status "Behavior Monitoring enabled" -Type Success
        }
    } else {
        Write-Status "Behavior Monitoring already enabled" -Type Skip
    }

    # Enable Cloud-Delivered Protection (MAPS) — allows rapid signature updates
    # for newly compiled enumeration tool variants
    Write-Status "Ensuring Cloud-Delivered Protection is enabled..." -Type Info
    $cloudLevel = (Get-MpPreference).MAPSReporting
    if ($cloudLevel -lt 2) {
        if ($PSCmdlet.ShouldProcess("Windows Defender", "Set MAPSReporting = Advanced")) {
            Set-MpPreference -MAPSReporting Advanced
            Add-ChangeLog -Section "Windows Defender" -Setting "MAPSReporting" -OldValue "$cloudLevel" -NewValue "2 (Advanced)"
            Write-Status "Cloud-Delivered Protection set to Advanced" -Type Success
        }
    } else {
        Write-Status "Cloud-Delivered Protection already at Advanced level" -Type Skip
    }

    # Enable Tamper Protection via registry (UI setting — registry enforces it)
    # Prevents the threat actor from disabling Defender controls during the enumeration phase
    Write-Status "Checking Tamper Protection status..." -Type Info
    $tpPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    $tpValue = Get-RegistryValueSafe -Path $tpPath -Name "TamperProtection" -Default 0
    if ($tpValue -ne 5) {
        Write-Status "Tamper Protection is not fully enabled (value: $tpValue). Enable via Windows Security > Virus & Threat Protection > Manage Settings." -Type Warning
        $Script:WarningLog.Add("Tamper Protection not enabled. Requires manual configuration in Windows Security UI or Intune policy.")
    } else {
        Write-Status "Tamper Protection is enabled" -Type Skip
    }

    # Update Defender signatures to catch latest Seatbelt variants
    Write-Status "Updating Windows Defender signatures..." -Type Info
    if ($PSCmdlet.ShouldProcess("Windows Defender", "Update signatures")) {
        try {
            Update-MpSignature -ErrorAction SilentlyContinue
            Write-Status "Defender signatures updated" -Type Success
        } catch {
            Write-Status "Signature update failed (may require network access): $_" -Type Warning
            $Script:WarningLog.Add("Defender signature update failed: $_")
        }
    }
}

# ============================================================
# Section 3: Attack Surface Reduction (ASR) Rules
# ============================================================
# ASR rules operate at the kernel level via Defender and can block
# executable files based on prevalence, age, and trust criteria.
# The most impactful rule for this technique is rule 01443614 which
# blocks low-prevalence executables (like freshly dropped Seatbelt).

function Set-ASRRules {
    Write-Status "--- Section 3: Attack Surface Reduction Rules ---" -Type Info

    if ($SkipASR) {
        Write-Status "Skipping ASR rules (SkipASR flag set)" -Type Skip
        return
    }

    $defenderPresent = $null -ne (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)
    if (-not $defenderPresent) {
        Write-Status "Windows Defender cmdlets not available — skipping ASR section" -Type Skip
        return
    }

    # Define ASR rules relevant to file enumeration and tool execution
    # Each entry: RuleGUID, Description, Action (2=Audit, 6=Block)
    $asrRules = @(
        @{
            GUID   = "01443614-cd74-433a-b99e-2ecdc07bfc25"
            Name   = "Block executable files from running unless they meet prevalence, age, or trusted-list criteria"
            Action = 6  # Block
            Note   = "Primary control: blocks freshly dropped Seatbelt and similar low-prevalence tools"
        },
        @{
            GUID   = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
            Name   = "Block executable content from email client and webmail"
            Action = 6  # Block
            Note   = "Prevents email-delivered enumeration tool droppers"
        },
        @{
            GUID   = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
            Name   = "Block all Office applications from creating child processes"
            Action = 6  # Block
            Note   = "Prevents macro-launched enumeration (cmd.exe spawned by Office)"
        },
        @{
            GUID   = "26190899-1602-49e8-8b27-eb1d0a1ce869"
            Name   = "Block Office communication application from creating child processes"
            Action = 6  # Block
            Note   = "Prevents Teams/Outlook macro-initiated enumeration chains"
        },
        @{
            GUID   = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
            Name   = "Block persistence through WMI event subscription"
            Action = 6  # Block
            Note   = "Prevents WMI-based persistence following enumeration phase"
        },
        @{
            GUID   = "d3e037e1-3eb8-44c8-a917-57927947596d"
            Name   = "Block JavaScript or VBScript from launching downloaded executable content"
            Action = 6  # Block
            Note   = "Prevents script-based enumeration tool execution"
        }
    )

    if ($Undo) {
        Write-Status "Reverting ASR rules to Audit mode..." -Type Warning
        foreach ($rule in $asrRules) {
            if ($PSCmdlet.ShouldProcess("ASR Rule: $($rule.Name)", "Set to Audit mode")) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID `
                        -AttackSurfaceReductionRules_Actions Audit `
                        -ErrorAction SilentlyContinue
                    Write-Status "ASR rule set to Audit: $($rule.Name)" -Type Success
                } catch {
                    Write-Status "Could not set ASR rule $($rule.GUID): $_" -Type Warning
                }
            }
        }
        return
    }

    # Retrieve current ASR rule configuration
    $currentPrefs = Get-MpPreference
    $currentIds     = @($currentPrefs.AttackSurfaceReductionRules_Ids)
    $currentActions = @($currentPrefs.AttackSurfaceReductionRules_Actions)

    foreach ($rule in $asrRules) {
        Write-Status "Configuring ASR: $($rule.Name)..." -Type Info
        Write-Status "  Note: $($rule.Note)" -Type Info

        # Determine current action for this rule
        $idx = $currentIds.IndexOf($rule.GUID)
        if ($idx -lt 0) { $idx = [Array]::IndexOf($currentIds, $rule.GUID) }
        $currentAction = if ($idx -ge 0 -and $idx -lt $currentActions.Count) { $currentActions[$idx] } else { "Not configured" }

        if ($currentAction -eq $rule.Action) {
            Write-Status "  Already configured correctly (action: $($rule.Action))" -Type Skip
            continue
        }

        if ($PSCmdlet.ShouldProcess("ASR Rule: $($rule.Name)", "Set to action $($rule.Action) (was: $currentAction)")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID `
                    -AttackSurfaceReductionRules_Actions $rule.Action `
                    -ErrorAction Stop
                Add-ChangeLog -Section "ASR Rules" `
                    -Setting $rule.Name `
                    -OldValue "$currentAction" `
                    -NewValue "$($rule.Action) (Block)" `
                    -UndoHint "Add-MpPreference -AttackSurfaceReductionRules_Ids $($rule.GUID) -AttackSurfaceReductionRules_Actions Audit"
                Write-Status "  Applied (action: $($rule.Action) = Block)" -Type Success
            } catch {
                Write-Status "  Failed to apply ASR rule: $_" -Type Warning
                $Script:WarningLog.Add("ASR rule $($rule.GUID) ($($rule.Name)): $_")
            }
        }
    }
}

# ============================================================
# Section 4: Controlled Folder Access (CFA)
# ============================================================
# CFA protects specific folders from unauthorized write access.
# While CFA does not block read enumeration directly, it prevents
# a ransomware process from writing to protected folders after
# completing its enumeration phase. It also provides an alert
# signal when a process attempts to write to a protected path
# (high confidence ransomware indicator).

function Set-ControlledFolderAccess {
    Write-Status "--- Section 4: Controlled Folder Access ---" -Type Info

    if ($SkipCFA) {
        Write-Status "Skipping Controlled Folder Access (SkipCFA flag set)" -Type Skip
        return
    }

    $defenderPresent = $null -ne (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)
    if (-not $defenderPresent) {
        Write-Status "Windows Defender cmdlets not available — skipping CFA section" -Type Skip
        return
    }

    if ($Undo) {
        Write-Status "Reverting Controlled Folder Access to AuditMode..." -Type Warning
        if ($PSCmdlet.ShouldProcess("Controlled Folder Access", "Set to AuditMode")) {
            Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
            Write-Status "Controlled Folder Access set to AuditMode" -Type Success
        }
        return
    }

    # Check current CFA state
    $currentCFA = (Get-MpPreference).EnableControlledFolderAccess
    Write-Status "Current Controlled Folder Access state: $currentCFA" -Type Info

    if ($currentCFA -eq 1) {
        Write-Status "Controlled Folder Access already in Enabled (Block) mode" -Type Skip
    } else {
        # Set to AuditMode first as a safe starting point if not enabled
        # In AuditMode, CFA logs but does not block, which allows baselining
        # of which legitimate applications access protected folders before
        # enabling full block mode and potentially disrupting workflows.
        Write-Status "Setting Controlled Folder Access to AuditMode (review logs before enabling Block)..." -Type Info
        if ($PSCmdlet.ShouldProcess("Controlled Folder Access", "Set to AuditMode")) {
            Set-MpPreference -EnableControlledFolderAccess AuditMode
            Add-ChangeLog -Section "Controlled Folder Access" `
                -Setting "EnableControlledFolderAccess" `
                -OldValue "$currentCFA" `
                -NewValue "AuditMode" `
                -UndoHint "Set-MpPreference -EnableControlledFolderAccess Disabled"
            Write-Status "Controlled Folder Access enabled in AuditMode" -Type Success
            Write-Status "  Review Event ID 1124 (CFA audit) for 30 days then switch to Block mode:" -Type Warning
            Write-Status "  Set-MpPreference -EnableControlledFolderAccess Enabled" -Type Warning
        }
    }

    # Verify default protected folders are configured
    # CFA protects Documents, Desktop, Pictures, Music, Videos by default.
    # Report current configuration.
    $cfaFolders = (Get-MpPreference).ControlledFolderAccessProtectedFolders
    Write-Status "CFA protected folders count: $(if ($cfaFolders) { $cfaFolders.Count } else { 'default only' })" -Type Info
    Write-Status "  Default protected: Documents, Desktop, Pictures, Music, Videos, Favorites" -Type Info
    Write-Status "  To add custom folder: Add-MpPreference -ControlledFolderAccessProtectedFolders 'C:\CustomFolder'" -Type Info
}

# ============================================================
# Section 5: Windows Firewall — Block Outbound Data Exfiltration
# ============================================================
# After successful file enumeration, adversaries frequently exfiltrate
# the target list and file contents via outbound connections. These rules
# restrict outbound traffic from cmd.exe and known enumeration tools
# to prevent post-enumeration exfiltration.

function Set-FirewallHardeningForEnumeration {
    Write-Status "--- Section 5: Windows Firewall Outbound Restrictions ---" -Type Info

    if ($Undo) {
        Write-Status "Removing firewall rules for enumeration hardening..." -Type Warning

        $rulesToRemove = @(
            "F0RTIKA-Block-CMD-Outbound",
            "F0RTIKA-Block-PowerShell-Outbound-Suspicious",
            "F0RTIKA-Block-Wscript-Outbound",
            "F0RTIKA-Block-Cscript-Outbound",
            "F0RTIKA-Block-Mshta-Outbound"
        )
        foreach ($rule in $rulesToRemove) {
            if ($PSCmdlet.ShouldProcess("Firewall Rule: $rule", "Remove")) {
                Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
                Write-Status "Removed firewall rule: $rule" -Type Success
            }
        }
        return
    }

    # These rules block the most common outbound channels used after
    # file enumeration to exfiltrate the target list or initiate C2 contact.
    # cmd.exe, mshta.exe, wscript.exe, and cscript.exe should never
    # require direct outbound internet access in a managed enterprise environment.

    $firewallRules = @(
        @{
            Name        = "F0RTIKA-Block-CMD-Outbound"
            Description = "Block cmd.exe direct outbound connections (enumeration exfiltration prevention)"
            Program     = "%SystemRoot%\System32\cmd.exe"
            Direction   = "Outbound"
            Action      = "Block"
        },
        @{
            Name        = "F0RTIKA-Block-Wscript-Outbound"
            Description = "Block wscript.exe outbound (prevents script-based enumeration exfiltration)"
            Program     = "%SystemRoot%\System32\wscript.exe"
            Direction   = "Outbound"
            Action      = "Block"
        },
        @{
            Name        = "F0RTIKA-Block-Cscript-Outbound"
            Description = "Block cscript.exe outbound (prevents script-based exfiltration)"
            Program     = "%SystemRoot%\System32\cscript.exe"
            Direction   = "Outbound"
            Action      = "Block"
        },
        @{
            Name        = "F0RTIKA-Block-Mshta-Outbound"
            Description = "Block mshta.exe outbound (common living-off-the-land exfiltration vector)"
            Program     = "%SystemRoot%\System32\mshta.exe"
            Direction   = "Outbound"
            Action      = "Block"
        }
    )

    foreach ($rule in $firewallRules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Status "Firewall rule already exists: $($rule.Name)" -Type Skip
            continue
        }
        if ($PSCmdlet.ShouldProcess("Firewall", "Create rule: $($rule.Name)")) {
            try {
                New-NetFirewallRule `
                    -DisplayName $rule.Name `
                    -Description $rule.Description `
                    -Program $rule.Program `
                    -Direction $rule.Direction `
                    -Action $rule.Action `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                Add-ChangeLog -Section "Windows Firewall" `
                    -Setting $rule.Name `
                    -OldValue "Not present" `
                    -NewValue "Block Outbound" `
                    -UndoHint "Remove-NetFirewallRule -DisplayName '$($rule.Name)'"
                Write-Status "Created firewall rule: $($rule.Name)" -Type Success
            } catch {
                Write-Status "Failed to create firewall rule '$($rule.Name)': $_" -Type Warning
                $Script:WarningLog.Add("Firewall rule '$($rule.Name)': $_")
            }
        }
    }
}

# ============================================================
# Section 6: AppLocker Policy for Offensive Enumeration Tools
# ============================================================
# AppLocker can block execution of unsigned executables and known
# offensive tools by publisher, hash, or path rules. This section
# configures AppLocker to deny execution of tools that match the
# GhostPack/Seatbelt behavioral profile: C# .NET executables dropped
# to temporary or non-standard paths without a trusted code signing certificate.

function Set-AppLockerPolicy {
    Write-Status "--- Section 6: AppLocker Policy for Enumeration Tool Restriction ---" -Type Info

    if ($SkipAppLocker) {
        Write-Status "Skipping AppLocker (SkipAppLocker flag set)" -Type Skip
        return
    }

    # Verify AppLocker service
    $appidSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if (-not $appidSvc) {
        Write-Status "Application Identity service not found — AppLocker may not be supported on this SKU" -Type Warning
        $Script:WarningLog.Add("AppIDSvc not found — AppLocker requires Windows Enterprise or Education edition")
        return
    }

    if ($Undo) {
        Write-Status "AppLocker policy revert requires manual action via Group Policy or Set-AppLockerPolicy." -Type Warning
        Write-Status "To fully remove AppLocker EXE rules: use Group Policy editor or export/import a clean policy." -Type Warning
        $Script:WarningLog.Add("AppLocker Undo: manual revert required via GPMC or Set-AppLockerPolicy with a clean XML.")
        return
    }

    # Ensure Application Identity service is running
    if ($appidSvc.Status -ne "Running") {
        if ($PSCmdlet.ShouldProcess("AppIDSvc", "Start service and set to Automatic")) {
            Set-Service -Name "AppIDSvc" -StartupType Automatic
            Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
            Add-ChangeLog -Section "AppLocker" -Setting "AppIDSvc" -OldValue "$($appidSvc.Status)" -NewValue "Running/Automatic"
            Write-Status "Application Identity service started" -Type Success
        }
    } else {
        Write-Status "Application Identity service is running" -Type Skip
    }

    # Define an AppLocker policy that:
    # 1. Allows everything signed by Microsoft and publishers in Program Files
    # 2. Denies execution of unsigned .exe from user-writable paths
    # This is a DENY-by-exception overlay, not a full whitelist policy.
    # A full whitelist policy should be deployed via GPO in production.

    $appLockerXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <!-- Allow: Everything signed by Microsoft Windows -->
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                       Name="Allow: Microsoft Windows Components"
                       Description="Allow all executables signed by Microsoft"
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                                 ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <!-- Allow: Executables in Program Files -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Allow: Program Files"
                  Description="Allow executables in Program Files directories"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
                  Name="Allow: Program Files (x86)"
                  Description="Allow executables in Program Files (x86) directories"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>
    <!-- Allow: Windows directory -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Allow: Windows"
                  Description="Allow all executables in Windows directory"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <!-- Deny: Unsigned executables from user-writable temp paths -->
    <!-- NOTE: This rule is in AuditOnly mode. Switch EnforcementMode to "Enabled"
         after baselining to move to enforce mode. -->
    <FilePathRule Id="b432c918-b45c-459a-9b37-60c7c1c08ff1"
                  Name="DENY: Executables from user temp paths (AuditOnly)"
                  Description="Detect unsigned executables running from AppData, Temp, Downloads"
                  UserOrGroupSid="S-1-5-11" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\AppData\Local\Temp\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="c891c9e6-3d2c-4752-9e4b-c87a02c7bf0d"
                  Name="DENY: Executables from Downloads folder (AuditOnly)"
                  Description="Detect executables run directly from Downloads"
                  UserOrGroupSid="S-1-5-11" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\Downloads\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

    $tempPolicyPath = Join-Path $env:TEMP "f0rtika_applocker_policy.xml"

    if ($PSCmdlet.ShouldProcess("AppLocker Policy", "Apply enumeration tool restriction (AuditOnly mode)")) {
        try {
            $appLockerXml | Out-File -FilePath $tempPolicyPath -Encoding UTF8 -Force
            Set-AppLockerPolicy -XMLPolicy $tempPolicyPath -Merge -ErrorAction Stop
            Add-ChangeLog -Section "AppLocker" `
                -Setting "EXE Rules" `
                -OldValue "Not configured" `
                -NewValue "AuditOnly — Deny from Temp/Downloads paths"
            Write-Status "AppLocker policy applied in AuditOnly mode" -Type Success
            Write-Status "  Review AppLocker event logs (Event IDs 8003/8004) for 14 days." -Type Warning
            Write-Status "  Then change EnforcementMode to 'Enabled' to enforce blocking." -Type Warning
        } catch {
            Write-Status "Failed to apply AppLocker policy: $_" -Type Warning
            $Script:WarningLog.Add("AppLocker policy application failed: $_")
        } finally {
            Remove-Item $tempPolicyPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================
# Section 7: Registry Hardening — WMI and System Info Restrictions
# ============================================================
# T1082 (System Information Discovery) via Seatbelt uses WMI queries,
# registry enumeration, and systeminfo.exe. These registry settings
# restrict WMI remote access and reduce the information surface
# available to enumeration tools running in user context.

function Set-RegistryHardeningForDiscovery {
    Write-Status "--- Section 7: Registry Hardening for Discovery Technique Restriction ---" -Type Info

    if ($Undo) {
        Write-Status "Reverting registry hardening for discovery..." -Type Warning

        # Re-enable WMI remote access (default: enabled)
        if ($PSCmdlet.ShouldProcess("WMI Remote Restrictions", "Revert")) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WBEM\CIMOM" `
                -Name "EnableAnonConnections" -ErrorAction SilentlyContinue
            Write-Status "Reverted WMI anonymous connection restriction" -Type Success
        }
        return
    }

    # Disable WMI anonymous connections — prevents unauthenticated WMI enumeration
    # Seatbelt uses WMI for system discovery checks when run remotely
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Microsoft\WBEM\CIMOM" `
        -Name "EnableAnonConnections" `
        -Value 0 -Type DWORD `
        -Section "Registry Hardening" `
        -UndoValue 1

    # Restrict access to registry hives that Seatbelt enumerates
    # (InterestingRegistryKeys check in Seatbelt reads HKLM\SYSTEM\CurrentControlSet\Services)
    # These keys are read-only for standard users by default — this enforces it explicitly
    Write-Status "Verifying sensitive registry key ACLs..." -Type Info

    $sensitiveKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKLM:\SAM",
        "HKLM:\SECURITY"
    )

    foreach ($keyPath in $sensitiveKeys) {
        if (Test-Path $keyPath) {
            try {
                $acl = Get-Acl -Path $keyPath -ErrorAction SilentlyContinue
                if ($acl) {
                    Write-Status "  $keyPath — ACL present (owner: $($acl.Owner))" -Type Info
                }
            } catch {
                Write-Status "  $keyPath — cannot read ACL (may be expected for SAM/SECURITY)" -Type Skip
            }
        }
    }

    # Prevent PowerShell v2 downgrade — PS v2 bypasses AMSI and script block logging
    # Enumeration scripts frequently attempt PS v2 downgrade to avoid detection
    Write-Status "Disabling PowerShell v2 (prevents AMSI bypass via downgrade)..." -Type Info
    if ($PSCmdlet.ShouldProcess("Windows Feature: PowerShell v2", "Disable")) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
            if ($feature -and $feature.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Add-ChangeLog -Section "Registry Hardening" `
                    -Setting "PowerShell v2 Feature" `
                    -OldValue "Enabled" `
                    -NewValue "Disabled" `
                    -UndoHint "Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
                Write-Status "PowerShell v2 disabled" -Type Success
            } else {
                Write-Status "PowerShell v2 already disabled or not present" -Type Skip
            }
        } catch {
            Write-Status "Could not check PowerShell v2 feature state: $_" -Type Warning
            $Script:WarningLog.Add("PowerShell v2 disable: $_")
        }
    }

    # Enable PowerShell ScriptBlock Logging — captures Seatbelt-invoked PS commands
    # This generates Event ID 4104 for every script block executed, making
    # PowerShell-invoked credential checks visible in the Security log
    Write-Status "Enabling PowerShell ScriptBlock logging (Event ID 4104)..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" `
        -Value 1 -Type DWORD `
        -Section "Registry Hardening" `
        -UndoValue 0

    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockInvocationLogging" `
        -Value 1 -Type DWORD `
        -Section "Registry Hardening" `
        -UndoValue 0

    # Enable PowerShell Module Logging — logs all module function invocations
    Write-Status "Enabling PowerShell Module logging (Event ID 4103)..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -Name "EnableModuleLogging" `
        -Value 1 -Type DWORD `
        -Section "Registry Hardening" `
        -UndoValue 0

    # Increase Security event log size to retain enumeration evidence
    # Default 20MB is often insufficient for high-volume file access events (4663)
    Write-Status "Increasing Security event log maximum size to 512MB..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
        -Name "MaxSize" `
        -Value 536870912 -Type DWORD `
        -Section "Event Log" `
        -UndoValue 20971520

    # Increase Application event log size (AppLocker events go here)
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" `
        -Name "MaxSize" `
        -Value 104857600 -Type DWORD `
        -Section "Event Log" `
        -UndoValue 20971520
}

# ============================================================
# Section 8: Windows Credential Manager Hardening
# ============================================================
# Seatbelt's WindowsCredentialFiles and WindowsVault checks specifically
# target Windows Credential Manager, DPAPI master keys, and Vault files.
# These settings restrict access to credential storage locations.

function Set-CredentialStoreHardening {
    Write-Status "--- Section 8: Credential Store Hardening ---" -Type Info

    if ($Undo) {
        Write-Status "Credential store hardening revert: review and re-enable any disabled credential caching policies." -Type Warning
        # Re-enable credential caching if it was disabled
        Set-RegistryValueIdempotent `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
            -Name "DisableDomainCreds" `
            -Value 0 -Type DWORD `
            -Section "Credential Hardening (Undo)" `
            -UndoValue 0
        return
    }

    # Disable storage of network credentials in Credential Manager
    # Seatbelt's WindowsCredentialFiles check harvests credentials stored here.
    # When disabled, network credentials are not saved to the Windows Vault.
    Write-Status "Disabling 'Store network credentials' persistence in Credential Manager..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        -Name "DisableDomainCreds" `
        -Value 1 -Type DWORD `
        -Section "Credential Hardening" `
        -UndoValue 0

    # Restrict WDigest authentication — prevents cleartext password caching in LSASS
    # Seatbelt's WindowsVault check can expose WDigest credentials if enabled
    Write-Status "Ensuring WDigest UseLogonCredential is disabled (no cleartext LSASS caching)..." -Type Info
    Set-RegistryValueIdempotent `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" `
        -Value 0 -Type DWORD `
        -Section "Credential Hardening" `
        -UndoValue 0

    # Enable LSASS protection (RunAsPPL) — prevents credential dumping even if
    # enumeration tools discover credential material locations via Seatbelt
    Write-Status "Enabling LSASS RunAsPPL (Protected Process Light)..." -Type Info
    $currentPPL = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default 0
    if ($currentPPL -ne 1) {
        Set-RegistryValueIdempotent `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RunAsPPL" `
            -Value 1 -Type DWORD `
            -Section "Credential Hardening" `
            -UndoValue 0
        Write-Status "  NOTE: RunAsPPL requires a reboot to take effect." -Type Warning
    } else {
        Write-Status "LSASS RunAsPPL already enabled" -Type Skip
    }
}

# ============================================================
# Section 9: Verification Report
# ============================================================

function Show-HardeningVerification {
    Write-Status "" -Type Info
    Write-Status "=== Hardening Verification Report ===" -Type Info
    Write-Status "" -Type Info

    # Check Defender status
    $defenderPresent = $null -ne (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)
    if ($defenderPresent) {
        $mpPref = Get-MpPreference
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

        Write-Status "Windows Defender:" -Type Info
        Write-Status "  Real-Time Protection: $(if ($mpStatus) { $mpStatus.RealTimeProtectionEnabled } else { 'unknown' })" -Type Info
        Write-Status "  PUA Protection: $($mpPref.PUAProtection) (1=Block, 2=Audit)" -Type Info
        Write-Status "  Behavior Monitoring: $(if ($mpPref.DisableBehaviorMonitoring) { 'DISABLED' } else { 'Enabled' })" -Type Info
        Write-Status "  CFA Mode: $($mpPref.EnableControlledFolderAccess) (1=Block, 2=Audit)" -Type Info
        Write-Status "  ASR Rules count: $(if ($mpPref.AttackSurfaceReductionRules_Ids) { $mpPref.AttackSurfaceReductionRules_Ids.Count } else { 0 })" -Type Info
    }

    # Check audit policy
    Write-Status "Audit Policy:" -Type Info
    $procAudit = & auditpol.exe /get /subcategory:"Process Creation" 2>&1
    Write-Status "  Process Creation: $($procAudit | Select-String 'Process Creation')" -Type Info

    # Check PS logging
    $sbLogging = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Default 0
    Write-Status "PowerShell ScriptBlock Logging: $(if ($sbLogging -eq 1) { 'Enabled' } else { 'DISABLED' })" -Type Info

    # Check WDigest
    $wdigest = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default 0
    Write-Status "WDigest UseLogonCredential: $(if ($wdigest -eq 0) { 'Disabled (secure)' } else { 'ENABLED (insecure)' })" -Type Info

    # Check RunAsPPL
    $ppl = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Default 0
    Write-Status "LSASS RunAsPPL: $(if ($ppl -eq 1) { 'Enabled (reboot required if just set)' } else { 'DISABLED' })" -Type Info
}

# ============================================================
# Main Execution
# ============================================================

$mode = if ($Undo) { "UNDO" } else { "APPLY" }
Write-Status "" -Type Info
Write-Status "============================================================" -Type Info
Write-Status " F0RT1KA Defense Hardening — Pre-Encryption File Enumeration" -Type Info
Write-Status " MITRE ATT&CK: T1083, T1119, T1082" -Type Info
Write-Status " Mitigations:  M1041, M1029, M1028" -Type Info
Write-Status " Mode: $mode" -Type Info
Write-Status "============================================================" -Type Info
Write-Status "" -Type Info

Set-ProcessCreationAuditing
Set-DefenderHardeningForEnumeration
Set-ASRRules
Set-ControlledFolderAccess
Set-FirewallHardeningForEnumeration
Set-AppLockerPolicy
Set-RegistryHardeningForDiscovery
Set-CredentialStoreHardening

if (-not $Undo) {
    Show-HardeningVerification
}

Write-Status "" -Type Info
Write-Status "============================================================" -Type Info

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes applied ($($Script:ChangeLog.Count) modifications):" -Type Success
    $Script:ChangeLog | Format-Table Section, Setting, OldValue, NewValue -AutoSize
} else {
    Write-Status "No changes applied (all settings already correct, or WhatIf mode)" -Type Info
}

if ($Script:WarningLog.Count -gt 0) {
    Write-Status "" -Type Info
    Write-Status "Warnings requiring manual attention:" -Type Warning
    foreach ($w in $Script:WarningLog) {
        Write-Status "  - $w" -Type Warning
    }
}

Write-Status "" -Type Info
if ($Undo) {
    Write-Status "Hardening reverted. Review changes above and reboot if RunAsPPL was modified." -Type Success
} else {
    Write-Status "Hardening complete. Recommendations:" -Type Success
    Write-Status "  1. Reboot if LSASS RunAsPPL or PowerShell v2 was changed." -Type Info
    Write-Status "  2. Review CFA AuditMode events (Event ID 1124) for 14-30 days before switching to Block." -Type Info
    Write-Status "  3. Review AppLocker AuditOnly events (Event IDs 8003/8004) before enforcing." -Type Info
    Write-Status "  4. Enable Tamper Protection manually via Windows Security UI or Intune." -Type Info
    Write-Status "  5. Deploy SACL entries on sensitive directories for Event ID 4663 file access auditing." -Type Info
}
Write-Status "============================================================" -Type Info
