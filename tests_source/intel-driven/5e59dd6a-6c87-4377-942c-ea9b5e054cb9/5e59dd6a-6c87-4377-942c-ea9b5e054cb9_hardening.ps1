<#
.SYNOPSIS
    Hardens Windows against Cloud Files API abuse, batch-oplock scanner-stall, and VSS TOCTOU
    credential-theft techniques.

.DESCRIPTION
    Applies security hardening to mitigate the BlueHammer technique class:
      - Cloud Files sync-root abuse (CfRegisterSyncRoot + fetch-placeholder callback interception)
      - Batch-oplock Defender freeze (FSCTL_REQUEST_BATCH_OPLOCK on scanner-accessed files)
      - VSS device enumeration + transacted-file-open TOCTOU setup
      - Downstream credential theft via offline SAM parsing

    MITRE ATT&CK:  T1211, T1562.001
    Mitigations:   M1050, M1048, M1047, M1038, M1022, M1024, M1018

    All changes are idempotent. The script reports the previous state alongside the applied
    state so you can tell what was already configured and what was changed.

.PARAMETER Undo
    Reverts all registry changes made by this script.
    NOTE: Tamper Protection and Credential Guard cannot be toggled programmatically when
    Tamper Protection is active — the script will report which items require manual action.

.PARAMETER WhatIf
    Shows what changes would be made without applying them.

.PARAMETER SkipRebootCheck
    Suppresses the reboot-required warning at the end of the run. Use for automation contexts
    where you will handle reboots externally.

.EXAMPLE
    .\5e59dd6a-6c87-4377-942c-ea9b5e054cb9_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\5e59dd6a-6c87-4377-942c-ea9b5e054cb9_hardening.ps1 -WhatIf
    Shows what would change without making changes.

.EXAMPLE
    .\5e59dd6a-6c87-4377-942c-ea9b5e054cb9_hardening.ps1 -Undo
    Reverts all registry hardening applied by this script.

.NOTES
    Author:      F0RT1KA Defense Guidance Generator
    Techniques:  T1211 (Cloud Files/VSS TOCTOU), T1562.001 (Batch-oplock stall)
    Requires:    Administrator privileges
    Idempotent:  Yes (safe to run multiple times)
    Reboot:      Required for RunAsPPL, Credential Guard, and some Defender settings.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipRebootCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# Admin-privilege check (mandatory per CLAUDE.md PS guidelines)
# ============================================================

function Test-AdminPrivilege {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-AdminPrivilege)) {
    Write-Error "This script requires Administrator privileges. Re-launch in an elevated session."
    exit 1
}

# ============================================================
# Execution policy bypass (mandatory per CLAUDE.md PS guidelines)
# ============================================================
# Ensure the current session can run unsigned scripts even if machine policy is restrictive.
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
} catch {
    # Non-fatal — script may already be running in a sufficiently permissive context.
}

# ============================================================
# Helpers
# ============================================================

$Script:RebootRequired  = $false
$Script:ChangeLog       = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:WhatIfActive    = $WhatIfPreference.IsPresent

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Skipped','Changed','AlreadySet')]
        [string]$Type = 'Info'
    )
    $map = @{
        Info       = 'Cyan'
        Success    = 'Green'
        Warning    = 'Yellow'
        Error      = 'Red'
        Skipped    = 'DarkGray'
        Changed    = 'Magenta'
        AlreadySet = 'DarkGreen'
    }
    $prefix = @{
        Info       = '[INFO]   '
        Success    = '[OK]     '
        Warning    = '[WARN]   '
        Error      = '[ERROR]  '
        Skipped    = '[SKIP]   '
        Changed    = '[CHANGED]'
        AlreadySet = '[SET]    '
    }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $map[$Type]
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Add-ChangeRecord {
    param(
        [string]$Control,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue,
        [string]$Note = ''
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Control   = $Control
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
        Note      = $Note
    })
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

function Set-RegDword {
    <#
    Sets a DWORD registry value idempotently. Reports the before/after state.
    Returns $true if a change was made, $false if value was already correct.
    #>
    param(
        [string]$Control,
        [string]$Path,
        [string]$Name,
        [int]   $Value,
        [string]$UndoValue   = $null,   # Value to restore on -Undo. $null = delete key.
        [string]$Note        = ''
    )

    if ($Undo) {
        $current = Get-RegValue -Path $Path -Name $Name
        if ($null -eq $UndoValue) {
            if ($null -ne $current) {
                if ($Script:WhatIfActive) {
                    Write-Status "WhatIf: would DELETE ${Path}\${Name} (currently=$current)" -Type Warning
                } else {
                    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
                    Write-Status "Reverted: deleted ${Path}\${Name} (was $current)" -Type Changed
                    Add-ChangeRecord -Control $Control -Target "${Path}\${Name}" -OldValue "$current" -NewValue 'deleted'
                }
            } else {
                Write-Status "Nothing to revert for ${Path}\${Name} (not present)" -Type AlreadySet
            }
        } else {
            $undoInt = [int]$UndoValue
            if ($current -ne $undoInt) {
                if ($Script:WhatIfActive) {
                    Write-Status "WhatIf: would SET ${Path}\${Name} = $undoInt (currently=$current)" -Type Warning
                } else {
                    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
                    Set-ItemProperty -Path $Path -Name $Name -Value $undoInt -Type DWord
                    Write-Status "Reverted: ${Path}\${Name} -> $undoInt (was $current)" -Type Changed
                    Add-ChangeRecord -Control $Control -Target "${Path}\${Name}" -OldValue "$current" -NewValue "$undoInt"
                }
            } else {
                Write-Status "Undo: ${Path}\${Name} already at target value $undoInt" -Type AlreadySet
            }
        }
        return
    }

    # Apply path
    $current = Get-RegValue -Path $Path -Name $Name
    if ($current -eq $Value) {
        Write-Status "${Control}: ${Name} already = $Value" -Type AlreadySet
        return
    }

    if ($Script:WhatIfActive) {
        Write-Status "WhatIf: would SET ${Path}\${Name} = $Value (currently=$current, note=$Note)" -Type Warning
        return
    }

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Status "${Control}: ${Name} = $Value (was $current). $Note" -Type Changed
    Add-ChangeRecord -Control $Control -Target "${Path}\${Name}" -OldValue "$current" -NewValue "$Value" -Note $Note
}

# ============================================================
# Section 1 — Defender Tamper Protection (read-only check)
# ============================================================
# Tamper Protection cannot be enabled via registry while it is already active — Windows
# enforces this intentionally. We check and report; actual enforcement requires Intune
# (MDE policy TamperProtection=5) or the Windows Security UI toggle.

function Invoke-TamperProtectionCheck {
    Write-SectionHeader "Defender Tamper Protection"

    $tpPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    $tpName = 'TamperProtection'
    $current = Get-RegValue -Path $tpPath -Name $tpName

    # TamperProtection values: 0=off, 1=on (no Intune), 4=not configured, 5=on (Intune-managed)
    if ($current -in @(1, 5)) {
        Write-Status "Tamper Protection is ENABLED (value=$current). No change needed." -Type AlreadySet
    } else {
        Write-Status "Tamper Protection is DISABLED or not configured (value=$current)." -Type Warning
        Write-Status "  ACTION REQUIRED: Enable via Windows Security UI or Intune (TamperProtection=5)." -Type Warning
        Write-Status "  This cannot be set programmatically while Tamper Protection is active." -Type Warning
        Write-Status "  Without Tamper Protection, phases 1-2 of BlueHammer can surgically disable Defender." -Type Warning
        Add-ChangeRecord -Control 'TamperProtection' -Target "${tpPath}\${tpName}" `
            -OldValue "$current" -NewValue 'manual action required' `
            -Note 'Cannot set programmatically — use Windows Security UI or Intune'
    }
}

# ============================================================
# Section 2 — LSA RunAsPPL (Protected Process Light for LSASS)
# ============================================================
# RunAsPPL=2 forces lsass.exe to run as a PPL. This is the most effective control
# against NTLM hash theft (phase 6) and limits token-duplication paths even if
# the offline SAM parse in phase 5 succeeds. Requires reboot.

function Invoke-LSARunAsPPL {
    Write-SectionHeader "LSA Protected Process Light (RunAsPPL)"

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    if ($Undo) {
        Write-Status "Reverting RunAsPPL to 0 (disabling PPL enforcement)..." -Type Warning
        Set-RegDword -Control 'LSA-RunAsPPL' -Path $lsaPath -Name 'RunAsPPL' `
            -Value 0 -UndoValue '0'
        Set-RegDword -Control 'LSA-RunAsPPL' -Path $lsaPath -Name 'RunAsPPLBoot' `
            -Value 0 -UndoValue '0'
        Write-Status "Reboot required to complete RunAsPPL reversion." -Type Warning
        $Script:RebootRequired = $true
        return
    }

    $current = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
    if ($current -ge 1) {
        Write-Status "RunAsPPL already set (value=$current). No change." -Type AlreadySet
    } else {
        # RunAsPPL = 2 uses UEFI variable lock (preferred on Secure Boot systems)
        # RunAsPPL = 1 is the legacy value — still effective without UEFI lock
        # We set 2 if Secure Boot is available, 1 otherwise.
        $secureBoot = $false
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            $secureBoot = $sb
        } catch { }

        $targetPPL = if ($secureBoot) { 2 } else { 1 }

        Set-RegDword -Control 'LSA-RunAsPPL' -Path $lsaPath -Name 'RunAsPPL' `
            -Value $targetPPL -UndoValue '0' `
            -Note "PPL level $targetPPL (SecureBoot=$secureBoot). Reboot required."
        Set-RegDword -Control 'LSA-RunAsPPL' -Path $lsaPath -Name 'RunAsPPLBoot' `
            -Value $targetPPL -UndoValue '0' `
            -Note "Boot-time PPL enforcement."

        Write-Status "RunAsPPL set to $targetPPL. REBOOT REQUIRED to take effect." -Type Warning
        $Script:RebootRequired = $true
    }
}

# ============================================================
# Section 3 — LSASS Audit Level
# ============================================================
# AuditLevel=8 enables lsass.exe audit logging via IFEO. This logs all OpenProcess
# calls against lsass.exe regardless of whether RunAsPPL is active — essential for
# detecting token-duplication attempts even if a process somehow bypasses PPL.

function Invoke-LsassAuditLevel {
    Write-SectionHeader "LSASS Access Audit Logging"

    $lsassIfeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'

    if ($Undo) {
        Write-Status "Removing LSASS IFEO AuditLevel..." -Type Warning
        Set-RegDword -Control 'LSASS-AuditLevel' -Path $lsassIfeoPath -Name 'AuditLevel' `
            -Value 0 -UndoValue $null
        return
    }

    Set-RegDword -Control 'LSASS-AuditLevel' -Path $lsassIfeoPath -Name 'AuditLevel' `
        -Value 8 -UndoValue $null `
        -Note "Logs all OpenProcess handles on lsass.exe to event ID 4656."
}

# ============================================================
# Section 4 — Credential Guard status check (read-only)
# ============================================================
# Credential Guard requires VBS+UEFI+TPM and must be configured via Group Policy or
# Intune. This section checks current status and reports. It does not attempt to enable
# it (configuration is too dependent on hardware/firmware context to be scripted reliably).

function Invoke-CredentialGuardCheck {
    Write-SectionHeader "Credential Guard Status (Check Only)"

    if ($Undo) {
        Write-Status "Credential Guard is hardware/firmware configured — skipping undo." -Type Skipped
        return
    }

    $cgPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $cgRunPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'

    $cgConfigured = Get-RegValue -Path $cgPath -Name 'EnableVirtualizationBasedSecurity'
    $cgRunning    = Get-RegValue -Path $cgRunPath -Name 'LsaCfgFlags'

    if ($cgRunning -ge 1) {
        Write-Status "Credential Guard appears ACTIVE (LsaCfgFlags=$cgRunning)." -Type AlreadySet
    } elseif ($cgConfigured -ge 1) {
        Write-Status "Credential Guard is CONFIGURED but may require reboot to activate (EnableVBS=$cgConfigured)." -Type Warning
    } else {
        Write-Status "Credential Guard does NOT appear to be configured." -Type Warning
        Write-Status "  ACTION REQUIRED: Enable via Group Policy:" -Type Warning
        Write-Status "    Computer Config > Admin Templates > System > Device Guard" -Type Warning
        Write-Status "    'Turn On Virtualization Based Security' = Enabled" -Type Warning
        Write-Status "    Credential Guard = 'Enabled with UEFI lock'" -Type Warning
        Write-Status "  Without Credential Guard, NTLM hashes recovered from an offline SAM parse" -Type Warning
        Write-Status "  can be used directly for pass-the-hash against network services." -Type Warning
    }
}

# ============================================================
# Section 5 — Attack Surface Reduction Rules
# ============================================================
# Three ASR rules directly mitigate the downstream phases of BlueHammer:
#
#  9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0  Block credential stealing from LSASS
#                                         (blocks OpenProcess(VM_READ) on lsass)
#
#  d1e49aac-8f56-4280-b9ba-993a6d77406c  Block process creations originating from
#                                         PSExec and WMI commands
#                                         (blocks BlueHammer phase 6 service creation)
#
#  be9ba2d9-53ea-4cdc-84e5-9b1eeee46550  Block Office apps from creating executable
#                                         content (general hygiene — included because
#                                         BlueHammer requires prior code execution,
#                                         and macro abuse is the most common vector)
#
# Mode: 1 = Block, 2 = Audit, 0 = Off
# Undo sets these back to 0 (Off). Organizations with existing ASR deployments should
# use Intune/MDE policy rather than this script to avoid conflicts.

$AsrRules = @(
    @{
        Guid    = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0'
        Name    = 'Block credential stealing from LSASS'
        Mode    = 1
        Why     = 'Blocks OpenProcess+ReadVirtualMemory on lsass.exe — limits phase 6 token theft'
    },
    @{
        Guid    = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        Name    = 'Block process creations from PSExec and WMI'
        Mode    = 1
        Why     = 'Blocks BlueHammer phase 6 CreateService/StartService SYSTEM-shell path'
    },
    @{
        Guid    = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        Name    = 'Block Office from creating executable content'
        Mode    = 1
        Why     = 'General hygiene — BlueHammer requires prior code execution; macro abuse is common initial access'
    }
)

function Invoke-ASRRules {
    Write-SectionHeader "Attack Surface Reduction (ASR) Rules"

    $asrRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'

    # Ensure defender MpEngine is running — ASR requires Windows Defender to be active
    $defenderRunning = $false
    try {
        $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
        $defenderRunning = ($svc -and $svc.Status -eq 'Running')
    } catch { }

    if (-not $defenderRunning) {
        Write-Status "Windows Defender service (WinDefend) is not running. ASR rules require an active Defender instance." -Type Warning
        Write-Status "Skipping ASR rule configuration. Verify Defender is enabled and re-run." -Type Skipped
        return
    }

    foreach ($rule in $AsrRules) {
        $guid    = $rule.Guid
        $name    = $rule.Name
        $mode    = $rule.Mode
        $why     = $rule.Why

        if ($Undo) {
            Set-RegDword -Control "ASR-$name" -Path $asrRegPath -Name $guid `
                -Value 0 -UndoValue $null
        } else {
            $current = Get-RegValue -Path $asrRegPath -Name $guid
            if ($current -eq $mode) {
                Write-Status "ASR [$name]: already mode=$mode." -Type AlreadySet
            } else {
                Set-RegDword -Control "ASR-$name" -Path $asrRegPath -Name $guid `
                    -Value $mode -UndoValue '0' -Note $why
            }
        }
    }

    if (-not $Undo) {
        Write-Status "ASR rules applied. Note: ASR enforcement requires MDE/Windows Defender to be in active mode." -Type Info
        Write-Status "Verify with: Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids" -Type Info
    }
}

# ============================================================
# Section 6 — Restrict LSASS access via Windows Defender
#              LSASS access protection (separate from RunAsPPL)
# ============================================================
# This registry key enables the Defender behavior-monitoring protection against
# credential-stealing tools. It complements RunAsPPL without requiring a reboot
# to take effect immediately (Defender applies it at scan-time).

function Invoke-DefenderLSASSProtection {
    Write-SectionHeader "Defender LSASS Access Protection"

    $defPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'

    if ($Undo) {
        Write-Status "Reverting Defender ASR EnableExploitProtection..." -Type Warning
        Set-RegDword -Control 'Defender-ASR-Enable' -Path $defPath -Name 'ExploitGuard_ASR_Rules' `
            -Value 0 -UndoValue '0'
        return
    }

    # ExploitGuard_ASR_Rules = 1 activates ASR rule processing globally (prerequisite for all rules above)
    Set-RegDword -Control 'Defender-ASR-Enable' -Path $defPath -Name 'ExploitGuard_ASR_Rules' `
        -Value 1 -UndoValue '0' `
        -Note 'Enables ASR rule enforcement globally (required for all ASR rules above)'
}

# ============================================================
# Section 7 — Cloud Files Filter Driver (CldFlt) restriction
# ============================================================
# CldFlt is the kernel-mode minifilter driver underlying the Cloud Files API.
# On systems that do not use OneDrive, iCloud, or corporate DLP tools that rely on
# Cloud Files, the service can be set to demand-start (3) rather than automatic (2).
# This does not prevent an attacker with admin rights from starting it, but it
# eliminates automatic load on boot and reduces the attack surface for privilege
# escalation via the minifilter interface.
#
# IMPORTANT: If OneDrive (or any sync client using cldapi.dll) is deployed on this
# endpoint, setting CldFlt to demand-start will break sync. Only apply this control
# on endpoints where Cloud Files sync is not used.
#
# The script checks for active sync providers before modifying the service start type.

function Invoke-CldFltHardening {
    Write-SectionHeader "Cloud Files Filter Driver (CldFlt) — Start-Type Restriction"

    $cldFltSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CldFlt'
    $syncRootMgrPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager'

    if ($Undo) {
        Write-Status "Reverting CldFlt start type to 2 (Automatic)..." -Type Warning
        Set-RegDword -Control 'CldFlt-StartType' -Path $cldFltSvcPath -Name 'Start' `
            -Value 2 -UndoValue '2'
        return
    }

    # Detect active sync root registrations (non-Windows providers)
    $activeSyncRoots = @()
    try {
        if (Test-Path $syncRootMgrPath) {
            $allRoots = Get-ChildItem -Path $syncRootMgrPath -ErrorAction SilentlyContinue
            foreach ($root in $allRoots) {
                $provName = Get-RegValue -Path $root.PSPath -Name 'DisplayNameResource'
                $id       = $root.PSChildName
                # Skip Microsoft built-in providers
                if ($id -notmatch '^Microsoft\.' -and $id -notmatch '^Windows\.') {
                    $activeSyncRoots += $id
                }
            }
        }
    } catch {
        Write-Status "Could not enumerate SyncRootManager — skipping auto-detect." -Type Warning
    }

    if ($activeSyncRoots.Count -gt 0) {
        Write-Status "Active non-Microsoft sync providers detected:" -Type Warning
        foreach ($r in $activeSyncRoots) {
            Write-Status "  $r" -Type Warning
        }
        Write-Status "CldFlt start-type change SKIPPED to avoid breaking active sync clients." -Type Skipped
        Write-Status "If these providers are authorized, this is expected. If unexpected, investigate." -Type Warning
        Write-Status "Manual check: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" -Type Info
        Add-ChangeRecord -Control 'CldFlt-StartType' -Target $cldFltSvcPath `
            -OldValue 'n/a' -NewValue 'skipped' -Note "Active sync providers found: $($activeSyncRoots -join ', ')"
        return
    }

    $current = Get-RegValue -Path $cldFltSvcPath -Name 'Start'
    if ($current -eq 3) {
        Write-Status "CldFlt already set to demand-start (3). No change." -Type AlreadySet
    } elseif ($null -eq $current) {
        Write-Status "CldFlt service registry key not found — driver may not be present on this SKU." -Type Skipped
    } else {
        Set-RegDword -Control 'CldFlt-StartType' -Path $cldFltSvcPath -Name 'Start' `
            -Value 3 -UndoValue "$current" `
            -Note "Changed from $current (auto) to 3 (demand-start). Reboot required to take effect."
        Write-Status "CldFlt set to demand-start (3). REBOOT REQUIRED." -Type Warning
        $Script:RebootRequired = $true
    }
}

# ============================================================
# Section 8 — Audit Policy: Object Access and Privilege Use
# ============================================================
# Enables the audit subcategories that surface BlueHammer's three observable primitives
# in the Security event log. These generate event IDs 4656 (handle request),
# 4663 (object access attempt), and 4673 (privilege use — SE_DEBUG, SE_TCB).
#
# Uses auditpol.exe rather than registry — the canonical tool for subcategory configuration.
# auditpol changes are immediate (no reboot required).

function Invoke-AuditPolicy {
    Write-SectionHeader "Audit Policy — Object Access and Privilege Use"

    $auditpol = "$env:SystemRoot\System32\auditpol.exe"

    if (-not (Test-Path $auditpol)) {
        Write-Status "auditpol.exe not found at expected path. Skipping audit policy configuration." -Type Skipped
        return
    }

    $auditSettings = @(
        @{ Category = 'Object Access';   SubCategory = 'File System';          Setting = 'Success,Failure' },
        @{ Category = 'Object Access';   SubCategory = 'Handle Manipulation';  Setting = 'Success,Failure' },
        @{ Category = 'Privilege Use';   SubCategory = 'Sensitive Privilege Use'; Setting = 'Success,Failure' },
        @{ Category = 'Detailed Tracking'; SubCategory = 'Process Creation';   Setting = 'Success' }
    )

    foreach ($entry in $auditSettings) {
        $cat  = $entry.Category
        $sub  = $entry.SubCategory
        $setting = $entry.Setting

        if ($Undo) {
            if ($Script:WhatIfActive) {
                Write-Status "WhatIf: would set audit '$sub' -> No Auditing" -Type Warning
                continue
            }
            & $auditpol /set /subcategory:"$sub" /success:disable /failure:disable 2>&1 | Out-Null
            Write-Status "Audit reverted: '$sub' -> No Auditing" -Type Changed
            continue
        }

        # Read current setting
        $currentOutput = & $auditpol /get /subcategory:"$sub" 2>&1
        $currentLine   = $currentOutput | Where-Object { $_ -match $sub } | Select-Object -First 1

        if ($Script:WhatIfActive) {
            Write-Status "WhatIf: would set audit '$sub' -> $setting | Current: $currentLine" -Type Warning
            continue
        }

        & $auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>&1 | Out-Null
        Write-Status "Audit set: '$sub' -> $setting" -Type Changed
        Add-ChangeRecord -Control 'AuditPolicy' -Target $sub -OldValue "$currentLine" -NewValue $setting
    }
}

# ============================================================
# Section 9 — Transacted File API Restriction Awareness Check
# ============================================================
# CreateFileTransactedW is deprecated and its use by non-installer processes is anomalous.
# Windows does not provide a policy control to disable KTM transactions globally without
# breaking legitimate installer scenarios. However, we can:
#   a) Verify that KB5021255 (or later cumulative for Win 11 22H2) is installed, which
#      addresses the specific TOCTOU window in the VSS snapshot path.
#   b) Report current KTM/TxF status for awareness.
# This section is read-only — it reports state and does not modify the system.

function Invoke-TransactedAPICheck {
    Write-SectionHeader "Transacted File API (KTM/TxF) — Advisory Check"

    if ($Undo) {
        Write-Status "Transacted API check is read-only — nothing to revert." -Type Skipped
        return
    }

    Write-Status "Checking Windows build for VSS TOCTOU patch status..." -Type Info

    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo) {
        $build = [int]$osInfo.BuildNumber
        Write-Status "OS Build: $build ($($osInfo.Caption))" -Type Info

        # KB5021255 applies to Windows 11 22H2 (build 22621). Build >= 22621.900 includes the fix.
        # For general guidance: any build from late December 2022 onward on 22H2 should have the patch.
        if ($build -ge 22621) {
            Write-Status "OS build is Windows 11 22H2 or later — VSS TOCTOU patch (KB5021255) may be present." -Type Info
            Write-Status "Verify: Get-HotFix -Id KB5021255" -Type Info
            try {
                $hotfix = Get-HotFix -Id 'KB5021255' -ErrorAction SilentlyContinue
                if ($hotfix) {
                    Write-Status "KB5021255 is INSTALLED (InstalledOn=$($hotfix.InstalledOn))." -Type AlreadySet
                } else {
                    Write-Status "KB5021255 not found. Ensure Windows Update is current." -Type Warning
                }
            } catch {
                Write-Status "Could not query hotfix status. Run 'Get-HotFix -Id KB5021255' manually." -Type Warning
            }
        } elseif ($build -lt 10240) {
            Write-Status "Cannot determine OS compatibility. Verify patch status manually." -Type Warning
        } else {
            Write-Status "OS build $build — verify that the latest cumulative update is installed." -Type Warning
            Write-Status "The VSS TOCTOU path used by BlueHammer phase 4 was addressed in Windows 11 22H2." -Type Warning
        }
    } else {
        Write-Status "Could not retrieve OS information via WMI." -Type Warning
    }

    Write-Status "" -Type Info
    Write-Status "Note: CreateFileTransactedW cannot be policy-disabled without breaking installer scenarios." -Type Info
    Write-Status "Detection via EDR telemetry is the primary mitigation for KTM/TxF abuse." -Type Info
    Write-Status "Alert on: any non-system, non-installer process calling CreateFileTransactedW." -Type Info
}

# ============================================================
# Section 10 — Local Account Security Reminder
# ============================================================
# BlueHammer's entire phase 5-6 payoff depends on local account credentials in the SAM.
# This section checks the local admin group membership and disabled state of the built-in
# Administrator account. It does not change passwords (unsafe to do in a hardening script),
# but it reports what needs attention.

function Invoke-LocalAccountReview {
    Write-SectionHeader "Local Account Security Review (Advisory)"

    if ($Undo) {
        Write-Status "Local account review is advisory — nothing to revert." -Type Skipped
        return
    }

    # Check built-in Administrator account (SID ending in -500)
    try {
        $adminAccount = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' } | Select-Object -First 1
        if ($adminAccount) {
            if ($adminAccount.Enabled) {
                Write-Status "Built-in Administrator account is ENABLED." -Type Warning
                Write-Status "  RECOMMENDATION: Disable if not required: Disable-LocalUser -Name 'Administrator'" -Type Warning
            } else {
                Write-Status "Built-in Administrator account is disabled." -Type AlreadySet
            }
        }
    } catch {
        Write-Status "Could not enumerate local users via Get-LocalUser. Try: net user" -Type Warning
    }

    # Enumerate members of the local Administrators group
    try {
        $adminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        Write-Status "Local Administrators group members:" -Type Info
        foreach ($m in $adminGroup) {
            Write-Status "  $($m.Name) [$($m.ObjectClass)] PrincipalSource=$($m.PrincipalSource)" -Type Info
        }
        if ($adminGroup.Count -gt 2) {
            Write-Status "More than 2 members in Administrators group — review for least-privilege compliance." -Type Warning
        }
    } catch {
        Write-Status "Could not enumerate Administrators group members. Try: net localgroup Administrators" -Type Warning
    }

    Write-Status "" -Type Info
    Write-Status "CREDENTIAL ROTATION REMINDER:" -Type Warning
    Write-Status "  If a BlueHammer-class test on this host returned exit code 101 (Unprotected)," -Type Warning
    Write-Status "  ALL local account passwords must be considered compromised and rotated immediately." -Type Warning
    Write-Status "  Include: all local users, service accounts with stored LSA secrets, cached domain creds." -Type Warning
    Write-Status "  Use LAPS if deployed: Reset-LapsPassword -ComputerName $($env:COMPUTERNAME)" -Type Warning
}

# ============================================================
# MAIN — orchestrate all sections
# ============================================================

$mode = if ($Undo) { 'UNDO (revert)' } else { 'APPLY (harden)' }
if ($Script:WhatIfActive) { $mode = "WHATIF ($mode)" }

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkCyan
Write-Host "  BlueHammer Technique-Class Hardening Script" -ForegroundColor Cyan
Write-Host "  MITRE T1211 / T1562.001  |  Mode: $mode" -ForegroundColor Cyan
Write-Host ("=" * 72) -ForegroundColor DarkCyan
Write-Host "  Techniques: Cloud Files API abuse, Batch-oplock scanner stall," -ForegroundColor DarkCyan
Write-Host "              VSS TOCTOU credential theft, Offline SAM parsing" -ForegroundColor DarkCyan
Write-Host ("=" * 72) -ForegroundColor DarkCyan

Invoke-TamperProtectionCheck
Invoke-LSARunAsPPL
Invoke-LsassAuditLevel
Invoke-CredentialGuardCheck
Invoke-DefenderLSASSProtection
Invoke-ASRRules
Invoke-CldFltHardening
Invoke-AuditPolicy
Invoke-TransactedAPICheck
Invoke-LocalAccountReview

# ============================================================
# Summary
# ============================================================

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkCyan
Write-Host "  Summary of Changes" -ForegroundColor Cyan
Write-Host ("=" * 72) -ForegroundColor DarkCyan

if ($Script:ChangeLog.Count -eq 0) {
    Write-Status "No changes made (all controls were already at target state, or WhatIf mode)." -Type Info
} else {
    $Script:ChangeLog | Format-Table -AutoSize -Property Timestamp, Control, OldValue, NewValue, Note
}

if ($Script:RebootRequired -and -not $SkipRebootCheck) {
    Write-Host ""
    Write-Status "REBOOT REQUIRED — The following controls will not take effect until the system is restarted:" -Type Warning
    Write-Status "  - LSA RunAsPPL (lsass.exe protection level change)" -Type Warning
    Write-Status "  - CldFlt start-type change (kernel driver load-on-boot behavior)" -Type Warning
}

Write-Host ""
Write-Status "Hardening script complete. Mode=$mode | Changes=$($Script:ChangeLog.Count)" -Type Success
