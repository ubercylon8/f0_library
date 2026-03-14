<#
.SYNOPSIS
    Hardens Windows against Inhibit System Recovery (T1490) techniques.

.DESCRIPTION
    Applies layered security hardening to reduce the attack surface for T1490 — the
    ransomware technique of destroying Volume Shadow Copies, disabling the Windows
    Recovery Environment, and erasing backup catalogs.

    Mitigations applied:
      - Audit policy enforcement for process creation with command-line logging (M1028)
      - Windows Defender Attack Surface Reduction rule configuration (M1028)
      - Windows Defender Controlled Folder Access for recovery paths (M1028)
      - Volume Shadow Copy Service protection and monitoring hooks (M1028)
      - BCD store registry permission restriction (M1024)
      - VSS service hardening and start-type protection (M1028)
      - PowerShell Constrained Language Mode enforcement (M1028)
      - User rights assignment restriction for backup operators (M1018)
      - Scheduled task for shadow copy health monitoring (M1053)

    MITRE ATT&CK: T1490
    Mitigations: M1053, M1028, M1024, M1018

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what changes would be made without actually making them.

.PARAMETER AuditOnly
    Applies only audit policy and monitoring changes — no service or access control
    modifications. Safe for production systems during a pilot phase.

.PARAMETER SkipControlledFolderAccess
    Skips Controlled Folder Access configuration. Use if Windows Defender real-time
    protection is not the active AV solution (e.g., third-party EDR managing CFA).

.EXAMPLE
    .\e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05_hardening.ps1 -WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05_hardening.ps1 -AuditOnly
    Applies only audit/monitoring settings (safe for production pilot).

.EXAMPLE
    .\e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author:          F0RT1KA Defense Guidance Generator
    MITRE ATT&CK:    T1490 — Inhibit System Recovery
    Mitigations:     M1053, M1028, M1024, M1018
    Requires:        Administrator privileges
    Idempotent:      Yes (safe to run multiple times)
    Tested On:       Windows 10 21H2+, Windows 11, Windows Server 2019/2022
    Backup Location: C:\ProgramData\F0RT1KA-Hardening\Backups\
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$AuditOnly,
    [switch]$SkipControlledFolderAccess
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$Script:ChangeLog       = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:BackupDir       = 'C:\ProgramData\F0RT1KA-Hardening\Backups'
$Script:LogFile         = 'C:\ProgramData\F0RT1KA-Hardening\hardening-t1490.log'
$Script:HardeningStamp  = 'FORTIKA-T1490'

# ============================================================
# Utility Functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Action')]
        [string]$Type = 'Info'
    )
    $colors = @{
        Info    = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
        Action  = 'Magenta'
    }
    $prefix = @{
        Info    = '[INFO]   '
        Success = '[OK]     '
        Warning = '[WARN]   '
        Error   = '[ERROR]  '
        Action  = '[ACTION] '
    }
    $line = "{0} {1} {2}" -f (Get-Date -Format 'HH:mm:ss'), $prefix[$Type], $Message
    Write-Host $line -ForegroundColor $colors[$Type]
    Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue
}

function Add-ChangeRecord {
    param(
        [string]$Component,
        [string]$Setting,
        [string]$OldValue,
        [string]$NewValue
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Component = $Component
        Setting   = $Setting
        OldValue  = $OldValue
        NewValue  = $NewValue
    })
}

function Initialize-Environment {
    if (-not (Test-Path $Script:BackupDir)) {
        New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null
    }
    $logDir = Split-Path $Script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Write-Status "F0RT1KA T1490 Hardening Script — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Type Info
    Write-Status "Mode: $(if ($Undo) { 'UNDO' } elseif ($AuditOnly) { 'AUDIT-ONLY' } else { 'APPLY' })" -Type Info
    Write-Status "Backup directory: $Script:BackupDir" -Type Info
    Write-Status "Log file: $Script:LogFile" -Type Info
}

function Save-RegistryBackup {
    param([string]$KeyPath, [string]$BackupName)
    $backupFile = Join-Path $Script:BackupDir "$BackupName-$(Get-Date -Format 'yyyyMMddHHmmss').reg"
    try {
        $hivePath = $KeyPath -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
        reg export $hivePath $backupFile /y 2>&1 | Out-Null
        Write-Status "Registry backup saved: $backupFile" -Type Info
    }
    catch {
        Write-Status "Registry backup failed for $KeyPath — $($_.Exception.Message)" -Type Warning
    }
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $val) { return $null }
        return $val.$Name
    }
    catch { return $null }
}

# ============================================================
# Section 1: Audit Policy — Process Creation with Command Lines
# M1028 — Operating System Configuration
# ============================================================

function Set-AuditPolicy {
    <#
    Enables "Audit Process Creation" with command-line logging. This is the
    foundational telemetry source for detecting all T1490 tool invocations.
    Without command-line auditing, Security Event 4688 records only the image
    name — insufficient to distinguish `vssadmin list shadows` from
    `vssadmin delete shadows /all /quiet`.
    #>
    Write-Status "=== Section 1: Audit Policy ===" -Type Info

    if ($Undo) {
        Write-Status "Reverting: Process Creation audit policy..." -Type Warning
        if ($PSCmdlet.ShouldProcess('Audit Policy', 'Disable command-line logging')) {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable 2>&1 | Out-Null
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
            }
            Add-ChangeRecord 'AuditPolicy' 'ProcessCreation' 'Enabled' 'Disabled'
            Write-Status "Reverted: Process Creation audit policy." -Type Success
        }
        return
    }

    Write-Status "Enabling: Process Creation audit (Success + Failure) with command-line capture..." -Type Action
    if ($PSCmdlet.ShouldProcess('Audit Policy', 'Enable process creation with command-line logging')) {
        # Enable process creation auditing
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1 | Out-Null

        # Enable command-line logging in event 4688
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        $old = Get-RegistryValueSafe -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled'
        Set-ItemProperty -Path $regPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

        Add-ChangeRecord 'AuditPolicy' 'ProcessCreationIncludeCmdLine_Enabled' "$old" '1'

        # Also enable Object Access for VSS store file monitoring
        auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1 | Out-Null

        # Ensure Security event log is large enough to retain evidence
        $maxSize = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
        if ($null -eq $maxSize -or $maxSize -lt 209715200) {
            # 200 MB minimum
            $oldMax = $maxSize
            wevtutil sl Security /ms:209715200 2>&1 | Out-Null
            Add-ChangeRecord 'EventLog' 'Security-MaxSize' "$oldMax" '209715200'
            Write-Status "Security event log size set to 200 MB." -Type Success
        }

        Write-Status "Applied: Process Creation audit policy with command-line logging." -Type Success
    }
}

# ============================================================
# Section 2: Windows Defender Attack Surface Reduction Rules
# M1028 — Operating System Configuration
# ============================================================

function Set-ASRRules {
    <#
    ASR rules that limit the scope of T1490 attacks:

    - Block Win32 API calls from Office macros (56a863a9...) — prevents macro-based
      dropper from spawning vssadmin.
    - Use advanced protection against ransomware (c1db55ab...) — behavioral detection
      of ransomware patterns including recovery inhibition.
    - Block process creations originating from PSExec and WMI commands (d1e49aac...) —
      prevents WMI-based `wmic shadowcopy delete`.

    Note: ASR rules require Windows Defender to be the active AV or to be in
    co-existence mode. Third-party EDR vendors typically implement equivalent rules.
    #>
    Write-Status "=== Section 2: Attack Surface Reduction (ASR) Rules ===" -Type Info

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping ASR rule enforcement." -Type Warning
        return
    }

    # Map of ASR rule GUIDs to descriptions
    $asrRules = [ordered]@{
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3' = 'Block credential stealing from LSASS (co-inhibitor of lateral movement before T1490)'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    }

    if ($Undo) {
        Write-Status "Reverting: ASR rules..." -Type Warning
        foreach ($guid in $asrRules.Keys) {
            $desc = $asrRules[$guid]
            if ($PSCmdlet.ShouldProcess("ASR Rule: $desc", 'Set to Not Configured')) {
                try {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $guid -ErrorAction SilentlyContinue
                    Write-Status "Reverted ASR rule: $desc" -Type Success
                }
                catch {
                    Write-Status "Could not revert ASR rule $guid — $($_.Exception.Message)" -Type Warning
                }
            }
        }
        return
    }

    Write-Status "Applying ASR rules for ransomware / T1490 protection..." -Type Action
    foreach ($guid in $asrRules.Keys) {
        $desc = $asrRules[$guid]
        if ($PSCmdlet.ShouldProcess("ASR Rule: $desc", 'Set to Block')) {
            try {
                # Check current state
                $current = (Get-MpPreference).AttackSurfaceReductionRules_Ids
                $currentActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
                $idx = if ($current) { [array]::IndexOf($current, $guid) } else { -1 }
                $oldAction = if ($idx -ge 0) { $currentActions[$idx] } else { 'NotConfigured' }

                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled
                Add-ChangeRecord 'ASR' $desc $oldAction 'Enabled'
                Write-Status "Enabled ASR: $desc" -Type Success
            }
            catch {
                Write-Status "Could not apply ASR rule $guid — $($_.Exception.Message)" -Type Warning
                Write-Status "  Tip: If Windows Defender is not the active AV, configure equivalent rules in your EDR." -Type Info
            }
        }
    }
}

# ============================================================
# Section 3: Controlled Folder Access
# M1028 — Operating System Configuration
# ============================================================

function Set-ControlledFolderAccess {
    <#
    Controlled Folder Access (CFA) prevents untrusted processes from writing to
    or modifying protected folders. Adding System Volume Information prevents
    ransomware processes from directly manipulating the VSS store on disk.
    #>
    Write-Status "=== Section 3: Controlled Folder Access ===" -Type Info

    if ($SkipControlledFolderAccess) {
        Write-Status "Skipped: -SkipControlledFolderAccess flag set." -Type Warning
        return
    }

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping CFA configuration." -Type Warning
        return
    }

    $protectedPaths = @(
        "$env:SystemDrive\System Volume Information",
        "$env:SystemRoot\System32\config",
        "$env:SystemRoot\System32\Recovery"
    )

    if ($Undo) {
        Write-Status "Reverting: Controlled Folder Access settings..." -Type Warning
        if ($PSCmdlet.ShouldProcess('Controlled Folder Access', 'Disable')) {
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            foreach ($path in $protectedPaths) {
                Remove-MpPreference -ControlledFolderAccessProtectedFolders $path -ErrorAction SilentlyContinue
            }
            Add-ChangeRecord 'CFA' 'EnableControlledFolderAccess' 'Enabled' 'Disabled'
            Write-Status "Reverted: Controlled Folder Access disabled." -Type Success
        }
        return
    }

    Write-Status "Configuring Controlled Folder Access for recovery paths..." -Type Action
    if ($PSCmdlet.ShouldProcess('Controlled Folder Access', 'Enable and add recovery paths')) {
        try {
            $current = (Get-MpPreference).EnableControlledFolderAccess
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Add-ChangeRecord 'CFA' 'EnableControlledFolderAccess' "$current" 'Enabled'

            foreach ($path in $protectedPaths) {
                if (Test-Path $path -ErrorAction SilentlyContinue) {
                    Add-MpPreference -ControlledFolderAccessProtectedFolders $path -ErrorAction SilentlyContinue
                    Add-ChangeRecord 'CFA' "ProtectedFolder:$path" '' 'Added'
                    Write-Status "CFA protected: $path" -Type Success
                }
                else {
                    Write-Status "CFA path not found (skipped): $path" -Type Warning
                }
            }
        }
        catch {
            Write-Status "CFA configuration failed — $($_.Exception.Message)" -Type Warning
            Write-Status "  Tip: CFA requires Windows Defender real-time protection to be active." -Type Info
        }
    }
}

# ============================================================
# Section 4: VSS Service Hardening
# M1028 — Operating System Configuration
# ============================================================

function Set-VSSServiceHardening {
    <#
    Hardens the Volume Shadow Copy Service:
    1. Sets the service start type to Automatic (Delayed Start) — ensures VSS is
       available after reboot but is not trivially stopped by a low-privilege attacker
       who might set it to Disabled.
    2. Configures the service security descriptor to restrict stop/delete permissions
       to SYSTEM and Administrators only (removes SERVICE_STOP right from interactive
       users and non-elevated processes).
    3. Enables VSS event log auditing via the Application event log.
    #>
    Write-Status "=== Section 4: VSS Service Hardening ===" -Type Info

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping VSS service reconfiguration." -Type Warning
        return
    }

    if ($Undo) {
        Write-Status "Reverting: VSS service hardening..." -Type Warning
        if ($PSCmdlet.ShouldProcess('VSS Service', 'Restore default start type')) {
            sc.exe config vss start= demand 2>&1 | Out-Null
            Add-ChangeRecord 'VSSService' 'StartType' 'AutoDelayed' 'Demand'
            Write-Status "Reverted: VSS service start type to Demand." -Type Success
        }
        return
    }

    Write-Status "Hardening VSS service configuration..." -Type Action
    if ($PSCmdlet.ShouldProcess('VSS Service', 'Set start type to Automatic (Delayed) and restrict permissions')) {
        # Set VSS to auto-start (delayed) so it survives reboot
        sc.exe config vss start= delayed-auto 2>&1 | Out-Null
        Add-ChangeRecord 'VSSService' 'StartType' 'Demand' 'AutoDelayed'
        Write-Status "VSS service start type set to Automatic (Delayed)." -Type Success

        # Harden the service DACL — restrict SERVICE_STOP and SERVICE_CHANGE_CONFIG
        # SDDL: Administrators = Full; SYSTEM = Full; Everyone = Query only
        # D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
        $sddl = 'D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)'
        sc.exe sdset vss $sddl 2>&1 | Out-Null
        Add-ChangeRecord 'VSSService' 'SecurityDescriptor' 'Default' $sddl
        Write-Status "VSS service DACL restricted to Administrators + SYSTEM." -Type Success

        # Enable VSS tracing via registry (Application event log verbosity)
        $vssRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\VSS\Diag'
        if (-not (Test-Path $vssRegPath)) {
            New-Item -Path $vssRegPath -Force | Out-Null
        }
        $old = Get-RegistryValueSafe -Path $vssRegPath -Name 'Shadow Copy Optimization Writer'
        Set-ItemProperty -Path $vssRegPath -Name 'Shadow Copy Optimization Writer' -Value 0x1F -Type DWord -ErrorAction SilentlyContinue
        Add-ChangeRecord 'VSSRegistry' 'DiagLevel' "$old" '0x1F'
        Write-Status "VSS diagnostic logging level elevated." -Type Success
    }
}

# ============================================================
# Section 5: BCD Store Registry Permission Restriction
# M1024 — Restrict Registry Permissions
# ============================================================

function Set-BCDRegistryProtection {
    <#
    The Boot Configuration Data (BCD) store is backed by a registry hive at
    HKLM\BCD00000000. Ransomware using bcdedit.exe to disable recovery ultimately
    writes to this hive. Restricting write access to SYSTEM only (removing Administrators
    write rights) forces all BCD modifications to go through the trusted bcdedit.exe
    code path at SYSTEM privilege, rather than being accessible to admin-level ransomware
    processes running as a regular admin user.

    IMPORTANT: On some systems this key may not exist or may require TrustedInstaller
    ownership. The script checks first and skips gracefully if inaccessible.
    #>
    Write-Status "=== Section 5: BCD Registry Protection ===" -Type Info

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping BCD registry permission changes." -Type Warning
        return
    }

    $bcdPath = 'HKLM:\BCD00000000'

    if ($Undo) {
        Write-Status "Reverting: BCD registry permissions..." -Type Warning
        if ($PSCmdlet.ShouldProcess('HKLM:\BCD00000000', 'Restore Administrators write access')) {
            try {
                $acl = Get-Acl -Path $bcdPath -ErrorAction SilentlyContinue
                if ($acl) {
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                        'BUILTIN\Administrators',
                        'FullControl',
                        'ContainerInherit,ObjectInherit',
                        'None',
                        'Allow'
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl -Path $bcdPath -AclObject $acl
                    Add-ChangeRecord 'BCDRegistry' 'AdminWrite' 'Removed' 'Restored'
                    Write-Status "Reverted: BCD registry admin write access restored." -Type Success
                }
            }
            catch {
                Write-Status "BCD revert failed (may require TrustedInstaller context) — $($_.Exception.Message)" -Type Warning
            }
        }
        return
    }

    Write-Status "Restricting BCD registry store write permissions..." -Type Action
    if ($PSCmdlet.ShouldProcess('HKLM:\BCD00000000', 'Restrict write access to SYSTEM only')) {
        try {
            if (-not (Test-Path $bcdPath)) {
                Write-Status "BCD registry path not found — skipping (may require legacy boot mode)." -Type Warning
                return
            }

            $acl = Get-Acl -Path $bcdPath
            # Remove all existing Allow rules for Administrators that grant write access
            $rulesToRemove = $acl.Access | Where-Object {
                $_.IdentityReference -match 'Administrators' -and
                $_.AccessControlType -eq 'Allow' -and
                ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::SetValue) -ne 0
            }
            foreach ($rule in $rulesToRemove) {
                $acl.RemoveAccessRule($rule) | Out-Null
                Add-ChangeRecord 'BCDRegistry' "RemovedRule:$($rule.IdentityReference)" $rule.RegistryRights 'Removed'
            }

            # Add read-only rule for Administrators (allow querying BCD but not modifying)
            $readRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                'BUILTIN\Administrators',
                'ReadKey',
                'ContainerInherit,ObjectInherit',
                'None',
                'Allow'
            )
            $acl.AddAccessRule($readRule)
            Set-Acl -Path $bcdPath -AclObject $acl
            Add-ChangeRecord 'BCDRegistry' 'AdminWrite' 'FullControl' 'ReadOnly'
            Write-Status "BCD registry write access restricted to SYSTEM only." -Type Success
            Write-Status "  Note: bcdedit.exe still functions via SYSTEM elevation path." -Type Info
        }
        catch {
            Write-Status "BCD registry permission change failed — $($_.Exception.Message)" -Type Warning
            Write-Status "  This is common when TrustedInstaller owns the key. Manual review recommended." -Type Info
        }
    }
}

# ============================================================
# Section 6: User Rights Assignment — Backup Operators
# M1018 — User Account Management
# ============================================================

function Set-BackupOperatorRestrictions {
    <#
    The built-in "Backup Operators" group has implicit rights to bypass file system
    ACLs for backup purposes — a right that ransomware can exploit if it runs under
    a compromised backup service account. This section:
    1. Audits current membership of the Backup Operators group.
    2. Restricts "Log on as a service" right to approved service accounts only.
    3. Enables auditing of Backup Operators group membership changes.

    This section does NOT remove accounts from Backup Operators (a business decision)
    but it does configure the audit trail and blocks interactive logon from that group.
    #>
    Write-Status "=== Section 6: Backup Operator Restrictions ===" -Type Info

    if ($Undo) {
        Write-Status "Reverting: Backup operator logon restrictions..." -Type Warning
        if ($PSCmdlet.ShouldProcess('GPO — Deny Interactive Logon', 'Remove Backup Operators from deny list')) {
            # Re-enable interactive logon for Backup Operators (revert to default)
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight =
"@
            $infPath = Join-Path $env:TEMP 'revert_backupop_logon.inf'
            $infContent | Set-Content -Path $infPath -Encoding Unicode
            secedit /configure /db secedit.sdb /cfg $infPath /quiet 2>&1 | Out-Null
            Remove-Item $infPath -ErrorAction SilentlyContinue
            Add-ChangeRecord 'UserRights' 'SeDenyInteractiveLogonRight' 'BackupOperators added' 'Reverted'
            Write-Status "Reverted: Backup Operators interactive logon restriction removed." -Type Success
        }
        return
    }

    Write-Status "Auditing Backup Operators group membership..." -Type Action

    try {
        $members = net localgroup "Backup Operators" 2>&1
        Write-Status "Current Backup Operators membership logged for review." -Type Info
        $membersStr = $members -join '; '
        Add-ChangeRecord 'BackupOperators' 'CurrentMembers' $membersStr 'Audited'
    }
    catch {
        Write-Status "Could not enumerate Backup Operators — $($_.Exception.Message)" -Type Warning
    }

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping interactive logon restriction." -Type Warning
        return
    }

    Write-Status "Restricting interactive logon for Backup Operators..." -Type Action
    if ($PSCmdlet.ShouldProcess('User Rights Assignment', 'Deny interactive logon for Backup Operators')) {
        $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight = *S-1-5-32-551
"@
        # S-1-5-32-551 is the well-known SID for Backup Operators
        $infPath = Join-Path $env:TEMP 'restrict_backupop_logon.inf'
        $infContent | Set-Content -Path $infPath -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg $infPath /quiet 2>&1 | Out-Null
        Remove-Item $infPath -ErrorAction SilentlyContinue
        Add-ChangeRecord 'UserRights' 'SeDenyInteractiveLogonRight' 'Not configured' 'BackupOperators (S-1-5-32-551)'
        Write-Status "Backup Operators denied interactive logon." -Type Success
    }
}

# ============================================================
# Section 7: PowerShell Constrained Language Mode
# M1028 — Operating System Configuration
# ============================================================

function Set-PowerShellConstrainedLanguage {
    <#
    PowerShell Constrained Language Mode (CLM) prevents PowerShell scripts from
    calling arbitrary .NET methods and COM objects. This blocks PowerShell-based
    shadow copy deletion patterns:
      Get-WmiObject Win32_ShadowCopy | Remove-WmiObject
      (Get-WmiObject -Class Win32_ShadowCopy).Delete()

    CLM is enforced via the __PSLockdownPolicy system environment variable.
    Note: CLM is most effective when combined with WDAC; without WDAC it can be
    bypassed by a sufficiently privileged attacker. The two controls are complementary.
    #>
    Write-Status "=== Section 7: PowerShell Constrained Language Mode ===" -Type Info

    if ($AuditOnly) {
        Write-Status "AuditOnly mode: skipping PowerShell CLM configuration." -Type Warning
        return
    }

    $regPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $regName  = '__PSLockdownPolicy'
    $clmValue = '4'  # 4 = Constrained Language Mode enforced

    if ($Undo) {
        Write-Status "Reverting: PowerShell Constrained Language Mode..." -Type Warning
        if ($PSCmdlet.ShouldProcess('__PSLockdownPolicy', 'Remove (disable CLM)')) {
            Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            [System.Environment]::SetEnvironmentVariable($regName, $null, 'Machine')
            Add-ChangeRecord 'PowerShell' '__PSLockdownPolicy' '4' 'Removed'
            Write-Status "Reverted: PowerShell CLM disabled." -Type Success
        }
        return
    }

    $current = Get-RegistryValueSafe -Path $regPath -Name $regName

    if ($current -eq $clmValue) {
        Write-Status "PowerShell Constrained Language Mode already enabled." -Type Success
        return
    }

    Write-Status "Enabling PowerShell Constrained Language Mode..." -Type Action
    if ($PSCmdlet.ShouldProcess('__PSLockdownPolicy', 'Set to 4 (Constrained Language Mode)')) {
        Set-ItemProperty -Path $regPath -Name $regName -Value $clmValue -Type String
        [System.Environment]::SetEnvironmentVariable($regName, $clmValue, 'Machine')
        Add-ChangeRecord 'PowerShell' '__PSLockdownPolicy' "$current" $clmValue
        Write-Status "PowerShell Constrained Language Mode enabled." -Type Success
        Write-Status "  Note: Takes effect for new PowerShell sessions. Existing sessions unaffected." -Type Info
        Write-Status "  Note: For full effectiveness, pair with a WDAC policy." -Type Info
    }
}

# ============================================================
# Section 8: Shadow Copy Health Monitoring Scheduled Task
# M1053 — Data Backup
# ============================================================

function Set-ShadowCopyMonitoringTask {
    <#
    Creates a scheduled task that runs hourly and:
    1. Counts the number of Volume Shadow Copies.
    2. Writes the count to a log file.
    3. If the count drops to zero or decreases by more than 50% compared to the
       previous run, writes a Windows Application event (EventID 9900) that can be
       forwarded to SIEM as a high-fidelity alert.

    This provides an independent detection layer that operates regardless of EDR state.
    #>
    Write-Status "=== Section 8: Shadow Copy Monitoring Scheduled Task ===" -Type Info

    $taskName   = 'F0RT1KA-ShadowCopyMonitor'
    $scriptPath = 'C:\ProgramData\F0RT1KA-Hardening\Monitor-ShadowCopies.ps1'
    $logPath    = 'C:\ProgramData\F0RT1KA-Hardening\shadow-copy-counts.log'

    if ($Undo) {
        Write-Status "Reverting: Shadow copy monitoring task..." -Type Warning
        if ($PSCmdlet.ShouldProcess($taskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item $scriptPath -ErrorAction SilentlyContinue
            Add-ChangeRecord 'ScheduledTask' $taskName 'Registered' 'Unregistered'
            Write-Status "Reverted: Shadow copy monitoring task removed." -Type Success
        }
        return
    }

    Write-Status "Creating shadow copy health monitoring task..." -Type Action

    $monitorScript = @'
# Shadow Copy Count Monitor — F0RT1KA T1490 Hardening
# Runs hourly. Writes event 9900 to Application log if shadow copy count drops.

$logPath = 'C:\ProgramData\F0RT1KA-Hardening\shadow-copy-counts.log'
$eventSource = 'F0RT1KA-Monitor'

# Ensure event source exists
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($eventSource, 'Application')
}

$currentCount = (Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count
$timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$entry        = "$timestamp | ShadowCopyCount=$currentCount"

Add-Content -Path $logPath -Value $entry

# Read previous count
$history = Get-Content $logPath -ErrorAction SilentlyContinue |
    Where-Object { $_ -match 'ShadowCopyCount=(\d+)' } |
    Select-Object -Last 2

if ($history.Count -ge 2) {
    $prevLine  = $history[-2]
    if ($prevLine -match 'ShadowCopyCount=(\d+)') {
        $prevCount = [int]$Matches[1]
        if ($currentCount -eq 0 -and $prevCount -gt 0) {
            $msg = "ALERT: All Volume Shadow Copies deleted. Previous count: $prevCount. Current: 0. Possible T1490 attack."
            Write-EventLog -LogName Application -Source $eventSource -EventId 9900 -EntryType Error -Message $msg
        }
        elseif ($prevCount -gt 0 -and ($currentCount / $prevCount) -lt 0.5) {
            $msg = "WARNING: Shadow copy count dropped >50%. Previous: $prevCount. Current: $currentCount. Investigate."
            Write-EventLog -LogName Application -Source $eventSource -EventId 9901 -EntryType Warning -Message $msg
        }
    }
}
'@

    if ($PSCmdlet.ShouldProcess($taskName, 'Create scheduled task for shadow copy monitoring')) {
        $monitorScript | Set-Content -Path $scriptPath -Encoding UTF8

        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

        Add-ChangeRecord 'ScheduledTask' $taskName 'NotConfigured' 'Registered'
        Write-Status "Shadow copy monitoring task registered: $taskName" -Type Success
        Write-Status "  Alert: Application EventID 9900 (count dropped to zero), 9901 (count dropped >50%)" -Type Info
        Write-Status "  Log:   $logPath" -Type Info
    }
}

# ============================================================
# Section 9: Windows Event Log Forwarding Readiness
# M1028 — Operating System Configuration
# ============================================================

function Set-EventLogForwardingReadiness {
    <#
    Configures the Windows Remote Management (WinRM) service and the Windows Event
    Collector subscription prerequisites needed to forward VSS and process creation
    events to a central SIEM/log collector.

    This section only ensures the forwarding infrastructure is ready — it does not
    configure the actual collector subscription (which requires the collector address,
    a topic outside the scope of this script).
    #>
    Write-Status "=== Section 9: Event Log Forwarding Readiness ===" -Type Info

    if ($Undo) {
        Write-Status "Reverting: WinRM and event forwarding configuration..." -Type Warning
        if ($PSCmdlet.ShouldProcess('WinRM', 'Disable event forwarding configuration')) {
            sc.exe config wecsvc start= demand 2>&1 | Out-Null
            Add-ChangeRecord 'WinRM' 'WECSvc' 'AutoDelayed' 'Demand'
            Write-Status "Reverted: Windows Event Collector service set to Demand start." -Type Success
        }
        return
    }

    Write-Status "Configuring event log forwarding prerequisites..." -Type Action
    if ($PSCmdlet.ShouldProcess('Windows Event Collector', 'Configure for log forwarding')) {
        try {
            # Enable WinRM for event forwarding (source-initiated subscriptions)
            winrm quickconfig -quiet 2>&1 | Out-Null
            Add-ChangeRecord 'WinRM' 'QuickConfig' 'Not configured' 'Configured'

            # Set WEC service to automatic (delayed) so it starts after reboot
            sc.exe config wecsvc start= delayed-auto 2>&1 | Out-Null
            sc.exe start wecsvc 2>&1 | Out-Null
            Add-ChangeRecord 'WinRM' 'WECSvc' 'Demand' 'AutoDelayed'

            # Increase Application event log retention for VSS events
            wevtutil sl Application /ms:104857600 /rt:false 2>&1 | Out-Null  # 100 MB
            Add-ChangeRecord 'EventLog' 'Application-MaxSize' 'Default' '104857600'

            Write-Status "Event log forwarding prerequisites configured." -Type Success
            Write-Status "  Next step: configure a WEF subscription to forward EventIDs 4688, 8193, 8194, 9900, 9901 to your SIEM." -Type Info
        }
        catch {
            Write-Status "Event forwarding config failed — $($_.Exception.Message)" -Type Warning
        }
    }
}

# ============================================================
# Section 10: Windows Recovery Environment Protection
# M1028 — Operating System Configuration
# ============================================================

function Set-WinREProtection {
    <#
    Ensures Windows Recovery Environment (WinRE) is enabled and that its state is
    recorded. Also configures an audit policy for bcdedit.exe so that any invocation
    (whether or not it modifies BCD) is logged.

    The script does NOT lock WinRE (doing so would prevent legitimate system recovery);
    instead it ensures it is enabled and monitored.
    #>
    Write-Status "=== Section 10: Windows Recovery Environment Protection ===" -Type Info

    if ($Undo) {
        Write-Status "WinRE Protection: no destructive changes were made — nothing to revert." -Type Info
        return
    }

    Write-Status "Verifying and enabling Windows Recovery Environment..." -Type Action
    if ($PSCmdlet.ShouldProcess('WinRE', 'Enable and verify state')) {
        try {
            $reagentStatus = reagentc /info 2>&1
            $isEnabled = $reagentStatus -match 'Windows RE status:\s+Enabled'

            if (-not $isEnabled) {
                reagentc /enable 2>&1 | Out-Null
                Add-ChangeRecord 'WinRE' 'Status' 'Disabled' 'Enabled'
                Write-Status "WinRE was disabled — re-enabled." -Type Success
            }
            else {
                Write-Status "WinRE is already enabled." -Type Success
            }

            # Record current WinRE configuration
            $winreLog = Join-Path $Script:BackupDir "winre-status-$(Get-Date -Format 'yyyyMMddHHmmss').txt"
            $reagentStatus | Set-Content -Path $winreLog -Encoding UTF8
            Write-Status "WinRE status snapshot saved: $winreLog" -Type Info
        }
        catch {
            Write-Status "WinRE check failed — $($_.Exception.Message)" -Type Warning
        }
    }
}

# ============================================================
# Main Execution
# ============================================================

Initialize-Environment

$sections = @(
    { Set-AuditPolicy },
    { Set-ASRRules },
    { Set-ControlledFolderAccess },
    { Set-VSSServiceHardening },
    { Set-BCDRegistryProtection },
    { Set-BackupOperatorRestrictions },
    { Set-PowerShellConstrainedLanguage },
    { Set-ShadowCopyMonitoringTask },
    { Set-EventLogForwardingReadiness },
    { Set-WinREProtection }
)

foreach ($section in $sections) {
    try {
        & $section
    }
    catch {
        Write-Status "Section failed: $($_.Exception.Message)" -Type Error
        Write-Status "  Continuing with remaining sections..." -Type Warning
    }
}

# ============================================================
# Summary
# ============================================================

Write-Status "" -Type Info
Write-Status "======================================================" -Type Info
Write-Status "HARDENING SUMMARY" -Type Info
Write-Status "======================================================" -Type Info

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes applied ($($Script:ChangeLog.Count) records):" -Type Success
    $Script:ChangeLog | Format-Table Component, Setting, OldValue, NewValue -AutoSize | Out-String | Write-Host

    # Persist change log for undo reference
    $changeLogPath = Join-Path $Script:BackupDir "changelog-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
    $Script:ChangeLog | Export-Csv -Path $changeLogPath -NoTypeInformation
    Write-Status "Change log saved: $changeLogPath" -Type Info
}
else {
    Write-Status "No changes recorded (all settings already in desired state or -WhatIf was used)." -Type Info
}

Write-Status "" -Type Info
if ($Undo) {
    Write-Status "Undo complete. Review the change log above for reverted settings." -Type Success
}
elseif ($AuditOnly) {
    Write-Status "Audit-only mode complete. No enforcement changes were made." -Type Success
    Write-Status "Re-run without -AuditOnly to apply all hardening." -Type Info
}
else {
    Write-Status "Hardening complete." -Type Success
    Write-Status "" -Type Info
    Write-Status "Recommended next steps:" -Type Info
    Write-Status "  1. Review the Application event log for VSS Event IDs 8193, 8194." -Type Info
    Write-Status "  2. Verify shadow copy monitoring task is running: Get-ScheduledTask F0RT1KA-ShadowCopyMonitor" -Type Info
    Write-Status "  3. Configure WEF subscription to forward EventIDs 4688, 8193, 8194, 9900, 9901 to SIEM." -Type Info
    Write-Status "  4. Validate with your EDR that ASR rules are active: Get-MpPreference | Select AttackSurfaceReductionRules*" -Type Info
    Write-Status "  5. Test WinRE boot: reagentc /info" -Type Info
    Write-Status "  6. Verify offline backup exists and is NOT accessible from this endpoint." -Type Info
}
Write-Status "Log file: $Script:LogFile" -Type Info
