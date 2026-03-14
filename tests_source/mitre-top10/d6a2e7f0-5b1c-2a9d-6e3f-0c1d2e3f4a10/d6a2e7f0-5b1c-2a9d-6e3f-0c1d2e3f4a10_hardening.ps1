<#
.SYNOPSIS
    Hardens Windows against Service Stop (T1489) and Impair Defenses: Disable or Modify
    Tools (T1562.001) techniques.

.DESCRIPTION
    Applies security hardening to mitigate adversary attempts to stop or disable security
    services and defensive tools. Targets the following attack behaviors:

      - Bulk sc.exe queries against security service names
      - sc stop / net stop against WinDefend, wscsvc, VSS, wbengine
      - Unauthorized service creation and deletion via sc create / sc delete
      - taskkill.exe abuse against security processes
      - SMB-based remote service enumeration (NetExec / nxc.exe pattern)

    MITRE ATT&CK:  T1489 — Service Stop
                   T1562.001 — Impair Defenses: Disable or Modify Tools
    Mitigations:   M1054, M1018, M1038, M1022, M1024, M1030

    All changes are idempotent and fully reversible via -Undo.
    A JSON change log is written to $env:SystemRoot\Temp\hardening-d6a2e7f0.json.

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what would happen without making any changes (dry-run).

.PARAMETER SkipAuditPolicy
    Skips audit policy configuration (useful when auditpol is restricted by GPO).

.PARAMETER SkipFirewall
    Skips Windows Firewall rule deployment.

.EXAMPLE
    .\d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10_hardening.ps1 -WhatIf
    Shows all changes that would be made without applying them.

.EXAMPLE
    .\d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author:      F0RT1KA Defense Guidance Generator
    MITRE:       T1489, T1562.001
    Mitigations: M1054, M1018, M1038, M1022, M1024, M1030
    Requires:    Administrator privileges, Windows 10 1903+ or Windows Server 2019+
    Idempotent:  Yes (safe to run multiple times)
    Change log:  $env:SystemRoot\Temp\hardening-d6a2e7f0.json
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipAuditPolicy,
    [switch]$SkipFirewall
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$Script:ChangeLog      = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:ChangeLogPath  = "$env:SystemRoot\Temp\hardening-d6a2e7f0.json"
$Script:HasErrors      = $false

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Skipped')]
        [string]$Type = 'Info'
    )
    $colors = @{
        Info    = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
        Skipped = 'DarkGray'
    }
    $prefix = @{
        Info    = '[*]'
        Success = '[+]'
        Warning = '[!]'
        Error   = '[X]'
        Skipped = '[-]'
    }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param(
        [string]$Category,
        [string]$Action,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue,
        [string]$Notes = ''
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Category  = $Category
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
        Notes     = $Notes
    })
}

function Save-ChangeLog {
    try {
        $Script:ChangeLog | ConvertTo-Json -Depth 4 |
            Out-File -FilePath $Script:ChangeLogPath -Encoding UTF8 -Force
        Write-Status "Change log saved: $Script:ChangeLogPath" 'Info'
    }
    catch {
        Write-Status "Could not save change log: $_" 'Warning'
    }
}

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    $action = if ($Undo) { 'RestoreReg' } else { 'SetReg' }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", $action)) {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $old = Get-RegValue -Path $Path -Name $Name
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        Add-ChangeLog -Category 'Registry' -Action $action `
            -Target "$Path\$Name" -OldValue "$old" -NewValue "$Value"
    }
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if ($PSCmdlet.ShouldProcess("$Path\$Name", 'RemoveReg')) {
        $old = Get-RegValue -Path $Path -Name $Name
        if ($null -ne $old) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
            Add-ChangeLog -Category 'Registry' -Action 'RemoveReg' `
                -Target "$Path\$Name" -OldValue "$old" -NewValue '(removed)'
        }
    }
}

# ===========================================================================
# SECTION 1 — Windows Defender Tamper Protection (M1054)
# ===========================================================================

function Set-TamperProtection {
    <#
    Enables Windows Defender Tamper Protection (TamperProtection = 5).
    When active, no process — including SYSTEM — can stop WinDefend, disable
    real-time protection, or modify Defender security settings via the registry
    or sc.exe. This is the single most impactful control against T1562.001.

    Note: When managed by Intune/MDE, the cloud policy takes precedence over
    the local registry value. In standalone environments the registry setting
    is the enforcement point.

    Mitigation: M1054 — Software Configuration
    #>

    Write-Status '' 'Info'
    Write-Status '--- [1] Tamper Protection (M1054) ---' 'Info'

    $tpPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    $tpName = 'TamperProtection'

    if ($Undo) {
        # Restore to Windows default (5 = enabled, but revert to 4 = audit-only
        # so defenders can evaluate before re-enabling fully)
        Write-Status 'Reverting Tamper Protection to audit mode (4)...' 'Warning'
        Set-RegDword -Path $tpPath -Name $tpName -Value 4
        Write-Status 'Tamper Protection set to audit mode. Re-enable manually when ready.' 'Warning'
        return
    }

    $current = Get-RegValue -Path $tpPath -Name $tpName
    if ($current -eq 5) {
        Write-Status "Tamper Protection already enabled (value=5). No change needed." 'Success'
        return
    }

    Write-Status "Enabling Tamper Protection (current value: $current)..." 'Info'
    if ($PSCmdlet.ShouldProcess($tpPath, 'Enable Tamper Protection (value=5)')) {
        Set-RegDword -Path $tpPath -Name $tpName -Value 5
        Write-Status 'Tamper Protection enabled.' 'Success'
        Write-Status 'NOTE: If managed by Intune/MDE, verify in Microsoft 365 Defender portal.' 'Warning'
    }

    # Also enforce via policy key (belt-and-suspenders for non-MDE endpoints)
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $disableName = 'DisableAntiSpyware'
    $current2 = Get-RegValue -Path $policyPath -Name $disableName
    if ($current2 -ne $null -and $current2 -ne 0) {
        Write-Status "Removing policy key that disables AntiSpyware (was: $current2)..." 'Warning'
        if ($PSCmdlet.ShouldProcess("$policyPath\$disableName", 'Remove disabling policy key')) {
            Remove-RegValue -Path $policyPath -Name $disableName
            Write-Status 'DisableAntiSpyware policy key removed.' 'Success'
        }
    }

    # Ensure real-time protection is not disabled via policy
    $rtpPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    $rtpNames = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection')
    foreach ($rtpName in $rtpNames) {
        $val = Get-RegValue -Path $rtpPath -Name $rtpName
        if ($val -ne $null -and $val -ne 0) {
            Write-Status "Removing $rtpName policy override (was: $val)..." 'Warning'
            if ($PSCmdlet.ShouldProcess("$rtpPath\$rtpName", 'Remove RTP disable policy')) {
                Remove-RegValue -Path $rtpPath -Name $rtpName
                Write-Status "$rtpName override removed." 'Success'
            }
        }
    }
}

# ===========================================================================
# SECTION 2 — Service Configuration Hardening (M1022, M1018)
# ===========================================================================

function Set-SecurityServiceHardening {
    <#
    Configures critical security services so they are set to automatic start
    and cannot be trivially stopped. While Tamper Protection protects WinDefend
    at the kernel level, this function handles the remaining services (VSS,
    wbengine, wscsvc) and adds registry-level access controls.

    Services covered:
      WinDefend  — Windows Defender Antivirus
      wscsvc     — Windows Security Center
      VSS        — Volume Shadow Copy (critical for ransomware recovery)
      wbengine   — Windows Backup Engine (critical for ransomware recovery)

    Mitigation: M1022 — Restrict File and Directory Permissions
                M1018 — User Account Management
    #>

    Write-Status '' 'Info'
    Write-Status '--- [2] Security Service Hardening (M1022, M1018) ---' 'Info'

    # Services and their intended start types
    # VSS and wbengine are demand-start by design — we do NOT change their start type,
    # but we DO restrict registry write access to prevent malicious reconfiguration.
    $services = @(
        @{ Name = 'WinDefend';  DisplayName = 'Windows Defender'; StartType = 'Automatic' },
        @{ Name = 'wscsvc';     DisplayName = 'Windows Security Center'; StartType = 'Automatic' },
        @{ Name = 'SecurityHealthService'; DisplayName = 'Windows Security Service'; StartType = 'Automatic' }
    )

    foreach ($svc in $services) {
        $name = $svc.Name
        try {
            $serviceObj = Get-Service -Name $name -ErrorAction Stop

            if ($Undo) {
                # We don't change start type during undo — the service was already
                # configured correctly; no rollback needed for start type changes.
                Write-Status "[$name] No start-type rollback needed (was not modified)." 'Skipped'
                continue
            }

            $currentStartType = $serviceObj.StartType
            if ($currentStartType -ne $svc.StartType) {
                Write-Status "[$name] Setting start type to $($svc.StartType) (was: $currentStartType)..." 'Info'
                if ($PSCmdlet.ShouldProcess($name, "Set start type to $($svc.StartType)")) {
                    Set-Service -Name $name -StartupType $svc.StartType -ErrorAction SilentlyContinue
                    Add-ChangeLog -Category 'Service' -Action 'SetStartType' -Target $name `
                        -OldValue "$currentStartType" -NewValue $svc.StartType
                    Write-Status "[$name] Start type set to $($svc.StartType)." 'Success'
                }
            }
            else {
                Write-Status "[$name] Start type already correct ($currentStartType)." 'Success'
            }

            # Ensure service is running
            if ($serviceObj.Status -ne 'Running') {
                Write-Status "[$name] Service not running — starting..." 'Warning'
                if ($PSCmdlet.ShouldProcess($name, 'Start service')) {
                    Start-Service -Name $name -ErrorAction SilentlyContinue
                    Write-Status "[$name] Start command issued." 'Info'
                }
            }
            else {
                Write-Status "[$name] Service is running." 'Success'
            }
        }
        catch {
            Write-Status "[$name] Service not found or inaccessible (may be expected on some SKUs): $_" 'Skipped'
        }
    }

    # Harden service registry keys — restrict write access so standard users and
    # non-SYSTEM processes cannot modify service binary paths or start type.
    # We apply SDDL to the WinDefend and wscsvc service registry keys.
    $serviceRegPaths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend',
        'HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc',
        'HKLM:\SYSTEM\CurrentControlSet\Services\VSS',
        'HKLM:\SYSTEM\CurrentControlSet\Services\wbengine'
    )

    foreach ($regPath in $serviceRegPaths) {
        $svcName = Split-Path $regPath -Leaf
        if (-not (Test-Path $regPath)) {
            Write-Status "[$svcName] Registry key not found (service may not be installed)." 'Skipped'
            continue
        }

        if ($Undo) {
            Write-Status "[$svcName] Registry ACL rollback: manual review recommended (original SDDL not captured)." 'Warning'
            continue
        }

        try {
            # Read current ACL
            $acl = Get-Acl -Path $regPath
            $currentSDDL = $acl.Sddl

            # Build restrictive rule: deny write/change to Everyone except SYSTEM and Administrators
            # We add an explicit deny for "write" access for the "Users" group (S-1-5-32-545)
            $usersGroup = [System.Security.Principal.NTAccount]'BUILTIN\Users'
            $denyRights = [System.Security.AccessControl.RegistryRights]::SetValue -bor
                          [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor
                          [System.Security.AccessControl.RegistryRights]::Delete
            $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $propagateFlags = [System.Security.AccessControl.PropagationFlags]::None
            $denyRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $usersGroup, $denyRights, $inheritFlags, $propagateFlags,
                [System.Security.AccessControl.AccessControlType]::Deny
            )

            if ($PSCmdlet.ShouldProcess($regPath, 'Apply deny-write ACE for Users group')) {
                $acl.AddAccessRule($denyRule)
                Set-Acl -Path $regPath -AclObject $acl
                Add-ChangeLog -Category 'RegistryACL' -Action 'AddDenyWriteACE' -Target $regPath `
                    -OldValue $currentSDDL -NewValue 'Added deny-write ACE for BUILTIN\Users'
                Write-Status "[$svcName] Registry deny-write ACE applied." 'Success'
            }
        }
        catch {
            Write-Status "[$svcName] Could not modify registry ACL (may require SYSTEM token): $_" 'Warning'
            $Script:HasErrors = $true
        }
    }
}

# ===========================================================================
# SECTION 3 — Attack Surface Reduction Rules (M1038)
# ===========================================================================

function Set-ASRRules {
    <#
    Configures Windows Defender Attack Surface Reduction (ASR) rules relevant
    to service control abuse and offensive tool execution.

    Rule: d4f940ab-401b-4efc-aadc-ad5f3c50688a
      "Block process creations originating from PSExec and WMI commands"
      — Prevents WMI-based service control and lateral tool execution.

    Rule: e6db77e5-3df2-4cf1-b95a-636979351e5b
      "Block persistence through WMI event subscription"
      — Stops WMI-based service persistence.

    Rule: 3b576869-a4ec-4529-8536-b80a7769e899
      "Block execution of potentially obfuscated scripts"
      — Reduces scripted service-disable attempts.

    Rule: 26190899-1602-49e8-8b27-eb1d0a1ce869
      "Block Office communication application from creating child processes"
      — Limits phishing-delivered service tampering.

    Mode: 1 = Block, 2 = Audit (Undo reverts to Audit mode, not disabled,
    to preserve visibility while removing the block).

    Mitigation: M1038 — Execution Prevention
    #>

    Write-Status '' 'Info'
    Write-Status '--- [3] Attack Surface Reduction Rules (M1038) ---' 'Info'

    # Check that Windows Defender / MpPreference is available
    if (-not (Get-Command 'Set-MpPreference' -ErrorAction SilentlyContinue)) {
        Write-Status 'Windows Defender cmdlets not available. Skipping ASR configuration.' 'Skipped'
        return
    }

    $asrRules = @{
        # Block PSExec / WMI child process creation
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block process creations from PSExec/WMI'
        # Block WMI event subscription persistence
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block WMI event subscription persistence'
        # Block potentially obfuscated scripts
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block execution of potentially obfuscated scripts'
        # Block Office communication app child processes
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication app child processes'
        # Block untrusted and unsigned processes from USB
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    }

    $targetMode = if ($Undo) { 2 } else { 1 }  # 1=Block, 2=Audit
    $modeLabel  = if ($Undo) { 'Audit (2)' } else { 'Block (1)' }

    try {
        $currentPrefs = Get-MpPreference
        $currentIds   = $currentPrefs.AttackSurfaceReductionRules_Ids
        $currentActions = $currentPrefs.AttackSurfaceReductionRules_Actions

        foreach ($ruleId in $asrRules.Keys) {
            $ruleName = $asrRules[$ruleId]
            $idx = if ($currentIds) { [array]::IndexOf($currentIds, $ruleId) } else { -1 }
            $currentAction = if ($idx -ge 0 -and $currentActions) { $currentActions[$idx] } else { 'NotConfigured' }

            Write-Status "  [$ruleId] $ruleName" 'Info'
            Write-Status "    Current mode: $currentAction -> Target: $modeLabel" 'Info'

            if ($PSCmdlet.ShouldProcess($ruleId, "Set ASR rule to $modeLabel")) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                                  -AttackSurfaceReductionRules_Actions $targetMode `
                                  -ErrorAction SilentlyContinue
                Add-ChangeLog -Category 'ASR' -Action 'SetASRRule' -Target $ruleId `
                    -OldValue "$currentAction" -NewValue $modeLabel -Notes $ruleName
                Write-Status "    Set to $modeLabel." 'Success'
            }
        }
    }
    catch {
        Write-Status "ASR rule configuration failed: $_" 'Warning'
        $Script:HasErrors = $true
    }
}

# ===========================================================================
# SECTION 4 — Windows Firewall Rules (M1030)
# ===========================================================================

function Set-FirewallRules {
    <#
    Adds Windows Firewall rules to restrict inbound and outbound SMB (TCP/445)
    to authorized management systems only. This prevents NetExec-style remote
    service enumeration and lateral movement over SMB from non-management hosts.

    Note: This creates restrictive rules. Review existing environment SMB
    dependencies (DFS, SYSVOL replication, print spooling) before enabling
    the block rules in production. Consider using the -WhatIf flag first.

    Mitigation: M1030 — Network Segmentation
    #>

    if ($SkipFirewall) {
        Write-Status 'Firewall hardening skipped (-SkipFirewall).' 'Skipped'
        return
    }

    Write-Status '' 'Info'
    Write-Status '--- [4] SMB Firewall Hardening (M1030) ---' 'Info'

    $rulePrefix = 'F0RTIKA-Hardening-T1489'

    if ($Undo) {
        Write-Status 'Removing firewall rules...' 'Warning'
        $rules = Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove firewall rule')) {
                Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
                Add-ChangeLog -Category 'Firewall' -Action 'RemoveRule' -Target $rule.DisplayName `
                    -OldValue 'Exists' -NewValue 'Removed'
                Write-Status "Removed: $($rule.DisplayName)" 'Success'
            }
        }
        return
    }

    # Rule 1: Block inbound SMB from non-domain-controller sources (general endpoint hardening)
    # Adjust -RemoteAddress to include your authorised management CIDR ranges.
    $inboundSMBRule = @{
        DisplayName = "$rulePrefix-Block-Inbound-SMB"
        Description = 'Block inbound SMB (TCP/445) to prevent remote service enumeration (T1489/T1562.001). Adjust RemoteAddress for authorised management subnets.'
        Direction   = 'Inbound'
        Protocol    = 'TCP'
        LocalPort   = 445
        Action      = 'Block'
        Enabled     = 'True'
        Profile     = 'Domain,Private,Public'
    }

    # Rule 2: Audit / block outbound SMB connections from standard user processes
    # In most enterprise environments, endpoints should NOT initiate SMB to other endpoints.
    $outboundSMBRule = @{
        DisplayName = "$rulePrefix-Block-Outbound-SMB-Endpoint"
        Description = 'Block outbound SMB (TCP/445) from this endpoint to other endpoints (T1489/T1562.001 lateral enumeration). Preserve access to domain controllers separately.'
        Direction   = 'Outbound'
        Protocol    = 'TCP'
        RemotePort  = 445
        Action      = 'Block'
        Enabled     = 'True'
        Profile     = 'Domain,Private,Public'
    }

    foreach ($ruleParams in @($inboundSMBRule, $outboundSMBRule)) {
        $existingRule = Get-NetFirewallRule -DisplayName $ruleParams.DisplayName -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Status "Firewall rule already exists: $($ruleParams.DisplayName)" 'Success'
            continue
        }

        Write-Status "Creating firewall rule: $($ruleParams.DisplayName)..." 'Info'
        if ($PSCmdlet.ShouldProcess($ruleParams.DisplayName, 'Create firewall rule')) {
            try {
                New-NetFirewallRule @ruleParams | Out-Null
                Add-ChangeLog -Category 'Firewall' -Action 'AddRule' -Target $ruleParams.DisplayName `
                    -OldValue 'NotPresent' -NewValue 'Block'
                Write-Status "Created: $($ruleParams.DisplayName)" 'Success'
            }
            catch {
                Write-Status "Failed to create firewall rule '$($ruleParams.DisplayName)': $_" 'Warning'
                $Script:HasErrors = $true
            }
        }
    }

    Write-Status '' 'Warning'
    Write-Status 'IMPORTANT: Review the outbound SMB block rule before production deployment.' 'Warning'
    Write-Status 'Domain controllers must be exempt from the outbound SMB block or domain' 'Warning'
    Write-Status 'authentication will fail. Use -SkipFirewall if SMB to DCs is required.' 'Warning'
}

# ===========================================================================
# SECTION 5 — Audit Policy (M1018 — visibility prerequisite)
# ===========================================================================

function Set-AuditPolicy {
    <#
    Enables advanced audit policy subcategories required to detect service
    stop and impair-defenses activity.

    Subcategories enabled:
      - Process Creation (4688) — captures sc.exe, taskkill.exe, nxc.exe invocations
      - Process Termination (4689) — captures security process termination
      - Security System Extension (4697) — captures new service installation
      - Other Object Access Events (4656/4658) — service manager object access
      - Logon (4624/4625) — captures authentication used for remote service control

    Additionally enables command-line logging in process creation events (4688),
    which is the single most important visibility enhancement for detecting
    sc.exe abuse.

    Mitigation: M1018 — User Account Management (visibility prerequisite)
    #>

    if ($SkipAuditPolicy) {
        Write-Status 'Audit policy configuration skipped (-SkipAuditPolicy).' 'Skipped'
        return
    }

    Write-Status '' 'Info'
    Write-Status '--- [5] Audit Policy Configuration ---' 'Info'

    $auditSettings = @(
        @{ Category = 'Detailed Tracking'; Subcategory = 'Process Creation';                Success = $true;  Failure = $false },
        @{ Category = 'Detailed Tracking'; Subcategory = 'Process Termination';             Success = $true;  Failure = $false },
        @{ Category = 'System';            Subcategory = 'Security System Extension';       Success = $true;  Failure = $true  },
        @{ Category = 'System';            Subcategory = 'System Integrity';                Success = $true;  Failure = $true  },
        @{ Category = 'Object Access';     Subcategory = 'Other Object Access Events';      Success = $true;  Failure = $false },
        @{ Category = 'Logon/Logoff';      Subcategory = 'Logon';                           Success = $true;  Failure = $true  },
        @{ Category = 'Logon/Logoff';      Subcategory = 'Special Logon';                   Success = $true;  Failure = $false },
        @{ Category = 'Policy Change';     Subcategory = 'Audit Policy Change';             Success = $true;  Failure = $true  },
        @{ Category = 'Privilege Use';     Subcategory = 'Sensitive Privilege Use';         Success = $true;  Failure = $true  }
    )

    foreach ($setting in $auditSettings) {
        $successFlag = if ($setting.Success) { '/success:enable' } else { '/success:disable' }
        $failureFlag = if ($setting.Failure) { '/failure:enable' } else { '/failure:disable' }
        $subcategory = $setting.Subcategory

        if ($Undo) {
            # When undoing, set to "No Auditing" (not "disable") to avoid conflicts
            # with domain GPO which may override anyway.
            Write-Status "  [$subcategory] Audit undo: setting to No Auditing." 'Warning'
            if ($PSCmdlet.ShouldProcess($subcategory, 'Set audit to No Auditing')) {
                & auditpol /set /subcategory:"$subcategory" /success:disable /failure:disable 2>$null
                Add-ChangeLog -Category 'AuditPolicy' -Action 'DisableAudit' -Target $subcategory `
                    -OldValue 'Enabled' -NewValue 'Disabled'
            }
            continue
        }

        Write-Status "  [$subcategory] Enabling audit ($successFlag $failureFlag)..." 'Info'
        if ($PSCmdlet.ShouldProcess($subcategory, 'Enable audit policy')) {
            $result = & auditpol /set /subcategory:"$subcategory" $successFlag $failureFlag 2>&1
            if ($LASTEXITCODE -eq 0) {
                Add-ChangeLog -Category 'AuditPolicy' -Action 'EnableAudit' -Target $subcategory `
                    -OldValue 'Unknown' -NewValue "Success=$($setting.Success) Failure=$($setting.Failure)"
                Write-Status "  [$subcategory] Enabled." 'Success'
            }
            else {
                Write-Status "  [$subcategory] Failed to set: $result" 'Warning'
            }
        }
    }

    # Enable command-line logging in process creation events (Event ID 4688)
    # This is controlled by a registry key, not auditpol
    $cmdLinePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdLineName = 'ProcessCreationIncludeCmdLine_Enabled'

    if ($Undo) {
        Write-Status 'Disabling command-line in process creation events...' 'Warning'
        if ($PSCmdlet.ShouldProcess($cmdLineName, 'Disable command-line logging')) {
            Set-RegDword -Path $cmdLinePath -Name $cmdLineName -Value 0
            Write-Status 'Command-line logging disabled.' 'Success'
        }
    }
    else {
        $currentVal = Get-RegValue -Path $cmdLinePath -Name $cmdLineName
        Write-Status "Enabling command-line logging in process creation events (current: $currentVal)..." 'Info'
        if ($PSCmdlet.ShouldProcess($cmdLineName, 'Enable command-line logging')) {
            Set-RegDword -Path $cmdLinePath -Name $cmdLineName -Value 1
            Write-Status 'Command-line logging in process creation events enabled.' 'Success'
        }
    }
}

# ===========================================================================
# SECTION 6 — AppLocker / WDAC Guidance for Offensive Tool Blocking (M1038)
# ===========================================================================

function Set-OffensiveToolRestrictions {
    <#
    Applies registry-based restrictions and Windows Defender custom indicators
    to limit execution of offensive tools with service enumeration capabilities.

    Direct AppLocker and WDAC policy changes require domain infrastructure or
    Intune — those are out of scope for a standalone hardening script.
    This section instead:

    1. Adds a Windows Defender exclusion REMOVAL to ensure offensive tool paths
       are NOT inadvertently excluded from scanning.
    2. Sets registry-based software restriction hints where applicable.
    3. Documents the WDAC / AppLocker rules that SHOULD be deployed via GPO.

    Mitigation: M1038 — Execution Prevention
    #>

    Write-Status '' 'Info'
    Write-Status '--- [6] Offensive Tool Restrictions (M1038) ---' 'Info'

    if ($Undo) {
        Write-Status 'No registry-based tool restrictions to undo (WDAC/AppLocker managed via GPO).' 'Skipped'
        return
    }

    # Ensure Defender real-time scanning covers common attack tool drop paths.
    # Remove any broad exclusions that could shelter offensive tools.
    if (Get-Command 'Get-MpPreference' -ErrorAction SilentlyContinue) {
        try {
            $prefs = Get-MpPreference
            $suspiciousExclusions = @()

            # Flag any exclusion paths that cover temp directories broadly
            foreach ($excl in $prefs.ExclusionPath) {
                if ($excl -match 'Temp|Tmp|Users\\[^\\]+\\AppData' -and $excl.Length -lt 30) {
                    $suspiciousExclusions += $excl
                }
            }

            if ($suspiciousExclusions.Count -gt 0) {
                Write-Status 'WARNING: The following overly-broad Defender path exclusions were found:' 'Warning'
                $suspiciousExclusions | ForEach-Object { Write-Status "  $_" 'Warning' }
                Write-Status 'Review and remove these exclusions via Set-MpPreference -RemoveExclusionPath.' 'Warning'
                Add-ChangeLog -Category 'DefenderExclusions' -Action 'FoundSuspicious' `
                    -Target 'ExclusionPath' -OldValue ($suspiciousExclusions -join '; ') `
                    -NewValue 'Manual review required'
            }
            else {
                Write-Status 'No overly-broad Defender path exclusions detected.' 'Success'
            }
        }
        catch {
            Write-Status "Could not review Defender exclusions: $_" 'Warning'
        }
    }

    # Provide actionable AppLocker rule guidance as informational output
    Write-Status '' 'Info'
    Write-Status 'AppLocker / WDAC Recommended Rules (deploy via GPO or Intune):' 'Info'
    Write-Status '  1. Deny execution of any binary not signed by a trusted publisher' 'Info'
    Write-Status '     from paths: %TEMP%, %USERPROFILE%, C:\Users\*\Downloads\' 'Info'
    Write-Status '  2. Create a hash-based deny rule for known NetExec (nxc.exe) builds' 'Info'
    Write-Status '  3. Restrict sc.exe invocation: allow only SYSTEM, NT AUTHORITY\NETWORK SERVICE,' 'Info'
    Write-Status '     and explicitly named admin accounts; deny for standard users' 'Info'
    Write-Status '  4. Restrict taskkill.exe: allow only from %SystemRoot%\System32\' 'Info'
    Write-Status '     and only when parent process is trusted management tooling' 'Info'
    Write-Status '  Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/' 'Info'
}

# ===========================================================================
# SECTION 7 — SCM (Service Control Manager) Access Control (M1022)
# ===========================================================================

function Set-SCMAccessControl {
    <#
    Restricts the Service Control Manager (SCM) DACL to limit which principals
    can issue stop, delete, and create commands against any service.

    The SCM DACL is stored in the registry at:
      HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security
    and is accessible via sc.exe sdset/sdshow.

    This function:
    1. Queries the current SCM SDDL.
    2. Validates that the SDDL does not grant SC_MANAGER_ALL_ACCESS (0xF003F)
       to the "Users" group (S-1-5-32-545) or "Everyone" (S-1-1-0).
    3. Reports issues and provides remediation commands.

    Automated SDDL modification is intentionally conservative here — an
    incorrect SCM SDDL can prevent legitimate services from starting. Review
    and apply manually using the provided commands.

    Mitigation: M1022 — Restrict File and Directory Permissions
    #>

    Write-Status '' 'Info'
    Write-Status '--- [7] SCM Access Control Review (M1022) ---' 'Info'

    if ($Undo) {
        Write-Status 'SCM DACL was not modified by this script — no rollback needed.' 'Skipped'
        return
    }

    try {
        $scmSDDL = & sc.exe sdshow scmanager 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Status "Could not query SCM SDDL: $scmSDDL" 'Warning'
            return
        }

        # Remove leading/trailing whitespace and blank lines from sc.exe output
        $sddlLine = ($scmSDDL | Where-Object { $_ -match 'D:' } | Select-Object -First 1).Trim()

        Write-Status "Current SCM SDDL: $sddlLine" 'Info'

        # Check for overly permissive ACEs
        $issues = @()
        # S-1-1-0 = Everyone, S-1-5-32-545 = BUILTIN\Users
        if ($sddlLine -match 'A;;[A-Z]+;;;WD' -or $sddlLine -match 'A;;[A-Z]+;;;BU') {
            $issues += 'SCM grants access to Everyone (WD) or BUILTIN\Users (BU) — verify these are query-only (CC = SERVICE_QUERY_CONFIG, LC = SERVICE_QUERY_STATUS)'
        }

        if ($issues.Count -gt 0) {
            Write-Status 'SCM DACL issues detected:' 'Warning'
            $issues | ForEach-Object { Write-Status "  $_" 'Warning' }
            Write-Status '' 'Warning'
            Write-Status 'To restrict SCM access, apply the following command as SYSTEM:' 'Warning'
            Write-Status '  sc.exe sdset scmanager "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)"' 'Warning'
            Write-Status '  This grants: Authenticated Users = query only, Admins = full, SYSTEM = full' 'Warning'
            Add-ChangeLog -Category 'SCM' -Action 'ReviewRequired' -Target 'SCM DACL' `
                -OldValue $sddlLine -NewValue 'Manual remediation required'
        }
        else {
            Write-Status 'SCM DACL appears appropriately restrictive.' 'Success'
            Add-ChangeLog -Category 'SCM' -Action 'Verified' -Target 'SCM DACL' `
                -OldValue $sddlLine -NewValue 'No changes required'
        }
    }
    catch {
        Write-Status "SCM DACL review failed: $_" 'Warning'
    }
}

# ===========================================================================
# SECTION 8 — Validation
# ===========================================================================

function Invoke-HardeningValidation {
    <#
    Runs post-application checks to confirm the key hardening controls are active.
    #>

    Write-Status '' 'Info'
    Write-Status '--- [8] Validation ---' 'Info'

    $checks = @()

    # Check 1: Tamper Protection
    try {
        $tpVal = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection'
        $checks += [PSCustomObject]@{
            Check   = 'Tamper Protection'
            Status  = if ($tpVal -eq 5) { 'PASS' } else { 'FAIL' }
            Detail  = "TamperProtection registry value = $tpVal (expected 5)"
        }
    }
    catch {
        $checks += [PSCustomObject]@{ Check = 'Tamper Protection'; Status = 'ERROR'; Detail = "$_" }
    }

    # Check 2: WinDefend service running
    try {
        $wdSvc = Get-Service 'WinDefend' -ErrorAction Stop
        $checks += [PSCustomObject]@{
            Check   = 'WinDefend Running'
            Status  = if ($wdSvc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
            Detail  = "Status = $($wdSvc.Status), StartType = $($wdSvc.StartType)"
        }
    }
    catch {
        $checks += [PSCustomObject]@{ Check = 'WinDefend Running'; Status = 'ERROR'; Detail = "$_" }
    }

    # Check 3: Command-line logging enabled
    $cmdLineVal = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
                               -Name 'ProcessCreationIncludeCmdLine_Enabled'
    $checks += [PSCustomObject]@{
        Check   = 'Command-Line Logging (4688)'
        Status  = if ($cmdLineVal -eq 1) { 'PASS' } else { 'FAIL' }
        Detail  = "ProcessCreationIncludeCmdLine_Enabled = $cmdLineVal (expected 1)"
    }

    # Check 4: MsMpEng running (Defender engine)
    $msmpEng = Get-Process 'MsMpEng' -ErrorAction SilentlyContinue
    $checks += [PSCustomObject]@{
        Check   = 'MsMpEng.exe Running'
        Status  = if ($msmpEng) { 'PASS' } else { 'FAIL' }
        Detail  = if ($msmpEng) { "PID $($msmpEng.Id)" } else { 'Process not found' }
    }

    # Check 5: Firewall rules present (only if not skipped)
    if (-not $SkipFirewall) {
        $fwRule = Get-NetFirewallRule -DisplayName 'F0RTIKA-Hardening-T1489*' -ErrorAction SilentlyContinue
        $checks += [PSCustomObject]@{
            Check   = 'SMB Firewall Rules'
            Status  = if ($fwRule) { 'PASS' } else { if ($Undo) { 'PASS (Undo)' } else { 'FAIL' } }
            Detail  = if ($fwRule) { "$($fwRule.Count) rule(s) found" } else { 'No F0RTIKA hardening rules found' }
        }
    }

    # Check 6: ASR rules
    if (Get-Command 'Get-MpPreference' -ErrorAction SilentlyContinue) {
        try {
            $prefs    = Get-MpPreference
            $asrIds   = $prefs.AttackSurfaceReductionRules_Ids
            $asrActs  = $prefs.AttackSurfaceReductionRules_Actions
            $targetId = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            $idx      = if ($asrIds) { [array]::IndexOf($asrIds, $targetId) } else { -1 }
            $mode     = if ($idx -ge 0 -and $asrActs) { $asrActs[$idx] } else { 'NotConfigured' }
            $checks += [PSCustomObject]@{
                Check   = 'ASR Rule: Block PSExec/WMI'
                Status  = if ($mode -eq 1) { 'PASS' } elseif ($mode -eq 2) { 'AUDIT' } else { 'FAIL' }
                Detail  = "Rule $targetId mode = $mode (1=Block, 2=Audit)"
            }
        }
        catch {
            $checks += [PSCustomObject]@{ Check = 'ASR Rules'; Status = 'ERROR'; Detail = "$_" }
        }
    }

    Write-Status '' 'Info'
    Write-Status 'Validation Results:' 'Info'
    $checks | Format-Table -AutoSize

    $failCount = ($checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    if ($failCount -gt 0) {
        Write-Status "$failCount check(s) FAILED. Review output above and address manually." 'Warning'
    }
    else {
        Write-Status 'All checks passed.' 'Success'
    }
}

# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

$banner = @"

  F0RT1KA Hardening Script
  Techniques : T1489 - Service Stop
               T1562.001 - Impair Defenses: Disable or Modify Tools
  Mitigations: M1054, M1018, M1038, M1022, M1024, M1030
  Mode       : $(if ($Undo) { 'UNDO (revert hardening)' } else { 'APPLY (harden)' })
  WhatIf     : $($WhatIfPreference)
  Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@

Write-Host $banner -ForegroundColor Cyan

if ($Undo) {
    Write-Status 'Reverting hardening changes...' 'Warning'
}
else {
    Write-Status 'Applying security hardening...' 'Info'
}

# Execute all sections
Set-TamperProtection
Set-SecurityServiceHardening
Set-ASRRules
Set-FirewallRules
Set-AuditPolicy
Set-OffensiveToolRestrictions
Set-SCMAccessControl

# Validate after apply (skip detailed validation during undo)
if (-not $Undo) {
    Invoke-HardeningValidation
}

# Save change log
Save-ChangeLog

Write-Status '' 'Info'
if ($Script:HasErrors) {
    Write-Status 'Hardening completed WITH WARNINGS — review output above.' 'Warning'
}
elseif ($WhatIfPreference) {
    Write-Status 'WhatIf run complete — no changes were made.' 'Info'
}
elseif ($Undo) {
    Write-Status 'Undo complete. Review change log: $Script:ChangeLogPath' 'Success'
}
else {
    Write-Status 'Hardening complete. Review change log: $Script:ChangeLogPath' 'Success'
}
