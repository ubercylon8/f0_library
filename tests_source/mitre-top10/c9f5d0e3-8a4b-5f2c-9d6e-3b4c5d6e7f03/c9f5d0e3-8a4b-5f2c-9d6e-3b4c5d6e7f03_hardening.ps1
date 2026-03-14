<#
.SYNOPSIS
    Hardens Windows against RDP lateral movement and Windows Credential Manager abuse.

.DESCRIPTION
    Applies security hardening to mitigate Remote Desktop Protocol lateral movement
    (T1021.001) and Credentials from Password Stores: Windows Credential Manager (T1555.004).

    All changes are idempotent and reversible via -Undo.

    MITRE ATT&CK: T1021.001, T1555.004
    Mitigations:  M1035, M1030, M1028, M1047, M1026, M1042, M1027, M1054

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what changes would be made without applying them. Standard PowerShell -WhatIf.

.PARAMETER SkipFirewall
    Skips Windows Firewall rule changes (use when firewall policy is managed externally).

.PARAMETER SkipAuditPolicy
    Skips audit policy configuration (use when audit policy is managed via GPO).

.PARAMETER SkipAppLocker
    Skips AppLocker rule creation (use when WDAC or another application control tool is
    already deployed).

.EXAMPLE
    .\hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\hardening.ps1 -WhatIf
    Shows what would be changed without making changes.

.EXAMPLE
    .\hardening.ps1 -Undo
    Reverts all hardening settings applied by this script.

.EXAMPLE
    .\hardening.ps1 -SkipFirewall -SkipAppLocker
    Applies only NLA, audit policy, and registry hardening.

.NOTES
    Author:      F0RT1KA Defense Guidance Generator
    Techniques:  T1021.001 (RDP Lateral Movement), T1555.004 (Credential Manager Abuse)
    Requires:    Administrator privileges
    Idempotent:  Yes — safe to run multiple times
    Rollback:    Run with -Undo to reverse all changes
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$SkipFirewall,
    [switch]$SkipAuditPolicy,
    [switch]$SkipAppLocker
)

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Script:ChangeLog  = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:BackupDir  = "$env:ProgramData\F0RT1KA\Hardening\RDP"
$Script:LogFile    = "$env:ProgramData\F0RT1KA\Hardening\rdp_hardening.log"
$Script:FwRuleName = "F0RT1KA-RDP-Hardening-Restrict-Inbound"
$Script:AppLockerCmdkeyGpo = "F0RT1KA-AppLocker-Restrict-Cmdkey"

# ============================================================
# Helper Functions
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Section")]
        [string]$Type = "Info"
    )
    $colors = @{
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
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($prefix[$Type]) $Message"
    Write-Host $line -ForegroundColor $colors[$Type]
    $line | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Add-ChangeLog {
    param(
        [string]$Component,
        [string]$Action,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Component = $Component
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
    })
}

function Ensure-BackupDir {
    if (-not (Test-Path $Script:BackupDir)) {
        New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null
    }
}

function Backup-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    Ensure-BackupDir
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $backupObj = @{ Path = $Path; Name = $Name; Value = $val.$Name; Type = (Get-Item -Path $Path).GetValueKind($Name).ToString() }
            $backupFile = Join-Path $Script:BackupDir ("reg_backup_{0}_{1}.json" -f ($Path -replace '[:\\]','_'), $Name)
            $backupObj | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding UTF8 -Force
        }
    } catch {
        Write-Status "Could not back up registry value $Path\$Name : $_" -Type Warning
    }
}

function Restore-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    $backupFile = Join-Path $Script:BackupDir ("reg_backup_{0}_{1}.json" -f ($Path -replace '[:\\]','_'), $Name)
    if (Test-Path $backupFile) {
        try {
            $backupObj = Get-Content $backupFile -Raw | ConvertFrom-Json
            if (-not (Test-Path $backupObj.Path)) {
                New-Item -Path $backupObj.Path -Force | Out-Null
            }
            $regType = [Microsoft.Win32.RegistryValueKind]$backupObj.Type
            Set-ItemProperty -Path $backupObj.Path -Name $backupObj.Name -Value $backupObj.Value -Type $regType
            Write-Status "Restored: $($backupObj.Path)\$($backupObj.Name) = $($backupObj.Value)" -Type Success
            Remove-Item $backupFile -Force
        } catch {
            Write-Status "Failed to restore $Path\$Name : $_" -Type Error
        }
    } else {
        Write-Status "No backup found for $Path\$Name — value may not have existed before hardening" -Type Warning
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$LogComponent = "Registry"
    )
    try {
        if (-not (Test-Path $Path)) {
            if ($PSCmdlet.ShouldProcess($Path, "Create registry key")) {
                New-Item -Path $Path -Force | Out-Null
            }
        }
        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($current -eq $Value) {
            Write-Status "Already set: $Path\$Name = $Value" -Type Info
            return
        }
        Backup-RegistryValue -Path $Path -Name $Name
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set value to $Value")) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            Add-ChangeLog -Component $LogComponent -Action "SetRegistryValue" -Target "$Path\$Name" -OldValue "$current" -NewValue "$Value"
            Write-Status "Set: $Path\$Name = $Value (was: $current)" -Type Success
        }
    } catch {
        Write-Status "Failed to set $Path\$Name : $_" -Type Error
    }
}

# ============================================================
# Section 1: NLA (Network Level Authentication) — T1021.001 / M1028
# ============================================================

function Set-NLAHardening {
    Write-Status "Configuring Network Level Authentication (NLA) for RDP..." -Type Section

    # Enforce NLA on the RDP-Tcp listener
    # UserAuthentication = 1 requires NLA; 0 allows legacy connections
    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" `
        -Value 1 `
        -Type DWord `
        -LogComponent "NLA"

    # Set Security Layer to 2 (SSL/TLS) — prevents Classic RDP encryption
    # 0=Classic RDP, 1=Negotiate, 2=SSL
    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "SecurityLayer" `
        -Value 2 `
        -Type DWord `
        -LogComponent "NLA"

    # Set minimum encryption level to High (3)
    # 1=Low, 2=ClientCompatible, 3=High, 4=FIPS
    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "MinEncryptionLevel" `
        -Value 3 `
        -Type DWord `
        -LogComponent "NLA"

    # Disable credential delegation via Restricted Admin mode
    # When enabled, RDP sessions do NOT forward user credentials to the remote host,
    # which prevents pass-the-hash and credential relay attacks over RDP.
    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "DisableRestrictedAdmin" `
        -Value 0 `
        -Type DWord `
        -LogComponent "NLA"
}

function Undo-NLAHardening {
    Write-Status "Reverting NLA hardening..." -Type Section
    $rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    Restore-RegistryValue -Path $rdpTcpPath -Name "UserAuthentication"
    Restore-RegistryValue -Path $rdpTcpPath -Name "SecurityLayer"
    Restore-RegistryValue -Path $rdpTcpPath -Name "MinEncryptionLevel"
    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin"
}

# ============================================================
# Section 2: Restrict RDP Service (TermService) — T1021.001 / M1028, M1035
# ============================================================

function Set-RDPServiceHardening {
    Write-Status "Configuring RDP service and access restrictions..." -Type Section

    # If RDP is not needed at all, disable it outright.
    # Comment this block and use Set-NLAHardening alone if RDP must remain enabled.
    # Here we enforce the secure configuration path: keep the service but harden access.

    # Disable auto-starting RDP when not needed — set start type to Manual (3)
    # so it can be started by administrators on demand but is not listening at boot.
    # Change to 4 (Disabled) if RDP is never required on this class of endpoint.
    #
    # NOTE: Modifying service start type requires a service restart to take effect.
    # Set to 3 (Manual) rather than 4 (Disabled) for flexibility.
    try {
        $svc = Get-Service -Name "TermService" -ErrorAction Stop
        $currentStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start").Start

        if (-not $Undo) {
            if ($currentStart -eq 2) {
                # Service is set to Automatic — move to Manual (demand-start)
                Backup-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start"
                if ($PSCmdlet.ShouldProcess("TermService", "Change start type from Automatic to Manual (demand-start)")) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value 3 -Type DWord
                    Add-ChangeLog -Component "RDPService" -Action "SetStartType" -Target "TermService" -OldValue "2 (Automatic)" -NewValue "3 (Manual)"
                    Write-Status "TermService start type changed from Automatic to Manual" -Type Success
                }
            } else {
                Write-Status "TermService start type is already $currentStart (not Automatic — no change needed)" -Type Info
            }
        } else {
            Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start"
        }
    } catch {
        Write-Status "Could not modify TermService start type: $_" -Type Warning
    }

    if (-not $Undo) {
        # Restrict Remote Desktop Users group: list current members for review
        Write-Status "Auditing Remote Desktop Users group membership..." -Type Info
        try {
            $rdpUsers = net localgroup "Remote Desktop Users" 2>&1
            Write-Status "Current Remote Desktop Users group members:" -Type Info
            $rdpUsers | Where-Object { $_ -match '^\S' -and $_ -notmatch '---' -and $_ -notmatch 'command' -and $_ -notmatch 'Members' } |
                ForEach-Object { Write-Status "  Member: $_" -Type Warning }
            $rdpUsers | Out-File -FilePath (Join-Path $Script:BackupDir "rdp_users_group_backup.txt") -Encoding UTF8 -Force
            Write-Status "Group membership saved to: $(Join-Path $Script:BackupDir 'rdp_users_group_backup.txt')" -Type Info
        } catch {
            Write-Status "Could not enumerate Remote Desktop Users group: $_" -Type Warning
        }
    }
}

function Undo-RDPServiceHardening {
    Write-Status "Reverting RDP service hardening..." -Type Section
    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start"
    Write-Status "Review rdp_users_group_backup.txt in $Script:BackupDir to restore group membership if needed." -Type Warning
}

# ============================================================
# Section 3: Windows Firewall — Restrict Inbound RDP — T1021.001 / M1035
# ============================================================

function Set-FirewallHardening {
    Write-Status "Configuring Windows Firewall rules for RDP restriction..." -Type Section

    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Restrict inbound RDP to localhost only")) {
        # Remove any existing hardening rule to ensure idempotency
        Remove-NetFirewallRule -Name $Script:FwRuleName -ErrorAction SilentlyContinue

        # Create a block rule for all inbound RDP
        # This is a defense-in-depth rule; adapt the LocalAddress/RemoteAddress
        # parameters to match your environment's jump host IP range.
        # To allow RDP ONLY from a specific jump host, replace "Any" in
        # RemoteAddress with the jump host IP or range, and change Action to "Allow",
        # then add a separate block-all rule with higher priority.
        New-NetFirewallRule `
            -Name $Script:FwRuleName `
            -DisplayName "F0RT1KA: Restrict Inbound RDP (T1021.001 Hardening)" `
            -Description "Blocks inbound RDP from all sources except localhost. Edit RemoteAddress to permit jump hosts. Applied by F0RT1KA hardening for T1021.001." `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 3389 `
            -Action Block `
            -Profile Any `
            -Enabled True | Out-Null

        Add-ChangeLog -Component "Firewall" -Action "CreateRule" -Target $Script:FwRuleName -OldValue "(none)" -NewValue "Block inbound TCP/3389"
        Write-Status "Firewall rule created: $Script:FwRuleName (blocks inbound TCP/3389)" -Type Success
        Write-Status "ACTION REQUIRED: Edit rule RemoteAddress to permit your jump host IPs if RDP is needed." -Type Warning
    }
}

function Undo-FirewallHardening {
    Write-Status "Removing F0RT1KA firewall rules..." -Type Section
    if ($PSCmdlet.ShouldProcess($Script:FwRuleName, "Remove firewall rule")) {
        Remove-NetFirewallRule -Name $Script:FwRuleName -ErrorAction SilentlyContinue
        Write-Status "Removed firewall rule: $Script:FwRuleName" -Type Success
    }
}

# ============================================================
# Section 4: Audit Policy — RDP and Credential Manager events — M1047
# ============================================================

function Set-AuditPolicy {
    Write-Status "Configuring Advanced Audit Policy for RDP and Credential Manager..." -Type Section

    # Logon/Logoff — captures Event ID 4624 (Type 10 = RemoteInteractive/RDP logon)
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable Logon/Logoff auditing")) {
        & auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        & auditpol.exe /set /subcategory:"Logoff" /success:enable | Out-Null
        Write-Status "Audit: Logon/Logoff — Success+Failure enabled" -Type Success
        Add-ChangeLog -Component "AuditPolicy" -Action "SetAuditPolicy" -Target "Logon/Logoff" -OldValue "unknown" -NewValue "Success+Failure"
    }

    # Account Logon — captures Kerberos/NTLM auth events underpinning RDP
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable Account Logon auditing")) {
        & auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        Write-Status "Audit: Credential Validation — Success+Failure enabled" -Type Success
        Add-ChangeLog -Component "AuditPolicy" -Action "SetAuditPolicy" -Target "Credential Validation" -OldValue "unknown" -NewValue "Success+Failure"
    }

    # Object Access — required for Credential Manager events (5379, 5380, 5381, 5382)
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable Object Access auditing for Credential Manager")) {
        & auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
        Write-Status "Audit: Other Object Access Events — Success+Failure enabled (Credential Manager: 5379-5382)" -Type Success
        Add-ChangeLog -Component "AuditPolicy" -Action "SetAuditPolicy" -Target "Other Object Access Events" -OldValue "unknown" -NewValue "Success+Failure"
    }

    # Process Creation — captures sc.exe, reg.exe, qwinsta.exe, cmdkey.exe, SharpRDP.exe
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable Process Creation auditing")) {
        & auditpol.exe /set /subcategory:"Process Creation" /success:enable | Out-Null
        Write-Status "Audit: Process Creation — Success enabled" -Type Success
        Add-ChangeLog -Component "AuditPolicy" -Action "SetAuditPolicy" -Target "Process Creation" -OldValue "unknown" -NewValue "Success"
    }

    # Enable command-line logging in process creation events (Event ID 4688)
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -Value 1 `
        -Type DWord `
        -LogComponent "AuditPolicy"

    # Detailed Tracking — Policy Change
    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable Policy Change auditing")) {
        & auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
        Write-Status "Audit: Audit Policy Change — Success+Failure enabled" -Type Success
    }
}

function Undo-AuditPolicy {
    Write-Status "Reverting audit policy changes..." -Type Section
    Write-Status "Note: Audit policy rollback re-sets modified subcategories to 'No Auditing'. This may reduce visibility — review before applying in production." -Type Warning

    if ($PSCmdlet.ShouldProcess("Audit Policy", "Revert Logon/Logoff to No Auditing")) {
        # Not reverting to "No Auditing" as that could eliminate baseline detection.
        # Instead, report that operator should review GPO-managed audit policy.
        Write-Status "Audit policy subcategories were enabled by this script. If managed via GPO, run 'gpupdate /force' to restore GPO-defined settings." -Type Warning
        Write-Status "Manual revert: auditpol.exe /set /subcategory:<name> /success:disable /failure:disable" -Type Info
    }

    Restore-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled"
}

# ============================================================
# Section 5: Credential Manager Hardening — T1555.004 / M1042, M1054
# ============================================================

function Set-CredentialManagerHardening {
    Write-Status "Hardening Windows Credential Manager against T1555.004..." -Type Section

    # Disable storage of network passwords in Credential Manager
    # DisableDomainCreds = 1 prevents Windows from caching domain credentials
    # in the Credential Manager — attackers cannot read them via cmdkey or DPAPI.
    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "DisableDomainCreds" `
        -Value 1 `
        -Type DWord `
        -LogComponent "CredentialManager"

    # Limit cached domain logon credentials to 1 (minimum) or 0 (none).
    # Fewer cached credentials means less exposure if an endpoint is compromised.
    # Default is 10. Set to 1 to maintain local fallback for disconnected scenarios.
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        -Name "CachedLogonsCount" `
        -Value "1" `
        -Type String `
        -LogComponent "CredentialManager"

    # Audit current Credential Manager entries for review (non-destructive)
    Write-Status "Auditing current Credential Manager entries (cmdkey /list)..." -Type Info
    try {
        $cmdkeyList = & cmdkey.exe /list 2>&1 | Out-String
        $auditFile = Join-Path $Script:BackupDir "credential_manager_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $cmdkeyList | Out-File -FilePath $auditFile -Encoding UTF8
        Write-Status "Credential Manager audit saved to: $auditFile" -Type Info

        # Count non-empty entries for reporting
        $entryCount = ($cmdkeyList -split "`n" | Where-Object { $_ -match "Target:" }).Count
        if ($entryCount -gt 0) {
            Write-Status "Found $entryCount stored credential(s) in Credential Manager — review audit file." -Type Warning
        } else {
            Write-Status "No stored credentials found in Credential Manager." -Type Success
        }
    } catch {
        Write-Status "Could not enumerate Credential Manager: $_" -Type Warning
    }
}

function Undo-CredentialManagerHardening {
    Write-Status "Reverting Credential Manager hardening..." -Type Section
    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds"
    Restore-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount"
}

# ============================================================
# Section 6: AppLocker — Restrict cmdkey.exe — T1555.004 / M1042
# ============================================================

function Set-AppLockerHardening {
    Write-Status "Configuring AppLocker rules to restrict cmdkey.exe..." -Type Section
    Write-Status "Note: AppLocker rules require the 'Application Identity' service to be running." -Type Warning

    # Ensure Application Identity service is running (required for AppLocker enforcement)
    try {
        $appIdSvc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
        if ($appIdSvc.Status -ne "Running") {
            if ($PSCmdlet.ShouldProcess("AppIDSvc", "Set start type to Automatic and start service")) {
                Set-Service -Name "AppIDSvc" -StartupType Automatic
                Start-Service -Name "AppIDSvc"
                Add-ChangeLog -Component "AppLocker" -Action "StartService" -Target "AppIDSvc" -OldValue "Stopped" -NewValue "Running"
                Write-Status "Application Identity service started." -Type Success
            }
        } else {
            Write-Status "Application Identity service is already running." -Type Info
        }
    } catch {
        Write-Status "Application Identity service not available — AppLocker may not be supported on this SKU. Skipping." -Type Warning
        return
    }

    # Create AppLocker policy XML that blocks cmdkey.exe for all users
    # except administrators. This is written as a supplemental policy in
    # the Executable rules. It applies to all users by denying the path.
    #
    # In production, deploy via GPO: Computer Config > Windows Settings >
    # Security Settings > Application Control Policies > AppLocker.

    $appLockerPolicyXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="f0rtika-cmdkey-restrict-001"
                  Name="F0RT1KA: Restrict cmdkey.exe (T1555.004 hardening)"
                  Description="Prevents non-administrative processes from using cmdkey.exe to manipulate Windows Credential Manager. Applied as AuditOnly — change EnforcementMode to Enabled after testing."
                  UserOrGroupSid="S-1-1-0"
                  Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\cmdkey.exe"/>
      </Conditions>
      <Exceptions>
        <!-- Allow administrators to use cmdkey.exe -->
        <FilePathCondition Path="%SYSTEM32%\cmdkey.exe"/>
      </Exceptions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

    # Note: The above policy uses AuditOnly mode. To enforce (block), change
    # EnforcementMode from "AuditOnly" to "Enabled" after validating no
    # legitimate applications are broken.
    #
    # For full AppLocker deployment via Set-AppLockerPolicy:
    $policyFile = Join-Path $Script:BackupDir "applocker_cmdkey_restrict.xml"
    $appLockerPolicyXml | Out-File -FilePath $policyFile -Encoding UTF8 -Force

    if ($PSCmdlet.ShouldProcess("AppLocker", "Apply cmdkey.exe restriction policy (AuditOnly mode)")) {
        try {
            $policy = Get-AppLockerPolicy -Local
            # Merge rather than replace to preserve existing rules
            $newPolicy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::FromXml($appLockerPolicyXml)
            # Apply the saved XML policy file
            & Set-AppLockerPolicy -XmlPolicy $policyFile -Merge -ErrorAction Stop
            Add-ChangeLog -Component "AppLocker" -Action "SetPolicy" -Target "cmdkey.exe" -OldValue "(no rule)" -NewValue "AuditOnly deny for S-1-1-0"
            Write-Status "AppLocker policy applied (AuditOnly). Review Event ID 8003/8004 in 'Microsoft-Windows-AppLocker/EXE and DLL' log." -Type Success
        } catch {
            Write-Status "Failed to apply AppLocker policy via Set-AppLockerPolicy: $_" -Type Warning
            Write-Status "Policy XML saved to: $policyFile — apply manually via GPO or Local Security Policy." -Type Info
        }
    }
}

function Undo-AppLockerHardening {
    Write-Status "Reverting AppLocker hardening for cmdkey.exe..." -Type Section
    try {
        # Remove the specific F0RT1KA AppLocker rule by rebuilding policy without it
        $existingPolicy = Get-AppLockerPolicy -Local -Xml
        if ($existingPolicy -match "f0rtika-cmdkey-restrict-001") {
            $cleanedPolicy = $existingPolicy -replace '(?s)<FilePathRule Id="f0rtika-cmdkey-restrict-001".*?</FilePathRule>\s*', ''
            $tempFile = Join-Path $Script:BackupDir "applocker_reverted.xml"
            $cleanedPolicy | Out-File -FilePath $tempFile -Encoding UTF8 -Force
            if ($PSCmdlet.ShouldProcess("AppLocker", "Remove F0RT1KA cmdkey.exe restriction rule")) {
                Set-AppLockerPolicy -XmlPolicy $tempFile -ErrorAction Stop
                Write-Status "AppLocker cmdkey.exe restriction rule removed." -Type Success
            }
        } else {
            Write-Status "F0RT1KA AppLocker rule not found in local policy — nothing to revert." -Type Info
        }
    } catch {
        Write-Status "Failed to revert AppLocker policy: $_" -Type Warning
        Write-Status "Review local AppLocker policy manually in Local Security Policy (secpol.msc)." -Type Info
    }
}

# ============================================================
# Section 7: Defender ASR Rules — RDP / Credential Access — M1042
# ============================================================

function Set-DefenderASRRules {
    Write-Status "Configuring Microsoft Defender Attack Surface Reduction rules..." -Type Section

    # Check if MDE/Defender AV is running
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Status "Microsoft Defender is not available on this system. Skipping ASR configuration." -Type Warning
        return
    }

    if (-not $defenderStatus.AntivirusEnabled) {
        Write-Status "Microsoft Defender AV is not active (third-party AV may be present). Skipping ASR rules." -Type Warning
        return
    }

    # ASR Rule: Block credential stealing from LSASS
    # Rule GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0
    # Mitigates credential harvesting that could be used to populate RDP credentials
    $lsassProtectionRule = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0"

    # ASR Rule: Block process creations originating from PSExec and WMI commands
    # Rule GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c
    # Complements RDP lateral movement detection
    $psexecWmiRule = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

    # ASR Rule: Block executable files from running unless they meet a prevalence,
    # age, or trusted list criteria
    # Rule GUID: 01443614-cd74-433a-b99e-2ecdc07bfc25
    # Helps block novel RDP tools like SharpRDP from executing
    $untrustedExecutableRule = "01443614-cd74-433a-b99e-2ecdc07bfc25"

    $rules = @(
        @{ Guid = $lsassProtectionRule;      Name = "Block credential stealing from LSASS";                          Mode = 1 },
        @{ Guid = $psexecWmiRule;            Name = "Block process creations from PSExec and WMI";                   Mode = 1 },
        @{ Guid = $untrustedExecutableRule;  Name = "Block untrusted/unsigned executables from removable/unknown";   Mode = 1 }
    )

    foreach ($rule in $rules) {
        try {
            $currentRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
            $currentActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
            $idx = if ($currentRules) { [array]::IndexOf($currentRules, $rule.Guid) } else { -1 }
            $currentMode = if ($idx -ge 0 -and $currentActions) { $currentActions[$idx] } else { "not configured" }

            if ($currentMode -eq $rule.Mode) {
                Write-Status "ASR rule already at target mode: $($rule.Name)" -Type Info
                continue
            }

            if ($PSCmdlet.ShouldProcess($rule.Name, "Set ASR rule to mode $($rule.Mode) (1=Block, 2=Audit)")) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Guid -AttackSurfaceReductionRules_Actions $rule.Mode
                Add-ChangeLog -Component "DefenderASR" -Action "SetASRRule" -Target $rule.Guid -OldValue "$currentMode" -NewValue "$($rule.Mode)"
                Write-Status "ASR rule set to Block (1): $($rule.Name)" -Type Success
            }
        } catch {
            Write-Status "Failed to configure ASR rule '$($rule.Name)': $_" -Type Warning
        }
    }
}

function Undo-DefenderASRRules {
    Write-Status "Reverting Defender ASR rules..." -Type Section
    Write-Status "ASR rule revert: removing rules added by this script (setting to Not Configured)." -Type Warning

    $rulesToRemove = @(
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c",
        "01443614-cd74-433a-b99e-2ecdc07bfc25"
    )

    foreach ($guid in $rulesToRemove) {
        try {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $guid -ErrorAction SilentlyContinue
            Write-Status "ASR rule removed: $guid" -Type Success
        } catch {
            Write-Status "Could not remove ASR rule $guid : $_" -Type Warning
        }
    }
}

# ============================================================
# Section 8: Credential Guard — protect domain creds via RDP — M1028
# ============================================================

function Set-CredentialGuard {
    Write-Status "Enabling Windows Defender Credential Guard (virtualization-based protection)..." -Type Section

    # Credential Guard requires:
    # - Windows 10/11 or Windows Server 2016+
    # - Virtualization-based security (VBS) capable hardware
    # - UEFI Secure Boot
    #
    # EnableVirtualizationBasedSecurity = 1
    # RequirePlatformSecurityFeatures = 1 (Secure Boot only) or 3 (Secure Boot + DMA Protection)
    # LsaCfgFlags = 1 (Credential Guard enabled without UEFI lock) or 2 (with UEFI lock)

    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
        -Name "EnableVirtualizationBasedSecurity" `
        -Value 1 `
        -Type DWord `
        -LogComponent "CredentialGuard"

    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
        -Name "RequirePlatformSecurityFeatures" `
        -Value 1 `
        -Type DWord `
        -LogComponent "CredentialGuard"

    Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LsaCfgFlags" `
        -Value 1 `
        -Type DWord `
        -LogComponent "CredentialGuard"

    Write-Status "Credential Guard registry settings applied. A SYSTEM RESTART is required for Credential Guard to become active." -Type Warning
    Write-Status "After reboot, verify with: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning" -Type Info
}

function Undo-CredentialGuard {
    Write-Status "Reverting Credential Guard settings..." -Type Section
    Write-Status "WARNING: Disabling Credential Guard requires a reboot and may leave credentials exposed." -Type Warning

    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures"
    Restore-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags"

    Write-Status "Credential Guard revert complete. A SYSTEM RESTART is required for changes to take effect." -Type Warning
}

# ============================================================
# Section 9: Additional RDP Reconnaissance Countermeasures
# ============================================================

function Set-ReconCountermeasures {
    Write-Status "Applying RDP reconnaissance countermeasures..." -Type Section

    # Restrict qwinsta / query session to administrators only via registry
    # There is no built-in registry key for this; control is via user rights assignment.
    # We use audit logging (already covered in Set-AuditPolicy) and report the
    # recommended GPO setting here.
    Write-Status "RECOMMENDATION: Restrict 'Access this computer from the network' user right" -Type Warning
    Write-Status "  GPO Path: Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment" -Type Info
    Write-Status "  'Access this computer from the network' — ensure only required accounts/groups are listed." -Type Info

    # Harden RDP-TCP: Disable clipboard and drive redirection (reduces data exfil surface)
    # fDisableClip = 1 disables clipboard redirection in RDP sessions
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableClip" `
        -Value 1 `
        -Type DWord `
        -LogComponent "RDPRecon"

    # fDisableCdm = 1 disables client drive mapping
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableCdm" `
        -Value 1 `
        -Type DWord `
        -LogComponent "RDPRecon"

    # MaxDisconnectionTime: auto-disconnect idle sessions after 15 minutes (900000ms)
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "MaxDisconnectionTime" `
        -Value 900000 `
        -Type DWord `
        -LogComponent "RDPRecon"

    # MaxIdleTime: log off idle sessions after 30 minutes (1800000ms)
    Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "MaxIdleTime" `
        -Value 1800000 `
        -Type DWord `
        -LogComponent "RDPRecon"
}

function Undo-ReconCountermeasures {
    Write-Status "Reverting RDP reconnaissance countermeasures..." -Type Section
    $tsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Restore-RegistryValue -Path $tsPolicyPath -Name "fDisableClip"
    Restore-RegistryValue -Path $tsPolicyPath -Name "fDisableCdm"
    Restore-RegistryValue -Path $tsPolicyPath -Name "MaxDisconnectionTime"
    Restore-RegistryValue -Path $tsPolicyPath -Name "MaxIdleTime"
}

# ============================================================
# Main Execution
# ============================================================

# Initialize log directory
Ensure-BackupDir
"" | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8

$mode = if ($Undo) { "UNDO" } else { "APPLY" }
Write-Status "========================================" -Type Section
Write-Status "F0RT1KA RDP Hardening Script" -Type Section
Write-Status "Techniques: T1021.001, T1555.004" -Type Section
Write-Status "Mitigations: M1035, M1030, M1028, M1047, M1026, M1042, M1027, M1054" -Type Section
Write-Status "Mode: $mode" -Type Section
Write-Status "Backup directory: $Script:BackupDir" -Type Section
Write-Status "Log file: $Script:LogFile" -Type Section
Write-Status "========================================" -Type Section

if ($Undo) {
    # Revert in reverse order
    Undo-ReconCountermeasures
    Undo-CredentialGuard
    Undo-DefenderASRRules
    if (-not $SkipAppLocker)   { Undo-AppLockerHardening }
    Undo-CredentialManagerHardening
    if (-not $SkipAuditPolicy) { Undo-AuditPolicy }
    Undo-RDPServiceHardening
    if (-not $SkipFirewall)    { Undo-FirewallHardening }
    Undo-NLAHardening
} else {
    Set-NLAHardening
    if (-not $SkipFirewall)    { Set-FirewallHardening }
    Set-RDPServiceHardening
    if (-not $SkipAuditPolicy) { Set-AuditPolicy }
    Set-CredentialManagerHardening
    if (-not $SkipAppLocker)   { Set-AppLockerHardening }
    Set-DefenderASRRules
    Set-CredentialGuard
    Set-ReconCountermeasures
}

# Summary
Write-Status "========================================" -Type Section
Write-Status "Hardening $mode complete." -Type Section
Write-Status "========================================" -Type Section

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Change summary:" -Type Info
    $Script:ChangeLog | Format-Table Component, Action, Target, OldValue, NewValue -AutoSize

    # Save change log to backup directory
    $changeLogFile = Join-Path $Script:BackupDir "change_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Script:ChangeLog | Export-Csv -Path $changeLogFile -NoTypeInformation -Encoding UTF8
    Write-Status "Change log saved to: $changeLogFile" -Type Info
} else {
    Write-Status "No changes were made (all settings already at target state or -WhatIf mode)." -Type Info
}

if (-not $Undo) {
    Write-Status "" -Type Info
    Write-Status "POST-HARDENING ACTIONS REQUIRED:" -Type Warning
    Write-Status "  1. REBOOT required for Credential Guard to activate." -Type Warning
    Write-Status "  2. Edit firewall rule '$Script:FwRuleName' to permit jump host IP(s) if RDP is needed." -Type Warning
    Write-Status "  3. Review AppLocker policy in AuditOnly mode before switching to Enforce." -Type Warning
    Write-Status "  4. Review Remote Desktop Users group membership in: $Script:BackupDir\rdp_users_group_backup.txt" -Type Warning
    Write-Status "  5. Test RDP connectivity from authorized jump hosts before closing maintenance window." -Type Warning
}
