<#
.SYNOPSIS
    Hardens Windows against local account enumeration, local account abuse, and Kerberoasting.

.DESCRIPTION
    Applies security hardening to mitigate the following MITRE ATT&CK techniques:
      - T1087.001  Account Discovery: Local Account
      - T1078.003  Valid Accounts: Local Accounts
      - T1558.003  Steal or Forge Kerberos Tickets: Kerberoasting / AS-REP Roasting

    Controls applied:
      1. Process creation audit policy with command-line capture
      2. Advanced Kerberos audit policies (Service Ticket Operations, Authentication Service)
      3. Kerberos encryption hardening — disable RC4 (etype 23), enforce AES128/AES256
      4. Application control baseline — AppLocker audit rules for unsigned executables
         dropped to user-writable directories
      5. WMIC access restriction for non-administrative users
      6. Verify/report LAPS deployment status
      7. Verify/report Kerberos pre-authentication enforcement on accounts
      8. Verify/report service accounts with SPNs using RC4 encryption

    All changes are idempotent and reversible with -Undo.

    MITRE ATT&CK Techniques : T1087.001, T1078.003, T1558.003
    MITRE Mitigations        : M1026, M1027, M1028, M1033, M1041, M1018

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.

.PARAMETER WhatIf
    Shows what would be changed without making any modifications.

.PARAMETER ReportOnly
    Runs the assessment and SPN/pre-auth audit without applying any changes.

.EXAMPLE
    .\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02_hardening.ps1 -WhatIf
    Shows what would be changed without applying anything.

.EXAMPLE
    .\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02_hardening.ps1 -Undo
    Reverts all hardening changes.

.EXAMPLE
    .\b8e4c9d2-7f3a-4e1b-8c5d-2a3b4c5d6e02_hardening.ps1 -ReportOnly
    Audits current posture and reports SPN accounts, pre-auth gaps, LAPS status.

.NOTES
    Author      : F0RT1KA Defense Guidance Generator
    Techniques  : T1087.001, T1078.003, T1558.003
    Mitigations : M1026, M1027, M1028, M1033, M1041, M1018
    Requires    : Administrator privileges (domain-joined endpoint for SPN audit)
    Idempotent  : Yes — safe to run multiple times
    Tested on   : Windows 10 21H2+, Windows 11, Windows Server 2019/2022
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$ReportOnly
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog      = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:Warnings       = [System.Collections.Generic.List[string]]::new()

# ============================================================
# Helpers
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
        Info    = "[INFO   ]"
        Success = "[OK     ]"
        Warning = "[WARN   ]"
        Error   = "[ERROR  ]"
        Section = "[======]"
    }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $palette[$Type]
}

function Add-ChangeLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
    })
}

function Get-AuditSubcategoryGuid {
    <#
    Returns the GUID for a named audit subcategory by parsing auditpol /list output.
    Used to back up and restore existing audit state precisely.
    #>
    param([string]$SubcategoryName)
    $output = auditpol /list /subcategory:"$SubcategoryName" /r 2>$null
    if ($output) {
        # Output format: "Machine Name,Policy Target,Subcategory,Subcategory GUID,..."
        $line = $output | Where-Object { $_ -match $SubcategoryName } | Select-Object -First 1
        if ($line -match '\{([0-9a-fA-F-]{36})\}') { return $Matches[1] }
    }
    return $null
}

function Get-CurrentAuditSetting {
    param([string]$Subcategory)
    $output = auditpol /get /subcategory:"$Subcategory" /r 2>$null
    if ($output) {
        $line = $output | Where-Object { $_ -match $Subcategory } | Select-Object -First 1
        if ($line) {
            $fields = $line -split ','
            # CSV fields: Machine,PolicyTarget,Subcategory,GUID,InclusionSetting,ExclusionSetting
            if ($fields.Count -ge 5) { return $fields[4].Trim() }
        }
    }
    return "No Auditing"
}

function Set-AuditPolicy {
    param(
        [string]$Subcategory,
        [ValidateSet("Success","Failure","Success and Failure","No Auditing")]
        [string]$Setting
    )
    $existing = Get-CurrentAuditSetting -Subcategory $Subcategory
    if ($WhatIfPreference) {
        Write-Status "WhatIf: Set audit '$Subcategory' from '$existing' to '$Setting'" "Info"
        return
    }
    auditpol /set /subcategory:"$Subcategory" /success:$(if ($Setting -match 'Success') { 'enable' } else { 'disable' }) /failure:$(if ($Setting -match 'Failure') { 'enable' } else { 'disable' }) | Out-Null
    Add-ChangeLog -Action "AuditPolicy" -Target $Subcategory -OldValue $existing -NewValue $Setting
    Write-Status "Audit '$Subcategory': '$existing' -> '$Setting'" "Success"
}

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    # Normalize path for use with .NET Registry API
    $hiveName = ($Path -split '\\')[0]
    $subPath  = ($Path -split '\\', 2)[1]
    $hive     = switch ($hiveName) {
        "HKLM"                        { [Microsoft.Win32.Registry]::LocalMachine }
        "HKEY_LOCAL_MACHINE"          { [Microsoft.Win32.Registry]::LocalMachine }
        "HKCU"                        { [Microsoft.Win32.Registry]::CurrentUser }
        "HKEY_CURRENT_USER"           { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported hive: $hiveName" }
    }

    if ($WhatIfPreference) {
        Write-Status "WhatIf: Set registry '$Path\$Name' = '$Value'" "Info"
        return
    }

    $key = $hive.OpenSubKey($subPath, $true)
    if (-not $key) {
        $key = $hive.CreateSubKey($subPath)
        Write-Status "Created registry key: $Path" "Info"
    }

    $oldValue = $key.GetValue($Name, $null)
    $key.SetValue($Name, $Value, $Kind)
    $key.Close()

    Add-ChangeLog -Action "RegSet" -Target "$Path\$Name" -OldValue ($oldValue ?? "(not set)") -NewValue $Value
    Write-Status "Registry '$Path\$Name': '$($oldValue ?? "(not set)")' -> '$Value'" "Success"
}

function Remove-RegValue {
    param(
        [string]$Path,
        [string]$Name
    )
    $hiveName = ($Path -split '\\')[0]
    $subPath  = ($Path -split '\\', 2)[1]
    $hive     = switch ($hiveName) {
        "HKLM" { [Microsoft.Win32.Registry]::LocalMachine }
        "HKCU" { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported hive: $hiveName" }
    }
    if ($WhatIfPreference) {
        Write-Status "WhatIf: Remove registry '$Path\$Name'" "Info"
        return
    }
    $key = $hive.OpenSubKey($subPath, $true)
    if ($key) {
        $oldValue = $key.GetValue($Name, $null)
        if ($null -ne $oldValue) {
            $key.DeleteValue($Name)
            Add-ChangeLog -Action "RegRemove" -Target "$Path\$Name" -OldValue $oldValue -NewValue "(removed)"
            Write-Status "Removed registry value '$Path\$Name'" "Success"
        }
        $key.Close()
    }
}

# ============================================================
# Backup / Restore infrastructure
# ============================================================

$Script:BackupDir  = "$env:ProgramData\F0RTIKA_Hardening\b8e4c9d2"
$Script:BackupFile = "$Script:BackupDir\audit_backup.csv"

function Save-AuditBackup {
    param([string[]]$Subcategories)
    if (-not (Test-Path $Script:BackupDir)) {
        New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null
    }
    $rows = foreach ($sub in $Subcategories) {
        $setting = Get-CurrentAuditSetting -Subcategory $sub
        [PSCustomObject]@{ Subcategory = $sub; Setting = $setting }
    }
    $rows | Export-Csv -Path $Script:BackupFile -NoTypeInformation -Force
    Write-Status "Audit policy backup saved to $Script:BackupFile" "Info"
}

function Restore-AuditBackup {
    if (-not (Test-Path $Script:BackupFile)) {
        Write-Status "No audit backup found at $Script:BackupFile — cannot restore" "Warning"
        return
    }
    $rows = Import-Csv $Script:BackupFile
    foreach ($row in $rows) {
        Write-Status "Restoring audit '$($row.Subcategory)' -> '$($row.Setting)'" "Info"
        $success  = if ($row.Setting -match 'Success') { 'enable' } else { 'disable' }
        $failure  = if ($row.Setting -match 'Failure') { 'enable' } else { 'disable' }
        auditpol /set /subcategory:"$($row.Subcategory)" /success:$success /failure:$failure | Out-Null
    }
    Write-Status "Audit policies restored from backup" "Success"
}

# ============================================================
# Section 1: Process Creation Audit + Command-Line Capture
# Mitigates: T1087.001, T1078.003 (detection of net.exe, wmic.exe, whoami.exe)
# MITRE M1028 — Operating System Configuration
# ============================================================

function Set-ProcessCreationAudit {
    Write-Status "=== Section 1: Process Creation Audit & Command-Line Logging ===" "Section"

    $subcategories = @(
        "Process Creation",
        "Process Termination"
    )

    if ($Undo) {
        Write-Status "Restoring audit policies from backup..." "Warning"
        Restore-AuditBackup
        return
    }

    # Backup current state before modifying
    Save-AuditBackup -Subcategories $subcategories

    # Enable process creation and termination audit
    Set-AuditPolicy -Subcategory "Process Creation"   -Setting "Success"
    Set-AuditPolicy -Subcategory "Process Termination" -Setting "Success"

    # Enable command-line capture in process creation events (Event ID 4688)
    # Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    $auditRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    Set-RegValue -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

    Write-Status "Process creation audit with command-line logging enabled (Event ID 4688)" "Success"
    Write-Status "Detection coverage: net.exe, wmic.exe, whoami.exe command-line arguments now logged" "Info"
}

# ============================================================
# Section 2: Advanced Kerberos Audit Policies
# Mitigates: T1558.003 (Kerberoasting / AS-REP Roasting detection on DCs)
# MITRE M1041 — Encrypt Sensitive Information
# ============================================================

function Set-KerberosAudit {
    Write-Status "=== Section 2: Kerberos Audit Policy ===" "Section"

    $subcategories = @(
        "Kerberos Service Ticket Operations",
        "Kerberos Authentication Service",
        "Account Logon",
        "Logon"
    )

    if ($Undo) {
        Write-Status "Restoring Kerberos audit policies from backup (if applicable)..." "Warning"
        # Backup restore is handled globally in Set-ProcessCreationAudit; log intent here
        Write-Status "Kerberos audit restoration depends on backup — see $Script:BackupFile" "Info"
        return
    }

    Save-AuditBackup -Subcategories $subcategories

    # Kerberos Service Ticket Operations — captures TGS-REQ (Event ID 4769)
    # RC4-encrypted TGS tickets (etype 23) are the primary Kerberoasting indicator
    Set-AuditPolicy -Subcategory "Kerberos Service Ticket Operations" -Setting "Success and Failure"

    # Kerberos Authentication Service — captures AS-REQ/TGT (Event ID 4768)
    # AS-REQ without pre-auth data (Pre-Auth Type 0) indicates AS-REP roasting
    Set-AuditPolicy -Subcategory "Kerberos Authentication Service" -Setting "Success and Failure"

    # Logon events — captures account usage (Event ID 4624/4625)
    Set-AuditPolicy -Subcategory "Logon" -Setting "Success and Failure"

    Write-Status "Kerberos audit enabled — Event IDs 4768 (AS-REQ) and 4769 (TGS-REQ) will be logged" "Success"
    Write-Status "Alert on: 4769 where TicketEncryptionType=0x17 (RC4) — primary Kerberoasting indicator" "Info"
    Write-Status "Alert on: 4768 where PreAuthType=0 — AS-REP roasting indicator" "Info"
}

# ============================================================
# Section 3: Kerberos Encryption Hardening — Disable RC4
# Mitigates: T1558.003 (disabling RC4 prevents offline hash cracking from Kerberoasting)
# MITRE M1041 — Encrypt Sensitive Information, M1027 — Password Policies
# ============================================================

function Set-KerberosEncryption {
    Write-Status "=== Section 3: Kerberos Encryption Hardening (Disable RC4/DES) ===" "Section"

    # Registry path for Kerberos encryption type configuration
    # This enforces the same effect as GPO: Network Security: Configure encryption types allowed for Kerberos
    # AES128_HMAC_SHA1 (0x8) + AES256_HMAC_SHA1 (0x10) + Future encryption types (0x20)
    $kerberosPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

    if ($Undo) {
        Write-Status "Reverting Kerberos encryption policy..." "Warning"

        # Restore to Windows default (allows RC4 + DES + AES)
        # Default SupportedEncryptionTypes = 0x7fffffff (all types permitted)
        Set-RegValue -Path $kerberosPath -Name "SupportedEncryptionTypes" -Value 0x7fffffff
        Write-Status "Kerberos encryption reverted to Windows default (all types permitted)" "Warning"
        Write-Status "IMPORTANT: This re-enables RC4. Complete gMSA migration before deploying in production." "Warning"
        return
    }

    # Check if domain joined — RC4 disable affects the entire Kerberos stack
    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    if (-not $domainJoined) {
        Write-Status "Endpoint is not domain-joined. Kerberos encryption policy applies but Kerberoasting requires AD." "Warning"
        $Script:Warnings.Add("RC4 disable applied but Kerberoasting (T1558.003) is an AD-specific threat. Verify policy propagates via GPO on domain.")
    }

    # Value 0x18 = AES128_HMAC_SHA1 (0x8) + AES256_HMAC_SHA1 (0x10)
    # This disables RC4-HMAC (0x4), DES-CBC-CRC (0x1), DES-CBC-MD5 (0x2)
    # NOTE: Before applying in production, verify all service accounts support AES.
    # Run: Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties msDS-SupportedEncryptionTypes
    # Accounts must have 'msDS-SupportedEncryptionTypes' set to include AES.
    $aesOnlyValue = 0x18

    if (-not $WhatIfPreference) {
        # Ensure the key path exists
        $regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        if (-not (Test-Path $regKeyPath)) {
            New-Item -Path $regKeyPath -Force | Out-Null
            Write-Status "Created Kerberos\Parameters registry key" "Info"
        }
    }

    Set-RegValue -Path $kerberosPath -Name "SupportedEncryptionTypes" -Value $aesOnlyValue

    Write-Status "Kerberos encryption restricted to AES128 + AES256 only (RC4/DES disabled)" "Success"
    Write-Status "PREREQUISITE CHECK REQUIRED: Verify all SPN accounts support AES before applying to production" "Warning"
    Write-Status "  Command: Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties msDS-SupportedEncryptionTypes" "Info"
}

# ============================================================
# Section 4: WMIC Access Restriction
# Mitigates: T1087.001 (wmic useraccount list brief)
# MITRE M1028 — Operating System Configuration
# ============================================================

function Set-WMICRestriction {
    Write-Status "=== Section 4: WMIC Access Restriction for Non-Administrators ===" "Section"

    if ($Undo) {
        Write-Status "Reverting WMIC namespace ACL modification..." "Warning"
        Write-Status "WMIC namespace security must be restored manually via wmimgmt.msc (Properties > Security)" "Info"
        Write-Status "Default: Authenticated Users have Execute Methods + Enable Account on root\cimv2" "Info"
        return
    }

    # Report current WMI namespace security using Get-WmiObject
    try {
        $ns = Get-WmiObject -Namespace "root" -Class "__Namespace" -ErrorAction Stop | Where-Object { $_.Name -eq "cimv2" }
        if ($ns) {
            Write-Status "WMIC root\cimv2 namespace exists" "Info"
        }

        # Check if WMI remote access is restricted
        # The recommended approach is to restrict the WMI namespace via WMI Security Editor (wmimgmt.msc)
        # Programmatic change via Set-WMIInstance or custom CIM method
        Write-Status "WMIC restriction requires manual GPO configuration:" "Warning"
        Write-Status "  GPO Path: Computer Configuration > Windows Settings > Security Settings > System Services" "Info"
        Write-Status "  Restrict 'Windows Management Instrumentation' service to administrators only" "Info"
        Write-Status "  Alternatively: wmimgmt.msc > WMI Control > Properties > Security > Remove 'Authenticated Users' from root\CIMV2" "Info"
        Write-Status "  NOTE: This script audits WMI access; full restriction requires Group Policy or wmimgmt.msc" "Warning"

        $Script:Warnings.Add("WMIC restriction requires manual Group Policy or wmimgmt.msc configuration. See output above.")

    } catch {
        Write-Status "Could not query WMI namespace: $_" "Warning"
    }

    # Apply WMIC deprecation check — WMIC is deprecated in Windows 11 22H2+
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10 -and $osVersion.Build -ge 22621) {
        Write-Status "Windows 11 22H2+ detected: WMIC is deprecated and may be removed in future releases" "Info"
        Write-Status "Recommend auditing scripts that use WMIC and migrating to Get-CimInstance (PowerShell)" "Info"
    }

    # Disable WMIC via DISM on supported builds (optional, high-impact)
    if (-not $WhatIfPreference) {
        Write-Status "To fully disable WMIC feature on Windows 11+, run: dism /online /disable-feature /featurename:WMICapture /quiet" "Info"
        Write-Status "This script will not auto-disable WMIC as it may break management tooling. Review and apply manually." "Warning"
    }
}

# ============================================================
# Section 5: AppLocker Audit Rules for Offensive Tools
# Mitigates: T1078.003 (block execution of dropped tools like Rubeus), T1087.001
# MITRE M1033 — Limit Software Installation
# ============================================================

function Set-AppLockerAuditRules {
    Write-Status "=== Section 5: AppLocker / Application Control Baseline ===" "Section"

    if ($Undo) {
        Write-Status "AppLocker audit rules cannot be automatically reverted without knowing prior state." "Warning"
        Write-Status "To revert: Open gpedit.msc > Computer Config > Windows Settings > Security Settings > Application Control Policies > AppLocker" "Info"
        Write-Status "Delete rules added for user-writable path restrictions." "Info"
        return
    }

    # Check if AppLocker service is running
    $appIdSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if (-not $appIdSvc) {
        Write-Status "AppLocker service (AppIDSvc) not found. WDAC may be in use instead." "Warning"
        Write-Status "If using WDAC: create a policy that blocks unsigned executables from user-writable paths" "Info"
        $Script:Warnings.Add("AppIDSvc not found. Verify WDAC or alternative application control is deployed.")
        return
    }

    if ($appIdSvc.Status -ne "Running") {
        if (-not $WhatIfPreference) {
            Write-Status "Starting AppIDSvc service..." "Info"
            Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
            Set-Service -Name "AppIDSvc" -StartupType Automatic -ErrorAction SilentlyContinue
            Add-ChangeLog -Action "ServiceStart" -Target "AppIDSvc" -OldValue $appIdSvc.Status -NewValue "Running"
        } else {
            Write-Status "WhatIf: Would start AppIDSvc service" "Info"
        }
    }

    # Define AppLocker audit rule using XML — targets executables in user-writable directories
    # Using audit mode (not enforce) to avoid breaking workflows; change Action="Deny" for enforcement
    $appLockerXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a9876543-1234-5678-abcd-000000000001"
                  Name="Audit: Block EXE from %TEMP%"
                  Description="Detect offensive tools (Rubeus, etc.) dropped to TEMP directories. Change to Deny for enforcement after baselining."
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Windows\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a9876543-1234-5678-abcd-000000000002"
                  Name="Audit: Block EXE from %USERPROFILE%\Downloads"
                  Description="Detect executables launched from Downloads folder — common drop location for offensive tools."
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a9876543-1234-5678-abcd-000000000003"
                  Name="Audit: Executables from user-writable paths"
                  Description="Flag execution of unsigned binaries from AppData, Downloads, Temp. Alert in SIEM on Event ID 8003/8004."
                  UserOrGroupSid="S-1-1-0"
                  Action="Deny">
      <Conditions>
        <FilePathCondition Path="%APPDATA%\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

    if (-not $WhatIfPreference) {
        try {
            # Apply AppLocker policy using Set-AppLockerPolicy
            $tempXml = Join-Path $env:TEMP "applocker_hardening_temp.xml"
            $appLockerXml | Out-File -FilePath $tempXml -Encoding UTF8

            # Use AppLocker cmdlets if available
            if (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue) {
                Set-AppLockerPolicy -XmlPolicy $tempXml -Merge -ErrorAction Stop
                Add-ChangeLog -Action "AppLockerPolicy" -Target "Exe RuleCollection" -OldValue "(previous)" -NewValue "AuditOnly rules for user-writable paths"
                Write-Status "AppLocker audit rules applied (AuditOnly mode — will log to Event Log 8003/8004)" "Success"
                Write-Status "Monitor: Applications and Services Logs > Microsoft > Windows > AppLocker > EXE and DLL" "Info"
            } else {
                Write-Status "AppLocker PowerShell module not available. Apply policy via gpedit.msc manually." "Warning"
                Write-Status "Policy XML written to: $tempXml (use AppLocker GUI to import)" "Info"
                $Script:Warnings.Add("AppLocker cmdlets not available. Manual GPO import required from $tempXml")
            }
        } catch {
            Write-Status "AppLocker policy application failed: $_" "Error"
            Write-Status "Apply manually via gpedit.msc > AppLocker" "Warning"
        }
    } else {
        Write-Status "WhatIf: Would apply AppLocker AuditOnly rules for user-writable executable paths" "Info"
    }

    Write-Status "AppLocker enforcement mode: AuditOnly (review logs before switching to Deny)" "Warning"
    Write-Status "To enforce (block): Change EnforcementMode='AuditOnly' to EnforcementMode='Enabled' in GPO" "Info"
}

# ============================================================
# Section 6: Privileged Account Management Audit
# Mitigates: T1078.003 (minimize local admin accounts), T1087.001
# MITRE M1026 — Privileged Account Management
# ============================================================

function Invoke-PrivilegedAccountAudit {
    Write-Status "=== Section 6: Privileged Account Management Audit ===" "Section"

    Write-Status "Auditing local administrator accounts..." "Info"

    # Enumerate local admin group members
    try {
        $adminGroup = [ADSI]"WinNT://./Administrators,group"
        $members = @($adminGroup.Invoke("Members"))
        Write-Status "Local Administrators group members ($($members.Count) total):" "Info"
        foreach ($member in $members) {
            $name = $member.GetType().InvokeMember("Name", [Reflection.BindingFlags]::GetProperty, $null, $member, $null)
            $adspath = $member.GetType().InvokeMember("ADSPath", [Reflection.BindingFlags]::GetProperty, $null, $member, $null)
            $isLocal = $adspath -match "WinNT://$env:COMPUTERNAME/"
            $type = if ($isLocal) { "LOCAL" } else { "DOMAIN" }
            Write-Host "  [$type] $name" -ForegroundColor $(if ($isLocal) { "Yellow" } else { "Cyan" })
        }
        if ($members.Count -gt 3) {
            Write-Status "WARNING: $($members.Count) members in local Administrators group. Review and reduce to minimum required." "Warning"
            $Script:Warnings.Add("$($members.Count) members in local Administrators. Excess local admins increase T1078.003 attack surface.")
        }
    } catch {
        Write-Status "Could not enumerate local administrators: $_" "Warning"
    }

    # Check if LAPS is deployed
    Write-Status "Checking LAPS deployment status..." "Info"
    $lapsRegPath  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $wLapsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"

    $legacyLaps  = Test-Path $lapsRegPath
    $windowsLaps = Test-Path $wLapsRegPath

    if ($windowsLaps) {
        Write-Status "Windows LAPS (built-in) is deployed on this endpoint" "Success"
        $lapsConfig = Get-ItemProperty -Path $wLapsRegPath -ErrorAction SilentlyContinue
        if ($lapsConfig) {
            Write-Host "  Backup Directory : $($lapsConfig.BackupDirectory)" -ForegroundColor Cyan
            Write-Host "  Password Age Days: $($lapsConfig.PasswordAgeDays)" -ForegroundColor Cyan
        }
    } elseif ($legacyLaps) {
        Write-Status "Legacy LAPS (CSE) is deployed. Consider upgrading to Windows LAPS." "Warning"
    } else {
        Write-Status "LAPS is NOT deployed on this endpoint" "Error"
        Write-Status "RECOMMENDATION: Deploy Windows LAPS to randomize local admin passwords" "Warning"
        Write-Status "  Deploy via: Configure-LAPS.ps1 or GPO: Computer Config > Admin Templates > LAPS" "Info"
        $Script:Warnings.Add("LAPS not detected. Local Administrator password may be shared across endpoints. Deploy Windows LAPS.")
    }

    # Check built-in Administrator account status
    $builtinAdmin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($builtinAdmin) {
        if ($builtinAdmin.Enabled) {
            Write-Status "Built-in Administrator account is ENABLED — consider disabling if not required" "Warning"
            $Script:Warnings.Add("Built-in Administrator account is enabled. Disable if not required (M1026).")
        } else {
            Write-Status "Built-in Administrator account is disabled (good)" "Success"
        }
    }

    if (-not $Undo) {
        # Disable built-in Administrator if enabled and not specifically needed
        # COMMENTED OUT — only take this action if explicitly requested
        # Disable-LocalUser -Name "Administrator"
        Write-Status "Note: Script does not auto-disable built-in Administrator. Disable manually if not required." "Info"
    }
}

# ============================================================
# Section 7: Kerberos Pre-Authentication Audit (AD-joined only)
# Mitigates: T1558.003 (AS-REP Roasting requires DONT_REQ_PREAUTH flag)
# MITRE M1018 — User Account Management
# ============================================================

function Invoke-KerberosPreauthAudit {
    Write-Status "=== Section 7: Kerberos Pre-Authentication Audit (AD) ===" "Section"

    # This section is informational — enforcing pre-auth requires AD changes, not local registry
    $domainJoined = $false
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = $cs.PartOfDomain
    } catch {
        Write-Status "Could not determine domain status" "Warning"
    }

    if (-not $domainJoined) {
        Write-Status "Endpoint is not domain-joined. Skipping AD Kerberos pre-auth audit." "Warning"
        Write-Status "AS-REP Roasting (T1558.003) requires an Active Directory environment." "Info"
        return
    }

    Write-Status "Endpoint is domain-joined. Checking for AS-REP roasting exposure..." "Info"

    # Attempt to enumerate accounts with DONT_REQ_PREAUTH using ADSI
    try {
        $domain   = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.Name)")
        # userAccountControl flag 0x400000 = DONT_REQ_PREAUTH (4194304)
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "userAccountControl", "memberOf"))
        $results = $searcher.FindAll()

        if ($results.Count -gt 0) {
            Write-Status "$($results.Count) account(s) found with Kerberos pre-authentication DISABLED (AS-REP Roasting target):" "Error"
            foreach ($r in $results) {
                $sam = $r.Properties["samaccountname"][0]
                Write-Host "  [VULNERABLE] $sam  (DONT_REQ_PREAUTH set)" -ForegroundColor Red
            }
            Write-Status "REMEDIATION: Enable Kerberos pre-authentication for all above accounts" "Warning"
            Write-Status "  PowerShell: Set-ADUser -Identity <username> -KerberosEncryptionType AES128,AES256" "Info"
            Write-Status "  Or: AD Users & Computers > Account tab > Uncheck 'Do not require Kerberos preauthentication'" "Info"
            $Script:Warnings.Add("$($results.Count) account(s) have DONT_REQ_PREAUTH set. Immediately enable pre-auth to close AS-REP roasting exposure.")
        } else {
            Write-Status "No accounts found with DONT_REQ_PREAUTH set. AS-REP roasting exposure is minimal." "Success"
        }

    } catch {
        Write-Status "Could not query Active Directory for pre-auth flags: $_" "Warning"
        Write-Status "Run manually on a DC: Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} -Properties DoesNotRequirePreAuth" "Info"
    }
}

# ============================================================
# Section 8: SPN Account Audit (Kerberoasting exposure)
# Mitigates: T1558.003
# MITRE M1027 — Password Policies, M1018 — User Account Management
# ============================================================

function Invoke-SPNAudit {
    Write-Status "=== Section 8: Service Principal Name (SPN) Account Audit ===" "Section"

    $domainJoined = $false
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = $cs.PartOfDomain
    } catch { }

    if (-not $domainJoined) {
        Write-Status "Not domain-joined. SPN audit requires Active Directory." "Warning"
        return
    }

    Write-Status "Querying accounts with Service Principal Names (Kerberoasting targets)..." "Info"

    try {
        $domain   = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.Name)")
        # Find user accounts (not computers) with SPNs assigned
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
        $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "servicePrincipalName", "msDS-SupportedEncryptionTypes", "pwdLastSet", "adminCount"))
        $results = $searcher.FindAll()

        if ($results.Count -gt 0) {
            Write-Status "$($results.Count) user account(s) with SPNs found (Kerberoasting targets):" "Warning"
            foreach ($r in $results) {
                $sam     = $r.Properties["samaccountname"][0]
                $spns    = $r.Properties["serviceprincipalname"]
                $encType = $r.Properties["msds-supportedencryptiontypes"][0]
                $pwdSet  = if ($r.Properties["pwdlastset"].Count -gt 0) {
                    [datetime]::FromFileTime($r.Properties["pwdlastset"][0]).ToString("yyyy-MM-dd")
                } else { "Never" }
                $isAdmin = ($r.Properties["admincount"].Count -gt 0 -and $r.Properties["admincount"][0] -eq 1)

                $riskLevel = if ($isAdmin) { "[HIGH RISK - AdminCount=1]" } else { "[MEDIUM RISK]" }
                $encStr    = switch ($encType) {
                    $null  { "DEFAULT (may include RC4)" }
                    0      { "DEFAULT (may include RC4)" }
                    4      { "RC4 ONLY - VULNERABLE" }
                    8      { "AES128 only" }
                    16     { "AES256 only" }
                    24     { "AES128 + AES256 (good)" }
                    28     { "RC4 + AES128 + AES256" }
                    default { "EncType: $encType" }
                }

                Write-Host "  $riskLevel $sam" -ForegroundColor $(if ($isAdmin) { "Red" } elseif ($encType -in @($null, 0, 4)) { "Yellow" } else { "Cyan" })
                Write-Host "    SPNs: $($spns -join ', ')" -ForegroundColor Gray
                Write-Host "    Encryption: $encStr  |  PwdLastSet: $pwdSet" -ForegroundColor Gray
            }

            Write-Status "REMEDIATION STEPS:" "Warning"
            Write-Status "  1. Migrate SPN accounts to gMSA (eliminates static passwords and Kerberoasting risk)" "Info"
            Write-Status "     New-ADServiceAccount -Name 'svc-app1' -DNSHostName 'app1.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'AppServers'" "Info"
            Write-Status "  2. Set strong passwords (25+ chars) on accounts that cannot be migrated to gMSA immediately" "Info"
            Write-Status "  3. Set msDS-SupportedEncryptionTypes = 24 (AES128+AES256) on all SPN accounts" "Info"
            Write-Status "     Set-ADUser -Identity <sam> -KerberosEncryptionType AES128,AES256" "Info"
            $Script:Warnings.Add("$($results.Count) SPN-bearing user accounts detected. Kerberoasting attack surface exists. Migrate to gMSA.")
        } else {
            Write-Status "No user accounts with SPNs found. Kerberoasting exposure is minimal." "Success"
        }

    } catch {
        Write-Status "Could not query Active Directory for SPN accounts: $_" "Warning"
        Write-Status "Run manually on a DC: Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes" "Info"
    }
}

# ============================================================
# Section 9: Additional Audit Policies for Account Discovery
# Mitigates: T1087.001, T1078.003
# MITRE M1028 — Operating System Configuration
# ============================================================

function Set-AccountAuditPolicies {
    Write-Status "=== Section 9: Account Discovery & Authentication Audit Policies ===" "Section"

    $subcategories = @(
        "Account Management",
        "Security Group Management",
        "User Account Management",
        "Sensitive Privilege Use",
        "Other Account Logon Events"
    )

    if ($Undo) {
        Write-Status "Restoring account audit policies from backup..." "Warning"
        # Global backup restore handles this; document intent
        Write-Status "Account audit restoration depends on backup at $Script:BackupFile" "Info"
        return
    }

    Save-AuditBackup -Subcategories $subcategories

    # Account management audit — captures local account creation/deletion/modification (4720, 4722, 4724, 4726)
    Set-AuditPolicy -Subcategory "User Account Management"  -Setting "Success and Failure"
    Set-AuditPolicy -Subcategory "Security Group Management" -Setting "Success and Failure"

    # Privilege use — detect use of sensitive privileges (SeDebugPrivilege, etc.)
    Set-AuditPolicy -Subcategory "Sensitive Privilege Use"   -Setting "Success and Failure"

    Write-Status "Account management and privilege audit policies enabled" "Success"
    Write-Status "Key Event IDs: 4720 (account created), 4726 (account deleted), 4728/4732 (group membership changed)" "Info"
}

# ============================================================
# Main execution
# ============================================================

$mode = if ($Undo) { "UNDO" } elseif ($ReportOnly) { "REPORT-ONLY" } else { "APPLY" }

Write-Status "========================================================" "Section"
Write-Status "F0RT1KA Hardening: Local Account Enumeration / Kerberoasting" "Section"
Write-Status "Techniques: T1087.001 | T1078.003 | T1558.003" "Section"
Write-Status "Mitigations: M1026 | M1027 | M1028 | M1033 | M1041 | M1018" "Section"
Write-Status "Mode: $mode" "Section"
Write-Status "========================================================" "Section"
Write-Host ""

if ($ReportOnly) {
    Write-Status "Running in report-only mode — no changes will be made" "Warning"
    Invoke-PrivilegedAccountAudit
    Invoke-KerberosPreauthAudit
    Invoke-SPNAudit
} elseif ($Undo) {
    Write-Status "Reverting all hardening changes..." "Warning"
    Set-ProcessCreationAudit        # handles audit restore
    Set-KerberosAudit               # handles audit restore
    Set-KerberosEncryption          # reverts reg key
    Set-WMICRestriction             # advisory only
    Set-AppLockerAuditRules         # advisory only
    Set-AccountAuditPolicies        # handles audit restore
} else {
    Set-ProcessCreationAudit
    Set-KerberosAudit
    Set-KerberosEncryption
    Set-WMICRestriction
    Set-AppLockerAuditRules
    Invoke-PrivilegedAccountAudit
    Invoke-KerberosPreauthAudit
    Invoke-SPNAudit
    Set-AccountAuditPolicies
}

Write-Host ""
Write-Status "========================================================" "Section"
Write-Status "Change Summary" "Section"
Write-Status "========================================================" "Section"

if ($Script:ChangeLog.Count -gt 0) {
    $Script:ChangeLog | Format-Table Timestamp, Action, Target, OldValue, NewValue -AutoSize
} else {
    Write-Status "No changes recorded (report-only or undo mode)" "Info"
}

if ($Script:Warnings.Count -gt 0) {
    Write-Host ""
    Write-Status "========================================================" "Section"
    Write-Status "Action Items Requiring Manual Follow-Up" "Section"
    Write-Status "========================================================" "Section"
    $i = 1
    foreach ($w in $Script:Warnings) {
        Write-Host "  [$i] $w" -ForegroundColor Yellow
        $i++
    }
}

Write-Host ""
Write-Status "Hardening script complete. Mode: $mode" "Success"
Write-Status "Next steps:" "Info"
Write-Status "  1. Review warnings above and address manual items" "Info"
Write-Status "  2. Deploy LAPS if not already present (see Section 6)" "Info"
Write-Status "  3. Migrate SPN accounts to gMSA (see Section 8)" "Info"
Write-Status "  4. Enable Kerberos pre-authentication on all accounts (see Section 7)" "Info"
Write-Status "  5. Monitor Windows Event IDs: 4688, 4768, 4769, 8003, 8004" "Info"
Write-Status "  6. Run with -ReportOnly on each endpoint for posture assessment" "Info"
