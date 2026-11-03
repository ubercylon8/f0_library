<#
.SYNOPSIS
    Applies selected Windows baseline hardening for a SentinelOne-protected host.

.DESCRIPTION
    Documentation artifact for administrative review; the baseline assessment does
    not execute this script. It configures selected local registry, NetBIOS, and
    advanced audit settings. It does not configure SentinelOne, Defender/ASR,
    LAPS, account policy, or the Print Spooler service.

    Original values are stored in a local JSON state file. Apply is idempotent and
    retains the first recorded baseline. Undo restores only values that still match
    the script-applied state, avoiding overwrite of later third-party changes.
    Central GPO or MDM policy can overwrite local settings and must be remediated
    separately. Reboot and runtime verification are required for some settings.

.PARAMETER Undo
    Restores recorded original registry, NetBIOS, and audit-policy values.

.PARAMETER WhatIf
    Shows changes without modifying configuration or writing rollback state.

.PARAMETER StatePath
    Rollback state location. Defaults to
    %ProgramData%\SentinelOneWindowsBaseline\state.json.

.EXAMPLE
    .\sentinelone_windows_baseline.ps1 -WhatIf
    Preview all selected local changes.

.EXAMPLE
    .\sentinelone_windows_baseline.ps1
    Apply selected local changes after pilot testing.

.EXAMPLE
    .\sentinelone_windows_baseline.ps1 -Undo -WhatIf
    Preview rollback without making changes.

.EXAMPLE
    .\sentinelone_windows_baseline.ps1 -Undo
    Restore recorded values that have not drifted.

.NOTES
    Author: F0RT1KA Defense Guidance Generator
    Requires: Administrator privileges; Windows PowerShell 5.1 or later.
    Idempotent: Yes; original state is preserved across repeated Apply runs.
    Impact: Test Credential Guard, Constrained Language Mode, SMB, NetBIOS,
    WPAD, IPv6 transition, and auditing changes against workload dependencies.
    Audit subcategory names and parsing assume English auditpol output; on
    localized systems, use the equivalent centrally managed audit policy.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [switch]$Undo,
    [string]$StatePath = (Join-Path -Path $env:ProgramData -ChildPath "SentinelOneWindowsBaseline\state.json")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$Script:StateDirty = $false
$Script:DriftCount = 0
$Script:ChangeLog = @()

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )

    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param([string]$Action, [string]$Target)

    $Script:ChangeLog += [PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Action    = $Action
        Target    = $Target
    }
}

function Initialize-State {
    if (Test-Path -LiteralPath $StatePath) {
        $Script:State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        return $true
    }

    $Script:State = [ordered]@{
        Version = 1
        Registry = @()
        NetBIOS  = @()
        Audit    = @()
    }
    return $false
}

function Save-State {
    if (-not $Script:StateDirty -or $WhatIfPreference) {
        return
    }

    $directory = Split-Path -Parent $StatePath
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $json = $Script:State | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $StatePath -Value $json -Encoding UTF8
    $Script:StateDirty = $false
    Write-Status "Rollback state saved to $StatePath" "Info"
}

function Get-RegistrySnapshot {
    param([string]$Path, [string]$Name)

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return [PSCustomObject]@{ Exists = $false; Value = $null; Kind = $null }
    }

    $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -eq $value) {
        $key.Close()
        return [PSCustomObject]@{ Exists = $false; Value = $null; Kind = $null }
    }

    $kind = $key.GetValueKind($Name).ToString()
    $key.Close()
    return [PSCustomObject]@{ Exists = $true; Value = $value; Kind = $kind }
}

function Test-ValueEqual {
    param($Left, $Right)

    if ($null -eq $Left -or $null -eq $Right) {
        return ($null -eq $Left -and $null -eq $Right)
    }
    return [string]$Left -eq [string]$Right
}

function Get-RegistryStateEntry {
    param([string]$Path, [string]$Name)

    return @($Script:State.Registry) |
        Where-Object { $_.Path -eq $Path -and $_.Name -eq $Name } |
        Select-Object -First 1
}

function Set-RegistryDword {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$Name,
        [uint32]$DesiredValue,
        [int[]]$AcceptedValues = @(),
        [string]$Description
    )

    $current = Get-RegistrySnapshot -Path $Path -Name $Name
    if ($AcceptedValues.Count -eq 0) {
        $AcceptedValues = @([int]$DesiredValue)
    }

    if ($current.Exists -and $AcceptedValues -contains [int]$current.Value) {
        Write-Status "Compliant: $Description ($Path\$Name)" "Info"
        return
    }

    $target = "$Path\$Name"
    if ($PSCmdlet.ShouldProcess($target, "Set DWORD to $DesiredValue — $Description")) {
        $entry = Get-RegistryStateEntry -Path $Path -Name $Name
        if ($null -eq $entry) {
            $entry = [PSCustomObject]@{
                Path           = $Path
                Name           = $Name
                OriginalExists = $current.Exists
                OriginalValue  = $current.Value
                OriginalKind   = $current.Kind
                AppliedValue   = $DesiredValue
                Description    = $Description
            }
            $Script:State.Registry = @($Script:State.Registry) + $entry
        } else {
            $entry.AppliedValue = $DesiredValue
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $DesiredValue -Force | Out-Null
        $Script:StateDirty = $true
        Add-ChangeLog -Action "Set $Description to $DesiredValue" -Target $target
    }
}

function Undo-RegistryChanges {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    foreach ($entry in @($Script:State.Registry)) {
        $current = Get-RegistrySnapshot -Path $entry.Path -Name $entry.Name
        $originalMatches = ($current.Exists -eq $entry.OriginalExists) -and
            (-not $current.Exists -or (Test-ValueEqual $current.Value $entry.OriginalValue))

        if ($originalMatches) {
            Write-Status "Already at original state: $($entry.Path)\$($entry.Name)" "Info"
            continue
        }

        $appliedMatches = $current.Exists -and (Test-ValueEqual $current.Value $entry.AppliedValue)
        if (-not $appliedMatches) {
            $Script:DriftCount++
            Write-Status "Skipped drifted value: $($entry.Path)\$($entry.Name)" "Warning"
            continue
        }

        $target = "$($entry.Path)\$($entry.Name)"
        if ($PSCmdlet.ShouldProcess($target, "Restore original registry state")) {
            if ($entry.OriginalExists) {
                if (-not (Test-Path -LiteralPath $entry.Path)) {
                    New-Item -Path $entry.Path -Force | Out-Null
                }
                New-ItemProperty -Path $entry.Path -Name $entry.Name -PropertyType $entry.OriginalKind -Value $entry.OriginalValue -Force | Out-Null
            } elseif ($current.Exists) {
                Remove-ItemProperty -Path $entry.Path -Name $entry.Name -Force
            }
            Add-ChangeLog -Action "Restored original state" -Target $target
        }
    }
}

function Set-NetBiosBaseline {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'")
    foreach ($adapter in $adapters) {
        if ([int]$adapter.TcpipNetbiosOptions -eq 2) {
            continue
        }

        $target = "NetBIOS over TCP/IP on adapter $($adapter.SettingID)"
        if ($PSCmdlet.ShouldProcess($target, "Set TcpipNetbiosOptions to 2 (disabled)")) {
            $entry = @($Script:State.NetBIOS) |
                Where-Object { $_.SettingID -eq $adapter.SettingID } |
                Select-Object -First 1
            if ($null -eq $entry) {
                $entry = [PSCustomObject]@{
                    SettingID       = $adapter.SettingID
                    OriginalOptions = [uint32]$adapter.TcpipNetbiosOptions
                    AppliedOptions  = [uint32]2
                }
                $Script:State.NetBIOS = @($Script:State.NetBIOS) + $entry
            } else {
                $entry.AppliedOptions = [uint32]2
            }

            $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
            if ($result.ReturnValue -ne 0) {
                throw "SetTcpipNetbios failed for $($adapter.SettingID) with return value $($result.ReturnValue)"
            }

            $Script:StateDirty = $true
            Add-ChangeLog -Action "Disabled NetBIOS over TCP/IP" -Target $target
        }
    }
}

function Undo-NetBiosChanges {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'")
    foreach ($entry in @($Script:State.NetBIOS)) {
        $adapter = $adapters | Where-Object { $_.SettingID -eq $entry.SettingID } | Select-Object -First 1
        if ($null -eq $adapter) {
            $Script:DriftCount++
            Write-Status "Skipped missing adapter: $($entry.SettingID)" "Warning"
            continue
        }

        if ([uint32]$adapter.TcpipNetbiosOptions -eq [uint32]$entry.OriginalOptions) {
            continue
        }
        if ([uint32]$adapter.TcpipNetbiosOptions -ne [uint32]$entry.AppliedOptions) {
            $Script:DriftCount++
            Write-Status "Skipped drifted adapter: $($entry.SettingID)" "Warning"
            continue
        }

        $target = "NetBIOS over TCP/IP on adapter $($entry.SettingID)"
        if ($PSCmdlet.ShouldProcess($target, "Restore TcpipNetbiosOptions to $($entry.OriginalOptions)")) {
            $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]$entry.OriginalOptions }
            if ($result.ReturnValue -ne 0) {
                throw "SetTcpipNetbios rollback failed for $($entry.SettingID) with return value $($result.ReturnValue)"
            }
            Add-ChangeLog -Action "Restored original NetBIOS state" -Target $target
        }
    }
}

function Get-AuditSnapshot {
    param([string]$Name)

    $output = @(& auditpol.exe /get "/subcategory:$Name" /r)
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol query failed for '$Name' with exit code $LASTEXITCODE"
    }

    $rows = @($output | ConvertFrom-Csv)
    if ($rows.Count -eq 0) {
        throw "auditpol returned no parseable row for '$Name'"
    }

    $properties = @($rows[0].PSObject.Properties)
    $setting = [string]$properties[$properties.Count - 1].Value
    return [PSCustomObject]@{
        Success = ($setting -match "(?i)\bSuccess\b")
        Failure = ($setting -match "(?i)\bFailure\b")
        Text    = $setting
    }
}

function Get-AuditStateEntry {
    param([string]$Name)

    return @($Script:State.Audit) |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -First 1
}

function Set-AuditPolicyValue {
    param([string]$Name, [bool]$Success, [bool]$Failure)

    $successText = if ($Success) { "enable" } else { "disable" }
    $failureText = if ($Failure) { "enable" } else { "disable" }
    & auditpol.exe /set "/subcategory:$Name" "/success:$successText" "/failure:$failureText" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol set failed for '$Name' with exit code $LASTEXITCODE"
    }
}

function Set-AuditBaseline {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name,
        [ValidateSet("success", "failure", "both")]
        [string]$Required
    )

    $current = Get-AuditSnapshot -Name $Name
    $desiredSuccess = $current.Success -or $Required -in @("success", "both")
    $desiredFailure = $current.Failure -or $Required -in @("failure", "both")
    if ($current.Success -eq $desiredSuccess -and $current.Failure -eq $desiredFailure) {
        Write-Status "Compliant audit policy: $Name" "Info"
        return
    }

    if ($PSCmdlet.ShouldProcess("Audit subcategory $Name", "Require $Required auditing")) {
        $entry = Get-AuditStateEntry -Name $Name
        if ($null -eq $entry) {
            $entry = [PSCustomObject]@{
                Name            = $Name
                OriginalSuccess = $current.Success
                OriginalFailure = $current.Failure
                AppliedSuccess  = $desiredSuccess
                AppliedFailure  = $desiredFailure
            }
            $Script:State.Audit = @($Script:State.Audit) + $entry
        } else {
            $entry.AppliedSuccess = $desiredSuccess
            $entry.AppliedFailure = $desiredFailure
        }

        Set-AuditPolicyValue -Name $Name -Success $desiredSuccess -Failure $desiredFailure
        $Script:StateDirty = $true
        Add-ChangeLog -Action "Set required auditing: $Required" -Target "Audit subcategory $Name"
    }
}

function Undo-AuditChanges {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    foreach ($entry in @($Script:State.Audit)) {
        $current = Get-AuditSnapshot -Name $entry.Name
        $originalMatches = $current.Success -eq $entry.OriginalSuccess -and $current.Failure -eq $entry.OriginalFailure
        if ($originalMatches) {
            continue
        }

        $appliedMatches = $current.Success -eq $entry.AppliedSuccess -and $current.Failure -eq $entry.AppliedFailure
        if (-not $appliedMatches) {
            $Script:DriftCount++
            Write-Status "Skipped drifted audit policy: $($entry.Name)" "Warning"
            continue
        }

        if ($PSCmdlet.ShouldProcess("Audit subcategory $($entry.Name)", "Restore original success/failure auditing")) {
            Set-AuditPolicyValue -Name $entry.Name -Success $entry.OriginalSuccess -Failure $entry.OriginalFailure
            Add-ChangeLog -Action "Restored original audit policy" -Target "Audit subcategory $($entry.Name)"
        }
    }
}

$stateExisted = Initialize-State
if ($Undo -and -not $stateExisted) {
    Write-Status "No rollback state exists at $StatePath; nothing to undo." "Warning"
    return
}

$auditRequirements = @(
    [PSCustomObject]@{ Name = "Logon"; Required = "both" },
    [PSCustomObject]@{ Name = "Logoff"; Required = "success" },
    [PSCustomObject]@{ Name = "Account Lockout"; Required = "failure" },
    [PSCustomObject]@{ Name = "Special Logon"; Required = "success" },
    [PSCustomObject]@{ Name = "Process Creation"; Required = "success" },
    [PSCustomObject]@{ Name = "Audit Policy Change"; Required = "success" },
    [PSCustomObject]@{ Name = "User Account Management"; Required = "both" },
    [PSCustomObject]@{ Name = "Computer Account Management"; Required = "success" },
    [PSCustomObject]@{ Name = "Security Group Management"; Required = "success" }
)

try {
    if ($Undo) {
        Write-Status "Previewing or restoring recorded local settings..." "Warning"
        Undo-RegistryChanges
        Undo-NetBiosChanges
        Undo-AuditChanges
    } else {
        Write-Status "Applying selected local Windows baseline settings..." "Info"

        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -DesiredValue 1 -AcceptedValues @(1, 2) -Description "LSASS Protected Process Light"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -DesiredValue 2 -AcceptedValues @(1, 2) -Description "Credential Guard without UEFI lock"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -DesiredValue 1 -Description "Virtualization-Based Security"

        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -DesiredValue 1 -Description "PowerShell Script Block Logging"
        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -DesiredValue 1 -Description "PowerShell Module Logging"
        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -DesiredValue 1 -Description "PowerShell Transcription"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -DesiredValue 4 -Description "PowerShell Constrained Language Policy"

        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -DesiredValue 1 -Description "SMB Server Signing Required"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -DesiredValue 1 -Description "SMB Client Signing Required"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EncryptData" -DesiredValue 1 -Description "SMB Server Encryption"
        Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -DesiredValue 1 -Description "SMB Null Session Restriction"

        if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10") {
            Set-RegistryDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -DesiredValue 4 -Description "SMBv1 Driver Disabled"
        } else {
            Write-Status "SMBv1 driver key is absent; no change required." "Info"
        }

        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -DesiredValue 0 -Description "LLMNR Disabled"
        Set-RegistryDword -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "WpadOverride" -DesiredValue 1 -Description "WPAD Override"

        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $ipv6Current = Get-RegistrySnapshot -Path $ipv6Path -Name "DisabledComponents"
        $ipv6Desired = [uint32]0x21
        if ($ipv6Current.Exists) {
            $ipv6Desired = ([uint32]$ipv6Current.Value -bor [uint32]0x21)
        }
        Set-RegistryDword -Path $ipv6Path -Name "DisabledComponents" -DesiredValue $ipv6Desired -Description "Disable IPv6 tunnel interfaces and prefer IPv4 while preserving other bits"

        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -DesiredValue 1 -Description "Restrict Printer Driver Installation"
        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -DesiredValue 0 -Description "Point and Print Installation Warning"
        Set-RegistryDword -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -DesiredValue 0 -Description "Point and Print Update Prompt"

        Set-NetBiosBaseline

        foreach ($requirement in $auditRequirements) {
            Set-AuditBaseline -Name $requirement.Name -Required $requirement.Required
        }
    }
} finally {
    Save-State
}

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes performed:" "Success"
    $Script:ChangeLog | Format-Table -AutoSize
}
if ($Script:DriftCount -gt 0) {
    Write-Status "$Script:DriftCount item(s) were skipped because they no longer match script-applied state." "Warning"
}

Write-Status "Selected local operation complete. SentinelOne central policy, LAPS, account policy, and Print Spooler service state were not changed." "Success"
Write-Status "Reboot and validate runtime state where required; confirm that central policy does not overwrite local settings." "Info"
