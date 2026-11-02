<#
.SYNOPSIS
    Hardens Windows against BYOVD, DLL side-loading, injection, LSASS access,
    security-tool impairment, recovery inhibition, and ransomware behaviors.

.DESCRIPTION
    Applies technique-focused Windows settings for T1562.001, T1211, T1055,
    T1003.001, T1490, and T1486, with discovery telemetry for T1518.001/T1082.
    The conservative baseline enables the built-in vulnerable-driver blocklist,
    selected ASR rules, LSA audit mode, command-line population, PowerShell
    Script Block Logging, safe DLL search, and Controlled Folder Access audit.

    High-impact enforcement is opt-in. All changes are idempotent. Original
    values are recorded under ProgramData and restored by -Undo. The script
    does not deploy a custom WDAC policy, change third-party security products,
    add exclusions, or target any security-test path or artifact.

.PARAMETER Undo
    Restores only the original values recorded by earlier runs of this script.

.PARAMETER EnforceLSAProtection
    Configures LSASS as a protected process without creating a UEFI lock.
    Requires Windows 11 22H2 or later and a restart. Audit plug-ins first.

.PARAMETER EnforceControlledFolderAccess
    Changes Controlled Folder Access and advanced ransomware ASR from audit to
    block/enabled mode. Test applications and exclusions before using this.

.PARAMETER EnableCredentialGuard
    Configures VBS and Credential Guard without creating a UEFI lock.
    Requires compatible hardware and a restart.

.PARAMETER EnableMemoryIntegrity
    Configures VBS and memory integrity (HVCI). Requires compatible hardware,
    drivers, and a restart. Validate recovery procedures first.

.PARAMETER WhatIf
    Shows operations without writing settings or rollback state.

.EXAMPLE
    .\hardening.ps1 -WhatIf
    Previews the conservative baseline.

.EXAMPLE
    .\hardening.ps1
    Applies the conservative baseline.

.EXAMPLE
    .\hardening.ps1 -EnforceLSAProtection -EnforceControlledFolderAccess
    Applies the baseline and the two named enforcement controls.

.EXAMPLE
    .\hardening.ps1 -Undo
    Restores settings changed by this script to their recorded original values.

.NOTES
    Requires administrator privileges on Windows.
    Microsoft Defender ASR/CFA settings are ineffective when Defender is not
    an active antimalware provider. Use supported central management in an
    enterprise and avoid conflicting local and centrally managed policies.
#>
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Undo,
    [switch]$EnforceLSAProtection,
    [switch]$EnforceControlledFolderAccess,
    [switch]$EnableCredentialGuard,
    [switch]$EnableMemoryIntegrity
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:StateRoot = Join-Path $env:ProgramData 'WindowsTechniqueHardening'
$script:StatePath = Join-Path $script:StateRoot 'original-state.json'
$script:Entries = New-Object 'System.Collections.Generic.List[object]'
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Failures = New-Object 'System.Collections.Generic.List[object]'
$script:NeedsRestart = $false

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Type = 'Info'
    )

    $colors = @{ Info = 'Cyan'; Success = 'Green'; Warning = 'Yellow'; Error = 'Red' }
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Target,
        [AllowNull()][object]$OldValue,
        [AllowNull()][object]$NewValue
    )

    $script:Changes.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Action    = $Action
        Target    = $Target
        OldValue  = if ($null -eq $OldValue) { '<absent>' } else { [string]$OldValue }
        NewValue  = if ($null -eq $NewValue) { '<absent>' } else { [string]$NewValue }
    })
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{ Exists = $false; Value = $null; Type = 'DWord' }
    }

    $key = Get-Item -LiteralPath $Path
    $exists = @($key.GetValueNames()) -contains $Name
    if (-not $exists) {
        return [PSCustomObject]@{ Exists = $false; Value = $null; Type = 'DWord' }
    }

    return [PSCustomObject]@{
        Exists = $true
        Value  = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        Type   = $key.GetValueKind($Name).ToString()
    }
}

function Save-State {
    $state = [PSCustomObject]@{
        Version = 1
        Entries = $script:Entries.ToArray()
    }

    if (-not (Test-Path -LiteralPath $script:StateRoot)) {
        New-Item -ItemType Directory -Path $script:StateRoot -Force | Out-Null
    }

    $json = $state | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $script:StatePath -Value $json -Encoding UTF8
}

function Load-State {
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return
    }

    $raw = Get-Content -LiteralPath $script:StatePath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Rollback state is empty: $script:StatePath"
    }

    $state = $raw | ConvertFrom-Json
    if ($state.Version -ne 1) {
        throw "Unsupported rollback state version: $($state.Version)"
    }

    foreach ($entry in @($state.Entries | Where-Object { $null -ne $_ })) {
        $script:Entries.Add($entry)
    }
}

function Find-StateEntry {
    param([Parameter(Mandatory = $true)][string]$Id)

    foreach ($entry in $script:Entries) {
        if ($entry.Id -eq $Id) {
            return $entry
        }
    }
    return $null
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('DWord', 'String', 'ExpandString', 'QWord', 'MultiString', 'Binary')][string]$Type,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$RequiresRestart,
        [switch]$PreserveEnabledMode,
        [switch]$PreserveGreaterDWord
    )

    $current = Get-RegistryValueState -Path $Path -Name $Name
    if ($current.Exists -and $current.Value -eq $Value) {
        Write-Status "Already configured: $Description" 'Info'
        return
    }

    if ($PreserveEnabledMode -and $current.Exists -and [string]$current.Value -eq '1' -and [string]$Value -eq '2') {
        Write-Status "Preserving stronger enabled mode: $Description" 'Info'
        return
    }

    if ($PreserveGreaterDWord -and $current.Exists -and [int64]$current.Value -gt [int64]$Value) {
        Write-Status "Preserving stronger platform security requirement: $Description" 'Info'
        return
    }

    $target = "$Path\$Name"
    if (-not $PSCmdlet.ShouldProcess($target, "Set $Description to $Value")) {
        return
    }

    if ($null -eq (Find-StateEntry -Id $Id)) {
        $script:Entries.Add([PSCustomObject]@{
            Id       = $Id
            Path     = $Path
            Name     = $Name
            Existed  = $current.Exists
            OldValue = $current.Value
            OldType  = $current.Type
        })
        Save-State
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null

    Add-ChangeLog -Action 'Set' -Target $target -OldValue $current.Value -NewValue $Value
    Write-Status "Configured: $Description" 'Success'
    if ($RequiresRestart) {
        $script:NeedsRestart = $true
    }
}

function Restore-RegistryEntry {
    param([Parameter(Mandatory = $true)][object]$Entry)

    $target = "$($Entry.Path)\$($Entry.Name)"
    $operation = if ($Entry.Existed) { "Restore original value $($Entry.OldValue)" } else { 'Remove value created by this script' }
    if (-not $PSCmdlet.ShouldProcess($target, $operation)) {
        return $false
    }

    if ($Entry.Existed) {
        if (-not (Test-Path -LiteralPath $Entry.Path)) {
            New-Item -Path $Entry.Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Entry.Path -Name $Entry.Name -PropertyType $Entry.OldType -Value $Entry.OldValue -Force | Out-Null
    } elseif (Test-Path -LiteralPath $Entry.Path) {
        $current = Get-RegistryValueState -Path $Entry.Path -Name $Entry.Name
        if ($current.Exists) {
            Remove-ItemProperty -LiteralPath $Entry.Path -Name $Entry.Name -Force
        }
    }

    Add-ChangeLog -Action 'Restore' -Target $target -OldValue $null -NewValue $Entry.OldValue
    Write-Status "Restored: $target" 'Success'
    return $true
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    try {
        & $Action
    } catch {
        $script:Failures.Add([PSCustomObject]@{ Step = $Name; Error = $_.Exception.Message })
        Write-Status "$Name failed: $($_.Exception.Message)" 'Error'
    }
}

function Set-DriverAndLibraryControls {
    Set-RegistryValue -Id 'DriverBlocklist' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
        -Name 'VulnerableDriverBlocklistEnable' -Value 1 -Type DWord `
        -Description 'Microsoft vulnerable-driver blocklist' -RequiresRestart

    Set-RegistryValue -Id 'SafeDllSearchMode' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name 'SafeDllSearchMode' -Value 1 -Type DWord `
        -Description 'Safe DLL search mode (does not replace application control)' -RequiresRestart
}

function Set-ASRControls {
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $ransomwareMode = if ($EnforceControlledFolderAccess) { '1' } else { '2' }

    $rules = @(
        @{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Mode = '1'; Name = 'Block abuse of exploited vulnerable signed drivers' },
        @{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Mode = '1'; Name = 'Block credential stealing from LSASS' },
        @{ Id = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; Mode = '1'; Name = 'Block copied or impersonated system tools' },
        @{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Mode = '1'; Name = 'Block Office applications from injecting code' },
        @{ Id = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Mode = $ransomwareMode; Name = 'Advanced ransomware protection' }
    )

    foreach ($rule in $rules) {
        Set-RegistryValue -Id "ASR:$($rule.Id)" -Path $path -Name $rule.Id `
            -Value $rule.Mode -Type String -Description $rule.Name -PreserveEnabledMode
    }
}

function Set-LSAControls {
    Set-RegistryValue -Id 'LSA:AuditLevel' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' `
        -Name 'AuditLevel' -Value 8 -Type DWord `
        -Description 'LSA plug-in and driver audit mode' -RequiresRestart

    if ($EnforceLSAProtection) {
        $build = [Environment]::OSVersion.Version.Build
        if ($build -lt 22621) {
            throw "RunAsPPL=2 requires Windows 11 22H2 or later; detected build $build. Use central policy and a validated compatibility plan for this OS."
        }

        $pplPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $ppl = Get-RegistryValueState -Path $pplPath -Name 'RunAsPPL'
        if ($ppl.Exists -and ([int]$ppl.Value -eq 1 -or [int]$ppl.Value -eq 2)) {
            Write-Status 'LSA protection is already configured; preserving the existing mode' 'Info'
        } else {
            Set-RegistryValue -Id 'LSA:RunAsPPL' -Path $pplPath `
                -Name 'RunAsPPL' -Value 2 -Type DWord `
                -Description 'LSA protection without UEFI lock' -RequiresRestart
        }
    }
}

function Set-RansomwareControls {
    $mode = if ($EnforceControlledFolderAccess) { 1 } else { 2 }
    Set-RegistryValue -Id 'CFA:Mode' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' `
        -Name 'EnableControlledFolderAccess' -Value $mode -Type DWord `
        -Description $(if ($mode -eq 1) { 'Controlled Folder Access enabled' } else { 'Controlled Folder Access audit mode' }) `
        -PreserveEnabledMode
}

function Set-TelemetryControls {
    Set-RegistryValue -Id 'Audit:ProcessCommandLine' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord `
        -Description 'Command lines in process creation events when process auditing is enabled'

    Set-RegistryValue -Id 'PowerShell:ScriptBlockLogging' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord `
        -Description 'PowerShell Script Block Logging'
}

function Set-VBSControls {
    if (-not ($EnableCredentialGuard -or $EnableMemoryIntegrity)) {
        return
    }

    $deviceGuardPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    Set-RegistryValue -Id 'VBS:Enabled' -Path $deviceGuardPath `
        -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord `
        -Description 'Virtualization-based security' -RequiresRestart

    Set-RegistryValue -Id 'VBS:PlatformRequirements' -Path $deviceGuardPath `
        -Name 'RequirePlatformSecurityFeatures' -Value 1 -Type DWord `
        -Description 'Secure Boot platform requirement' -RequiresRestart -PreserveGreaterDWord

    if ($EnableCredentialGuard) {
        Set-RegistryValue -Id 'VBS:CredentialGuard' -Path $deviceGuardPath `
            -Name 'LsaCfgFlags' -Value 2 -Type DWord `
            -Description 'Credential Guard without UEFI lock' -RequiresRestart
    }

    if ($EnableMemoryIntegrity) {
        Set-RegistryValue -Id 'VBS:MemoryIntegrity' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
            -Name 'Enabled' -Value 1 -Type DWord `
            -Description 'Memory integrity (HVCI)' -RequiresRestart
    }
}

function Write-DefenderCapabilityWarning {
    $command = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Write-Status 'Defender status is unavailable. ASR and Controlled Folder Access require a supported, active Defender Antivirus provider.' 'Warning'
        return
    }

    try {
        $status = Get-MpComputerStatus
        $modeProperty = $status.PSObject.Properties['AMRunningMode']
        if ($null -ne $modeProperty -and [string]$modeProperty.Value -ne 'Normal') {
            Write-Status "Defender AMRunningMode is '$($modeProperty.Value)'. ASR/CFA policy was configured, but active protection is not implied. Use the active security product's supported controls." 'Warning'
        } elseif ($status.PSObject.Properties['RealTimeProtectionEnabled'] -and -not $status.RealTimeProtectionEnabled) {
            Write-Status 'Defender real-time protection is off. Configured ASR/CFA values do not establish active protection.' 'Warning'
        }
    } catch {
        Write-Status "Could not confirm Defender operational state: $($_.Exception.Message)" 'Warning'
    }
}

function Invoke-Apply {
    Write-Status 'Applying technique-focused Windows hardening baseline' 'Info'
    Write-DefenderCapabilityWarning

    Invoke-Step -Name 'Driver and DLL controls' -Action { Set-DriverAndLibraryControls }
    Invoke-Step -Name 'ASR controls' -Action { Set-ASRControls }
    Invoke-Step -Name 'LSA controls' -Action { Set-LSAControls }
    Invoke-Step -Name 'Ransomware controls' -Action { Set-RansomwareControls }
    Invoke-Step -Name 'Telemetry controls' -Action { Set-TelemetryControls }
    Invoke-Step -Name 'VBS controls' -Action { Set-VBSControls }

    Write-Status 'Deploy the current Microsoft WDAC vulnerable-driver blocklist separately in audit mode; this script does not replace WDAC policies.' 'Info'
    Write-Status 'Review security-product tamper protection and service health in the supported vendor management console.' 'Info'
}

function Invoke-Undo {
    if ($script:Entries.Count -eq 0) {
        Write-Status 'No recorded changes exist for this script; nothing to undo' 'Info'
        return
    }

    Write-Status "Restoring $($script:Entries.Count) recorded setting(s)" 'Warning'
    for ($index = $script:Entries.Count - 1; $index -ge 0; $index--) {
        $entry = $script:Entries[$index]
        Invoke-Step -Name "Restore $($entry.Id)" -Action {
            $restored = Restore-RegistryEntry -Entry $entry
            if ($restored) {
                $script:Entries.RemoveAt($index)
                Save-State
                $script:NeedsRestart = $true
            }
        }
    }

    if ($script:Entries.Count -eq 0 -and $script:Failures.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($script:StatePath, 'Remove completed rollback state')) {
            if (Test-Path -LiteralPath $script:StatePath) {
                Remove-Item -LiteralPath $script:StatePath -Force
            }
            if ((Test-Path -LiteralPath $script:StateRoot) -and @((Get-ChildItem -LiteralPath $script:StateRoot -Force)).Count -eq 0) {
                Remove-Item -LiteralPath $script:StateRoot -Force
            }
        }
    } elseif ($WhatIfPreference) {
        Write-Status "WhatIf: rollback state remains unchanged at $script:StatePath" 'Info'
    } else {
        Write-Status "Rollback state retained at $script:StatePath for unresolved entries" 'Warning'
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This hardening script can run only on Windows.'
}
if (-not (Test-IsAdministrator)) {
    throw 'Administrator privileges are required. Restart PowerShell as administrator.'
}

if ($Undo -and ($EnforceLSAProtection -or $EnforceControlledFolderAccess -or $EnableCredentialGuard -or $EnableMemoryIntegrity)) {
    Write-Status 'Apply-mode switches are ignored during -Undo' 'Warning'
}

Invoke-Step -Name 'Load rollback state' -Action { Load-State }
if ($script:Failures.Count -eq 0) {
    if ($Undo) {
        Invoke-Undo
    } else {
        Invoke-Apply
    }
}

if ($script:Changes.Count -gt 0) {
    Write-Status 'Change summary:' 'Info'
    $script:Changes | Format-Table -AutoSize
}
if ($script:NeedsRestart) {
    Write-Status 'Restart Windows and verify operational state before considering the changed protections effective.' 'Warning'
}
if ($script:Failures.Count -gt 0) {
    throw "$($script:Failures.Count) hardening action(s) failed. Review the errors and retained rollback state before retrying."
}

Write-Status 'Complete. Verify effective policy and security-product health; configuration alone is not proof of enforcement.' 'Success'
