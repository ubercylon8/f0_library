<#
.SYNOPSIS
    Applies conservative PowerShell logging and Point and Print hardening.

.DESCRIPTION
    Optional documentation artifact for a Sophos-managed Windows baseline.
    The read-only assessment does not execute this script.

    Changes are limited to:
      - PowerShell Script Block Logging
      - PowerShell Module Logging, including the wildcard module-name policy
      - Administrator-only Point and Print driver installation
      - Point and Print installation and update warnings

    Original values are recorded before each change. Repeated runs are
    idempotent, and -Undo restores only values recorded by this script.

    This script does not configure Sophos Central, Defender ASR, services,
    LAPS, Credential Guard, VBS, audit policy, account policy, SMB, LLMNR,
    NetBIOS, WPAD, IPv6, transcription output, or application control.
    Manage those controls centrally after role-specific compatibility testing.
    It is not a complete CIS Benchmark implementation.

.PARAMETER Undo
    Restores values captured before changes made by this script. Values that
    were already compliant before the first run are not changed by rollback.

.PARAMETER WhatIf
    Shows proposed registry and rollback actions without changing the registry
    or creating/updating rollback state.

.EXAMPLE
    .\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -WhatIf
    Previews all proposed changes.

.EXAMPLE
    .\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1
    Applies the conservative settings and records prior values.

.EXAMPLE
    .\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -Undo -WhatIf
    Previews rollback using the existing state file.

.EXAMPLE
    .\8ee949ce-7d96-4688-a808-7917dd907db0_hardening.ps1 -Undo
    Restores recorded prior values or removes values created by the script.

.NOTES
    Author: F0RT1KA Defense Guidance Generator
    Guidance date: 2026-11-03
    Requires: Administrator privileges; Windows PowerShell 5.1 or PowerShell 7+
    Idempotent: Yes
    Rollback state: %ProgramData%\SecurityBaseline\SophosWindowsBaseline
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Undo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StateDirectory = Join-Path $env:ProgramData 'SecurityBaseline\SophosWindowsBaseline'
$StatePath = Join-Path $StateDirectory 'state.json'
$Script:ChangeLog = @()

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $colors = @{ Info = 'Cyan'; Success = 'Green'; Warning = 'Yellow'; Error = 'Red' }
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue
    )

    $Script:ChangeLog += [pscustomobject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Action    = $Action
        Target    = $Target
        OldValue  = $OldValue
        NewValue  = $NewValue
    }
}

function Read-StateEntries {
    $entries = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return ,$entries
    }

    $document = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($document.SchemaVersion -ne 1) {
        throw "Unsupported rollback state schema at $StatePath"
    }

    foreach ($entry in @($document.Entries)) {
        if ($null -ne $entry) {
            [void]$entries.Add($entry)
        }
    }

    return ,$entries
}

function Save-StateEntries {
    param(
        [System.Collections.ArrayList]$Entries
    )

    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    $document = [ordered]@{
        SchemaVersion = 1
        UpdatedAt     = (Get-Date).ToString('o')
        Entries       = @($Entries)
    }

    $temporaryPath = "$StatePath.tmp"
    $document | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $StatePath -Force
}

function Find-StateEntry {
    param(
        [System.Collections.ArrayList]$Entries,
        [string]$Id
    )

    foreach ($entry in $Entries) {
        if ($entry.Id -eq $Id) {
            return $entry
        }
    }

    return $null
}

function Get-RegistryState {
    param(
        [psobject]$Target
    )

    $state = [pscustomobject]@{
        Id           = $Target.Id
        RegistryPath = $Target.RegistryPath
        Name         = $Target.Name
        Exists       = $false
        Value        = $null
        Kind         = $Target.Kind
    }

    if (-not (Test-Path -LiteralPath $Target.RegistryPath -PathType Container)) {
        return $state
    }

    $key = Get-Item -LiteralPath $Target.RegistryPath
    if ($key.GetValueNames() -notcontains $Target.Name) {
        return $state
    }

    $state.Exists = $true
    $state.Value = $key.GetValue($Target.Name)
    $state.Kind = $key.GetValueKind($Target.Name).ToString()
    return $state
}

function Test-DesiredState {
    param(
        [psobject]$Current,
        [psobject]$Target
    )

    return (
        $Current.Exists -and
        $Current.Kind -eq $Target.Kind -and
        [string]$Current.Value -eq [string]$Target.Value
    )
}

function Set-RegistryValue {
    param(
        [psobject]$Target
    )

    if (-not (Test-Path -LiteralPath $Target.RegistryPath -PathType Container)) {
        New-Item -Path $Target.RegistryPath -Force | Out-Null
    }

    New-ItemProperty `
        -Path $Target.RegistryPath `
        -Name $Target.Name `
        -Value $Target.Value `
        -PropertyType $Target.Kind `
        -Force | Out-Null
}

function Restore-RegistryState {
    param(
        [psobject]$Entry
    )

    if ($Entry.Exists) {
        if (-not (Test-Path -LiteralPath $Entry.RegistryPath -PathType Container)) {
            New-Item -Path $Entry.RegistryPath -Force | Out-Null
        }

        New-ItemProperty `
            -Path $Entry.RegistryPath `
            -Name $Entry.Name `
            -Value $Entry.Value `
            -PropertyType ([string]$Entry.Kind) `
            -Force | Out-Null
        return
    }

    if (Test-Path -LiteralPath $Entry.RegistryPath -PathType Container) {
        $key = Get-Item -LiteralPath $Entry.RegistryPath
        if ($key.GetValueNames() -contains $Entry.Name) {
            Remove-ItemProperty -Path $Entry.RegistryPath -Name $Entry.Name
        }
    }
}

function Get-HardeningTargets {
    return @(
        [pscustomobject]@{
            Id           = 'PowerShell.ScriptBlockLogging'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Name         = 'EnableScriptBlockLogging'
            Value        = 1
            Kind         = 'DWord'
        },
        [pscustomobject]@{
            Id           = 'PowerShell.ModuleLogging'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            Name         = 'EnableModuleLogging'
            Value        = 1
            Kind         = 'DWord'
        },
        [pscustomobject]@{
            Id           = 'PowerShell.ModuleLogging.AllModules'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
            Name         = '*'
            Value        = '*'
            Kind         = 'String'
        },
        [pscustomobject]@{
            Id           = 'PointAndPrint.RestrictDriverInstallation'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Name         = 'RestrictDriverInstallationToAdministrators'
            Value        = 1
            Kind         = 'DWord'
        },
        [pscustomobject]@{
            Id           = 'PointAndPrint.InstallWarning'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Name         = 'NoWarningNoElevationOnInstall'
            Value        = 0
            Kind         = 'DWord'
        },
        [pscustomobject]@{
            Id           = 'PointAndPrint.UpdatePrompt'
            RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Name         = 'UpdatePromptSettings'
            Value        = 0
            Kind         = 'DWord'
        }
    )
}

function Apply-Hardening {
    $entries = Read-StateEntries

    foreach ($target in Get-HardeningTargets) {
        $current = Get-RegistryState -Target $target
        $displayTarget = "$($target.RegistryPath)\$($target.Name)"

        if (Test-DesiredState -Current $current -Target $target) {
            Write-Status "Already compliant: $displayTarget" 'Info'
            continue
        }

        if ($PSCmdlet.ShouldProcess($displayTarget, "Set to '$($target.Value)' ($($target.Kind))")) {
            if ($null -eq (Find-StateEntry -Entries $entries -Id $target.Id)) {
                [void]$entries.Add($current)
                Save-StateEntries -Entries $entries
            }

            $oldValue = '<absent>'
            if ($current.Exists) {
                $oldValue = "$($current.Value) ($($current.Kind))"
            }

            Set-RegistryValue -Target $target
            Add-ChangeLog -Action 'Set' -Target $displayTarget -OldValue $oldValue -NewValue "$($target.Value) ($($target.Kind))"
            Write-Status "Configured: $displayTarget" 'Success'
        }
    }
}

function Undo-Hardening {
    $entries = Read-StateEntries
    if ($entries.Count -eq 0) {
        Write-Status 'No recorded script changes require rollback.' 'Info'
        return
    }

    for ($index = $entries.Count - 1; $index -ge 0; $index--) {
        $entry = $entries[$index]
        $displayTarget = "$($entry.RegistryPath)\$($entry.Name)"
        $restoredValue = '<absent>'
        if ($entry.Exists) {
            $restoredValue = "$($entry.Value) ($($entry.Kind))"
        }

        if ($PSCmdlet.ShouldProcess($displayTarget, "Restore prior state: $restoredValue")) {
            $current = Get-RegistryState -Target $entry
            $oldValue = '<absent>'
            if ($current.Exists) {
                $oldValue = "$($current.Value) ($($current.Kind))"
            }

            Restore-RegistryState -Entry $entry
            $entries.RemoveAt($index)

            if ($entries.Count -eq 0) {
                Remove-Item -LiteralPath $StatePath -Force
            } else {
                Save-StateEntries -Entries $entries
            }

            Add-ChangeLog -Action 'Restore' -Target $displayTarget -OldValue $oldValue -NewValue $restoredValue
            Write-Status "Restored: $displayTarget" 'Success'
        }
    }
}

try {
    if ($Undo) {
        Write-Status 'Reverting recorded logging and Point and Print changes...' 'Warning'
        Undo-Hardening
    } else {
        Write-Status 'Applying conservative logging and Point and Print hardening...' 'Info'
        Apply-Hardening
    }

    if ($Script:ChangeLog.Count -gt 0) {
        $Script:ChangeLog | Format-Table -AutoSize
    }

    Write-Status 'Complete. Reconcile local exceptions with central GPO/MDM policy.' 'Success'
} catch {
    Write-Status $_.Exception.Message 'Error'
    throw
}
