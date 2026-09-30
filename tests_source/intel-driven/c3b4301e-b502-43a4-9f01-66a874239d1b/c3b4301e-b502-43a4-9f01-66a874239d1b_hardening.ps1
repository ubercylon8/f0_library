<#
.SYNOPSIS
    Hardens a Windows endpoint against Star Blizzard "RedFlick"/CosmicPulse-style
    LOLBin espionage chains (LNK/conhost delivery, ssh.exe LocalCommand cradle,
    curl.exe transfers, obfuscated PowerShell, silent msiexec, scheduled-task
    persistence, CPL/rundll32 execution, HTTP C2).

.DESCRIPTION
    Technique-focused hardening for MITRE ATT&CK:
      T1204.002 (malicious file / event-invite LNK),
      T1105      (ingress tool transfer via ssh.exe/curl.exe),
      T1059.001  (PowerShell base64 extraction + Invoke-Expression),
      T1218.007  (msiexec silent install),
      T1053.005  (scheduled-task persistence),
      T1218.011  (rundll32/control.exe CPL execution, user-writable paths),
      T1071.001  (HTTP C2 beaconing).

    Applied controls:
      - Defender ASR rules (email-delivered executable content, obfuscated
        scripts, untrusted executables, PSExec/WMI process creation)
      - Defender network protection, cloud-delivered protection (MAPS), PUA
      - PowerShell script-block / module / transcription logging
      - Process-creation auditing incl. command lines (EID 4688)
      - Scheduled-task auditing (EID 4698/4699/4700/4701/4702) + TaskScheduler
        operational log enablement
      - Registry audit subcategory (for HKCU\Software\Classes staging detection)
      - Windows Installer hardening (AlwaysInstallElevated=0, verbose logging)
      - WebClient (WebDAV) service disabled - breaks WebDAV UNC payload fetch
      - SmartScreen enforced at "Block" level
      - File extensions visible (defeats ".pdf.lnk" masquerade)
      - Optional (-RestrictEgress): outbound firewall block for ssh.exe TCP/22
      - Optional (-RemoveOpenSSHClient): remove the OpenSSH Client capability

    Mitigations (MITRE): M1040, M1038, M1017, M1049, M1042, M1026, M1047,
    M1028, M1018, M1050, M1031, M1054.

    All changes are idempotent and reversible. Prior state is backed up to
    %ProgramData%\EndpointHardening\Backups\ and restored with -Undo.

.PARAMETER Undo
    Reverts all changes made by this script (using the stored backup).

.PARAMETER RestrictEgress
    Additionally creates an outbound Windows Firewall rule blocking the
    system OpenSSH client (ssh.exe) from reaching TCP/22 (RedFlick uses
    "ssh.exe -o PermitLocalCommand=yes -o LocalCommand=..." as a download
    cradle). Skip if your organization legitimately uses outbound SSH from
    endpoints; use a jump-host allowlist instead.

.PARAMETER RemoveOpenSSHClient
    Additionally removes the OpenSSH Client Windows capability entirely
    (M1042 - Disable or Remove Feature or Program). Requires Windows Update
    connectivity. -Undo reinstalls it.

.EXAMPLE
    .\c3b4301e-b502-43a4-9f01-66a874239d1b_hardening.ps1
    Applies all default hardening settings.

.EXAMPLE
    .\c3b4301e-b502-43a4-9f01-66a874239d1b_hardening.ps1 -RestrictEgress
    Applies hardening plus the outbound SSH firewall block.

.EXAMPLE
    .\c3b4301e-b502-43a4-9f01-66a874239d1b_hardening.ps1 -Undo
    Reverts all hardening settings (including optional ones if applied).

.EXAMPLE
    .\c3b4301e-b502-43a4-9f01-66a874239d1b_hardening.ps1 -WhatIf
    Shows what would change without making changes.

.NOTES
    Author: F0RT1KA Defense Guidance Generator
    Basis:  Microsoft Threat Intelligence, "Star Blizzard refines phishing and
            malware delivery with the RedFlick technique" (2026-09-29)
    Requires: Administrator privileges, Windows 10/11 or Server 2019+
    Idempotent: Yes (safe to run multiple times)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$RestrictEgress,
    [switch]$RemoveOpenSSHClient
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog = @()
$Script:PSCmdletContext = $PSCmdlet

$BackupDir   = Join-Path $env:ProgramData 'EndpointHardening\Backups'
$BackupFile  = Join-Path $BackupDir 'lolbin-chain-hardening-backup.json'
$TranscriptDir = Join-Path $env:ProgramData 'EndpointHardening\Transcripts'

# ASR rules relevant to this chain (GUIDs verified against the Microsoft Learn
# ASR rules reference):
$Script:AsrRules = [ordered]@{
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Enabled'  # Block executable content from email client and webmail (LNK/BAT delivery)
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Enabled'  # Block execution of potentially obfuscated scripts (base64 + IEX)
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Enabled'  # Block untrusted/low-prevalence executables (dropped binaries, CPL DLL)
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Enabled'  # Block process creations originating from PSExec and WMI
}
$Script:SshFirewallRuleName = 'Hardening - Block outbound SSH (OpenSSH client)'

# ============================================================
# Helpers
# ============================================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
}

function Add-ChangeLog {
    param([string]$Action, [string]$Target, [string]$OldValue, [string]$NewValue)
    $Script:ChangeLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Action; Target = $Target
        OldValue  = $OldValue; NewValue = $NewValue
    }
}

# Central ShouldProcess gate: honours -WhatIf / -Confirm for every mutation,
# including native commands (auditpol, wevtutil) that ignore preference vars.
function Invoke-Change {
    param([string]$Target, [string]$Action, [scriptblock]$Apply)
    if ($Script:PSCmdletContext.ShouldProcess($Target, $Action)) {
        & $Apply
        return $true
    }
    Write-Status "SKIPPED (WhatIf): $Action on $Target" "Warning"
    return $false
}

function New-BackupStore {
    [ordered]@{
        Created       = (Get-Date).ToString('o')
        RegValues     = [ordered]@{}
        Audit         = @{}
        TaskSchedLog  = $null
        Defender      = @{ AsrPrior = @{}; Prefs = @{} }
        WebClient     = $null
        FirewallRule  = $false
        OpenSSHClient = $false
    }
}

function Save-Backup {
    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }
    $Script:Backup | ConvertTo-Json -Depth 8 | Set-Content -Path $BackupFile -Encoding UTF8
    Write-Status "Backup of prior state saved: $BackupFile" "Info"
}

function ConvertFrom-JsonObjectToHashtable {
    param($Node)
    if ($Node -is [System.Management.Automation.PSObject]) {
        $h = [ordered]@{}
        foreach ($p in $Node.PSObject.Properties) { $h[$p.Name] = ConvertFrom-JsonObjectToHashtable $p.Value }
        return $h
    }
    return $Node
}

function Get-MapEntries {
    # Uniform iteration over hashtables, ordered dictionaries and PSCustomObjects
    param($Map)
    if ($null -eq $Map) { return @() }
    if ($Map -is [System.Collections.IDictionary]) {
        return @($Map.GetEnumerator() | ForEach-Object { @{ Name = [string]$_.Key; Value = $_.Value } })
    }
    return @($Map.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } })
}

function Load-Backup {
    if (Test-Path $BackupFile) {
        try {
            $raw = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
            $Script:Backup = [ordered]@{
                Created       = $raw.Created
                RegValues     = if ($null -ne $raw.RegValues) { ConvertFrom-JsonObjectToHashtable $raw.RegValues } else { [ordered]@{} }
                Audit         = if ($null -ne $raw.Audit)     { ConvertFrom-JsonObjectToHashtable $raw.Audit }     else { @{} }
                TaskSchedLog  = $raw.TaskSchedLog
                Defender      = @{
                    AsrPrior = if ($null -ne $raw.Defender.AsrPrior) { ConvertFrom-JsonObjectToHashtable $raw.Defender.AsrPrior } else { @{} }
                    Prefs    = if ($null -ne $raw.Defender.Prefs)    { ConvertFrom-JsonObjectToHashtable $raw.Defender.Prefs }    else { @{} }
                }
                WebClient     = $raw.WebClient
                FirewallRule  = $raw.FirewallRule
                OpenSSHClient = $raw.OpenSSHClient
            }
            return $true
        } catch {
            Write-Status "Backup file unreadable ($BackupFile): $($_.Exception.Message)" "Error"
        }
    }
    return $false
}

function Remove-KnownRegistryValues {
    # No-backup fallback undo: delete the values this script sets (all of them
    # correspond to "Not Configured" OS defaults once removed).
    $targets = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Names = 'EnableScriptBlockLogging','EnableScriptBlockInvocationLogging' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';      Names = 'EnableModuleLogging','ModuleNames' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Names = 'EnableTranscripting','EnableInvocationHeader','OutputDirectory' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';   Names = 'ProcessCreationIncludeCmdLine_Enabled' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer';                     Names = 'AlwaysInstallElevated','Logging' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                        Names = 'EnableSmartScreen','ShellSmartScreenLevel' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer';                Names = 'SmartScreenEnabled' }
    )
    foreach ($t in $targets) {
        foreach ($n in $t.Names) {
            Invoke-Change -Target $t.Path -Action "remove $n (no backup - revert to OS default)" -Apply {
                Remove-ItemProperty -Path $t.Path -Name $n -ErrorAction SilentlyContinue
            } | Out-Null
            Add-ChangeLog -Action 'Remove-RegistryValue' -Target "$($t.Path)\$n" -OldValue '(hardened)' -NewValue '(absent = OS default)'
        }
    }
    foreach ($advPath in (Get-UserHivePaths -SubPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced')) {
        Invoke-Change -Target $advPath -Action 'remove HideFileExt (restore OS default)' -Apply {
            Remove-ItemProperty -Path $advPath -Name 'HideFileExt' -ErrorAction SilentlyContinue
        } | Out-Null
    }
}

# --- Registry helpers (backup-then-set, restore on -Undo) ---

function Backup-RegValue {
    param([string]$Path, [string]$Name)
    $key = "$Path|$Name"
    if ($Script:Backup.RegValues.Contains($key)) { return }   # first-seen wins: re-runs keep the ORIGINAL prior value
    if (Test-Path $Path) {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item -and $null -ne $item.$Name) {
            $kind = 'String'
            try { $kind = [string]((Get-Item $Path).GetValueKind($Name)) } catch {}
            $Script:Backup.RegValues[$key] = @{ Existed = $true; Value = $item.$Name; Kind = $kind }
            return
        }
    }
    $Script:Backup.RegValues[$key] = @{ Existed = $false }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [ValidateSet('DWord','String')][string]$Kind)
    Backup-RegValue -Path $Path -Name $Name
    $result = Invoke-Change -Target "$Path" -Action "set $Name = '$Value' ($Kind)" -Apply {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
    }
    if ($result) { Add-ChangeLog -Action 'Set-RegistryValue' -Target "$Path\$Name" -OldValue '(prior)' -NewValue "$Value" }
}

function Restore-RegValues {
    foreach ($e in (Get-MapEntries -Map $Script:Backup.RegValues)) {
        $parts = $e.Name -split '\|', 2
        $path = $parts[0]; $name = $parts[1]; $info = $e.Value
        if ($info.Existed) {
            Invoke-Change -Target $path -Action "restore $name = '$($info.Value)'" -Apply {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                $val = $info.Value
                if ($info.Kind -eq 'DWord') { $val = [int]$val }
                New-ItemProperty -Path $path -Name $name -Value $val -PropertyType $info.Kind -Force | Out-Null
            } | Out-Null
        } else {
            Invoke-Change -Target $path -Action "remove $name (did not exist before)" -Apply {
                Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            } | Out-Null
        }
        Add-ChangeLog -Action 'Restore-RegistryValue' -Target "$path\$name" -OldValue '(hardened)' -NewValue $(if ($info.Existed) { "$($info.Value)" } else { '(removed)' })
    }
}

function Get-UserHivePaths {
    param([string]$SubPath)
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
        ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)\$SubPath" }
}

# --- Audit policy helpers ---

function Get-AuditSubcategoryState {
    param([string]$Subcategory)
    $state = @{ Success = $false; Failure = $false }
    try {
        $rows = & auditpol.exe /get /subcategory:"$Subcategory" /r 2>$null | ConvertFrom-Csv
        $row = $rows | Where-Object { $_ } | Select-Object -First 1
        if ($row) {
            $prop = $row.PSObject.Properties | Where-Object { $_.Name -match 'Inclusion' } | Select-Object -First 1
            if (-not $prop) { $prop = $row.PSObject.Properties | Select-Object -Skip 4 -First 1 }
            if ($prop) {
                if ($prop.Value -match 'Success') { $state.Success = $true }
                if ($prop.Value -match 'Failure') { $state.Failure = $true }
            }
        }
    } catch {}
    $state
}

function Backup-AuditSubcategory {
    param([string]$Subcategory)
    if (-not $Script:Backup.Audit.ContainsKey($Subcategory)) {
        $Script:Backup.Audit[$Subcategory] = Get-AuditSubcategoryState -Subcategory $Subcategory
    }
}

function Set-AuditSubcategory {
    param([string]$Subcategory, [bool]$Success, [bool]$Failure, [switch]$SkipBackup)
    if (-not $SkipBackup) { Backup-AuditSubcategory -Subcategory $Subcategory }
    $s = if ($Success) { 'enable' } else { 'disable' }
    $f = if ($Failure) { 'enable' } else { 'disable' }
    $ok = Invoke-Change -Target "Audit subcategory '$Subcategory'" -Action "set success=$Success failure=$Failure" -Apply {
        & auditpol.exe /set /subcategory:"$Subcategory" /success:$s /failure:$f | Out-Null
    }
    if ($ok) { Add-ChangeLog -Action 'Set-AuditPolicy' -Target $Subcategory -OldValue '(prior)' -NewValue "success=$Success failure=$Failure" }
}

# ============================================================
# Hardening functions - technique-specific mitigations
# ============================================================

function Set-ASRRules {
    if ($Undo) {
        Write-Status "Reverting ASR rules to prior state..." "Warning"
        try {
            $priorMap = @{}
            foreach ($e in (Get-MapEntries -Map $Script:Backup.Defender.AsrPrior)) { $priorMap[$e.Name] = $e.Value }
            $pref = Get-MpPreference
            $ids    = @($pref.AttackSurfaceReductionRules_Ids      | ForEach-Object { [string]$_ })
            $actions = @($pref.AttackSurfaceReductionRules_Actions)
            $finalIds = @(); $finalActions = @()
            for ($i = 0; $i -lt $ids.Count; $i++) {
                $guid = $ids[$i].ToLower()
                if ($Script:AsrRules.Contains($guid)) {
                    if ($priorMap.ContainsKey($guid) -and $priorMap[$guid]) {
                        $finalIds += $ids[$i]; $finalActions += [string]$priorMap[$guid]  # was Audit/other before us
                    }
                    # else: rule did not exist before us -> drop it
                } else {
                    $finalIds += $ids[$i]; $finalActions += [string]$actions[$i]
                }
            }
            Invoke-Change -Target 'Defender ASR rules' -Action 'restore prior rule set' -Apply {
                if ($finalIds.Count -gt 0) {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids ([guid[]]$finalIds) -AttackSurfaceReductionRules_Actions ([string[]]$finalActions)
                } else {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids ([guid[]]@()) -AttackSurfaceReductionRules_Actions ([string[]]@())
                }
            } | Out-Null
            Add-ChangeLog -Action 'Undo-ASR' -Target 'Defender ASR rules' -OldValue 'hardened set' -NewValue 'prior set'
        } catch { Write-Status "ASR undo failed: $($_.Exception.Message)" "Error" }
        return
    }

    try { $null = Get-MpComputerStatus -ErrorAction Stop } catch {
        Write-Status "Microsoft Defender cmdlets unavailable (third-party AV or Defender removed) - skipping ASR rules. Apply equivalent execution-prevention (M1038) in your AV/EDR console." "Warning"
        return
    }

    Write-Status "Configuring Defender ASR rules..." "Info"
    try {
        $pref      = Get-MpPreference
        $curIds    = @($pref.AttackSurfaceReductionRules_Ids      | ForEach-Object { [string]$_ })
        $curActions = @($pref.AttackSurfaceReductionRules_Actions)
        $current   = @{}
        for ($i = 0; $i -lt $curIds.Count; $i++) { $current[$curIds[$i].ToLower()] = [string]$curActions[$i] }

        $finalIds = @(); $finalActions = @()
        for ($i = 0; $i -lt $curIds.Count; $i++) {
            $finalIds += $curIds[$i]
            $finalActions += [string]$curActions[$i]
        }
        foreach ($guid in $Script:AsrRules.Keys) {
            $g = $guid.ToLower()
            if ($current.ContainsKey($g) -and $current[$g] -eq $Script:AsrRules[$g]) { continue }   # already set -> idempotent
            if (-not $current.ContainsKey($g)) {
                $finalIds += $guid; $finalActions += $Script:AsrRules[$guid]
            } else {
                for ($i = 0; $i -lt $finalIds.Count; $i++) {
                    if ($finalIds[$i].ToLower() -eq $g) { $finalActions[$i] = $Script:AsrRules[$g] }
                }
            }
            if (-not $Script:Backup.Defender.AsrPrior.Contains($g)) {
                $Script:Backup.Defender.AsrPrior[$g] = $current[$g]        # may be $null = did not exist
            }
        }
        if ($finalIds.Count -gt 0) {
            $ok = Invoke-Change -Target 'Defender ASR rules' -Action "enable $($Script:AsrRules.Count) ASR rules (Block mode)" -Apply {
                Set-MpPreference -AttackSurfaceReductionRules_Ids ([guid[]]$finalIds) -AttackSurfaceReductionRules_Actions ([string[]]$finalActions)
            }
            if ($ok) {
                Add-ChangeLog -Action 'Set-ASR' -Target 'Defender ASR rules' -OldValue '(varies)' -NewValue ($Script:AsrRules.Keys -join ', ')
                Write-Status "Tip: initially deploy ASR in Audit mode (action 'Audit' per rule) if breakage is a concern; the obfuscated-script and email-content rules are the highest-value for this chain." "Info"
            }
        }
    } catch { Write-Status "ASR configuration failed: $($_.Exception.Message)" "Error" }
}

function Set-DefenderFeatures {
    param([hashtable]$Settings)
    if ($Undo) {
        Write-Status "Reverting Defender feature preferences..." "Warning"
        foreach ($e in (Get-MapEntries -Map $Script:Backup.Defender.Prefs)) {
            $p = $e.Name; $val = "$($e.Value)"
            try {
                Invoke-Change -Target "Defender preference $p" -Action "restore '$val'" -Apply ([scriptblock]::Create("Set-MpPreference -$p `"$val`"")) | Out-Null
            } catch {
                Write-Status "Could not restore Defender preference ${p}: $($_.Exception.Message)" "Warning"
            }
        }
        Add-ChangeLog -Action 'Undo-DefenderPrefs' -Target 'Defender preferences' -OldValue 'hardened' -NewValue 'prior'
        return
    }

    try { $null = Get-MpComputerStatus -ErrorAction Stop } catch {
        Write-Status "Defender cmdlets unavailable - skipping Defender feature configuration." "Warning"
        return
    }
    Write-Status "Configuring Defender protection features (network protection, cloud protection, PUA)..." "Info"
    try {
        $pref = Get-MpPreference
        foreach ($p in $Settings.Keys) {
            $cur = $pref.$p
            if (-not $Script:Backup.Defender.Prefs.Contains($p)) {
                $Script:Backup.Defender.Prefs[$p] = [string]$cur
            }
            if ("$cur" -eq "$($Settings[$p])") { continue }   # idempotent
            $desired = $Settings[$p]
            $ok = Invoke-Change -Target "Defender preference $p" -Action "set $desired" -Apply ([scriptblock]::Create("Set-MpPreference -$p `"$desired`""))
            if ($ok) { Add-ChangeLog -Action 'Set-DefenderPref' -Target $p -OldValue "$cur" -NewValue "$desired" }
        }
    } catch { Write-Status "Defender feature configuration failed: $($_.Exception.Message)" "Error" }
}

function Set-PowerShellLogging {
    Write-Status "Enabling PowerShell script-block, module and transcription logging..." "Info"
    $psRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

    if ($Undo) {
        Write-Status "Reverting PowerShell logging (registry values restore from backup)..." "Warning"
        # values restored en-masse by Restore-RegValues in main undo flow
        return
    }

    Set-RegValue -Path "$psRoot\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'          -Value 1 -Kind DWord   # EID 4104: records the decoded base64 payload before Invoke-Expression
    Set-RegValue -Path "$psRoot\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Kind DWord
    Set-RegValue -Path "$psRoot\ModuleLogging"      -Name 'EnableModuleLogging'               -Value 1 -Kind DWord
    Set-RegValue -Path "$psRoot\ModuleLogging"      -Name 'ModuleNames'                       -Value '*' -Kind String
    Set-RegValue -Path "$psRoot\Transcription"      -Name 'EnableTranscripting'               -Value 1 -Kind DWord
    Set-RegValue -Path "$psRoot\Transcription"      -Name 'EnableInvocationHeader'            -Value 1 -Kind DWord
    if (-not (Test-Path $TranscriptDir)) {
        Invoke-Change -Target $TranscriptDir -Action 'create transcription output directory' -Apply { New-Item -Path $TranscriptDir -ItemType Directory -Force | Out-Null } | Out-Null
    }
    Set-RegValue -Path "$psRoot\Transcription"      -Name 'OutputDirectory'                   -Value $TranscriptDir -Kind String
    Write-Status "Consider Constrained Language Mode for interactive users (GPO: __PSLockdownPolicy=4) - strategic item, pilot before rollout." "Info"
}

function Set-ProcessCreationAuditing {
    Write-Status "Enabling process-creation auditing with command lines (EID 4688)..." "Info"
    if ($Undo) {
        Set-AuditSubcategory -Subcategory 'Process Creation' -Success $false -Failure $false -SkipBackup
        return
    }
    Set-AuditSubcategory -Subcategory 'Process Creation' -Success $true -Failure $false
    # Include command line in 4688 events - exposes: conhost --headless, ssh -o LocalCommand=,
    # curl -o, msiexec /i /q, rundll32 Control_RunDLL, schtasks /Create
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Kind DWord
}

function Set-ScheduledTaskAuditing {
    Write-Status "Enabling scheduled-task auditing (EID 4698/4699/4700/4701/4702) + Task Scheduler operational log..." "Info"
    if ($Undo) {
        $prior = $Script:Backup.Audit['Other Object Access Events']
        if ($prior) {
            Set-AuditSubcategory -Subcategory 'Other Object Access Events' -Success ([bool]$prior.Success) -Failure ([bool]$prior.Failure) -SkipBackup
        } else {
            Set-AuditSubcategory -Subcategory 'Other Object Access Events' -Success $false -Failure $false -SkipBackup
        }
        if ($null -ne $Script:Backup.TaskSchedLog) {
            $enabled = [bool]$Script:Backup.TaskSchedLog
            Invoke-Change -Target 'Microsoft-Windows-TaskScheduler/Operational' -Action "set enabled=$enabled" -Apply {
                & wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:$(if ($enabled) { 'true' } else { 'false' }) | Out-Null
            } | Out-Null
        }
        return
    }
    Set-AuditSubcategory -Subcategory 'Other Object Access Events' -Success $true -Failure $true

    # Task history is disabled by default on Windows - enable the operational log
    $wasEnabled = $false
    try {
        $gl = & wevtutil.exe gl Microsoft-Windows-TaskScheduler/Operational 2>$null
        $line = ($gl | Where-Object { $_ -match '^enabled:' } | Select-Object -First 1)
        if ($line) { $wasEnabled = ($line -replace 'enabled:\s*', '').Trim() -eq 'true' }
    } catch {}
    if ($null -eq $Script:Backup.TaskSchedLog) { $Script:Backup.TaskSchedLog = $wasEnabled }
    $ok = Invoke-Change -Target 'Microsoft-Windows-TaskScheduler/Operational' -Action 'enable channel' -Apply {
        & wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
    }
    if ($ok) { Add-ChangeLog -Action 'Enable-EventLog' -Target 'Microsoft-Windows-TaskScheduler/Operational' -OldValue "$wasEnabled" -NewValue 'true' }
    Write-Status "Alert on task creation events for non-admin principals and ONLOGON-trigger tasks (fake 'network component' persistence pattern)." "Info"
}

function Set-RegistryAuditing {
    Write-Status "Enabling Registry audit subcategory (HKCU staging detection, e.g. Software\Classes payload keys)..." "Info"
    if ($Undo) {
        $prior = $Script:Backup.Audit['Registry']
        if ($prior) {
            Set-AuditSubcategory -Subcategory 'Registry' -Success ([bool]$prior.Success) -Failure ([bool]$prior.Failure) -SkipBackup
        } else {
            Set-AuditSubcategory -Subcategory 'Registry' -Success $false -Failure $false -SkipBackup
        }
        return
    }
    Set-AuditSubcategory -Subcategory 'Registry' -Success $true -Failure $true
    Write-Status "Note: classic registry auditing additionally needs SACLs on monitored keys (EID 4657). Sysmon EID 12/13 on HKCU\Software\Classes is the lower-noise detection for payload-staging keys." "Info"
}

function Set-MsiHardening {
    Write-Status "Hardening Windows Installer (AlwaysInstallElevated=0, verbose install logging)..." "Info"
    if ($Undo) { return }   # registry values restored by Restore-RegValues

    # Explicitly deny per-user elevated installs (M1042 for msiexec /q chains)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Kind DWord
    # If any user hive carries a per-user AlwaysInstallElevated=1, neutralize it (only when present)
    foreach ($hivePath in (Get-UserHivePaths -SubPath 'SOFTWARE\Policies\Microsoft\Windows\Installer')) {
        if (Test-Path $hivePath) {
            $val = (Get-ItemProperty -Path $hivePath -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
            if ($null -ne $val -and $val -ne 0) {
                Set-RegValue -Path $hivePath -Name 'AlwaysInstallElevated' -Value 0 -Kind DWord
            }
        }
    }
    # Verbose MSI logging -> %TEMP%\MSI*.log evidence for silent installs (M1047)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'Logging' -Value 'voicewarmup' -Kind String
}

function Set-WebClientDisabled {
    Write-Status "Disabling the WebClient (WebDAV) service..." "Info"
    $svc = Get-Service -Name WebClient -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Status "WebClient service not present on this host - nothing to do (already an effective mitigation)." "Info"
        return
    }

    if ($Undo) {
        if ($null -eq $Script:Backup.WebClient) {
            Write-Status "No WebClient prior state recorded - restoring OS default (Manual, stopped)." "Warning"
            Invoke-Change -Target 'WebClient service' -Action 'set Manual startup' -Apply { Set-Service -Name WebClient -StartupType Manual } | Out-Null
            return
        }
        $prior = $Script:Backup.WebClient
        $startType = switch ("$($prior.StartMode)") { 'Auto' { 'Automatic' } 'Manual' { 'Manual' } 'Disabled' { 'Disabled' } default { 'Manual' } }
        Invoke-Change -Target 'WebClient service' -Action "restore startup=$startType" -Apply { Set-Service -Name WebClient -StartupType $startType } | Out-Null
        if ($prior.WasRunning) {
            Invoke-Change -Target 'WebClient service' -Action 'start service (was running before)' -Apply { Start-Service -Name WebClient -ErrorAction SilentlyContinue } | Out-Null
        }
        Add-ChangeLog -Action 'Undo-WebClient' -Target 'WebClient' -OldValue 'Disabled' -NewValue $startType
        return
    }

    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='WebClient'" -ErrorAction SilentlyContinue
    if ($null -eq $Script:Backup.WebClient) {
        $Script:Backup.WebClient = @{ StartMode = $(if ($wmi) { $wmi.StartMode } else { 'Manual' }); WasRunning = ($svc.Status -eq 'Running') }
    }
    $ok = Invoke-Change -Target 'WebClient service' -Action 'stop and disable (breaks WebDAV UNC payload fetch)' -Apply {
        if ($svc.Status -eq 'Running') { Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue }
        Set-Service -Name WebClient -StartupType Disabled
    }
    if ($ok) { Add-ChangeLog -Action 'Disable-Service' -Target 'WebClient' -OldValue "$($wmi.StartMode)/$($svc.Status)" -NewValue 'Disabled/Stopped' }
}

function Set-SmartScreenEnforced {
    Write-Status "Enforcing SmartScreen at 'Block' level..." "Info"
    if ($Undo) { return }   # registry values restored by Restore-RegValues
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'      -Value 1      -Kind DWord
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Kind String
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Block' -Kind String
}

function Set-ShowFileExtensions {
    Write-Status "Making file extensions visible for all logged-on users (defeats '.pdf.lnk' masquerade)..." "Info"
    if ($Undo) { return }   # registry values restored by Restore-RegValues
    foreach ($advPath in (Get-UserHivePaths -SubPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced')) {
        Set-RegValue -Path $advPath -Name 'HideFileExt' -Value 0 -Kind DWord
    }
    Write-Status "Users must restart Explorer (or sign out/in) to see the change. Also deploy via GPO for roaming profiles." "Info"
}

function Add-SshEgressBlock {
    Write-Status "Adding outbound firewall block for the OpenSSH client (TCP/22)..." "Info"
    $existing = Get-NetFirewallRule -DisplayName $Script:SshFirewallRuleName -ErrorAction SilentlyContinue
    if ($Undo) {
        if ($existing -or $Script:Backup.FirewallRule) {
            Invoke-Change -Target $Script:SshFirewallRuleName -Action 'remove firewall rule' -Apply {
                Remove-NetFirewallRule -DisplayName $Script:SshFirewallRuleName -ErrorAction SilentlyContinue
            } | Out-Null
            Add-ChangeLog -Action 'Undo-Firewall' -Target $Script:SshFirewallRuleName -OldValue 'Block' -NewValue '(removed)'
        }
        return
    }
    if ($existing) {
        Write-Status "Firewall rule already present - idempotent skip." "Info"
        $Script:Backup.FirewallRule = $true
        return
    }
    $sshPath = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path $sshPath)) {
        Write-Status "ssh.exe not found at $sshPath - no egress block needed on this host." "Info"
        return
    }
    $ok = Invoke-Change -Target $Script:SshFirewallRuleName -Action 'block ssh.exe outbound TCP/22 (PermitLocalCommand cradle egress)' -Apply {
        New-NetFirewallRule -DisplayName $Script:SshFirewallRuleName -Direction Outbound -Program $sshPath -Protocol TCP -RemotePort 22 -Action Block -Profile Any -Description "Blocks the OpenSSH client from reaching external SSH endpoints (LOLBin download-cradle abuse). Replace with allowlist exceptions for approved jump hosts if outbound SSH is required." | Out-Null
    }
    if ($ok) {
        $Script:Backup.FirewallRule = $true
        Add-ChangeLog -Action 'Add-FirewallRule' -Target $Script:SshFirewallRuleName -OldValue '(none)' -NewValue 'Outbound Block ssh.exe TCP/22'
    }
}

function Remove-OpenSSHClient {
    Write-Status "Removing the OpenSSH Client Windows capability (optional, M1042)..." "Info"
    try { $caps = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like 'OpenSSH.Client*' } }
    catch { Write-Status "Get-WindowsCapability unavailable: $($_.Exception.Message)" "Warning"; return }

    if ($Undo) {
        if ($Script:Backup.OpenSSHClient) {
            $cap = $caps | Select-Object -First 1
            if ($cap) {
                Invoke-Change -Target $cap.Name -Action 'reinstall OpenSSH Client capability' -Apply {
                    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
                } | Out-Null
                Add-ChangeLog -Action 'Undo-WindowsCapability' -Target $cap.Name -OldValue 'Removed' -NewValue 'Installed'
            }
        }
        return
    }
    $cap = $caps | Select-Object -First 1
    if (-not $cap) { Write-Status "OpenSSH Client capability not present - nothing to do." "Info"; return }
    if ($cap.State -ne 'Installed') { Write-Status "OpenSSH Client already absent (State=$($cap.State))." "Info"; return }
    $ok = Invoke-Change -Target $cap.Name -Action 'remove OpenSSH Client capability' -Apply {
        Remove-WindowsCapability -Online -Name $cap.Name | Out-Null
    }
    if ($ok) {
        $Script:Backup.OpenSSHClient = $true
        Add-ChangeLog -Action 'Remove-WindowsCapability' -Target $cap.Name -OldValue 'Installed' -NewValue 'Removed'
    }
}

# ============================================================
# Main Execution
# ============================================================

if ($Undo) {
    Write-Status "Reverting hardening changes..." "Warning"
    if (-not (Load-Backup)) {
        Write-Status "No backup file found at $BackupFile - removing known hardened values (back to OS defaults) and reversing service/audit changes without prior-state restore." "Warning"
        $Script:Backup = New-BackupStore
        Remove-KnownRegistryValues
    }
    Set-ASRRules
    Set-DefenderFeatures
    Set-ProcessCreationAuditing
    Set-ScheduledTaskAuditing
    Set-RegistryAuditing
    Set-WebClientDisabled
    Add-SshEgressBlock          # removes the rule if present
    Remove-OpenSSHClient        # reinstalls if we removed it
    Restore-RegValues           # PowerShell logging, MSI, SmartScreen, HideFileExt, cmd-line audit value
} else {
    Write-Status "Applying hardening against Star Blizzard RedFlick/CosmicPulse LOLBin chain (T1204.002, T1105, T1059.001, T1218.007, T1053.005, T1218.011, T1071.001)..." "Info"

    # Load any existing backup so re-runs preserve the ORIGINAL prior state
    if (-not (Load-Backup)) { $Script:Backup = New-BackupStore }

    Set-ASRRules
    Set-DefenderFeatures -Settings @{
        EnableNetworkProtection = 'Enabled'   # blocks C2 destinations for system processes (curl.exe beacons)
        MAPSReporting           = 'Advanced'  # cloud-delivered protection (dependency of the prevalence ASR rule)
        SubmitSamplesConsent    = '1'         # send safe samples automatically
        PUAProtection           = '1'         # block potentially unwanted applications
    }
    Set-PowerShellLogging
    Set-ProcessCreationAuditing
    Set-ScheduledTaskAuditing
    Set-RegistryAuditing
    Set-MsiHardening
    Set-WebClientDisabled
    Set-SmartScreenEnforced
    Set-ShowFileExtensions
    if ($RestrictEgress)       { Add-SshEgressBlock }   else { Write-Status "Skipping egress firewall rule (-RestrictEgress not given)." "Info" }
    if ($RemoveOpenSSHClient)  { Remove-OpenSSHClient } else { Write-Status "Skipping OpenSSH Client removal (-RemoveOpenSSHClient not given)." "Info" }

    if ($WhatIfPreference) {
        Write-Status "WhatIf mode - backup file not written." "Warning"
    } else {
        Save-Backup
    }
}

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes applied:" "Success"
    $Script:ChangeLog | Format-Table -AutoSize
} else {
    Write-Status "No changes were needed (system already in the desired state)." "Success"
}

Write-Status "Complete. Verify with: Get-MpPreference, auditpol /get /category:* , Get-Service WebClient, wevtutil gl Microsoft-Windows-TaskScheduler/Operational" "Success"
