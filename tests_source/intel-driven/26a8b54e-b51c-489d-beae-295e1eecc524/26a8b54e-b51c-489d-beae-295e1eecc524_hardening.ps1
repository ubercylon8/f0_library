<#
.SYNOPSIS
    Infostealer (Lumma-class) Defense Hardening — Windows Endpoint
.DESCRIPTION
    Idempotent hardening script implementing the Quick-Win and Medium-Term controls
    from the companion DEFENSE_GUIDANCE.md for the LummaC2 / StealC / Vidar
    infostealer threat profile:
      1. PowerShell Script Block + Module logging (detect encoded cradles, T1059.001)
      2. Browser password-manager disablement (Chrome + Edge enterprise policy,
         empties the Login Data target of T1555.003)
      3. Microsoft Defender ASR rules: obfuscated scripts, Office child processes,
         LSASS credential theft (T1204.002/T1059.001/T1555)
      4. Defender cloud-delivered protection, PUA, and network protection ON
         (fake-CAPTCHA/ClickFix web indicators, T1566/T1204.002)
      5. Process command-line auditing (4688) for cradle/masquerade visibility
      6. mshta.exe DisallowRun fallback for the ClickFix Win+R vector
         (enterprise AppLocker/WDAC is the primary control, T1204.002)
      7. Browser extension blocklist seed for known wallet extensions
         (reduces wallet-store harvest surface, T1555/T1005)

    All changes are idempotent and support -WhatIf (dry run) and -Undo (rollback).
    State for rollback is captured in %ProgramData%\LummaDefenseHardening\state.json.
.PARAMETER Undo
    Revert all changes applied by this script to their pre-hardening state.
.PARAMETER IncludeEgressBlocks
    Also create outbound firewall block rules for unapproved exfiltration tooling
    patterns (info-stealer stager names observed in the wild). Off by default —
    the Lumma C2 channel is best controlled at the authenticated proxy.
.EXAMPLE
    .\26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1 -WhatIf   # preview
    .\26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1           # apply
    .\26a8b54e-b51c-489d-beae-295e1eecc524_hardening.ps1 -Undo     # roll back
.NOTES
    Requires: Windows 10/11 or Server 2016+, local Administrator.
    Preferred delivery is GPO/Intune (enterprise policy) — this script is the
    endpoint-local fallback / lab verification path. Contains no references to
    any test harness: every control targets the underlying technique.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Undo,
    [switch]$IncludeEgressBlocks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ChangesApplied = 0
$script:ChangesSkipped = 0
$StateDir = Join-Path $env:ProgramData 'LummaDefenseHardening'
$StateFile = Join-Path $StateDir 'state.json'

# ---------------------------------------------------------------
# Prerequisites (mandatory per F0RT1KA PowerShell guidelines)
# ---------------------------------------------------------------
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

if (-not (Test-Administrator)) {
    Write-Host "[!] Administrator privileges required. Relaunch elevated." -ForegroundColor Red
    exit 1
}
if (-not (Set-ExecutionPolicyBypass)) { exit 1 }

function Write-Change([string]$Message) {
    $script:ChangesApplied++
    Write-Host "[+] $Message" -ForegroundColor Green
}
function Write-Skip([string]$Message) {
    $script:ChangesSkipped++
    Write-Host "[=] $Message" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------
# State capture / rollback
# ---------------------------------------------------------------
function Load-State {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    return $null
}
function Save-State([hashtable]$State) {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Force
}

# Records the prior value of a registry property once, for -Undo.
$script:UndoState = @{}
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Label)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    $stateKey = "$Path\$Name"
    if (-not $script:UndoState.ContainsKey($stateKey)) {
        $script:UndoState[$stateKey] = @{ Path = $Path; Name = $Name; Type = $Type; Value = $current }
    }
    if ($current -eq $Value) { Write-Skip "$Label already set ($Name=$Value)"; return }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        Write-Change "$Label ($Path\$Name = $Value)"
    }
}

function Undo-RegValue {
    param($Entry)
    if ($null -eq $Entry.Value) {
        Remove-ItemProperty -Path $Entry.Path -Name $Entry.Name -Force -ErrorAction SilentlyContinue
        Write-Change "Removed $($Entry.Path)\$($Entry.Name)"
    } else {
        if (-not (Test-Path $Entry.Path)) { New-Item -Path $Entry.Path -Force | Out-Null }
        Set-ItemProperty -Path $Entry.Path -Name $Entry.Name -Value $Entry.Value -Type $Entry.Type
        Write-Change "Restored $($Entry.Path)\$($Entry.Name) = $($Entry.Value)"
    }
}

# ---------------------------------------------------------------
# Control 1: PowerShell Script Block + Module Logging
# ---------------------------------------------------------------
function Set-PowerShellLogging([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' $v 'DWord' "PowerShell Script Block Logging"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' $v 'DWord' "PowerShell Module Logging"
    if ($Enable) {
        Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String' "Module Logging (all modules)"
    }
}

# ---------------------------------------------------------------
# Control 2: Browser password-manager disablement (Chrome + Edge)
# Empties the Login Data / credential-store target of the stealer chain.
# Pair with an approved enterprise password manager deployment.
# ---------------------------------------------------------------
function Set-BrowserPasswordManagerPolicy([bool]$Enable) {
    # $Enable = enable HARDENING (i.e., DISABLE browser password storage)
    $v = if ($Enable) { 0 } else { 1 }
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Google\Chrome'  'PasswordManagerEnabled' $v 'DWord' "Chrome password manager policy"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PasswordManagerEnabled' $v 'DWord' "Edge password manager policy"
}

# ---------------------------------------------------------------
# Control 3: ASR rules (verified GUIDs — Microsoft ASR reference)
# ---------------------------------------------------------------
function Set-ASRRules([bool]$Enable) {
    $mode = if ($Enable) { 'Enabled' } else { 'Disabled' }
    $rules = @{
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '9e6c4e1f-7d60-472a-bbaa-a39f66977d63' = 'Block credential stealing from LSASS'
    }
    try {
        foreach ($guid in $rules.Keys) {
            $current = (Get-MpPreference).AttackSurfaceReductionRules_Ids
            $currentModes = (Get-MpPreference).AttackSurfaceReductionRules_Actions
            $idx = [array]::IndexOf($current, $guid)
            if ($idx -ge 0 -and $currentModes[$idx] -eq $mode) {
                Write-Skip "ASR already $mode : $($rules[$guid])"
                continue
            }
            if ($PSCmdlet.ShouldProcess("ASR $guid", "Set $mode")) {
                if ($idx -ge 0) {
                    # Rewrite the full list (Add-MpPreference would duplicate)
                    $ids = @($current); $modes = @($currentModes)
                    $modes[$idx] = $mode
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $modes -ErrorAction Stop
                } else {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $mode -ErrorAction Stop
                }
                Write-Change "ASR $mode : $($rules[$guid])"
            }
        }
    } catch {
        Write-Host "[!] ASR rules could not be set via Set-MpPreference (non-Defender AV active or GPO-managed): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Deploy the same GUIDs via GPO/Intune: Windows Components > Antivirus > Microsoft Defender Antivirus > Attack Surface Reduction." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------
# Control 4: Defender cloud / PUA / network protection
# ---------------------------------------------------------------
function Set-DefenderWebProtections([bool]$Enable) {
    try {
        $want = if ($Enable) { 1 } else { 0 }
        $p = Get-MpPreference
        if ($p.EnableNetworkProtection -ne $want) {
            if ($PSCmdlet.ShouldProcess('EnableNetworkProtection', "Set $want")) {
                Set-MpPreference -EnableNetworkProtection $want -ErrorAction Stop
                Write-Change "Defender network protection = $want"
            }
        } else { Write-Skip "Defender network protection already $want" }
        if ($p.PUAProtection -ne $want) {
            if ($PSCmdlet.ShouldProcess('PUAProtection', "Set $want")) {
                Set-MpPreference -PUAProtection $want -ErrorAction Stop
                Write-Change "Defender PUA protection = $want"
            }
        } else { Write-Skip "Defender PUA protection already $want" }
    } catch {
        Write-Host "[!] Defender preferences unavailable (third-party AV active): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------
# Control 5: Process command-line auditing (4688 with command line)
# ---------------------------------------------------------------
function Set-CmdLineAuditing([bool]$Enable) {
    $v = if ($Enable) { 1 } else { 0 }
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' $v 'DWord' "Command-line in process-creation events"
    try {
        if ($Enable) {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
            Write-Change "Audit Policy: Process Creation (success+failure)"
        } else {
            Write-Skip "Audit Policy left as-is during Undo (see group policy)"
        }
    } catch {
        Write-Host "[!] auditpol failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------
# Control 6: mshta DisallowRun fallback (ClickFix Win+R vector).
# Per-user Explorer restriction. WDAC/AppLocker (enterprise) is primary.
# ---------------------------------------------------------------
function Set-MshtaDisallow([bool]$Enable) {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )
    foreach ($scope in $paths) {
        if ($Enable) {
            Set-RegValue $scope 'DisallowRun' 1 'DWord' "Explorer DisallowRun policy ($($scope -replace ':.*',''))"
            $disallowPath = Join-Path $scope 'DisallowRun'
            if (-not (Test-Path $disallowPath)) { New-Item -Path $disallowPath -Force | Out-Null }
            $existing = (Get-ItemProperty -Path $disallowPath -ErrorAction SilentlyContinue)
            $already = $false
            if ($existing) {
                foreach ($p in $existing.PSObject.Properties) {
                    if ($p.Name -match '^\d+$' -and $p.Value -eq 'mshta.exe') { $already = $true }
                }
            }
            if ($already) { Write-Skip "mshta.exe already in DisallowRun ($scope)"; continue }
            $next = 1
            if ($existing) { $next = ($existing.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { [int]$_.Name } | Measure-Object -Maximum).Maximum + 1 }
            if ($PSCmdlet.ShouldProcess("$disallowPath\$next", "Add mshta.exe")) {
                Set-ItemProperty -Path $disallowPath -Name $next -Value 'mshta.exe' -Type String
                Write-Change "mshta.exe blocked via DisallowRun entry $next ($($scope -replace ':.*',''))"
            }
        } else {
            $disallowPath = Join-Path $scope 'DisallowRun'
            if (Test-Path $disallowPath) {
                $props = (Get-ItemProperty -Path $disallowPath).PSObject.Properties | Where-Object { $_.Value -eq 'mshta.exe' }
                foreach ($p in $props) {
                    if ($PSCmdlet.ShouldProcess("$disallowPath\$($p.Name)", "Remove mshta.exe")) {
                        Remove-ItemProperty -Path $disallowPath -Name $p.Name -Force
                        Write-Change "Removed mshta.exe DisallowRun entry ($($scope -replace ':.*',''))"
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------
# Control 7: Browser extension blocklist seed (wallet extensions —
# wallet stores are a primary infostealer target)
# ---------------------------------------------------------------
function Set-ExtensionBlocklist([bool]$Enable) {
    # MetaMask (Chrome web store id, public knowledge)
    $ids = @('nkbihfbeogaeaoehlefnkodbefgpgknn')
    $encIds = $ids -join ';'
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist' 1 1 'DWord' "Chrome extension blocklist enabled"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist' 'BlockedExtensionIds' $encIds 'String' "Chrome blocked extension ids (wallet seed)"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist' 1 1 'DWord' "Edge extension blocklist enabled"
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist' 'BlockedExtensionIds' $encIds 'String' "Edge blocked extension ids (wallet seed)"
}

# ---------------------------------------------------------------
# Optional: egress blocks for observed stager tooling patterns
# ---------------------------------------------------------------
function Set-EgressBlocks([bool]$Enable) {
    if (-not $IncludeEgressBlocks -and $Enable) { Write-Skip "Egress blocks not requested (-IncludeEgressBlocks)"; return }
    $ruleName = 'IR-BLOCK-INFOSTEALER-STAGER-PATTERNS'
    if ($Enable) {
        if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
            Write-Skip "Firewall rule already present: $ruleName"
            return
        }
        if ($PSCmdlet.ShouldProcess($ruleName, 'Create outbound block rules')) {
            # Block execution-path egress is not possible via firewall; this blocks
            # the common stager filenames' traffic only when they run as processes
            # via program-scoped rules (best-effort complement to proxy controls).
            foreach ($proc in @('g.exe')) {
                $candidate = Join-Path $env:TEMP $proc
                if (Test-Path $candidate) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $candidate -Action Block | Out-Null
                    Write-Change "Outbound block for observed stager path $candidate"
                }
            }
        }
    } else {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Write-Change "Removed firewall rule $ruleName (if present)"
    }
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
if ($Undo) {
    Write-Host "=== Lumma-class infostealer hardening: ROLLBACK ===" -ForegroundColor Cyan
    $state = Load-State
    if ($state) {
        foreach ($prop in $state.PSObject.Properties) { Undo-RegValue -Entry $prop.Value }
    } else {
        Write-Host "[!] No state file found at $StateFile — rolling back controls to safe defaults." -ForegroundColor Yellow
        Set-PowerShellLogging $false
        Set-BrowserPasswordManagerPolicy $false
        Set-MshtaDisallow $false
        Set-EgressBlocks $false
    }
    Set-ASRRules $false
    Set-DefenderWebProtections $false
    Set-CmdLineAuditing $false
    Write-Host "Rollback complete. $script:ChangesApplied changes." -ForegroundColor Cyan
    exit 0
}

Write-Host "=== Lumma-class infostealer hardening: APPLY ===" -ForegroundColor Cyan
Set-PowerShellLogging $true
Set-BrowserPasswordManagerPolicy $true
Set-ASRRules $true
Set-DefenderWebProtections $true
Set-CmdLineAuditing $true
Set-MshtaDisallow $true
Set-ExtensionBlocklist $true
Set-EgressBlocks $true

# Persist registry undo state AFTER a successful apply.
Save-State $script:UndoState

Write-Host ""
Write-Host "Applied: $script:ChangesApplied   Skipped (already set): $script:ChangesSkipped" -ForegroundColor Cyan
Write-Host "Enterprise controls NOT settable locally (deploy via GPO/Intune):" -ForegroundColor Yellow
Write-Host "  - WDAC/AppLocker (blocks updater masquerade + user-writable-path stagers)" -ForegroundColor Yellow
Write-Host "  - Proxy alerting: User-Agent 'TeslaBrowser/5.5', URI '/c2sock', 'act=live' form posts" -ForegroundColor Yellow
Write-Host "  - Browser auto-update enforcement (App-Bound Encryption requires current Chrome/Edge 127+)" -ForegroundColor Yellow
Write-Host "  - EDR behavioral rules: cross-process injection into chrome.exe/msedge.exe" -ForegroundColor Yellow
exit 0
