# =============================================================================
# PROMPTFLUX v1 — Windows Hardening Script
# Test UUID: 0a749b39-409e-46f5-9338-ee886b439cfa
# =============================================================================
# This script applies the defensive controls described in
# 0a749b39-409e-46f5-9338-ee886b439cfa_DEFENSE_GUIDANCE.md. Run elevated.
#
# Safe to re-run (idempotent). Each section can be disabled independently via
# the $apply* booleans at the top.
# =============================================================================

param(
    [switch]$WhatIf,
    [switch]$Verbose
)

#Requires -RunAsAdministrator

# =============================================================================
# Admin privilege check + execution policy bypass
# =============================================================================

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# Ensure execution policy allows this session (bypass if needed).
try {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass' -and $currentPolicy -ne 'Unrestricted') {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    }
} catch {
    Write-Warning "Could not set execution policy to Bypass for this session: $_"
}

$applyDisableWSH          = $true   # Section 1 — disable Windows Script Host
$applyASR                 = $true   # Section 2 — enable ASR rules
$applyStartupFIM          = $true   # Section 3 — audit Startup folder writes
$applyAppLockerStub       = $false  # Section 4 — generate AppLocker policy stub (review before enforcing)
$applyDefenderExclusionGuard = $true # Section 5 — alert on odd Defender exclusions

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $color = switch ($Level) {
        "INFO"  { "Cyan" }
        "OK"    { "Green" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) -ForegroundColor $color
}

# =============================================================================
# Section 1 — Disable Windows Script Host
# =============================================================================
if ($applyDisableWSH) {
    Log "Disabling Windows Script Host (blocks VBS/JS dropper execution)" "INFO"
    $wshKey = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    if ($WhatIf) {
        Log "WhatIf: would set $wshKey Enabled = 0" "INFO"
    } else {
        try {
            if (-not (Test-Path $wshKey)) {
                New-Item -Path $wshKey -Force | Out-Null
            }
            New-ItemProperty -Path $wshKey -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
            Log "WSH disabled at $wshKey\Enabled=0" "OK"
        } catch {
            Log "Failed to disable WSH: $_" "ERROR"
        }
    }
}

# =============================================================================
# Section 2 — ASR rules
# =============================================================================
if ($applyASR) {
    Log "Enabling Defender Attack Surface Reduction rules" "INFO"
    $asrRules = @(
        # Block JavaScript or VBScript from launching downloaded executable content
        @{ GUID = "D3E037E1-3EB8-44C8-A917-57927947596D"; Description = "Block JS/VBS launching downloaded content"; Action = "Enabled" },
        # Block Office applications from creating executable content
        @{ GUID = "3B576869-A4EC-4529-8536-B80A7769E899"; Description = "Block Office creating executable content"; Action = "Enabled" },
        # Block executable files from running unless they meet a prevalence, age, or trusted list criterion (audit first)
        @{ GUID = "01443614-CD74-433A-B99E-2ECDC07BFC25"; Description = "Block low-prevalence / unsigned EXE"; Action = "AuditMode" },
        # Block abuse of exploited vulnerable signed drivers
        @{ GUID = "56A863A9-875E-4185-98A7-B882C64B5CE5"; Description = "Block exploited vulnerable signed drivers"; Action = "Enabled" }
    )
    foreach ($rule in $asrRules) {
        if ($WhatIf) {
            Log ("WhatIf: would enable ASR rule {0} ({1}) action={2}" -f $rule.GUID, $rule.Description, $rule.Action) "INFO"
        } else {
            try {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID `
                                 -AttackSurfaceReductionRules_Actions $rule.Action -ErrorAction Stop
                Log ("ASR rule enabled: {0} ({1}) action={2}" -f $rule.GUID, $rule.Description, $rule.Action) "OK"
            } catch {
                Log ("Failed to enable ASR rule {0}: {1}" -f $rule.GUID, $_) "WARN"
            }
        }
    }
}

# =============================================================================
# Section 3 — Startup-folder audit (surfaces unauthorised writes)
# =============================================================================
if ($applyStartupFIM) {
    Log "Enabling audit on Startup folders" "INFO"
    $paths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) {
            Log "Path missing, skipping: $p" "WARN"
            continue
        }
        if ($WhatIf) {
            Log "WhatIf: would enable SACL audit on $p" "INFO"
            continue
        }
        try {
            $acl = Get-Acl -Path $p -Audit
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AuditFlags]::Success
            )
            $acl.AddAuditRule($rule)
            Set-Acl -Path $p -AclObject $acl
            Log "Audit SACL applied to $p" "OK"
        } catch {
            Log "Failed to apply SACL to ${p}: $_" "ERROR"
        }
    }

    # Enable object-access auditing (required for SACL to produce EventID 4663)
    if (-not $WhatIf) {
        try {
            & auditpol.exe /set /subcategory:"File System" /success:enable /failure:disable | Out-Null
            Log "auditpol: File System success auditing enabled" "OK"
        } catch {
            Log "Failed to update audit policy: $_" "WARN"
        }
    }
}

# =============================================================================
# Section 4 — AppLocker policy stub (generates XML; does NOT enforce)
# =============================================================================
if ($applyAppLockerStub) {
    Log "Generating AppLocker policy stub" "INFO"
    $policyPath = "$env:ProgramData\PROMPTFLUX_AppLocker_Policy.xml"
    $stub = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="00000000-0000-0000-0000-PROMPTFLUX001" Name="Block EXE from user-writable paths" Description="PROMPTFLUX hardening — review before enforcing" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\F0\*.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-PROMPTFLUX002" Name="Block EXE from Temp" Description="PROMPTFLUX hardening — review before enforcing" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%USERPROFILE%\AppData\Local\Temp\*.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="00000000-0000-0000-0000-PROMPTFLUX003" Name="Block VBS from user-writable paths" Description="PROMPTFLUX hardening — review before enforcing" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\F0\*.vbs" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
    if ($WhatIf) {
        Log "WhatIf: would write $policyPath" "INFO"
    } else {
        $stub | Set-Content -Path $policyPath -Encoding UTF8
        Log "AppLocker stub written to $policyPath (AuditOnly — review before enforcing)" "OK"
    }
}

# =============================================================================
# Section 5 — Defender exclusion guard (surfaces odd path/process exclusions)
# =============================================================================
if ($applyDefenderExclusionGuard) {
    Log "Auditing Defender exclusion list for suspicious entries" "INFO"
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $paths = $mp.ExclusionPath
        $procs = $mp.ExclusionProcess
        $suspicious = @()
        foreach ($p in $paths) {
            if ($p -match '(?i)(\\Users\\Public|\\AppData\\Local\\Temp|\\ProgramData(?!\\Microsoft)|^C:\\F0)') {
                $suspicious += $p
            }
        }
        if ($suspicious.Count -gt 0) {
            Log ("ALERT: suspicious Defender exclusion paths found: {0}" -f ($suspicious -join ', ')) "WARN"
        } else {
            Log "No suspicious Defender exclusion paths found" "OK"
        }
        if ($procs -and ($procs.Count -gt 0)) {
            Log ("Defender process exclusions in place: {0}" -f ($procs -join ', ')) "INFO"
        }
    } catch {
        Log "Could not read Defender preferences: $_" "WARN"
    }
}

Log "PROMPTFLUX hardening complete. Review messages above." "OK"
