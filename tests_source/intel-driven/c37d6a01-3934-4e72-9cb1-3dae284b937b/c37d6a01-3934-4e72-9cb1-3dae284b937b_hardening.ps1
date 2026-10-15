<#
.SYNOPSIS
    Hardens Windows against tailcat/Tailscale-DERP tunneled C2, ingress tool
    transfer of dual-use tunneling binaries, unauthenticated SSH shells, and
    exfiltration over encrypted tunnels (Kothamine technique class).

.DESCRIPTION
    Applies security hardening to mitigate MITRE ATT&CK techniques
    T1105, T1572, T1021.004, T1005, T1041. All changes are idempotent and
    reversible with -Undo.

    Controls applied:
      1. Microsoft Defender: cloud-delivered protection (MAPS Advanced),
         PUA protection in block mode, network protection, real-time monitoring
      2. ASR rules: executable prevalence/age/trusted-list rule and
         potentially-obfuscated-scripts rule (block mode)
      3. Process creation auditing with command line (Event ID 4688)
      4. Network connection / filtering-platform connection auditing
      5. AppLocker executable rules in AUDIT mode for user-writable paths
         (baseline for later enforcement via WDAC/GPO)
      6. Advisory egress-blocking guidance for Tailscale DERP / tailcat
         infrastructure where Tailscale is not sanctioned (see output)

    This script hardens against the TECHNIQUE, not any specific tool: it does
    not reference test paths, binaries, or artifacts.

    Test ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
    MITRE ATT&CK: T1105, T1572, T1021.004, T1005, T1041
    Mitigations: M1031, M1037, M1042, M1035, M1030, M1057

.PARAMETER Undo
    Reverts all changes made by this script.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening.ps1
    Applies all hardening settings.

.EXAMPLE
    .\c37d6a01-3934-4e72-9cb1-3dae284b937b_hardening.ps1 -Undo
    Reverts all hardening settings.

.NOTES
    Author: F0RT1KA Defense Guidance Generator
    Date: 2026-10-14
    Requires: Administrator privileges
    Tested on: Windows 10/11, Windows Server 2019/2022
    Idempotent: Yes (safe to run multiple times)

.LINK
    https://attack.mitre.org/techniques/T1572/
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$Script:ChangeLog = @()
$Script:LogFile = Join-Path $env:TEMP "kothamine_tailcat_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Header")]
        [string]$Type = "Info"
    )
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red"; Header = "Magenta" }
    $prefix = @{ Info = "[*]"; Success = "[+]"; Warning = "[!]"; Error = "[-]"; Header = "[=]" }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
    Add-Content -Path $Script:LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $($prefix[$Type]) $Message" -ErrorAction SilentlyContinue
}

function Add-ChangeLog {
    param([string]$Action, [string]$Target, [string]$OldValue, [string]$NewValue)
    $Script:ChangeLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action = $Action; Target = $Target
        OldValue = $OldValue; NewValue = $NewValue
    }
}

# ============================================================================
# 1. Microsoft Defender feature switches
# ============================================================================

function Set-DefenderProtection {
    # MAPS membership: 0=Disabled, 1=Basic, 2=Advanced
    # PUAProtection:   0=Disabled, 1=Enabled(block), 2=AuditMode
    # EnableNetworkProtection: 0=Disabled, 1=Enabled, 2=AuditMode
    $settings = @(
        @{ Name = "MAPSReporting";            Value = 2; Description = "Cloud-delivered protection (MAPS Advanced)" }
        @{ Name = "SubmitSamplesConsent";     Value = 1; Description = "Sample submission consent (send safe samples automatically)" }
        @{ Name = "PUAProtection";            Value = 1; Description = "PUA protection in block mode" }
        @{ Name = "EnableNetworkProtection";  Value = 1; Description = "Network protection (blocks low-reputation egress) in block mode" }
        @{ Name = "DisableRealtimeMonitoring"; Value = 0; Description = "Real-time protection enabled" }
    )

    foreach ($s in $settings) {
        $current = $null
        try { $current = (Get-MpPreference).($s.Name) } catch { }
        if ($Undo) {
            if ($PSCmdlet.ShouldProcess($s.Name, "Revert Defender setting to default")) {
                # 0 = feature off / not configured for every switch in this set
                $undoParams = @{ $s.Name = 0 }
                Set-MpPreference @undoParams
                Write-Status "Reverted Defender setting $($s.Name)" "Warning"
                Add-ChangeLog "Revert" "Defender:$($s.Name)" "$current" "0"
            }
        } else {
            if ($current -eq $s.Value) {
                Write-Status "Already set: $($s.Description)" "Success"
            } else {
                if ($PSCmdlet.ShouldProcess($s.Name, "Set Defender preference")) {
                    $prefParams = @{ $s.Name = $s.Value }
                    Set-MpPreference @prefParams
                    Write-Status "Configured: $($s.Description) (was: $current)" "Success"
                    Add-ChangeLog "Set" "Defender:$($s.Name)" "$current" "$($s.Value)"
                }
            }
        }
    }
}

# ============================================================================
# 2. Attack Surface Reduction (ASR) rules
# ============================================================================

function Set-ASRRules {
    # Rule GUIDs (Microsoft ASR reference):
    #   01443614-cd74-433a-b99e-2ecdc07bfc25 = Block executable files from running
    #       unless they meet a prevalence, age, or trusted list criterion
    #       -> counters freshly downloaded tunneling binaries (T1105/T1572)
    #   5beb7efe-fd9a-4556-801d-275e5ffc04cc = Block execution of potentially
    #       obfuscated scripts -> counters npm install-script loaders/stagers
    #   d1e49aac-8f56-4280-b9ba-993a6d77406c = Block process creations originating
    #       from PSExec and WMI commands -> limits operator lateral movement
    $asrRules = @(
        @{ Guid = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Description = "Block executables without prevalence/age/trusted-list (freshly-downloaded tools)" }
        @{ Guid = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Description = "Block execution of potentially obfuscated scripts (npm loader stagers)" }
        @{ Guid = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; Description = "Block process creations from PSExec/WMI (operator lateral movement)" }
    )

    $prefs = Get-MpPreference
    $existingIds    = @($prefs.AttackSurfaceReductionRules_Ids)
    $existingAction = @($prefs.AttackSurfaceReductionRules_Actions)

    foreach ($rule in $asrRules) {
        if ($Undo) {
            if ($existingIds -contains $rule.Guid) {
                if ($PSCmdlet.ShouldProcess($rule.Guid, "Remove ASR rule")) {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule.Guid -AttackSurfaceReductionRules_Actions Disabled
                    Write-Status "Disabled ASR rule: $($rule.Description)" "Warning"
                    Add-ChangeLog "Revert" "ASR:$($rule.Guid)" "Enabled" "Disabled"
                }
            }
        } else {
            $idx = [Array]::IndexOf($existingIds, $rule.Guid)
            $currentAction = if ($idx -ge 0) { $existingAction[$idx] } else { $null }
            if ($currentAction -eq 1) {
                Write-Status "ASR already in block mode: $($rule.Description)" "Success"
            } else {
                if ($PSCmdlet.ShouldProcess($rule.Guid, "Enable ASR rule in block mode")) {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule.Guid -AttackSurfaceReductionRules_Actions Enabled
                    Write-Status "ASR enabled (block): $($rule.Description)" "Success"
                    Add-ChangeLog "Set" "ASR:$($rule.Guid)" "$currentAction" "1 (Block)"
                }
            }
        }
    }

    if (-not $Undo) {
        Write-Status "NOTE: audit ASR impact first on developer fleets — the prevalence rule can block legitimate newly-released tooling. Review Event ID 1121/1122 in 'Microsoft-Windows-Windows Defender/Operational'." "Info"
    }
}

# ============================================================================
# 3. Audit policy: process creation with command line, network connections
# ============================================================================

function Set-AuditPolicy {
    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("Audit Policy", "Revert process/network auditing")) {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
            auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable | Out-Null
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
            }
            Write-Status "Reverted audit policy (process creation, filtering platform connection, command-line capture)" "Warning"
            Add-ChangeLog "Revert" "AuditPolicy" "Enabled" "Disabled"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess("Audit Policy", "Enable process creation + command line + network connection auditing")) {
        auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
        # 4688 command-line capture — the highest-value telemetry for catching
        # `serve no-auth-ssh` / `recv` / `cp` style tunnel command lines
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        New-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null

        # Windows Filtering Platform connections (5156/5158) — visibility into
        # outbound UDP/443 DERP flows per process
        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable | Out-Null

        Write-Status "Enabled process creation auditing with command line (4688)" "Success"
        Write-Status "Enabled Filtering Platform Connection auditing (5156/5158)" "Success"
        Add-ChangeLog "Set" "AuditPolicy:ProcessCreation+CmdLine+WFP" "NotConfigured" "Enabled"
    }
}

# ============================================================================
# 4. AppLocker baseline (AUDIT mode) for user-writable paths
# ============================================================================

function Set-AppLockerBaseline {
    # Audit-mode executable rules: log (Event 8003/8004 in
    # Microsoft-Windows-AppLocker/EXE and DLL) when unsigned binaries run from
    # user-writable locations — the classic landing zone for downloaded
    # tunneling tools. Enforcement is left to a managed WDAC/GPO rollout.
    $policyPath = Join-Path $env:ProgramData "F0RT1KA\AppLocker_Audit_Policy.xml"

    if ($Undo) {
        if ($PSCmdlet.ShouldProcess("AppLocker", "Remove audit baseline policy")) {
            if (Test-Path $policyPath) { Remove-Item $policyPath -Force }
            Write-Status "Removed AppLocker audit baseline file (live policy, if imported via GPO, must be removed there)" "Warning"
            Add-ChangeLog "Revert" "AppLocker" "AuditBaseline" "Removed"
        }
        return
    }

    $policyXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a1b2c3d4-0001-4000-8000-000000000001" Name="Allow Windows (system)" Description="Allow execution from system directories" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a1b2c3d4-0002-4000-8000-000000000002" Name="Allow Program Files" Description="Allow execution from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a1b2c3d4-0003-4000-8000-000000000003" Name="Audit executables in user-writable paths" Description="Audit-only: execution from user-writable, non-standard locations (downloaded tools landing zone)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

    if ($PSCmdlet.ShouldProcess("AppLocker", "Write audit-mode baseline policy")) {
        $dir = Split-Path $policyPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $policyXml | Out-File -FilePath $policyPath -Encoding UTF8 -Force
        Write-Status "Wrote AppLocker audit-mode baseline to $policyPath" "Success"
        Write-Status "Import with: Set-AppLockerPolicy -XmlPolicy '$policyPath' (pilot on a test OU; ensures the AppIDSvc service is running)" "Info"
        Add-ChangeLog "Set" "AppLocker:$policyPath" "Absent" "AuditOnly baseline written"
    }
}

# ============================================================================
# 5. Egress-control advisory (Tailscale DERP / tunneling SaaS)
# ============================================================================

function Write-EgressGuidance {
    Write-Status "Egress filtering advisory (apply at proxy/firewall/DNS layer):" "Header"
    Write-Host @"
  Where Tailscale is NOT a sanctioned tool, block AND alert on:
    - DNS/TLS SNI: derp*.tailscale.com, *.tailscale.com DERP relay hostnames
    - DERP map endpoint: tailcat.dev/derpmap.json
    - Tailscale control plane: login.tailscale.com, controlplane.tailscale.com
    - Long-lived UDP/443 flows to Tailscale relay anycast ranges (netflow/Zeek)
  Where Tailscale IS sanctioned, restrict to a managed, ACL'd tailnet and alert
  on DERP-map fetches from hosts without an authorized tailscaled.
  Rationale: encrypted tunnel C2 (T1572) survives content inspection; the
  durable control is which destinations endpoints may reach at all (M1037).
"@ -ForegroundColor Yellow
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Status "Kothamine tailcat technique-class hardening (T1105, T1572, T1021.004, T1005, T1041)" "Header"
Write-Status "Log file: $Script:LogFile" "Info"

if ($Undo) {
    Write-Status "Reverting hardening changes..." "Warning"
    Set-AppLockerBaseline
    Set-AuditPolicy
    Set-ASRRules
    Set-DefenderProtection
} else {
    Write-Status "Applying hardening..." "Info"
    Set-DefenderProtection
    Set-ASRRules
    Set-AuditPolicy
    Set-AppLockerBaseline
    Write-EgressGuidance
}

if ($Script:ChangeLog.Count -gt 0) {
    Write-Status "Changes applied:" "Success"
    $Script:ChangeLog | Format-Table -AutoSize
}

Write-Status "Complete. Verify with: Get-MpPreference; auditpol /get /category:*; Get-AppLockerPolicy -Effective -Xml" "Success"
