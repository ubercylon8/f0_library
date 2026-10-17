<#
.SYNOPSIS
    Hardening for: ScreenConnect Unsanctioned RMM Abuse for Third-Party Access
    Test UUID: 208ef54b-06bc-4610-87b6-520aea57517e
    Techniques: T1199, T1219, T1543.003, T1567.002

.DESCRIPTION
    ScreenConnect (ConnectWise) is a LEGITIMATE, vendor-signed RMM. This script
    does NOT blanket-block the vendor product. It hardens against UNSANCTIONED RMM
    abuse via governance + telemetry:
      1. Enables service-installation auditing (Security 4697 / System 7045)
      2. Inventories and FLAGS any existing ScreenConnect install/service so you
         can confirm whether it is sanctioned
      3. (opt-in) Merges an AppLocker DENY policy for the ScreenConnect publisher
      4. (opt-in) Creates outbound firewall BLOCK rules for any currently-installed
         ScreenConnect agent binaries (relay containment)

    Review switches before running in production. Application control changes can
    disrupt sanctioned IT usage — scope to your environment.

.PARAMETER EnableAppLockerDeny
    Merge an AppLocker deny rule for the ScreenConnect publisher (Exe + Msi
    collections). WARNING: blocks ALL ScreenConnect. If ScreenConnect IS your
    sanctioned RMM, do NOT use this — allow-list your instance instead.

.PARAMETER BlockInstalledAgentEgress
    Create outbound Windows Firewall block rules for any ScreenConnect agent
    binaries found installed on this host (cuts an active relay).

.NOTES
    Run as Administrator. Idempotent where practical.
#>

[CmdletBinding()]
param(
    [switch]$EnableAppLockerDeny,
    [switch]$BlockInstalledAgentEgress
)

# ---------------------------------------------------------------------------
# Privilege + execution-policy bootstrap (per CLAUDE.md PowerShell guidelines)
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-EnsureAdmin {
    if (-not (Test-IsAdmin)) {
        Write-Warning "Administrator privileges required. Relaunching elevated..."
        $psi = @{
            FilePath     = 'powershell.exe'
            ArgumentList = @('-ExecutionPolicy','Bypass','-NoProfile','-File',"`"$PSCommandPath`"") + `
                           $(if ($EnableAppLockerDeny) {'-EnableAppLockerDeny'}) + `
                           $(if ($BlockInstalledAgentEgress) {'-BlockInstalledAgentEgress'})
            Verb         = 'RunAs'
        }
        try { Start-Process @psi } catch { Write-Error "Elevation cancelled/failed: $_" }
        exit
    }
}

# Bypass execution policy for THIS process only (does not persist machine-wide).
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch {}

Invoke-EnsureAdmin

$divider = ('=' * 65)
Write-Host $divider -ForegroundColor Cyan
Write-Host "ScreenConnect Unsanctioned RMM Abuse - Hardening" -ForegroundColor Cyan
Write-Host "UUID: 208ef54b-06bc-4610-87b6-520aea57517e" -ForegroundColor Cyan
Write-Host $divider -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Enable service-installation auditing (T1543.003 telemetry)
# ---------------------------------------------------------------------------
Write-Host "[1] Enabling service-installation auditing (Security 4697 / System 7045)..." -ForegroundColor Green
try {
    # 4697 (a service was installed) lives under 'Security System Extension'.
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null
    Write-Host "    Enabled 'Security System Extension' auditing (4697)." -ForegroundColor Gray
    Write-Host "    System 7045 (Service Control Manager) is logged by default in the System log." -ForegroundColor Gray
} catch {
    Write-Warning "    Failed to set audit policy: $_"
}
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Inventory + FLAG existing ScreenConnect installs/services
# ---------------------------------------------------------------------------
Write-Host "[2] Inventorying ScreenConnect presence (confirm sanctioned vs unsanctioned)..." -ForegroundColor Green

$svcs = Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue
if ($svcs) {
    foreach ($s in $svcs) {
        Write-Host "    [FLAG] Service present: '$($s.Name)' status=$($s.Status)" -ForegroundColor Yellow
    }
    Write-Host "    -> If these instance-id(s) are NOT your sanctioned RMM, treat as an incident." -ForegroundColor Yellow
} else {
    Write-Host "    No 'ScreenConnect Client (*)' service found." -ForegroundColor Gray
}

$installDirs = @()
foreach ($root in @("$env:ProgramFiles(x86)","$env:ProgramFiles","$env:ProgramData")) {
    if ($root) {
        $installDirs += Get-ChildItem -Path $root -Filter 'ScreenConnect Client (*' -Directory -ErrorAction SilentlyContinue
    }
}
if ($installDirs) {
    foreach ($d in $installDirs) { Write-Host "    [FLAG] Install dir: $($d.FullName)" -ForegroundColor Yellow }
} else {
    Write-Host "    No ScreenConnect install directory found." -ForegroundColor Gray
}
Write-Host ""

# ---------------------------------------------------------------------------
# 3. (opt-in) AppLocker deny for the ScreenConnect publisher
# ---------------------------------------------------------------------------
if ($EnableAppLockerDeny) {
    Write-Host "[3] Merging AppLocker DENY policy for ScreenConnect publisher..." -ForegroundColor Green
    Write-Warning "    This DENIES ALL ScreenConnect. If it is your sanctioned RMM, cancel and allow-list your instance instead."
    $policyXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePublisherRule Id="a1b2c3d4-208e-4b06-87b6-000000000001" Name="DENY ScreenConnect (unsanctioned RMM)" Description="Deny ScreenConnect access agent" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="SCREENCONNECT*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePublisherRule Id="a1b2c3d4-208e-4b06-87b6-000000000002" Name="DENY ScreenConnect MSI (unsanctioned RMM)" Description="Deny ScreenConnect installer" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="SCREENCONNECT*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
'@
    $tmp = Join-Path $env:TEMP "sc_applocker_deny_208ef54b.xml"
    try {
        $policyXml | Out-File -FilePath $tmp -Encoding ascii -Force
        Set-AppLockerPolicy -XmlPolicy $tmp -Merge -ErrorAction Stop
        Write-Host "    AppLocker deny policy merged. Ensure the Application Identity service (AppIDSvc) is running/enforced via GPO." -ForegroundColor Gray
    } catch {
        Write-Warning "    Failed to merge AppLocker policy: $_"
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
    Write-Host ""
} else {
    Write-Host "[3] AppLocker deny skipped (use -EnableAppLockerDeny to apply). Prefer WDAC/AppLocker ALLOW-LISTING of your sanctioned RMM." -ForegroundColor DarkGray
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 4. (opt-in) Block egress of any installed ScreenConnect agent binaries
# ---------------------------------------------------------------------------
if ($BlockInstalledAgentEgress) {
    Write-Host "[4] Creating outbound firewall BLOCK rules for installed ScreenConnect agents..." -ForegroundColor Green
    $agentExes = @()
    foreach ($d in $installDirs) {
        $agentExes += Get-ChildItem -Path $d.FullName -Filter 'ScreenConnect*.exe' -File -Recurse -ErrorAction SilentlyContinue
    }
    if ($agentExes) {
        foreach ($exe in $agentExes) {
            $ruleName = "BLOCK ScreenConnect egress - $($exe.Name)"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
                    -Program $exe.FullName -Profile Any -ErrorAction SilentlyContinue | Out-Null
                Write-Host "    Blocked egress: $($exe.FullName)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "    No installed ScreenConnect agent binaries found to block." -ForegroundColor Gray
    }
    Write-Host "    NOTE: also block '*.screenconnect.com' relay domains at your proxy/firewall for defense in depth." -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "[4] Agent egress block skipped (use -BlockInstalledAgentEgress to apply)." -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host $divider -ForegroundColor Cyan
Write-Host "Hardening complete. Key follow-ups:" -ForegroundColor Cyan
Write-Host "  - Maintain an RMM allow-list (sanctioned tool + instance-id + relay host)." -ForegroundColor Gray
Write-Host "  - Alert on service names matching 'ScreenConnect Client (*' not on the allow-list." -ForegroundColor Gray
Write-Host "  - Block '*.screenconnect.com' egress from hosts without a sanctioned RMM." -ForegroundColor Gray
Write-Host "  - Patch self-hosted ScreenConnect servers for CVE-2024-1709." -ForegroundColor Gray
Write-Host $divider -ForegroundColor Cyan
