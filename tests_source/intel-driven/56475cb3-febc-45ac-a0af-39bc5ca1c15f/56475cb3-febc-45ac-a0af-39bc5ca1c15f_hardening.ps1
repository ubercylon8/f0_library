<#
.SYNOPSIS
    Hardening script for the 3CX 3CXDesktopApp Cascading Supply-Chain Compromise
    test techniques (Lazarus / UNC4736).

.DESCRIPTION
    Applies and/or audits Windows controls that blunt the modeled techniques:
      - T1574.002  DLL side-loading (safe DLL search order, ASR)
      - T1027.003 / T1071.001  ICO steganography + GitHub-CDN C2 egress
      - T1555.003  browser credential theft (App-Bound Encryption)
      - T1497      sandbox/dormancy evasion (audit visibility)
      - T1195.002  supply-chain risk (WDAC/AppLocker path-pinning guidance)

    Idempotent. Reports current posture before changing anything. Use -Audit to
    only report without modifying the system.

.PARAMETER Audit
    Report current posture without making changes.

.NOTES
    MITRE ATT&CK: T1195.002, T1574.002, T1497, T1027.003, T1071.001, T1555.003
    Test ID: 56475cb3-febc-45ac-a0af-39bc5ca1c15f
    Run as Administrator.
#>

param(
    [switch]$Audit
)

# ============================================================================
# Privilege check + execution-policy bypass (project PowerShell guidelines)
# ============================================================================

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-ExecutionPolicyBypass {
    try {
        $current = Get-ExecutionPolicy -Scope Process
        if ($current -ne 'Bypass') {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            Write-Host "[*] Execution policy set to Bypass for this process." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Could not set execution policy: $_"
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Warning "This script must be run as Administrator. Re-launch from an elevated PowerShell prompt."
    Write-Host    "  Example: Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$PSCommandPath`"'"
    exit 1
}

Ensure-ExecutionPolicyBypass

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Hardening: 3CX Cascading Supply-Chain Compromise (Lazarus)" -ForegroundColor Cyan
Write-Host " Mode: $(if ($Audit) { 'AUDIT (no changes)' } else { 'APPLY' })"  -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

function Set-RegistryValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Rationale)
    Write-Host "`n[+] $Rationale" -ForegroundColor Yellow
    $existing = $null
    if (Test-Path $Path) {
        $existing = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    }
    Write-Host "    $Path\$Name  (current: $existing  target: $Value)"
    if ($Audit) { Write-Host "    [audit] skipped" -ForegroundColor DarkGray; return }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Host "    [applied]" -ForegroundColor Green
}

# ============================================================================
# T1574.002 — DLL side-loading resilience
# ============================================================================
Write-Host "`n=== T1574.002: DLL Side-Loading ===" -ForegroundColor Cyan

Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name 'SafeDllSearchMode' -Value 1 `
    -Rationale 'Enable safe DLL search order (system dirs before the app dir).'

Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
    -Name 'CWDIllegalInDllSearch' -Value 0xFFFFFFFF -Type 'DWord' `
    -Rationale 'Remove the current working directory from the DLL search path entirely.'

# Microsoft Defender ASR rules (reduce side-load / LOLBin abuse)
if (-not $Audit) {
    Write-Host "`n[+] Enabling Defender ASR rules relevant to side-loading / stealer behavior" -ForegroundColor Yellow
    $asrRules = @{
        # Block executable files unless they meet prevalence/age/trusted-list criteria
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Enabled'
        # Block credential stealing from LSASS (defense-in-depth)
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Enabled'
        # Block process creations from PSExec/WMI commands
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'AuditMode'
    }
    foreach ($id in $asrRules.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $asrRules[$id] -ErrorAction Stop
            Write-Host "    ASR $id => $($asrRules[$id])" -ForegroundColor Green
        } catch {
            Write-Warning "    Could not set ASR rule $id ($_)"
        }
    }
} else {
    Write-Host "`n[audit] ASR rules not modified. Current ASR config:" -ForegroundColor DarkGray
    try { (Get-MpPreference).AttackSurfaceReductionRules_Ids } catch {}
}

# ============================================================================
# T1071.001 / T1027.003 — C2 egress + ICO steganography visibility
# ============================================================================
Write-Host "`n=== T1071.001 / T1027.003: C2 egress + ICO stego ===" -ForegroundColor Cyan
Write-Host "[i] Route egress through a TLS-inspecting proxy and alert on non-browser"
Write-Host "    processes fetching .ico/asset files from raw.githubusercontent.com."
Write-Host "[i] Scan stored .ico files for data appended past the icon image using the"
Write-Host "    provided YARA rule (ICO_Steganography_Appended_Encrypted_Payload)."

# Enable DNS client logging for egress visibility
if (-not $Audit) {
    try {
        wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true | Out-Null
        Write-Host "[applied] Enabled Microsoft-Windows-DNS-Client/Operational log." -ForegroundColor Green
    } catch { Write-Warning "Could not enable DNS client operational log: $_" }
} else {
    Write-Host "[audit] DNS client operational log not modified." -ForegroundColor DarkGray
}

# ============================================================================
# T1555.003 — Browser credential theft
# ============================================================================
Write-Host "`n=== T1555.003: Browser Credential Theft ===" -ForegroundColor Cyan

# Enforce App-Bound Encryption / block third-party access via Edge policy where present
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' `
    -Name 'BrowserAddProfileEnabled' -Value 0 `
    -Rationale 'Restrict unmanaged Edge profiles (reduces uncontrolled credential stores).'

Write-Host "`n[i] Ensure Chrome/Edge App-Bound Encryption is active (default in current"
Write-Host "    channels) so credential blobs cannot be decrypted outside the browser."
Write-Host "[i] Deploy an EDR file-access rule denying NON-browser processes read access"
Write-Host "    to 'Login Data', 'key4.db', and 'logins.json'."

# ============================================================================
# T1497 — Sandbox/dormancy evasion visibility
# ============================================================================
Write-Host "`n=== T1497: Sandbox / Dormancy Evasion ===" -ForegroundColor Cyan
if (-not $Audit) {
    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Write-Host "[applied] Enabled Process Creation auditing." -ForegroundColor Green
    } catch { Write-Warning "Could not enable process creation auditing: $_" }
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 `
        -Rationale 'Include full command line in process-creation events for hunt visibility.'
} else {
    Write-Host "[audit] Audit policy not modified." -ForegroundColor DarkGray
}

# ============================================================================
# T1195.002 — Supply-chain / trusted-binary risk (guidance)
# ============================================================================
Write-Host "`n=== T1195.002: Supply-Chain / Trusted-Binary Risk ===" -ForegroundColor Cyan
Write-Host "[i] Deploy WDAC or AppLocker to PIN vendor applications to their signed"
Write-Host "    install path. This blocks a relocated / trojanized copy from running"
Write-Host "    out of a user-writable directory even if it is validly signed."
Write-Host "[i] Maintain a certificate-revocation runbook: be ready to deny-list a"
Write-Host "    vendor's signing certificate quickly on a disclosed pipeline breach."

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Hardening pass complete ($(if ($Audit) { 'audit only' } else { 'applied' }))." -ForegroundColor Cyan
Write-Host " Re-run the F0RT1KA test to confirm detections fire post-hardening." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
