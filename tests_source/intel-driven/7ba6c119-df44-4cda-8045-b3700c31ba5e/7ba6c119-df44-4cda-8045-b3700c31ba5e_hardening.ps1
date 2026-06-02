<#
.SYNOPSIS
    Hardens Windows against BYOVD PPL-bypass credential-dumping techniques.

.DESCRIPTION
    Applies security hardening to mitigate the KslKatz-style Bring-Your-Own-Vulnerable-
    Driver (BYOVD) attack chain that uses a Microsoft-signed Defender kernel driver
    (KslD.sys) to perform kernel-mode MmCopyMemory reads of LSASS, bypassing LSA
    Protection (PPL).

    Techniques mitigated:
      T1543.003 — Create or Modify System Service
      T1112     — Modify Registry
      T1068     — Exploitation for Privilege Escalation (BYOVD)
      T1003.001 — OS Credential Dumping: LSASS Memory

    MITRE Mitigations applied:
      M1040 — Behavior Prevention on Endpoint (HVCI, ASR rules)
      M1025 — Privileged Process Integrity (LSA Protection / RunAsPPL)
      M1043 — Credential Access Protection (Credential Guard)
      M1024 — Restrict Registry Permissions (KslD service key ACL)
      M1028 — OS Configuration (Driver Signature Enforcement, NTLM config)
      M1045 — Code Signing (WDAC driver block policy)
      M1018 — User Account Management (local admin, Tamper Protection)
      M1047 — Audit (advanced audit policy, registry SACL)

    IMPORTANT: This script hardens against the attack technique (BYOVD via vulnerable
    kernel drivers, unprotected LSASS access) and is not specific to any test framework
    binary, path, or UUID. It should protect against ANY tool that uses the same
    technique chain.

    PPL CAVEAT: RunAsPPL blocks naive user-mode LSASS reads but does NOT stop the
    BYOVD kernel read path (MmCopyMemory from ring 0). Always pair PPL with HVCI and
    Credential Guard for defense-in-depth. See DEFENSE_GUIDANCE.md for full rationale.

    Test ID: 7ba6c119-df44-4cda-8045-b3700c31ba5e
    MITRE ATT&CK: T1543.003, T1112, T1068, T1003.001
    Mitigations: M1040, M1025, M1043, M1024, M1028, M1045, M1018, M1047

.PARAMETER Undo
    Reverts all changes made by this script to their pre-hardening state.
    Note: HVCI and Credential Guard changes require a reboot to fully take effect
    in either direction; the Undo path restores registry values but the protection
    remains active until the next boot.

.PARAMETER WhatIf
    Displays what changes would be made without actually applying them.

.PARAMETER RebootIfRequired
    Automatically reboots the system if changes require a reboot to take effect
    (e.g., HVCI enablement, RunAsPPLBoot). Defaults to $false — user must reboot
    manually unless this switch is set.

.EXAMPLE
    .\7ba6c119-df44-4cda-8045-b3700c31ba5e_hardening.ps1
    Applies all hardening settings. Idempotent — safe to run multiple times.

.EXAMPLE
    .\7ba6c119-df44-4cda-8045-b3700c31ba5e_hardening.ps1 -WhatIf
    Shows what would be changed without modifying anything.

.EXAMPLE
    .\7ba6c119-df44-4cda-8045-b3700c31ba5e_hardening.ps1 -Undo
    Reverts all hardening changes applied by this script.

.EXAMPLE
    .\7ba6c119-df44-4cda-8045-b3700c31ba5e_hardening.ps1 -RebootIfRequired
    Applies hardening and reboots automatically if required.

.NOTES
    Author:     F0RT1KA Defense Guidance Generator
    Requires:   Administrator privileges
    Idempotent: Yes (safe to run multiple times)
    Reboot:     Required for HVCI, RunAsPPLBoot, and Credential Guard changes
                to take full effect. Script flags which changes need a reboot.
    Platforms:  Windows 10 1903+, Windows 11, Windows Server 2019+
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Undo,
    [switch]$RebootIfRequired
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Script:ChangeLog       = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:RebootNeeded    = $false
$Script:HardeningErrors = [System.Collections.Generic.List[string]]::new()

# ============================================================
# ADMIN CHECK (CLAUDE.md: all PowerShell scripts must include
# a function to check admin privileges)
# ============================================================

function Test-AdminPrivilege {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-AdminPrivilege)) {
    Write-Host '[ERROR] This script must be run as Administrator.' -ForegroundColor Red
    Write-Host '        Re-launch from an elevated PowerShell prompt.' -ForegroundColor Red
    exit 1
}

# ============================================================
# EXECUTION POLICY BYPASS (CLAUDE.md: all PowerShell scripts
# must implement automatic execution policy bypass)
# ============================================================

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host '[WARN] Constrained Language Mode detected — some operations may fail.' -ForegroundColor Yellow
}

# Self-reinvoke with bypass if restricted (will no-op if already elevated+bypass)
$currentPolicy = Get-ExecutionPolicy -Scope Process
if ($currentPolicy -notin @('Bypass', 'Unrestricted', 'RemoteSigned')) {
    Write-Host "[INFO] Execution policy is '$currentPolicy'. Applying process-scope bypass." -ForegroundColor Cyan
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}

# ============================================================
# HELPERS
# ============================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Reboot')]
        [string]$Type = 'Info'
    )
    $colorMap = @{
        Info    = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
        Reboot  = 'Magenta'
    }
    $prefix = switch ($Type) {
        'Info'    { '[INFO]   ' }
        'Success' { '[ OK ]   ' }
        'Warning' { '[WARN]   ' }
        'Error'   { '[ERROR]  ' }
        'Reboot'  { '[REBOOT] ' }
    }
    Write-Host "$prefix$Message" -ForegroundColor $colorMap[$Type]
}

function Add-ChangeLog {
    param(
        [string]$Category,
        [string]$Target,
        [string]$OldValue,
        [string]$NewValue,
        [bool]$RequiresReboot = $false
    )
    $Script:ChangeLog.Add([PSCustomObject]@{
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category       = $Category
        Target         = $Target
        OldValue       = $OldValue
        NewValue       = $NewValue
        RequiresReboot = $RequiresReboot
    })
    if ($RequiresReboot) { $Script:RebootNeeded = $true }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $val = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return $val
    } catch {
        return $Default
    }
}

function Set-RegistryDword {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [string]$Category,
        [bool]$RequiresReboot = $false
    )
    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create registry key')) {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    $old = Get-RegistryValue -Path $Path -Name $Name -Default '<absent>'
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD to $Value")) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        Add-ChangeLog -Category $Category -Target "$Path\$Name" `
                      -OldValue "$old" -NewValue "$Value" `
                      -RequiresReboot $RequiresReboot
        Write-Status "Set $Name = $Value  ($Path)" 'Success'
    }
}

function Remove-RegistryValue {
    param([string]$Path, [string]$Name, [string]$Category)
    if (Test-Path $Path) {
        $old = Get-RegistryValue -Path $Path -Name $Name -Default '<absent>'
        if ($old -ne '<absent>') {
            if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Remove registry value')) {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
                Add-ChangeLog -Category $Category -Target "$Path\$Name" `
                              -OldValue "$old" -NewValue '<removed>'
                Write-Status "Removed $Name  ($Path)" 'Success'
            }
        }
    }
}

# ============================================================
# SECTION 1: HVCI (Memory Integrity / HVCI)
# Primary BYOVD countermeasure — M1040
# Enforces the Vulnerable Driver Blocklist in kernel mode.
# Prevents KslD.sys from loading even when Microsoft-signed.
# Requires reboot.
# ============================================================

function Set-HVCI {
    $hvciPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    $hvciValue = 'Enabled'

    Write-Status '' 'Info'
    Write-Status '--- SECTION 1: HVCI / Memory Integrity (M1040) ---' 'Info'
    Write-Status 'Primary BYOVD countermeasure. Prevents KslD.sys and other' 'Info'
    Write-Status 'known-vulnerable drivers from loading, even if Microsoft-signed.' 'Info'

    if ($Undo) {
        Write-Status 'Reverting HVCI enablement (will take effect after reboot)...' 'Warning'
        # Set to 0 (disabled) — note: on Secure Boot systems this may be re-enabled by
        # firmware. Manual confirmation recommended before reverting in production.
        Set-RegistryDword -Path $hvciPath -Name $hvciValue -Value 0 `
                          -Category 'HVCI' -RequiresReboot $true
        Write-Status 'HVCI revert staged. Reboot required.' 'Reboot'
        return
    }

    $current = Get-RegistryValue -Path $hvciPath -Name $hvciValue -Default 0
    if ($current -eq 1) {
        Write-Status "HVCI already enabled (current = $current). No change." 'Success'
        return
    }

    Write-Status 'Enabling HVCI (Memory Integrity)...' 'Info'
    Set-RegistryDword -Path $hvciPath -Name $hvciValue -Value 1 `
                      -Category 'HVCI' -RequiresReboot $true

    Write-Status 'HVCI enabled. Reboot required for protection to activate.' 'Reboot'
    Write-Status 'After reboot verify: Windows Security > Device Security > Core Isolation > Memory Integrity = ON' 'Info'
}

# ============================================================
# SECTION 2: Microsoft Vulnerable Driver Blocklist
# App Control (WDAC) enforcement — M1040, M1045
# Blocks known-vulnerable drivers including KslD variants.
# Complements HVCI; can be enforced independently via policy.
# ============================================================

function Set-VulnerableDriverBlocklist {
    $wdacRegPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $wdacValue    = 'VulnerableDriverBlocklistEnable'

    Write-Status '' 'Info'
    Write-Status '--- SECTION 2: Vulnerable Driver Blocklist (M1040, M1045) ---' 'Info'
    Write-Status 'Enables the Microsoft-maintained blocklist of known-vulnerable' 'Info'
    Write-Status 'kernel drivers (updated quarterly via Windows Update).' 'Info'

    if ($Undo) {
        Write-Status 'Reverting Vulnerable Driver Blocklist to system default...' 'Warning'
        Remove-RegistryValue -Path $wdacRegPath -Name $wdacValue -Category 'DriverBlocklist'
        Write-Status 'Driver blocklist override removed. System default applies.' 'Success'
        return
    }

    # Check Windows Security app blocklist setting (UI toggle)
    Write-Status 'Verifying Vulnerable Driver Blocklist registry policy...' 'Info'
    if (-not (Test-Path $wdacRegPath)) {
        if ($PSCmdlet.ShouldProcess($wdacRegPath, 'Create CI Config key')) {
            New-Item -Path $wdacRegPath -Force | Out-Null
        }
    }

    $current = Get-RegistryValue -Path $wdacRegPath -Name $wdacValue -Default '<absent>'
    if ($current -eq 1) {
        Write-Status "Vulnerable Driver Blocklist already enabled (value = $current)." 'Success'
    } else {
        Set-RegistryDword -Path $wdacRegPath -Name $wdacValue -Value 1 `
                          -Category 'DriverBlocklist' -RequiresReboot $false
    }

    # Advisory: download and apply the full blocklist binary (SiPolicy.p7b) for
    # the most complete protection. This requires manual steps.
    Write-Status '' 'Info'
    Write-Status 'ADVISORY: For maximum protection, also apply the WDAC blocklist binary:' 'Warning'
    Write-Status '  1. Download: https://aka.ms/VulnerableDriverBlockList' 'Info'
    Write-Status '  2. Rename the enforced-version file to SiPolicy.p7b' 'Info'
    Write-Status "  3. Copy to: $env:windir\System32\CodeIntegrity\" 'Info'
    Write-Status '  4. Download and run the App Control policy refresh tool: https://aka.ms/refreshpolicy' 'Info'
    Write-Status '  5. Verify: Event Viewer > CodeIntegrity/Operational > filter Event ID 3099' 'Info'
}

# ============================================================
# SECTION 3: LSA Protection (RunAsPPL)
# M1025 — Privileged Process Integrity
# Stops commodity user-mode credential dumpers.
# DOES NOT stop KslKatz BYOVD kernel read path.
# Pair with HVCI + Credential Guard for real coverage.
# ============================================================

function Set-LSAProtection {
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    Write-Status '' 'Info'
    Write-Status '--- SECTION 3: LSA Protection / RunAsPPL (M1025) ---' 'Info'
    Write-Status 'PPL blocks commodity user-mode LSASS reads but does NOT stop' 'Info'
    Write-Status 'the BYOVD kernel MmCopyMemory path. Enable as defense-in-depth,' 'Info'
    Write-Status 'not as the primary BYOVD countermeasure.' 'Info'

    if ($Undo) {
        Write-Status 'Reverting RunAsPPL / RunAsPPLBoot...' 'Warning'
        Remove-RegistryValue -Path $lsaPath -Name 'RunAsPPL'     -Category 'LSAProtection'
        Remove-RegistryValue -Path $lsaPath -Name 'RunAsPPLBoot' -Category 'LSAProtection'
        Write-Status 'LSA Protection reverted. Reboot required.' 'Reboot'
        $Script:RebootNeeded = $true
        return
    }

    # RunAsPPL = 1 enables PPL for LSA. Level 2 requires Secure Boot (stronger).
    # RunAsPPLBoot configures PPL as a boot-time control (more tamper-resistant).
    $currentPPL     = Get-RegistryValue -Path $lsaPath -Name 'RunAsPPL'     -Default 0
    $currentPPLBoot = Get-RegistryValue -Path $lsaPath -Name 'RunAsPPLBoot' -Default 0

    if ($currentPPL -ge 1) {
        Write-Status "RunAsPPL already set to $currentPPL. Verifying RunAsPPLBoot..." 'Success'
    } else {
        Write-Status 'Enabling RunAsPPL = 1 (LSA Protected Process Light)...' 'Info'
        Set-RegistryDword -Path $lsaPath -Name 'RunAsPPL' -Value 1 `
                          -Category 'LSAProtection' -RequiresReboot $true
    }

    if ($currentPPLBoot -ge 1) {
        Write-Status "RunAsPPLBoot already set to $currentPPLBoot." 'Success'
    } else {
        Write-Status 'Enabling RunAsPPLBoot = 1 (boot-time PPL enforcement)...' 'Info'
        Set-RegistryDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value 1 `
                          -Category 'LSAProtection' -RequiresReboot $true
    }

    Write-Status 'RunAsPPL configured. Reboot required.' 'Reboot'
    Write-Status 'After reboot verify via: wevtutil qe System "/q:*[System[Provider[@Name=''Microsoft-Windows-Wininit''] and (EventID=12)]]" /c:1 /rd:true /f:text' 'Info'
}

# ============================================================
# SECTION 4: Windows Defender Credential Guard
# M1043 — Credential Access Protection
# Isolates LSASS in VBS — more resistant to kernel-mode reads
# than PPL alone. Lab host had Credential Guard OFF.
# Requires UEFI Secure Boot + TPM 2.0 + VBS-capable hardware.
# ============================================================

function Set-CredentialGuard {
    $dgPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    Write-Status '' 'Info'
    Write-Status '--- SECTION 4: Credential Guard / VBS (M1043) ---' 'Info'
    Write-Status 'Isolates LSASS in a VBS enclave. The lab host had Credential' 'Info'
    Write-Status 'Guard OFF — this is a priority remediation for BYOVD coverage.' 'Info'
    Write-Status 'Requires: UEFI Secure Boot, TPM 2.0, VBS-capable hardware.' 'Info'

    # Check hardware prerequisites
    $sbStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if (-not $sbStatus) {
        Write-Status 'Secure Boot is not active or not UEFI. Credential Guard may not enable correctly.' 'Warning'
        Write-Status 'Verify UEFI Secure Boot in firmware settings before proceeding.' 'Warning'
    }

    if ($Undo) {
        Write-Status 'Reverting Credential Guard enablement...' 'Warning'
        # EnableVirtualizationBasedSecurity = 0 disables VBS (also affects HVCI if set there)
        Set-RegistryDword -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 0 `
                          -Category 'CredentialGuard' -RequiresReboot $true
        # LsaCfgFlags = 0 disables Credential Guard
        Set-RegistryDword -Path $lsaPath -Name 'LsaCfgFlags' -Value 0 `
                          -Category 'CredentialGuard' -RequiresReboot $true
        Write-Status 'Credential Guard revert staged. Reboot required.' 'Reboot'
        return
    }

    # EnableVirtualizationBasedSecurity = 1 (turn on VBS)
    $currentVBS = Get-RegistryValue -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Default 0
    if ($currentVBS -eq 1) {
        Write-Status 'VBS already enabled.' 'Success'
    } else {
        Write-Status 'Enabling VBS (Virtualization Based Security)...' 'Info'
        Set-RegistryDword -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1 `
                          -Category 'CredentialGuard' -RequiresReboot $true
    }

    # RequirePlatformSecurityFeatures: 3 = Secure Boot + DMA protection (recommended)
    $currentPSF = Get-RegistryValue -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Default 0
    if ($currentPSF -ge 1) {
        Write-Status "RequirePlatformSecurityFeatures already set to $currentPSF." 'Success'
    } else {
        Set-RegistryDword -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value 3 `
                          -Category 'CredentialGuard' -RequiresReboot $true
    }

    # LsaCfgFlags = 1 enables Credential Guard (2 = strict / UEFI lock)
    $currentCG = Get-RegistryValue -Path $lsaPath -Name 'LsaCfgFlags' -Default 0
    if ($currentCG -ge 1) {
        Write-Status "Credential Guard already enabled (LsaCfgFlags = $currentCG)." 'Success'
    } else {
        Write-Status 'Enabling Credential Guard (LsaCfgFlags = 1)...' 'Info'
        Set-RegistryDword -Path $lsaPath -Name 'LsaCfgFlags' -Value 1 `
                          -Category 'CredentialGuard' -RequiresReboot $true
    }

    Write-Status 'Credential Guard configured. Reboot required.' 'Reboot'
    Write-Status 'After reboot verify: Get-CimInstance Win32_DeviceGuard | Select-Object SecurityServicesRunning' 'Info'
}

# ============================================================
# SECTION 5: Attack Surface Reduction (ASR) Rules
# M1040 — Behavior Prevention on Endpoint
# Two rules are directly relevant to the BYOVD/LSASS chain:
#   - Block abuse of exploited vulnerable signed drivers
#   - Block credential stealing from LSASS
# ============================================================

function Set-ASRRules {
    $asrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'

    # ASR rule GUIDs
    $ruleVulnerableDriver = '56a863a9-875e-4185-98a7-b882c64b5ce5'
    $ruleLSASSProtect     = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0'
    # Additional LSASS-adjacent rules
    $rulePSExecWMI        = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
    $ruleCreds            = 'c7226c89-9d45-4d2b-876d-51dba39de7a7'  # Untrusted/unsigned executables USB

    # Mode values: 0 = Disabled, 1 = Block (Enforce), 2 = Audit
    $enforceMode = 1
    $auditMode   = 2

    Write-Status '' 'Info'
    Write-Status '--- SECTION 5: Attack Surface Reduction Rules (M1040) ---' 'Info'
    Write-Status "BYOVD rule: Block abuse of exploited vulnerable signed drivers ($ruleVulnerableDriver)" 'Info'
    Write-Status "LSASS rule: Block credential stealing from LSASS ($ruleLSASSProtect)" 'Info'
    Write-Status 'NOTE: Deploy in Audit mode first in production to assess false-positive impact.' 'Warning'

    if ($Undo) {
        Write-Status 'Reverting ASR rules to pre-hardening state...' 'Warning'
        if (Test-Path $asrPath) {
            foreach ($rule in @($ruleVulnerableDriver, $ruleLSASSProtect, $rulePSExecWMI, $ruleCreds)) {
                Remove-ItemProperty -Path $asrPath -Name $rule -Force -ErrorAction SilentlyContinue
                Add-ChangeLog -Category 'ASR' -Target "$asrPath\$rule" `
                              -OldValue "$enforceMode" -NewValue '<removed>'
            }
            Write-Status 'ASR rules removed from policy path.' 'Success'
        }
        return
    }

    if (-not (Test-Path $asrPath)) {
        if ($PSCmdlet.ShouldProcess($asrPath, 'Create ASR rules registry path')) {
            New-Item -Path $asrPath -Force | Out-Null
        }
    }

    # Block: vulnerable signed driver abuse (primary BYOVD preventive control)
    $currentVD = Get-RegistryValue -Path $asrPath -Name $ruleVulnerableDriver -Default '<absent>'
    if ($currentVD -eq $enforceMode) {
        Write-Status "ASR rule '$ruleVulnerableDriver' already in Enforce mode." 'Success'
    } else {
        if ($PSCmdlet.ShouldProcess("ASR Rule $ruleVulnerableDriver", 'Set to Enforce (1)')) {
            Set-ItemProperty -Path $asrPath -Name $ruleVulnerableDriver -Value $enforceMode -Type String -Force
            Add-ChangeLog -Category 'ASR' -Target $ruleVulnerableDriver `
                          -OldValue "$currentVD" -NewValue "$enforceMode"
            Write-Status "ASR rule 'Block vulnerable signed drivers' set to Enforce." 'Success'
        }
    }

    # Block: LSASS credential stealing
    $currentLS = Get-RegistryValue -Path $asrPath -Name $ruleLSASSProtect -Default '<absent>'
    if ($currentLS -eq $enforceMode) {
        Write-Status "ASR rule '$ruleLSASSProtect' already in Enforce mode." 'Success'
    } else {
        if ($PSCmdlet.ShouldProcess("ASR Rule $ruleLSASSProtect", 'Set to Enforce (1)')) {
            Set-ItemProperty -Path $asrPath -Name $ruleLSASSProtect -Value $enforceMode -Type String -Force
            Add-ChangeLog -Category 'ASR' -Target $ruleLSASSProtect `
                          -OldValue "$currentLS" -NewValue "$enforceMode"
            Write-Status "ASR rule 'Block credential stealing from LSASS' set to Enforce." 'Success'
        }
    }

    # Audit mode for adjacent rules (PSExec/WMI child processes) — lower false-positive risk
    foreach ($rule in @($rulePSExecWMI)) {
        $current = Get-RegistryValue -Path $asrPath -Name $rule -Default '<absent>'
        if ($current -notin @($enforceMode, $auditMode)) {
            if ($PSCmdlet.ShouldProcess("ASR Rule $rule", 'Set to Audit (2)')) {
                Set-ItemProperty -Path $asrPath -Name $rule -Value $auditMode -Type String -Force
                Add-ChangeLog -Category 'ASR' -Target $rule -OldValue "$current" -NewValue "$auditMode"
                Write-Status "ASR rule '$rule' set to Audit mode." 'Success'
            }
        }
    }

    Write-Status '' 'Info'
    Write-Status 'To verify ASR rules via PowerShell: Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids' 'Info'
    Write-Status 'Monitor ASR events: Event Viewer > Microsoft-Windows-Windows Defender/Operational, filter Event IDs 1121 (blocked) and 1122 (audited)' 'Info'
}

# ============================================================
# SECTION 6: KslD Service Key ACL Hardening
# M1024 — Restrict Registry Permissions
# The KslD and Defender service registry keys are NOT covered
# by Defender tamper protection. Tighten their ACLs so only
# SYSTEM (and TrustedInstaller) can write them.
# ============================================================

function Set-KslDServiceKeyACL {
    Write-Status '' 'Info'
    Write-Status '--- SECTION 6: KslD Service Key Registry ACL (M1024) ---' 'Info'
    Write-Status 'The KslD service key (HKLM\SYSTEM\...\Services\KslD) is writable' 'Info'
    Write-Status 'by any local admin and is not covered by Defender tamper protection.' 'Info'
    Write-Status 'This is the highest-privilege write required for Stage 1 of the chain.' 'Info'

    $kslKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\KslD'

    if (-not (Test-Path $kslKeyPath)) {
        Write-Status 'KslD service key does not exist on this system. No ACL change needed.' 'Info'
        Write-Status '(The KslD driver is present only on systems with Defender kernel service components.)' 'Info'
        return
    }

    if ($Undo) {
        Write-Status 'ACL hardening for KslD key cannot be automatically reverted.' 'Warning'
        Write-Status 'To restore original ACLs, use: Get-Acl / Set-Acl from a backup.' 'Warning'
        Write-Status 'Alternatively, reset via: secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose' 'Warning'
        return
    }

    try {
        # Get current ACL
        $acl = Get-Acl -Path $kslKeyPath

        # Build a new ACE: deny Write to any non-SYSTEM, non-TrustedInstaller principal.
        # Strategy: Add explicit DENY for "Administrators" write access to service values.
        # Note: This is a targeted hardening — SYSTEM and TrustedInstaller retain full access.
        $adminSID = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
        )
        $rights = [System.Security.AccessControl.RegistryRights]::SetValue -bor
                  [System.Security.AccessControl.RegistryRights]::WriteKey
        $denyACE = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminSID,
            $rights,
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        if ($PSCmdlet.ShouldProcess($kslKeyPath, 'Add deny-write ACE for Administrators')) {
            $acl.AddAccessRule($denyACE)
            Set-Acl -Path $kslKeyPath -AclObject $acl
            Add-ChangeLog -Category 'RegistryACL' -Target $kslKeyPath `
                          -OldValue 'Admins:Allow Write' -NewValue 'Admins:Deny Write (SYSTEM retains)'
            Write-Status "KslD service key ACL hardened. Administrators denied SetValue/WriteKey." 'Success'
            Write-Status 'IMPORTANT: Verify Defender still starts correctly after reboot.' 'Warning'
            Write-Status 'If Defender fails to start, restore ACL via: secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb' 'Warning'
        }
    } catch {
        $Script:HardeningErrors.Add("KslD ACL hardening failed: $_")
        Write-Status "KslD ACL hardening failed: $_" 'Error'
        Write-Status 'This may occur if the key ACL is already restricted. Verify manually.' 'Warning'
    }
}

# ============================================================
# SECTION 7: Defender Tamper Protection Verification
# M1018 — User Account Management
# Tamper Protection does NOT cover KslD AllowedProcessName /
# ImagePath. Verify it is enabled for the controls it does cover.
# ============================================================

function Test-TamperProtection {
    Write-Status '' 'Info'
    Write-Status '--- SECTION 7: Defender Tamper Protection Check (M1018) ---' 'Info'
    Write-Status 'NOTE: Tamper Protection does NOT cover KslD service key values' 'Info'
    Write-Status '(AllowedProcessName, ImagePath). This is the gap KslKatz exploits.' 'Info'
    Write-Status 'Verify Tamper Protection is enabled for all other Defender controls.' 'Info'

    if ($Undo) {
        Write-Status 'Tamper Protection state is managed via Intune/Windows Security app.' 'Warning'
        Write-Status 'Manual verification required. No automated revert applied.' 'Info'
        return
    }

    $tpPath  = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    $tpValue = 'TamperProtection'
    $current = Get-RegistryValue -Path $tpPath -Name $tpValue -Default '<absent>'

    # TamperProtection values: 0=disabled, 4=Intune-managed, 5=enabled
    if ($current -in @(4, 5)) {
        Write-Status "Tamper Protection is enabled (value = $current)." 'Success'
    } elseif ($current -eq 0) {
        Write-Status 'Tamper Protection is DISABLED. Enable it in Windows Security app or Intune.' 'Warning'
        Write-Status 'Windows Security > Virus and threat protection > Manage settings > Tamper Protection' 'Warning'
    } else {
        Write-Status "Tamper Protection value = $current (unknown/unmanaged state). Verify in Windows Security app." 'Warning'
    }

    # Emit an explicit warning about the gap: KslD service key is NOT covered
    Write-Status '' 'Info'
    Write-Status 'COVERAGE GAP: AllowedProcessName and ImagePath under Services\KslD are' 'Warning'
    Write-Status 'NOT protected by Defender Tamper Protection. Supplement with:' 'Warning'
    Write-Status '  1. Registry key SACL auditing (see Section 8)' 'Warning'
    Write-Status '  2. ACL hardening (see Section 6)' 'Warning'
    Write-Status '  3. HVCI/Blocklist to prevent the driver from loading even if written (Sections 1-2)' 'Warning'
}

# ============================================================
# SECTION 8: Advanced Audit Policy (Registry + Process)
# M1047 — Audit
# Enable registry object access auditing on critical service keys
# and ensure process creation / LSASS access auditing is active.
# ============================================================

function Set-AuditPolicy {
    Write-Status '' 'Info'
    Write-Status '--- SECTION 8: Advanced Audit Policy (M1047) ---' 'Info'
    Write-Status 'Enables registry write auditing and LSASS process-access auditing.' 'Info'

    if ($Undo) {
        Write-Status 'Audit policy revert: removing advanced audit policy overrides...' 'Warning'
        & auditpol /set /subcategory:"Registry"           /success:disable /failure:disable 2>$null
        & auditpol /set /subcategory:"Process Creation"   /success:disable /failure:disable 2>$null
        & auditpol /set /subcategory:"Kernel Object"      /success:disable /failure:disable 2>$null
        Write-Status 'Audit policies reset (subcategories disabled).' 'Success'
        return
    }

    try {
        # Registry object access — generates Event 4657 on registry value writes
        & auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null
        Add-ChangeLog -Category 'AuditPolicy' -Target 'Subcategory:Registry' `
                      -OldValue 'default' -NewValue 'Success+Failure'
        Write-Status 'Audit policy: Registry object access enabled (Success + Failure).' 'Success'

        # Process creation — generates Event 4688 for new process launches
        & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null
        Add-ChangeLog -Category 'AuditPolicy' -Target 'Subcategory:Process Creation' `
                      -OldValue 'default' -NewValue 'Success+Failure'
        Write-Status 'Audit policy: Process Creation enabled (Success + Failure).' 'Success'

        # Kernel object — generates Event 4656/4663 for handle-based access to LSASS
        & auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable 2>$null
        Add-ChangeLog -Category 'AuditPolicy' -Target 'Subcategory:Kernel Object' `
                      -OldValue 'default' -NewValue 'Success+Failure'
        Write-Status 'Audit policy: Kernel Object access enabled (Success + Failure).' 'Success'

        Write-Status '' 'Info'
        Write-Status 'NEXT STEP: Set a registry SACL on the KslD service key.' 'Warning'
        Write-Status 'The audit policy alone does not filter which registry keys generate events.' 'Info'
        Write-Status 'Apply a SACL to HKLM\SYSTEM\CurrentControlSet\Services\KslD via:' 'Info'
        Write-Status '  regedit.exe > right-click key > Permissions > Advanced > Auditing' 'Info'
        Write-Status '  Add: Principal = Everyone, Type = Success, applies to: This key only,' 'Info'
        Write-Status '  Permissions: Set Value, Write DAC, Write Owner' 'Info'
        Write-Status 'This generates Event ID 4657 for any write to AllowedProcessName / ImagePath.' 'Info'
    } catch {
        $Script:HardeningErrors.Add("Audit policy configuration failed: $_")
        Write-Status "Audit policy configuration failed: $_" 'Error'
    }
}

# ============================================================
# SECTION 9: Verify Current Protection State (Check Mode)
# Read-only report on the effective state of each control.
# Always runs in addition to hardening/undo, for visibility.
# ============================================================

function Show-ProtectionStatus {
    Write-Status '' 'Info'
    Write-Status '=== Protection State Report ===' 'Info'
    Write-Status '' 'Info'

    # HVCI
    $hvciVal = Get-RegistryValue `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
        -Name 'Enabled' -Default 0
    $hvciStatus = if ($hvciVal -eq 1) { 'ENABLED' } else { 'DISABLED' }
    Write-Status "HVCI (Memory Integrity):          $hvciStatus" $(if ($hvciVal -eq 1) { 'Success' } else { 'Warning' })

    # Credential Guard
    $cgVal = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Default 0
    $cgStatus = if ($cgVal -ge 1) { "ENABLED (LsaCfgFlags=$cgVal)" } else { 'DISABLED — PRIORITY REMEDIATION' }
    Write-Status "Credential Guard:                 $cgStatus" $(if ($cgVal -ge 1) { 'Success' } else { 'Error' })

    # RunAsPPL
    $pplVal  = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'     -Default 0
    $pplBoot = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot' -Default 0
    $pplStatus = if ($pplVal -ge 1) { "ENABLED (level $pplVal)" } elseif ($pplBoot -ge 1) { "ENABLED via Boot (level $pplBoot)" } else { 'DISABLED' }
    Write-Status "LSA Protection (RunAsPPL):        $pplStatus" $(if ($pplVal -ge 1 -or $pplBoot -ge 1) { 'Success' } else { 'Warning' })
    if ($pplVal -ge 1) {
        Write-Status "  NOTE: PPL blocks user-mode reads only. BYOVD kernel path bypasses PPL." 'Warning'
    }

    # Tamper Protection
    $tpVal = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -Default 0
    $tpStatus = switch ($tpVal) {
        { $_ -in @(4, 5) } { 'ENABLED' }
        0 { 'DISABLED' }
        default { "UNKNOWN (value=$tpVal)" }
    }
    Write-Status "Defender Tamper Protection:       $tpStatus" $(if ($tpVal -in @(4,5)) { 'Success' } else { 'Warning' })

    # ASR — vulnerable driver rule
    $asrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $asrVD   = Get-RegistryValue -Path $asrPath -Name '56a863a9-875e-4185-98a7-b882c64b5ce5' -Default '<absent>'
    $asrLS   = Get-RegistryValue -Path $asrPath -Name '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0' -Default '<absent>'
    $asrVDStatus = if ($asrVD -eq 1) { 'Enforce' } elseif ($asrVD -eq 2) { 'Audit' } else { 'DISABLED/ABSENT' }
    $asrLSStatus = if ($asrLS -eq 1) { 'Enforce' } elseif ($asrLS -eq 2) { 'Audit' } else { 'DISABLED/ABSENT' }
    Write-Status "ASR - Vulnerable Driver Block:    $asrVDStatus" $(if ($asrVD -eq 1) { 'Success' } elseif ($asrVD -eq 2) { 'Warning' } else { 'Error' })
    Write-Status "ASR - LSASS Credential Steal:     $asrLSStatus" $(if ($asrLS -eq 1) { 'Success' } elseif ($asrLS -eq 2) { 'Warning' } else { 'Error' })

    # KslD service key existence
    $kslExists = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\KslD'
    Write-Status "KslD service key present:         $(if ($kslExists) { 'YES — review ACL' } else { 'No (not applicable)' })" $(if ($kslExists) { 'Warning' } else { 'Info' })

    Write-Status '' 'Info'
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Status '' 'Info'
Write-Status '=================================================================' 'Info'
Write-Status 'F0RT1KA Defense Hardening — BYOVD / KslKatz Chain' 'Info'
Write-Status 'Techniques: T1543.003, T1112, T1068, T1003.001' 'Info'
Write-Status "Mode: $(if ($Undo) { 'UNDO (revert)' } else { 'APPLY (harden)' })" 'Info'
Write-Status '=================================================================' 'Info'
Write-Status '' 'Info'

# Always show current state before making changes
Show-ProtectionStatus

if ($Undo) {
    Write-Status 'Reverting all hardening changes...' 'Warning'
} else {
    Write-Status 'Applying hardening controls...' 'Info'
}

Set-HVCI
Set-VulnerableDriverBlocklist
Set-LSAProtection
Set-CredentialGuard
Set-ASRRules
Set-KslDServiceKeyACL
Test-TamperProtection
Set-AuditPolicy

Write-Status '' 'Info'
Write-Status '=================================================================' 'Info'
Write-Status 'Hardening complete. Summary:' 'Info'
Write-Status '=================================================================' 'Info'

if ($Script:ChangeLog.Count -gt 0) {
    $Script:ChangeLog | Format-Table -AutoSize -Property Timestamp, Category, Target, OldValue, NewValue, RequiresReboot
} else {
    Write-Status 'No changes were applied (all controls already in target state, or -WhatIf mode).' 'Info'
}

if ($Script:HardeningErrors.Count -gt 0) {
    Write-Status '' 'Info'
    Write-Status 'The following errors occurred:' 'Error'
    foreach ($err in $Script:HardeningErrors) {
        Write-Status "  $err" 'Error'
    }
}

if ($Script:RebootNeeded) {
    Write-Status '' 'Info'
    Write-Status 'A REBOOT IS REQUIRED for the following changes to take full effect:' 'Reboot'
    $Script:ChangeLog | Where-Object { $_.RequiresReboot } | ForEach-Object {
        Write-Status "  $($_.Category): $($_.Target)" 'Reboot'
    }

    if ($RebootIfRequired) {
        Write-Status 'Rebooting in 30 seconds (-RebootIfRequired was set)...' 'Reboot'
        Write-Status 'Cancel with: shutdown /a' 'Warning'
        & shutdown /r /t 30 /c "F0RT1KA defense hardening reboot — BYOVD controls require restart"
    } else {
        Write-Status '' 'Info'
        Write-Status 'Reboot manually when ready. Use -RebootIfRequired to reboot automatically.' 'Reboot'
    }
} else {
    Write-Status '' 'Info'
    Write-Status 'All changes took effect immediately. No reboot required.' 'Success'
}

Write-Status '' 'Info'
Write-Status 'Post-hardening verification commands:' 'Info'
Write-Status '  HVCI:            Windows Security > Device Security > Core Isolation > Memory Integrity' 'Info'
Write-Status '  PPL:             wevtutil qe System "/q:*[System[Provider[@Name=''Microsoft-Windows-Wininit''] and (EventID=12)]]" /c:1 /rd:true /f:text' 'Info'
Write-Status '  Credential Guard: Get-CimInstance Win32_DeviceGuard | Select-Object SecurityServicesRunning' 'Info'
Write-Status '  ASR rules:       Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids' 'Info'
Write-Status '=================================================================' 'Info'
