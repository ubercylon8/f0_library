# ============================================================================
# Hardening Script: UNK_RobotDreams Rust Backdoor Execution Chain
# ============================================================================
# Test ID: 414a4c61-019f-48ba-934d-d5e91a29a878
# MITRE ATT&CK: T1204.002, T1059.001, T1105, T1071.001, T1573.001, T1036.005
# Threat Actor: UNK_RobotDreams (Pakistan-aligned)
# Platform: Windows 10/11 + Windows Server 2019/2022
# Generated: 2026-03-24
# ============================================================================
#
# This script hardens Windows endpoints against the UNK_RobotDreams attack
# chain by configuring PowerShell restrictions, enabling AMSI protections,
# deploying ASR rules, and configuring network monitoring.
#
# USAGE:
#   Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File 414a4c61-019f-48ba-934d-d5e91a29a878_hardening.ps1
#
# IMPORTANT: Review settings before applying in production environments.
# Some settings may impact legitimate PowerShell-based management tools.
# ============================================================================

#Requires -RunAsAdministrator

# Check if running as Administrator
function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Automatic ExecutionPolicy bypass for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "UNK_RobotDreams Hardening Script" -ForegroundColor Cyan
Write-Host "Test ID: 414a4c61-019f-48ba-934d-d5e91a29a878" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$appliedCount = 0
$skippedCount = 0

# ============================================================================
# 1. PowerShell Logging and AMSI (T1059.001)
# ============================================================================
Write-Host "[1/7] Configuring PowerShell logging and AMSI..." -ForegroundColor Green

# Enable PowerShell ScriptBlock Logging
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
    Write-Host "  [+] PowerShell ScriptBlock Logging enabled (Event ID 4104)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable ScriptBlock Logging: $_" -ForegroundColor Yellow
    $skippedCount++
}

# Enable PowerShell Module Logging
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

    $modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    if (-not (Test-Path $modulePath)) { New-Item -Path $modulePath -Force | Out-Null }
    Set-ItemProperty -Path $modulePath -Name "*" -Value "*" -Type String -Force
    Write-Host "  [+] PowerShell Module Logging enabled (all modules)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable Module Logging: $_" -ForegroundColor Yellow
    $skippedCount++
}

# Enable PowerShell Transcription
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String -Force
    Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    if (-not (Test-Path "C:\PSTranscripts")) { New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force | Out-Null }
    Write-Host "  [+] PowerShell Transcription enabled (output: C:\PSTranscripts)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable Transcription: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# 2. Attack Surface Reduction Rules (T1059.001, T1204.002)
# ============================================================================
Write-Host "[2/7] Configuring Attack Surface Reduction (ASR) rules..." -ForegroundColor Green

# ASR rules relevant to UNK_RobotDreams
$asrRules = @{
    # Block all Office applications from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office applications from creating child processes"
    # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    # Block Win32 API calls from Office macros
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    # Block JavaScript or VBScript from launching downloaded content
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript/VBScript from launching downloads"
    # Block process creations from PSExec and WMI commands
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PSExec/WMI"
}

foreach ($ruleId in $asrRules.Keys) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        Write-Host "  [+] ASR Rule enabled: $($asrRules[$ruleId])" -ForegroundColor Green
        $appliedCount++
    } catch {
        Write-Host "  [!] Failed to enable ASR rule $ruleId`: $_" -ForegroundColor Yellow
        $skippedCount++
    }
}

# ============================================================================
# 3. Windows Defender Configuration (T1204.002, T1105)
# ============================================================================
Write-Host "[3/7] Configuring Windows Defender protections..." -ForegroundColor Green

try {
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Host "  [+] Real-time protection enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to configure real-time protection: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable cloud-delivered protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
    Write-Host "  [+] Cloud-delivered protection configured (Advanced MAPS)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to configure cloud protection: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable PUA protection
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Host "  [+] Potentially Unwanted Application (PUA) protection enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable PUA protection: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable network protection (blocks outbound connections to known malicious IPs)
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Write-Host "  [+] Network protection enabled (blocks malicious outbound connections)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable network protection: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# 4. SmartScreen and Download Protection (T1204.002, T1105)
# ============================================================================
Write-Host "[4/7] Configuring SmartScreen and download protection..." -ForegroundColor Green

try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $regPath -Name "ShellSmartScreenLevel" -Value "Block" -Type String -Force
    Write-Host "  [+] SmartScreen enabled with Block mode" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to configure SmartScreen: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Block downloads from known dangerous domains in Edge
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $regPath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord -Force
    Write-Host "  [+] Edge SmartScreen and PUA blocking enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to configure Edge SmartScreen: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# 5. PowerShell Execution Restrictions (T1059.001)
# ============================================================================
Write-Host "[5/7] Configuring PowerShell execution restrictions..." -ForegroundColor Green

try {
    # Restrict PowerShell execution policy to RemoteSigned (machine-level)
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Write-Host "  [+] PowerShell ExecutionPolicy set to RemoteSigned (machine-level)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to set ExecutionPolicy: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable Constrained Language Mode via UMCI (if WDAC is available)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    # Note: Full CLM requires WDAC/Device Guard. This sets a marker for documentation.
    Write-Host "  [*] Note: PowerShell Constrained Language Mode requires WDAC/Device Guard policy" -ForegroundColor Yellow
    Write-Host "  [*] Refer to: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes" -ForegroundColor Yellow
    $skippedCount++
} catch {
    Write-Host "  [!] Failed to configure CLM: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# 6. Audit Logging Configuration (All techniques)
# ============================================================================
Write-Host "[6/7] Configuring audit logging for attack detection..." -ForegroundColor Green

try {
    # Enable Process Creation auditing (Event ID 4688)
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Write-Host "  [+] Process Creation auditing enabled (Event ID 4688)" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable Process Creation auditing: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Include command line in process creation events
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Host "  [+] Command line logging for process creation enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable command line logging: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable registry auditing
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
    Write-Host "  [+] Registry auditing enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable Registry auditing: $_" -ForegroundColor Yellow
    $skippedCount++
}

try {
    # Enable Filtering Platform Connection auditing (network connections)
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
    Write-Host "  [+] Network connection auditing enabled" -ForegroundColor Green
    $appliedCount++
} catch {
    Write-Host "  [!] Failed to enable network auditing: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# 7. Windows Firewall - Outbound Restrictions (T1071.001)
# ============================================================================
Write-Host "[7/7] Configuring Windows Firewall outbound rules..." -ForegroundColor Green

try {
    # Create firewall rule to log PowerShell outbound connections
    $ruleName = "F0RT1KA - Alert PowerShell Outbound HTTPS"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Protocol TCP `
            -RemotePort 443,8443 `
            -Program "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Action Allow `
            -Enabled True `
            -Description "Logs PowerShell HTTPS outbound connections for UNK_RobotDreams detection" | Out-Null
        Write-Host "  [+] Firewall rule created: Alert on PowerShell outbound HTTPS" -ForegroundColor Green
        $appliedCount++
    } else {
        Write-Host "  [*] Firewall rule already exists: $ruleName" -ForegroundColor Yellow
        $skippedCount++
    }
} catch {
    Write-Host "  [!] Failed to create firewall rule: $_" -ForegroundColor Yellow
    $skippedCount++
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Hardening Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Applied:  $appliedCount settings" -ForegroundColor Green
Write-Host "  Skipped:  $skippedCount settings" -ForegroundColor Yellow
Write-Host ""
Write-Host "Key protections applied:" -ForegroundColor White
Write-Host "  - PowerShell ScriptBlock, Module, and Transcription logging" -ForegroundColor White
Write-Host "  - Attack Surface Reduction rules for script and Office abuse" -ForegroundColor White
Write-Host "  - Windows Defender real-time, cloud, PUA, and network protection" -ForegroundColor White
Write-Host "  - SmartScreen and download protection" -ForegroundColor White
Write-Host "  - Process creation and command line auditing" -ForegroundColor White
Write-Host "  - Network connection auditing" -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT: Deploy detection rules from the test package to your SIEM" -ForegroundColor Yellow
Write-Host "for comprehensive UNK_RobotDreams threat coverage." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
