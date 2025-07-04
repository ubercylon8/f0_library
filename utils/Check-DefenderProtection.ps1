#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Checks Windows Defender registry values to verify if the host is protected.
.DESCRIPTION
    Examines registry keys targeted by CyberEye RAT to determine if Defender features are enabled.
    Reports current values and protection status.
.AUTHOR
    Security assessment script for Windows Defender protection verification.
#>

# Function to check if running with admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check and bypass execution policy
function Bypass-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    Write-Host "Current execution policy: $currentPolicy" -ForegroundColor Gray
    
    if ($currentPolicy -eq "Restricted" -or $currentPolicy -eq "AllSigned") {
        Write-Host "Restrictive execution policy detected. Attempting to bypass..." -ForegroundColor Yellow
        try {
            # Relaunch script with -ExecutionPolicy Bypass
            $scriptPath = $MyInvocation.MyCommand.Path
            if (-not $scriptPath) {
                Write-Host "Error: Script path not found. Save this script to a .ps1 file and run it again." -ForegroundColor Red
                exit 1
            }
            $bypassCommand = "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""
            Write-Host "Relaunching script with bypassed execution policy..." -ForegroundColor Yellow
            Invoke-Expression $bypassCommand
            exit 0  # Exit current session after relaunch
        }
        catch {
            Write-Host "Failed to bypass execution policy: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "Execution policy allows script execution. Proceeding..." -ForegroundColor Gray
    }
}

# Exit if not running as admin
if (-not (Test-Admin)) {
    Write-Host "This script requires administrative privileges. Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# Check and bypass execution policy if needed
Bypass-ExecutionPolicy

Write-Host "`n=== Windows Defender Protection Status Check ===" -ForegroundColor Cyan
Write-Host "Checking registry values targeted by CyberEye RAT...`n" -ForegroundColor Yellow

# Define registry paths and expected protected values
$registryChecks = @(
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        Name = "TamperProtection"
        ProtectedValue = 1
        Description = "Tamper Protection"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        Name = "DisableAntiSpyware"
        ProtectedValue = 0
        Description = "Anti-Spyware Protection"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Name = "DisableBehaviorMonitoring"
        ProtectedValue = 0
        Description = "Behavior Monitoring"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Name = "DisableOnAccessProtection"
        ProtectedValue = 0
        Description = "On-Access Protection"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Name = "DisableScanOnRealtimeEnable"
        ProtectedValue = 0
        Description = "Real-time Scanning"
    }
)

$protectionStatus = $true

# Check each registry value
foreach ($check in $registryChecks) {
    Write-Host "Checking: $($check.Description)" -ForegroundColor White
    Write-Host "  Path: $($check.Path)" -ForegroundColor Gray
    Write-Host "  Key: $($check.Name)" -ForegroundColor Gray
    
    if (Test-Path $check.Path) {
        try {
            $currentValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $check.Name
            
            if ($null -eq $currentValue) {
                Write-Host "  Current Value: Not Set (Default behavior applies)" -ForegroundColor Green
                Write-Host "  Status: PROTECTED - Registry key not configured" -ForegroundColor Green
            }
            else {
                Write-Host "  Current Value: $currentValue" -ForegroundColor Cyan
                
                if ($currentValue -eq $check.ProtectedValue) {
                    Write-Host "  Status: PROTECTED - Value indicates feature is enabled" -ForegroundColor Green
                }
                else {
                    Write-Host "  Status: VULNERABLE - Value indicates feature is disabled" -ForegroundColor Red
                    $protectionStatus = $false
                }
            }
        }
        catch {
            Write-Host "  Current Value: Not Set (Default behavior applies)" -ForegroundColor Green
            Write-Host "  Status: PROTECTED - Registry key not configured" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  Current Value: Path does not exist (Default behavior applies)" -ForegroundColor Green
        Write-Host "  Status: PROTECTED - No policy override configured" -ForegroundColor Green
    }
    Write-Host ""
}

# Additional check: Query Windows Defender status via PowerShell cmdlet
Write-Host "=== Windows Defender Service Status ===" -ForegroundColor Cyan
try {
    $defenderStatus = Get-MpPreference -ErrorAction Stop
    Write-Host "Real-time Protection Enabled: $(-not $defenderStatus.DisableRealtimeMonitoring)" -ForegroundColor Cyan
    Write-Host "Behavior Monitoring Enabled: $(-not $defenderStatus.DisableBehaviorMonitoring)" -ForegroundColor Cyan
    Write-Host "IOAV Protection Enabled: $(-not $defenderStatus.DisableIOAVProtection)" -ForegroundColor Cyan
    Write-Host "Script Scanning Enabled: $(-not $defenderStatus.DisableScriptScanning)" -ForegroundColor Cyan
}
catch {
    Write-Host "Unable to query Windows Defender status via Get-MpPreference" -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Overall protection assessment
Write-Host "`n=== Overall Protection Assessment ===" -ForegroundColor Cyan
if ($protectionStatus) {
    Write-Host "RESULT: HOST IS PROTECTED" -ForegroundColor Green -BackgroundColor DarkGreen
    Write-Host "All checked registry values indicate Windows Defender features are enabled." -ForegroundColor Green
    Write-Host "The host should be protected against CyberEye RAT registry manipulation attempts." -ForegroundColor Green
}
else {
    Write-Host "RESULT: HOST IS VULNERABLE" -ForegroundColor Red -BackgroundColor DarkRed
    Write-Host "One or more Windows Defender features are disabled via registry." -ForegroundColor Red
    Write-Host "The host may be vulnerable to malware that attempts to disable security features." -ForegroundColor Red
    Write-Host "`nRecommendation: Reset Windows Defender to default settings or enable the disabled features." -ForegroundColor Yellow
}

Write-Host "`nScript execution completed." -ForegroundColor Gray