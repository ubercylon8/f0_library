<#
.SYNOPSIS
    Deploys F0RT1KA Results Collector as a Windows Scheduled Task

.DESCRIPTION
    This script:
    - Checks for administrator privileges
    - Copies f0_collector.exe to c:\F0
    - Deploys configuration file
    - Creates scheduled task to run collection every 5 minutes
    - Verifies deployment

.PARAMETER CollectorPath
    Path to f0_collector.exe (default: .\f0_collector.exe)

.PARAMETER ConfigPath
    Path to collector_config.json (default: .\collector_config.json)

.PARAMETER Interval
    Collection interval in minutes (default: 5)

.EXAMPLE
    .\deploy-collector-task.ps1
    Deploy with default settings

.EXAMPLE
    .\deploy-collector-task.ps1 -Interval 10
    Deploy with 10-minute collection interval
#>

param(
    [string]$CollectorPath = ".\f0_collector.exe",
    [string]$ConfigPath = ".\collector_config.json",
    [int]$Interval = 5
)

# Check for administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "F0RT1KA Results Collector Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify source files exist
Write-Host "[1/6] Verifying source files..." -ForegroundColor Yellow
if (-not (Test-Path $CollectorPath)) {
    Write-Error "Collector executable not found: $CollectorPath"
    exit 1
}

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found: $ConfigPath"
    exit 1
}

Write-Host "  ✓ Collector executable: $CollectorPath" -ForegroundColor Green
Write-Host "  ✓ Configuration file: $ConfigPath" -ForegroundColor Green

# Create F0 directory if it doesn't exist
Write-Host ""
Write-Host "[2/6] Creating c:\F0 directory..." -ForegroundColor Yellow
if (-not (Test-Path "c:\F0")) {
    New-Item -ItemType Directory -Path "c:\F0" -Force | Out-Null
    Write-Host "  ✓ Created c:\F0" -ForegroundColor Green
} else {
    Write-Host "  ✓ c:\F0 already exists" -ForegroundColor Green
}

# Create collected subdirectory
if (-not (Test-Path "c:\F0\collected")) {
    New-Item -ItemType Directory -Path "c:\F0\collected" -Force | Out-Null
    Write-Host "  ✓ Created c:\F0\collected" -ForegroundColor Green
}

# Copy collector executable
Write-Host ""
Write-Host "[3/6] Copying collector executable..." -ForegroundColor Yellow
Copy-Item -Path $CollectorPath -Destination "c:\F0\f0_collector.exe" -Force
Write-Host "  ✓ Copied to c:\F0\f0_collector.exe" -ForegroundColor Green

# Copy configuration file
Write-Host ""
Write-Host "[4/6] Deploying configuration..." -ForegroundColor Yellow

# Check if config already exists
if (Test-Path "c:\F0\collector_config.json") {
    $response = Read-Host "Configuration file already exists. Overwrite? (y/n)"
    if ($response -eq "y") {
        Copy-Item -Path $ConfigPath -Destination "c:\F0\collector_config.json" -Force
        Write-Host "  ✓ Configuration updated" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Keeping existing configuration" -ForegroundColor Yellow
    }
} else {
    Copy-Item -Path $ConfigPath -Destination "c:\F0\collector_config.json" -Force
    Write-Host "  ✓ Configuration deployed" -ForegroundColor Green
}

# Set file permissions (restrict to SYSTEM and Administrators)
Write-Host ""
Write-Host "[5/6] Setting file permissions..." -ForegroundColor Yellow
$acl = Get-Acl "c:\F0\collector_config.json"
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow"
)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow"
)

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
Set-Acl -Path "c:\F0\collector_config.json" -AclObject $acl

Write-Host "  ✓ Restricted permissions to SYSTEM and Administrators" -ForegroundColor Green

# Create scheduled task
Write-Host ""
Write-Host "[6/6] Creating scheduled task..." -ForegroundColor Yellow

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName "F0RT1KA Results Collector" -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "  ⚠ Removing existing scheduled task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName "F0RT1KA Results Collector" -Confirm:$false
}

# Create task action
$action = New-ScheduledTaskAction -Execute "c:\F0\f0_collector.exe" -Argument "collect --once"

# Create trigger (run every N minutes, starting now)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval) -RepetitionDuration ([TimeSpan]::MaxValue)

# Create principal (run as SYSTEM)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Create settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

# Register task
Register-ScheduledTask `
    -TaskName "F0RT1KA Results Collector" `
    -Description "Collects F0RT1KA test results and exports to Elasticsearch" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings | Out-Null

Write-Host "  ✓ Scheduled task created" -ForegroundColor Green
Write-Host "  ✓ Collection interval: Every $Interval minutes" -ForegroundColor Green

# Verify deployment
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test collector
Write-Host "Testing collector..." -ForegroundColor Yellow
$testResult = & "c:\F0\f0_collector.exe" validate 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Collector validation PASSED" -ForegroundColor Green
} else {
    Write-Host "⚠ Collector validation FAILED" -ForegroundColor Red
    Write-Host "  Please check configuration and Elasticsearch connectivity" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review configuration: c:\F0\collector_config.json" -ForegroundColor White
Write-Host "  2. Update Elasticsearch settings (API key, endpoints)" -ForegroundColor White
Write-Host "  3. Test manually: c:\F0\f0_collector.exe collect --once --verbose" -ForegroundColor White
Write-Host "  4. View logs: c:\F0\collector.log" -ForegroundColor White
Write-Host "  5. Check status: c:\F0\f0_collector.exe status" -ForegroundColor White
Write-Host ""
Write-Host "Scheduled task will run every $Interval minutes starting now." -ForegroundColor Yellow
Write-Host ""
