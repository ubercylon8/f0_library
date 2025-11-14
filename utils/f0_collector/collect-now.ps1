<#
.SYNOPSIS
    Manually run F0RT1KA Results Collector

.DESCRIPTION
    Simple script to manually trigger collection with verbose output

.EXAMPLE
    .\collect-now.ps1
    Run collection with verbose output
#>

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "F0RT1KA Results Collector - Manual Run" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if collector exists
if (-not (Test-Path "c:\F0\f0_collector.exe")) {
    Write-Error "Collector not found at c:\F0\f0_collector.exe"
    Write-Host "Please run deploy-collector-task.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Run collector
Write-Host "Running collector..." -ForegroundColor Yellow
Write-Host ""

& "c:\F0\f0_collector.exe" collect --once --verbose

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

if ($LASTEXITCODE -eq 0) {
    Write-Host "Collection completed successfully!" -ForegroundColor Green
} else {
    Write-Host "Collection failed with exit code: $LASTEXITCODE" -ForegroundColor Red
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "View full logs: c:\F0\collector.log" -ForegroundColor Yellow
Write-Host "Check status: c:\F0\f0_collector.exe status" -ForegroundColor Yellow
Write-Host ""
