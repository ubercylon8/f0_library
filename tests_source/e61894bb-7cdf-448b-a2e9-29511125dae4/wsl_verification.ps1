# WSL Verification and Installation Script for Qilin Simulation
# This script checks for WSL availability and installs it if needed

Write-Host "Qilin WSL Verification Starting..." -ForegroundColor Yellow

# Check if WSL is installed
try {
    $wslStatus = wsl --status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "WSL detected, checking distribution..." -ForegroundColor Green
        
        # Check if we have a working distribution
        $distroTest = wsl echo "WSL_TEST_OK" 2>&1
        if ($distroTest -eq "WSL_TEST_OK") {
            Write-Host "WSL is functional and ready" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "WSL installed but no working distribution found" -ForegroundColor Orange
        }
    }
} catch {
    Write-Host "WSL not detected, proceeding with installation..." -ForegroundColor Red
}

# Enable WSL feature if not enabled
Write-Host "Enabling WSL feature..." -ForegroundColor Yellow
try {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
    Write-Host "WSL feature enabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to enable WSL feature: $($_.Exception.Message)" -ForegroundColor Red
}

# Check if we can install WSL via winget or direct download
Write-Host "Attempting WSL installation..." -ForegroundColor Yellow
try {
    # Try modern WSL installation
    wsl --install --no-launch
    Write-Host "WSL installation completed" -ForegroundColor Green
} catch {
    Write-Host "WSL installation failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback: Try to download Ubuntu manually
    Write-Host "Attempting manual Ubuntu installation..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://aka.ms/wslubuntu2004" -OutFile "$env:TEMP\Ubuntu.appx"
        Add-AppxPackage "$env:TEMP\Ubuntu.appx"
        Write-Host "Ubuntu distribution installed manually" -ForegroundColor Green
    } catch {
        Write-Host "Manual installation also failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Final verification
Write-Host "Performing final WSL verification..." -ForegroundColor Yellow
try {
    $finalTest = wsl echo "INSTALLATION_SUCCESS" 2>&1
    if ($finalTest -eq "INSTALLATION_SUCCESS") {
        Write-Host "WSL installation and verification successful!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "WSL verification failed after installation" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Final verification failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}