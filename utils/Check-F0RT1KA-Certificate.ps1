# F0RT1KA Certificate Troubleshooting Script
# This script helps diagnose certificate installation issues on Windows endpoints

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "F0RT1KA Certificate Diagnostic Tool" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check 1: Current User Context
Write-Host "[1] Checking Execution Context..." -ForegroundColor Yellow
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "  Current User: $($currentUser.Name)" -ForegroundColor White
Write-Host "  Is Admin: $isAdmin" -ForegroundColor White
Write-Host "  User SID: $($currentUser.User.Value)" -ForegroundColor White

if (-not $isAdmin) {
    Write-Host "  [!] WARNING: Not running as Administrator - certificate installation requires elevation" -ForegroundColor Red
}
Write-Host ""

# Check 2: F0RT1KA Certificate in Root Store
Write-Host "[2] Checking LocalMachine\Root Store..." -ForegroundColor Yellow
$f0rtikaCert = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*F0RT1KA*" }

if ($f0rtikaCert) {
    Write-Host "  [+] F0RT1KA Certificate FOUND" -ForegroundColor Green
    Write-Host "      Subject: $($f0rtikaCert.Subject)" -ForegroundColor White
    Write-Host "      Thumbprint: $($f0rtikaCert.Thumbprint)" -ForegroundColor White
    Write-Host "      Valid From: $($f0rtikaCert.NotBefore)" -ForegroundColor White
    Write-Host "      Valid Until: $($f0rtikaCert.NotAfter)" -ForegroundColor White

    # Check if expired
    if ($f0rtikaCert.NotAfter -lt (Get-Date)) {
        Write-Host "      [!] WARNING: Certificate has EXPIRED" -ForegroundColor Red
    }
} else {
    Write-Host "  [-] F0RT1KA Certificate NOT FOUND" -ForegroundColor Red
    Write-Host "      This explains the access denied error!" -ForegroundColor Red
}
Write-Host ""

# Check 3: Test Execution Logs
Write-Host "[3] Checking Test Execution Logs..." -ForegroundColor Yellow
$logFiles = @(
    "C:\F0\test_execution_log.txt",
    "C:\F0\test_execution_log.json"
)

$logsFound = $false
foreach ($logFile in $logFiles) {
    if (Test-Path $logFile) {
        $logsFound = $true
        Write-Host "  [+] Found: $logFile" -ForegroundColor Green

        # Check for certificate-related errors
        $content = Get-Content $logFile -Raw
        if ($content -match "certificate|Certificate|CERTIFICATE") {
            Write-Host "      Certificate-related content found:" -ForegroundColor Yellow
            Select-String -Path $logFile -Pattern "certificate|Certificate|CERTIFICATE" -Context 2 |
                ForEach-Object { Write-Host "      $_" -ForegroundColor White }
        }
    }
}

if (-not $logsFound) {
    Write-Host "  [-] No test execution logs found in C:\F0\" -ForegroundColor Red
    Write-Host "      The test binary may have failed before logging initialized" -ForegroundColor Red
}
Write-Host ""

# Check 4: F0 Directory Contents
Write-Host "[4] Checking C:\F0 Directory..." -ForegroundColor Yellow
if (Test-Path "C:\F0") {
    Write-Host "  [+] C:\F0 exists" -ForegroundColor Green
    $f0Files = Get-ChildItem -Path "C:\F0" -File | Select-Object Name, Length, LastWriteTime
    if ($f0Files) {
        Write-Host "  Files found:" -ForegroundColor White
        $f0Files | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host "      $_" }
    } else {
        Write-Host "  [-] Directory is empty" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [-] C:\F0 does not exist" -ForegroundColor Red
}
Write-Host ""

# Check 5: PowerShell Execution Policy
Write-Host "[5] Checking PowerShell Execution Policy..." -ForegroundColor Yellow
$execPolicy = Get-ExecutionPolicy -List
Write-Host "  Current Policies:" -ForegroundColor White
$execPolicy | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host "      $_" }
Write-Host ""

# Check 6: Windows Event Logs (for certificate-related errors)
Write-Host "[6] Checking Recent Security Events..." -ForegroundColor Yellow
try {
    $recentEvents = Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*certificate*" -or $_.Message -like "*F0RT1KA*" }

    if ($recentEvents) {
        Write-Host "  [+] Found certificate-related events:" -ForegroundColor Yellow
        $recentEvents | Select-Object TimeCreated, Id, Message -First 5 |
            Format-List | Out-String | ForEach-Object { Write-Host "      $_" }
    } else {
        Write-Host "  [-] No recent certificate-related events" -ForegroundColor White
    }
} catch {
    Write-Host "  [!] Unable to access event logs: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Diagnosis Summary
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "DIAGNOSIS SUMMARY" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if (-not $f0rtikaCert) {
    Write-Host "[!] ISSUE IDENTIFIED: F0RT1KA certificate is NOT installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "RECOMMENDED ACTION:" -ForegroundColor Yellow
    Write-Host "1. Manually install the certificate using the command below:" -ForegroundColor White
    Write-Host "   Import-Certificate -FilePath 'path\to\F0RT1KA.cer' -CertStoreLocation Cert:\LocalMachine\Root" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "2. Or run the test binary again (it should auto-install)" -ForegroundColor White
    Write-Host ""
    Write-Host "3. If the test binary fails immediately, check:" -ForegroundColor White
    Write-Host "   - LimaCharlie is executing with SYSTEM privileges" -ForegroundColor White
    Write-Host "   - Test binary includes cert_installer pre-flight check" -ForegroundColor White
} elseif ($f0rtikaCert.NotAfter -lt (Get-Date)) {
    Write-Host "[!] ISSUE IDENTIFIED: F0RT1KA certificate is EXPIRED" -ForegroundColor Red
    Write-Host ""
    Write-Host "RECOMMENDED ACTION:" -ForegroundColor Yellow
    Write-Host "1. Remove expired certificate:" -ForegroundColor White
    Write-Host "   Get-ChildItem Cert:\LocalMachine\Root | Where-Object {`$_.Subject -like '*F0RT1KA*'} | Remove-Item" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "2. Install new certificate with updated validity period" -ForegroundColor White
} else {
    Write-Host "[+] Certificate appears correctly installed" -ForegroundColor Green
    Write-Host ""
    Write-Host "If you're still getting 'access denied', check:" -ForegroundColor Yellow
    Write-Host "1. The binary signature: Get-AuthenticodeSignature 'path\to\test.exe'" -ForegroundColor White
    Write-Host "2. SmartScreen settings may be blocking execution" -ForegroundColor White
    Write-Host "3. Windows Defender Application Control (WDAC) policies" -ForegroundColor White
    Write-Host "4. Test execution logs in C:\F0\ for actual error details" -ForegroundColor White
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
