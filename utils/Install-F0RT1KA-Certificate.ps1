# F0RT1KA Certificate Auto-Installation Script
# Standalone version with embedded certificate
# Installs F0RT1KA code signing certificate to Trusted Root store
# No parameters required - certificate is embedded in script

$ErrorActionPreference = "Stop"

# Embedded F0RT1KA Certificate (Base64)
$CertBase64 = @"
MIIFeTCCA2GgAwIBAgIUbnW5hrRpEeLCrQhxA7sawBm46mYwDQYJKoZIhvcNAQELBQAwTDErMCkGA1UEAwwiRjBSVDFLQSBTZWN1cml0eSBUZXN0aW5nIEZyYW1ld29yazEQMA4GA1UECgwHRjBSVDFLQTELMAkGA1UEBhMCVVMwHhcNMjUxMDI1MDI0NjQ2WhcNMzAxMDI0MDI0NjQ2WjBMMSswKQYDVQQDDCJGMFJUMUtBIFNlY3VyaXR5IFRlc3RpbmcgRnJhbWV3b3JrMRAwDgYDVQQKDAdGMFJUMUtBMQswCQYDVQQGEwJVUzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL25zBNJrAMve7ScNuLziXq0LuBdNe+tJsOMqvvINjb+2ekFtlNHLsiKAYR22B8GqVxXZdVNbAybS8cF+/l6ollUJMOp4WaezA9nRW1pSK0lzMVXSZ/uTfcySngzM7eNM9YUSTfYhv5x+fzHNEltgCw2z0/XNQs37ZYtlmo3MdMkNdWUGbQugEyGs8OzVklz9Y11mOF7ootvD/bsLmpA8hr9cpdTCPsQpwALwPqAo/db7Yr8zcTIQoM31+vIX3jgz3Mj2QgRhm7TuVgg5/wA/MoNu8GEVCuQVgrSkoQAKXTloO/x5SbY+f5r+Zd3cbsq+zfYiSnLqTv5UrcaKgjXn85AYUXrixXdVCtIEPRJCvTuanoknG+ned4z3bti1FJnDn/peRtQXmbS51ratZw0h2iD2xJdRohv+rw5/cuqu5xzSqmkZqHQ0rJkBDYABjlAeMAjsIZ61hcWwzQPFkvkrCkbHdKHXJKcgSMT3dryynwkODHJyDf/t6Ld3fsrbryYgaB4BGN5Lw6OGzYwjr3QTeXoJVf1tp9TyUZbGpgv9z5vyd0Lqi7bMD3w5lIW1xNDl+hfyvWR4xbaieVYYW++KED8iKyzZ1wMzFnMaEelj6UohOFh71/TSySICp/93HBuQ8icx34zhtKGwQp/L3mZUY8e3VCqOlwme8VdMMW7utxlAgMBAAGjUzBRMB0GA1UdDgQWBBSXfpglV9QT+Q578S4IPZx/IRlAmzAfBgNVHSMEGDAWgBSXfpglV9QT+Q578S4IPZx/IRlAmzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAdlbbOnuz7MHy8dbg2n291+CIbwHqm35nPax5TAOMzMGASkRBcz8HxQfte4t6xSg1YDpyo6pGeSZ8J46/3OFat8fM29w9j2E+TdpQ0wKnqk0Tu3Av8PlRzkxuR67M6YA7TyU9EIM3zcmoT2iuLIXrsonAs9I6T3W+feNIH4c/NBqIW3YMi/rVJZ4m3IJ6LVjsr7tVINXzejwsPvXBMO4iN+s/z9L/4Qxxn6Kh4E3UWQqYY9Sp6MCow1YoTti+9WkRq6PB2CKAzNw8o66yevPybmFTRwlH+ljtPRa6youVkd4zhlIOVTDbfXBiJr+uFykKXhlYGV+3+0vMEnqG5yYhtuD5rMwaE9244OZzHcVlGiU7qAspwZh/go2mpcnOdjJ6/qDUApsioReFbzIaLzFSTf1DDFBF49UGRBTXNwsyErfVyHcvgPjgKKo6uKG1tQ4kKr7nTwKxntFnZqF+fO85uy1fxkMaX77xM36wHFNUh/V0rLcry3wcmiWNgzbpBy+bNpw3ZHbyulXe0EH8VSl4Z1BWhUqM9ACqodOgsr7zW5t3s5a1RoQ85ZLbRn0XERQX2fFbQygtS7e38H3ZU1rfl6LbUxzSFDbHHSC8xcuqpcC+bQsYTS2DcUHcxmiI3shw0KTy+Zn3c6JCD7/VWjWK2MYdDOFojUO2BhrfQTQZ0Tg==
"@

# Log function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] [F0RT1KA-CERT] $Message"
}

# Main installation logic
try {
    Write-Log "==================================================================="
    Write-Log "F0RT1KA Certificate Installation - Standalone Version"
    Write-Log "==================================================================="

    # Check execution context
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $currentIdentity.IsSystem

    Write-Log "Execution Context:"
    Write-Log "  User: $($currentIdentity.Name)"
    Write-Log "  Is Admin: $isAdmin"
    Write-Log "  Is SYSTEM: $isSystem"

    if (-not $isAdmin -and -not $isSystem) {
        Write-Log "ERROR: Administrator privileges required" "ERROR"
        Write-Log "Please run this script as Administrator or SYSTEM" "ERROR"
        Write-Log ""
        Write-Log "To run as Administrator:"
        Write-Log "  1. Right-click PowerShell and select 'Run as Administrator'"
        Write-Log "  2. Navigate to script directory and run:"
        Write-Log "     .\Install-F0RT1KA-Certificate.ps1"
        Write-Log ""
        Write-Log "Or use this command:"
        Write-Log "  Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File .\Install-F0RT1KA-Certificate.ps1'"
        exit 1
    }

    # System Information
    Write-Log ""
    Write-Log "System Information:"
    Write-Log "  Computer: $env:COMPUTERNAME"
    Write-Log "  OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
    Write-Log "  Architecture: $env:PROCESSOR_ARCHITECTURE"

    # Define certificate store
    $certStore = "Cert:\LocalMachine\Root"
    Write-Log ""
    Write-Log "Target Certificate Store: $certStore (Trusted Root Certification Authorities)"

    # Check if certificate already installed
    Write-Log ""
    Write-Log "Phase 1: Checking for existing F0RT1KA certificate..."

    $existingCert = Get-ChildItem $certStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -like "*F0RT1KA Security Testing Framework*"
    }

    if ($existingCert) {
        Write-Log "Certificate already installed - no action needed" "INFO"
        Write-Log ""
        Write-Log "Certificate Details:"
        Write-Log "  Subject: $($existingCert.Subject)"
        Write-Log "  Issuer: $($existingCert.Issuer)"
        Write-Log "  Thumbprint: $($existingCert.Thumbprint)"
        Write-Log "  Valid From: $($existingCert.NotBefore)"
        Write-Log "  Valid Until: $($existingCert.NotAfter)"
        Write-Log "  Serial Number: $($existingCert.SerialNumber)"
        Write-Log ""
        Write-Log "==================================================================="
        Write-Log "RESULT: SUCCESS (Certificate already present)"
        Write-Log "==================================================================="
        exit 0
    }

    Write-Log "Certificate not found - proceeding with installation"

    # Phase 2: Decode base64 certificate data
    Write-Log ""
    Write-Log "Phase 2: Decoding certificate data..."

    if ([string]::IsNullOrWhiteSpace($CertBase64)) {
        throw "Certificate data is empty or null"
    }

    Write-Log "  Certificate data length: $($CertBase64.Length) characters"

    try {
        $certBytes = [System.Convert]::FromBase64String($CertBase64)
        Write-Log "  Decoded certificate size: $($certBytes.Length) bytes"
    } catch {
        throw "Failed to decode base64 certificate data: $($_.Exception.Message)"
    }

    # Phase 3: Create temporary certificate file
    Write-Log ""
    Write-Log "Phase 3: Creating temporary certificate file..."

    $tempCertPath = "$env:TEMP\F0RT1KA-$(Get-Date -Format 'yyyyMMdd-HHmmss').cer"

    try {
        [System.IO.File]::WriteAllBytes($tempCertPath, $certBytes)
        Write-Log "  Certificate written to: $tempCertPath"

        # Verify file was created
        if (-not (Test-Path $tempCertPath)) {
            throw "Certificate file was not created at expected path"
        }

        $fileInfo = Get-Item $tempCertPath
        Write-Log "  File size: $($fileInfo.Length) bytes"

    } catch {
        throw "Failed to create temporary certificate file: $($_.Exception.Message)"
    }

    # Phase 4: Import certificate to Trusted Root store
    Write-Log ""
    Write-Log "Phase 4: Installing certificate to Trusted Root store..."

    try {
        $cert = Import-Certificate -FilePath $tempCertPath -CertStoreLocation $certStore -ErrorAction Stop
        Write-Log "  Certificate imported successfully"
        Write-Log "  Thumbprint: $($cert.Thumbprint)"

    } catch {
        # Cleanup temp file before throwing
        Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
        throw "Failed to import certificate: $($_.Exception.Message)"
    }

    # Phase 5: Verify installation
    Write-Log ""
    Write-Log "Phase 5: Verifying certificate installation..."

    $verifyCheck = Get-ChildItem $certStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -like "*F0RT1KA Security Testing Framework*"
    }

    if ($verifyCheck) {
        Write-Log "  Verification PASSED - Certificate found in store"
        Write-Log ""
        Write-Log "Installed Certificate Details:"
        Write-Log "  Subject: $($verifyCheck.Subject)"
        Write-Log "  Issuer: $($verifyCheck.Issuer)"
        Write-Log "  Thumbprint: $($verifyCheck.Thumbprint)"
        Write-Log "  Valid From: $($verifyCheck.NotBefore)"
        Write-Log "  Valid Until: $($verifyCheck.NotAfter)"
        Write-Log "  Serial Number: $($verifyCheck.SerialNumber)"
        Write-Log "  Has Private Key: $($verifyCheck.HasPrivateKey)"

        # Calculate days until expiration
        $daysUntilExpiry = ($verifyCheck.NotAfter - (Get-Date)).Days
        Write-Log "  Days Until Expiry: $daysUntilExpiry"

        if ($daysUntilExpiry -lt 30) {
            Write-Log "  WARNING: Certificate expires in less than 30 days!" "WARN"
        }

    } else {
        # Cleanup temp file before throwing
        Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
        throw "Certificate installation verification failed - certificate not found in store after import"
    }

    # Phase 6: Cleanup temporary file
    Write-Log ""
    Write-Log "Phase 6: Cleaning up temporary files..."

    try {
        Remove-Item -Path $tempCertPath -Force -ErrorAction Stop
        Write-Log "  Temporary file deleted: $tempCertPath"
    } catch {
        Write-Log "  Warning: Failed to delete temporary file: $($_.Exception.Message)" "WARN"
        # Don't fail the entire operation due to cleanup issue
    }

    # Success summary
    Write-Log ""
    Write-Log "==================================================================="
    Write-Log "RESULT: SUCCESS"
    Write-Log "==================================================================="
    Write-Log "F0RT1KA certificate successfully installed to Trusted Root store"
    Write-Log "Endpoint is now configured to trust F0RT1KA signed binaries"
    Write-Log "Certificate Thumbprint: $($verifyCheck.Thumbprint)"
    Write-Log ""
    Write-Log "You can now run F0RT1KA security tests without certificate warnings"
    Write-Log "==================================================================="

    exit 0

} catch {
    # Error handling
    Write-Log "" "ERROR"
    Write-Log "===================================================================" "ERROR"
    Write-Log "FATAL ERROR: Certificate Installation Failed" "ERROR"
    Write-Log "===================================================================" "ERROR"
    Write-Log "Error Message: $($_.Exception.Message)" "ERROR"
    Write-Log "Error Type: $($_.Exception.GetType().FullName)" "ERROR"

    if ($_.ScriptStackTrace) {
        Write-Log "" "ERROR"
        Write-Log "Stack Trace:" "ERROR"
        Write-Log "$($_.ScriptStackTrace)" "ERROR"
    }

    Write-Log "===================================================================" "ERROR"

    # Cleanup temp file if it exists
    if ($tempCertPath -and (Test-Path $tempCertPath)) {
        try {
            Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
            Write-Log "Temporary file cleaned up after error" "INFO"
        } catch {
            # Ignore cleanup errors
        }
    }

    exit 1
}
