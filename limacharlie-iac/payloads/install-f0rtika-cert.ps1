# F0RT1KA Certificate Auto-Installation via LimaCharlie
# Runs automatically when new sensors enroll
# Part of LimaCharlie Infrastructure as Code deployment

param(
    [Parameter(Mandatory=$true)]
    [string]$CertBase64
)

$ErrorActionPreference = "Stop"

# Log function for LimaCharlie (output captured in RECEIPT event)
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] [F0RT1KA-CERT] $Message"
}

# Main installation logic
try {
    Write-Log "==================================================================="
    Write-Log "F0RT1KA Certificate Installation - LimaCharlie IaC Deployment"
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
        Write-Log "WARNING: Not running with elevated privileges" "WARN"
        Write-Log "Certificate installation requires Administrator or SYSTEM privileges" "WARN"
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
    Write-Log "==================================================================="

    exit 0

} catch {
    # Error handling
    Write-Log "" "ERROR"
    Write-Log "==================================================================" "ERROR"
    Write-Log "FATAL ERROR: Certificate Installation Failed" "ERROR"
    Write-Log "==================================================================" "ERROR"
    Write-Log "Error Message: $($_.Exception.Message)" "ERROR"
    Write-Log "Error Type: $($_.Exception.GetType().FullName)" "ERROR"

    if ($_.ScriptStackTrace) {
        Write-Log "" "ERROR"
        Write-Log "Stack Trace:" "ERROR"
        Write-Log "$($_.ScriptStackTrace)" "ERROR"
    }

    Write-Log "==================================================================" "ERROR"

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
