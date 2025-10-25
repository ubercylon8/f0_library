// Package cert_installer provides automatic certificate installation for F0RT1KA security tests.
// This module ensures the F0RT1KA code signing certificate is installed on endpoints before test execution,
// enabling self-healing security test deployment without manual certificate management.
package cert_installer

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed F0RT1KA.cer
var f0rtikaCert []byte

const (
	certSubject = "CN=F0RT1KA Security Testing Framework"
	certStore   = "Cert:\\LocalMachine\\Root"
)

// EnsureCertificateInstalled checks if the F0RT1KA code signing certificate is installed
// in the LocalMachine\Root certificate store. If not present, it automatically installs
// the certificate using PowerShell with SYSTEM privileges (assuming LimaCharlie execution context).
//
// This function is designed to be called at the start of each F0RT1KA test to ensure
// the endpoint is properly configured for signed binary execution.
//
// Returns:
//   - nil if certificate is already installed or successfully installed
//   - error if installation fails
//
// Example usage:
//
//	func main() {
//	    if err := cert_installer.EnsureCertificateInstalled(); err != nil {
//	        Endpoint.Say("❌ FATAL: Certificate installation failed: %v", err)
//	        Endpoint.Stop(Endpoint.UnexpectedTestError)
//	    }
//	    // Continue with test...
//	}
func EnsureCertificateInstalled() error {
	// Step 1: Check if certificate is already installed
	installed, err := isCertificateInstalled()
	if err != nil {
		return fmt.Errorf("failed to check certificate status: %v", err)
	}

	if installed {
		// Certificate already present - no action needed
		return nil
	}

	// Step 2: Certificate not installed - install it now
	fmt.Println("⚠️  F0RT1KA certificate not found - installing...")

	if err := installCertificate(); err != nil {
		return fmt.Errorf("certificate installation failed: %v", err)
	}

	// Step 3: Verify installation succeeded
	installed, err = isCertificateInstalled()
	if err != nil {
		return fmt.Errorf("failed to verify certificate installation: %v", err)
	}

	if !installed {
		return fmt.Errorf("certificate installation completed but verification failed")
	}

	fmt.Println("✅ F0RT1KA certificate installed successfully")
	return nil
}

// isCertificateInstalled checks if the F0RT1KA certificate exists in the LocalMachine\Root store
func isCertificateInstalled() (bool, error) {
	// Use -like instead of -eq to handle full subject strings like "C=US, O=F0RT1KA, CN=F0RT1KA Security Testing Framework"
	psScript := fmt.Sprintf(`
		$cert = Get-ChildItem %s | Where-Object {$_.Subject -like "*F0RT1KA Security Testing Framework*"}
		if ($cert) {
			Write-Output "INSTALLED"
		} else {
			Write-Output "NOT_INSTALLED"
		}
	`, certStore)

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("PowerShell check failed: %v - %s", err, string(output))
	}

	result := strings.TrimSpace(string(output))
	return result == "INSTALLED", nil
}

// installCertificate installs the embedded F0RT1KA certificate to LocalMachine\Root store
func installCertificate() error {
	// Step 1: Write embedded certificate to temporary file
	targetDir := "C:\\F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	certPath := filepath.Join(targetDir, "F0RT1KA-temp.cer")
	if err := os.WriteFile(certPath, f0rtikaCert, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %v", err)
	}
	defer os.Remove(certPath) // Clean up temp file

	// Step 2: Install certificate using PowerShell Import-Certificate
	psScript := fmt.Sprintf(`
		try {
			$cert = Import-Certificate -FilePath "%s" -CertStoreLocation %s -ErrorAction Stop
			if ($cert) {
				Write-Output "SUCCESS: $($cert.Thumbprint)"
			} else {
				Write-Output "ERROR: Import returned null"
				exit 1
			}
		} catch {
			Write-Output "ERROR: $($_.Exception.Message)"
			exit 1
		}
	`, certPath, certStore)

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		return fmt.Errorf("PowerShell import failed: %v - %s", err, outputStr)
	}

	if !strings.HasPrefix(outputStr, "SUCCESS:") {
		return fmt.Errorf("certificate import failed: %s", outputStr)
	}

	return nil
}

// GetCertificateInfo returns information about the embedded F0RT1KA certificate
// This is a utility function for debugging and verification
func GetCertificateInfo() string {
	return fmt.Sprintf("F0RT1KA Security Testing Framework Certificate\n"+
		"Subject: %s\n"+
		"Store: %s\n"+
		"Size: %d bytes", certSubject, certStore, len(f0rtikaCert))
}
