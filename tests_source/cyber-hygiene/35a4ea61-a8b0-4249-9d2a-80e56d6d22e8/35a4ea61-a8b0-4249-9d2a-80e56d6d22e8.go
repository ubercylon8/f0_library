//go:build windows
// +build windows

/*
ID: 35a4ea61-a8b0-4249-9d2a-80e56d6d22e8
NAME: LSASS Protection Validator
TECHNIQUES: T1003.001, T1003.002, T1550.002
UNIT: response
CREATED: 2026-01-11
*/

// LSASS Protection Validator - Cyber Hygiene Test
//
// This test validates that LSASS (Local Security Authority Subsystem Service)
// protection mechanisms are properly configured to prevent credential theft
// attacks like Mimikatz.
//
// Configuration Checks:
// 1. RunAsPPL - LSASS Protected Process Light mode
// 2. VBS Enabled - Virtualization Based Security
// 3. Credential Guard - Hardware-based credential isolation
//
// Exit Codes:
// - 126: All checks pass (COMPLIANT)
// - 101: One or more checks fail (NON-COMPLIANT)
// - 999: Test error (insufficient privileges)
//
// CIS Benchmark Reference:
// - CIS Controls v8: 4.1 (Establish Secure Configuration)
// - CIS Controls v8: 10.5 (Enable Anti-Exploitation Features)

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "35a4ea61-a8b0-4249-9d2a-80e56d6d22e8"
	TEST_NAME = "LSASS Protection Validator"
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Description string
	Compliant   bool
	Value       string
	Expected    string
	Details     string
}

// test performs the LSASS protection validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "credential_access",
		Severity:   "critical",
		Techniques: []string{"T1003.001", "T1003.002", "T1550.002"},
		Tactics:    []string{"credential-access"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "lsass-protection", "credential-guard", "configuration-validation"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Phase 0: Initialization
	LogPhaseStart(0, "Initialization")

	// Check for admin privileges (required for registry access)
	if !isAdmin() {
		Endpoint.Say("[!] ERROR: Administrator privileges required for this test")
		LogMessage("ERROR", "Initialization", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Insufficient privileges")
		SaveLog(999, "Administrator privileges required")
		Endpoint.Stop(999)
	}

	LogMessage("INFO", "Initialization", "Running with administrator privileges")
	LogPhaseEnd(0, "success", "Initialization complete")

	// Phase 1: RunAsPPL Check
	LogPhaseStart(1, "RunAsPPL Check")
	runAsPPLResult := checkRunAsPPL()
	logCheckResult(1, runAsPPLResult)
	if runAsPPLResult.Compliant {
		LogPhaseEnd(1, "success", "RunAsPPL is enabled")
	} else {
		LogPhaseEnd(1, "failed", "RunAsPPL is not enabled")
	}

	// Phase 2: VBS Enabled Check
	LogPhaseStart(2, "VBS Enabled Check")
	vbsResult := checkVBSEnabled()
	logCheckResult(2, vbsResult)
	if vbsResult.Compliant {
		LogPhaseEnd(2, "success", "Virtualization Based Security is enabled")
	} else {
		LogPhaseEnd(2, "failed", "Virtualization Based Security is not enabled")
	}

	// Phase 3: Credential Guard Check
	LogPhaseStart(3, "Credential Guard Check")
	credGuardResult := checkCredentialGuard()
	logCheckResult(3, credGuardResult)
	if credGuardResult.Compliant {
		LogPhaseEnd(3, "success", "Credential Guard is running")
	} else {
		LogPhaseEnd(3, "failed", "Credential Guard is not running")
	}

	// Phase 4: Determine Overall Compliance
	LogPhaseStart(4, "Compliance Determination")

	allCompliant := runAsPPLResult.Compliant && vbsResult.Compliant && credGuardResult.Compliant
	passedChecks := 0
	if runAsPPLResult.Compliant {
		passedChecks++
	}
	if vbsResult.Compliant {
		passedChecks++
	}
	if credGuardResult.Compliant {
		passedChecks++
	}

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("                    LSASS PROTECTION VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	printCheckSummary("RunAsPPL (Protected Process Light)", runAsPPLResult)
	printCheckSummary("VBS (Virtualization Based Security)", vbsResult)
	printCheckSummary("Credential Guard", credGuardResult)
	Endpoint.Say("")
	Endpoint.Say("--------------------------------------------------------------------------------")
	Endpoint.Say("Overall: %d/3 checks passed", passedChecks)

	if allCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] All LSASS protection mechanisms are properly configured.")
		Endpoint.Say("            System is hardened against credential theft attacks.")
		LogMessage("SUCCESS", "Compliance", "All 3 LSASS protection checks passed - system is COMPLIANT")
		LogPhaseEnd(4, "success", fmt.Sprintf("All checks passed (%d/3)", passedChecks))
		SaveLog(126, "System is COMPLIANT - all LSASS protection mechanisms enabled")
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] LSASS protection is incomplete.")
		Endpoint.Say("                System may be vulnerable to credential theft attacks.")
		Endpoint.Say("")
		Endpoint.Say("Remediation Steps:")
		if !runAsPPLResult.Compliant {
			Endpoint.Say("  - Enable RunAsPPL: Set registry key")
			Endpoint.Say("    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 (or 2)")
		}
		if !vbsResult.Compliant {
			Endpoint.Say("  - Enable VBS: Configure via Group Policy or registry")
			Endpoint.Say("    HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity = 1")
		}
		if !credGuardResult.Compliant {
			Endpoint.Say("  - Enable Credential Guard: Use Windows Security or Group Policy")
			Endpoint.Say("    Requires hardware support (TPM 2.0, UEFI, Secure Boot)")
		}

		LogMessage("WARNING", "Compliance", fmt.Sprintf("Only %d/3 checks passed - system is NON-COMPLIANT", passedChecks))
		LogPhaseEnd(4, "failed", fmt.Sprintf("Not all checks passed (%d/3)", passedChecks))
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - only %d/3 LSASS protection mechanisms enabled", passedChecks))
		Endpoint.Stop(101)
	}
}

// checkRunAsPPL checks if LSASS is running as Protected Process Light
func checkRunAsPPL() CheckResult {
	result := CheckResult{
		Name:        "RunAsPPL",
		Description: "LSASS Protected Process Light mode",
		Expected:    "1 or 2",
	}

	Endpoint.Say("[*] Checking RunAsPPL registry key...")
	LogMessage("INFO", "RunAsPPL", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL")

	// Open the LSA registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("Failed to open registry key: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] Failed to access LSA registry key: %v", err)
		LogMessage("ERROR", "RunAsPPL", result.Details)
		return result
	}
	defer key.Close()

	// Try to read RunAsPPL value
	value, _, err := key.GetIntegerValue("RunAsPPL")
	if err != nil {
		// Key doesn't exist - not configured
		result.Value = "Not configured"
		result.Details = "RunAsPPL registry value does not exist"
		result.Compliant = false
		Endpoint.Say("    [!] RunAsPPL not configured (value does not exist)")
		LogMessage("WARNING", "RunAsPPL", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	// RunAsPPL = 1 or 2 indicates enabled
	// 1 = Enabled with UEFI lock
	// 2 = Enabled without UEFI lock (can be disabled)
	if value == 1 || value == 2 {
		result.Compliant = true
		if value == 1 {
			result.Details = "RunAsPPL enabled with UEFI lock (most secure)"
		} else {
			result.Details = "RunAsPPL enabled without UEFI lock"
		}
		Endpoint.Say("    [+] RunAsPPL is ENABLED (value=%d)", value)
		LogMessage("SUCCESS", "RunAsPPL", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("RunAsPPL value is %d (expected 1 or 2)", value)
		Endpoint.Say("    [-] RunAsPPL is DISABLED (value=%d)", value)
		LogMessage("WARNING", "RunAsPPL", result.Details)
	}

	return result
}

// checkVBSEnabled checks if Virtualization Based Security is enabled
func checkVBSEnabled() CheckResult {
	result := CheckResult{
		Name:        "VBS Enabled",
		Description: "Virtualization Based Security",
		Expected:    "1",
	}

	Endpoint.Say("[*] Checking Virtualization Based Security...")
	LogMessage("INFO", "VBS", "Checking HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity")

	// Open the DeviceGuard registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard`, registry.QUERY_VALUE)
	if err != nil {
		result.Value = "Key not accessible"
		result.Details = fmt.Sprintf("DeviceGuard registry key not found: %v", err)
		result.Compliant = false
		Endpoint.Say("    [!] DeviceGuard registry key not found")
		LogMessage("WARNING", "VBS", result.Details)
		return result
	}
	defer key.Close()

	// Read EnableVirtualizationBasedSecurity value
	value, _, err := key.GetIntegerValue("EnableVirtualizationBasedSecurity")
	if err != nil {
		result.Value = "Not configured"
		result.Details = "EnableVirtualizationBasedSecurity value does not exist"
		result.Compliant = false
		Endpoint.Say("    [!] VBS not configured (value does not exist)")
		LogMessage("WARNING", "VBS", result.Details)
		return result
	}

	result.Value = fmt.Sprintf("%d", value)

	if value == 1 {
		result.Compliant = true
		result.Details = "Virtualization Based Security is enabled in registry"
		Endpoint.Say("    [+] VBS is ENABLED (value=%d)", value)
		LogMessage("SUCCESS", "VBS", result.Details)
	} else {
		result.Compliant = false
		result.Details = fmt.Sprintf("VBS value is %d (expected 1)", value)
		Endpoint.Say("    [-] VBS is DISABLED (value=%d)", value)
		LogMessage("WARNING", "VBS", result.Details)
	}

	return result
}

// checkCredentialGuard checks if Credential Guard is actively running
func checkCredentialGuard() CheckResult {
	result := CheckResult{
		Name:        "Credential Guard",
		Description: "Hardware-based credential isolation",
		Expected:    "Running (SecurityServicesRunning contains 2)",
	}

	Endpoint.Say("[*] Checking Credential Guard status via WMI...")
	LogMessage("INFO", "CredentialGuard", "Querying Win32_DeviceGuard for SecurityServicesRunning")

	// Use PowerShell to query WMI for Credential Guard status
	// SecurityServicesRunning array containing 2 means Credential Guard is running
	psScript := `
$cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($cg) {
    $services = $cg.SecurityServicesRunning
    if ($services -contains 2) {
        Write-Output "RUNNING:$($services -join ',')"
    } else {
        Write-Output "NOT_RUNNING:$($services -join ',')"
    }
} else {
    Write-Output "WMI_NOT_AVAILABLE"
}
`

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		result.Value = "Query failed"
		result.Details = fmt.Sprintf("PowerShell query failed: %v - %s", err, stderr.String())
		result.Compliant = false
		Endpoint.Say("    [!] Failed to query Credential Guard status: %v", err)
		LogMessage("ERROR", "CredentialGuard", result.Details)

		// Save PowerShell output for debugging
		saveCredentialGuardOutput(stdout.String(), stderr.String())
		return result
	}

	output := strings.TrimSpace(stdout.String())
	saveCredentialGuardOutput(output, stderr.String())

	if output == "WMI_NOT_AVAILABLE" {
		result.Value = "WMI unavailable"
		result.Details = "Win32_DeviceGuard WMI class not available - Device Guard not configured"
		result.Compliant = false
		Endpoint.Say("    [!] Device Guard WMI class not available")
		LogMessage("WARNING", "CredentialGuard", result.Details)
		return result
	}

	parts := strings.SplitN(output, ":", 2)
	if len(parts) == 2 {
		status := parts[0]
		services := parts[1]

		if status == "RUNNING" {
			result.Value = fmt.Sprintf("Running (services: %s)", services)
			result.Details = "Credential Guard is actively running"
			result.Compliant = true
			Endpoint.Say("    [+] Credential Guard is RUNNING (services: %s)", services)
			LogMessage("SUCCESS", "CredentialGuard", result.Details)
		} else {
			result.Value = fmt.Sprintf("Not running (services: %s)", services)
			result.Details = "Credential Guard is configured but not running (service 2 not in SecurityServicesRunning)"
			result.Compliant = false
			Endpoint.Say("    [-] Credential Guard is NOT RUNNING (services: %s)", services)
			LogMessage("WARNING", "CredentialGuard", result.Details)
		}
	} else {
		result.Value = "Unexpected output"
		result.Details = fmt.Sprintf("Unexpected WMI output format: %s", output)
		result.Compliant = false
		Endpoint.Say("    [!] Unexpected output from WMI query: %s", output)
		LogMessage("ERROR", "CredentialGuard", result.Details)
	}

	return result
}

// saveCredentialGuardOutput saves the PowerShell output for debugging
func saveCredentialGuardOutput(stdout, stderr string) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, "credentialguard_output.txt")
	content := fmt.Sprintf("=== Credential Guard WMI Query Output ===\n\nSTDOUT:\n%s\n\nSTDERR:\n%s\n", stdout, stderr)

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		LogMessage("WARNING", "CredentialGuard", fmt.Sprintf("Failed to save output: %v", err))
	} else {
		LogMessage("INFO", "CredentialGuard", fmt.Sprintf("Output saved to: %s", outputPath))
	}
}

// logCheckResult logs a check result to the structured log
func logCheckResult(phaseNum int, result CheckResult) {
	LogMessage("INFO", result.Name, fmt.Sprintf("Check: %s", result.Description))
	LogMessage("INFO", result.Name, fmt.Sprintf("Expected: %s", result.Expected))
	LogMessage("INFO", result.Name, fmt.Sprintf("Actual: %s", result.Value))
	LogMessage("INFO", result.Name, fmt.Sprintf("Compliant: %v", result.Compliant))
	LogMessage("INFO", result.Name, fmt.Sprintf("Details: %s", result.Details))
}

// printCheckSummary prints a formatted check summary
func printCheckSummary(name string, result CheckResult) {
	status := "FAIL"
	if result.Compliant {
		status = "PASS"
	}
	Endpoint.Say("[%s] %-45s Value: %s", status, name, result.Value)
}

// isAdmin checks if the process is running with administrator privileges
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: LSASS Protection Validator")
	Endpoint.Say("  Test ID: %s", TEST_UUID)
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("This is a READ-ONLY configuration validation test.")
	Endpoint.Say("")

	// Ensure C:\F0 exists for log output
	os.MkdirAll("c:\\F0", 0755)

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// Timeout: 2 minutes (should complete much faster)
	timeout := 2 * time.Minute

	select {
	case <-done:
		Endpoint.Say("")
		Endpoint.Say("Test completed successfully")
	case <-time.After(timeout):
		Endpoint.Say("")
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(999, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(999)
	}
}
