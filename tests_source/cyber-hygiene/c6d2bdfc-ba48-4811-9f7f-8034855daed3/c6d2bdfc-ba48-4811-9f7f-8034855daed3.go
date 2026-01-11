//go:build windows
// +build windows

/*
ID: c6d2bdfc-ba48-4811-9f7f-8034855daed3
NAME: Print Spooler Hardening Validator
TECHNIQUES: T1547.012, T1569.002, T1068
UNIT: response
CREATED: 2026-01-11
*/

// Print Spooler Hardening Validator - Cyber Hygiene Test
//
// This test validates that the Windows Print Spooler service is properly hardened
// or disabled. PrintNightmare (CVE-2021-34527) demonstrated severe risk with remote
// code execution using SYSTEM privileges. CISA issued Emergency Directive 21-04
// specifically for this vulnerability.
//
// Configuration Checks:
// 1. Spooler Service Status - Disabled or not running
// 2. Point and Print NoWarningNoElevationOnInstall - Must be 0
// 3. Point and Print UpdatePromptSettings - Must be 0
// 4. RestrictDriverInstallationToAdministrators - Must be 1
//
// Exit Codes:
// - 126: Service disabled OR (running with all restrictions) (COMPLIANT)
// - 101: Service running without proper restrictions (NON-COMPLIANT)
// - 999: Test error (insufficient privileges)
//
// CIS Benchmark Reference:
// - CIS Controls v8: 4.8 (Uninstall/Disable Unnecessary Services)
// - CIS Controls v8: 7.7 (Remediate Vulnerabilities Based on Risk)

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "c6d2bdfc-ba48-4811-9f7f-8034855daed3"
	TEST_NAME = "Print Spooler Hardening Validator"
)

// Service start types
const (
	SERVICE_START_BOOT     = 0
	SERVICE_START_SYSTEM   = 1
	SERVICE_START_AUTO     = 2
	SERVICE_START_MANUAL   = 3
	SERVICE_START_DISABLED = 4
)

// CheckResult represents the result of a single configuration check
type CheckResult struct {
	Name        string
	Description string
	Compliant   bool
	Value       string
	Expected    string
	Details     string
	Skipped     bool
}

// test performs the Print Spooler hardening validation
func test() {
	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "persistence",
		Severity:   "high",
		Techniques: []string{"T1547.012", "T1569.002", "T1068"},
		Tactics:    []string{"persistence", "privilege-escalation"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
		Tags: []string{"cyber-hygiene", "print-spooler", "printnightmare", "cve-2021-34527", "configuration-validation"},
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

	// Check for admin privileges (required for service and registry access)
	if !isAdmin() {
		Endpoint.Say("[!] ERROR: Administrator privileges required for this test")
		LogMessage("ERROR", "Initialization", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Insufficient privileges")
		SaveLog(999, "Administrator privileges required")
		Endpoint.Stop(999)
	}

	LogMessage("INFO", "Initialization", "Running with administrator privileges")
	LogPhaseEnd(0, "success", "Initialization complete")

	// Phase 1: Check Spooler Service Status
	LogPhaseStart(1, "Spooler Service Check")
	serviceResult := checkSpoolerService()
	logCheckResult(1, serviceResult)
	if serviceResult.Compliant {
		LogPhaseEnd(1, "success", "Print Spooler service is disabled or not running")
	} else {
		LogPhaseEnd(1, "failed", "Print Spooler service is running")
	}

	// If service is disabled/stopped, we're compliant - Point and Print checks not required
	var pointAndPrintResults []CheckResult
	allPointAndPrintChecksPass := true

	if serviceResult.Compliant {
		Endpoint.Say("")
		Endpoint.Say("[*] Spooler service is disabled/stopped - Point and Print checks are optional")
		Endpoint.Say("    (Disabling the service is the recommended hardening approach)")
		LogMessage("INFO", "PointAndPrint", "Spooler disabled - Point and Print restrictions not required for compliance")

		// Still run the checks for informational purposes, but mark as skipped for compliance
		LogPhaseStart(2, "Point and Print Check (Informational)")
		pointAndPrintResults = checkPointAndPrintRestrictions(true) // informational mode
		for _, r := range pointAndPrintResults {
			logCheckResult(2, r)
		}
		LogPhaseEnd(2, "success", "Point and Print checks completed (informational)")
	} else {
		// Service is running - Point and Print restrictions are REQUIRED
		LogPhaseStart(2, "Point and Print Restrictions Check")
		Endpoint.Say("")
		Endpoint.Say("[!] Spooler service is RUNNING - checking Point and Print restrictions...")
		pointAndPrintResults = checkPointAndPrintRestrictions(false) // required mode

		for _, r := range pointAndPrintResults {
			logCheckResult(2, r)
			if !r.Compliant && !r.Skipped {
				allPointAndPrintChecksPass = false
			}
		}

		if allPointAndPrintChecksPass {
			LogPhaseEnd(2, "success", "All Point and Print restrictions are in place")
		} else {
			LogPhaseEnd(2, "failed", "Point and Print restrictions are incomplete")
		}
	}

	// Phase 3: Check for Domain Controller
	LogPhaseStart(3, "Domain Controller Check")
	isDC := isDomainController()
	if isDC {
		Endpoint.Say("[!] WARNING: This appears to be a Domain Controller")
		Endpoint.Say("    Domain Controllers should ALWAYS have Print Spooler DISABLED")
		Endpoint.Say("    See: CVE-2021-1675, CVE-2021-34527 (PrintNightmare)")
		LogMessage("WARNING", "DomainController", "Domain Controllers should ALWAYS have Print Spooler disabled")
		if !serviceResult.Compliant {
			LogMessage("CRITICAL", "DomainController", "Print Spooler is running on Domain Controller - HIGH RISK")
		}
	}
	LogPhaseEnd(3, "success", fmt.Sprintf("Domain Controller check complete (isDC: %v)", isDC))

	// Phase 4: Determine Overall Compliance
	LogPhaseStart(4, "Compliance Determination")

	// Compliance logic:
	// - Service disabled/stopped = COMPLIANT (regardless of Point and Print settings)
	// - Service running + ALL Point and Print restrictions = COMPLIANT
	// - Service running + ANY Point and Print missing = NON-COMPLIANT

	overallCompliant := false
	complianceReason := ""

	if serviceResult.Compliant {
		overallCompliant = true
		complianceReason = "Print Spooler service is disabled/stopped (best practice)"
	} else if allPointAndPrintChecksPass {
		overallCompliant = true
		complianceReason = "Print Spooler running with all Point and Print restrictions in place"
	} else {
		overallCompliant = false
		complianceReason = "Print Spooler running without proper Point and Print restrictions"
	}

	// Count passed checks for summary
	passedChecks := 0
	totalChecks := 1 // Service check

	if serviceResult.Compliant {
		passedChecks++
	}

	// Only count Point and Print checks if service is running
	if !serviceResult.Compliant {
		for _, r := range pointAndPrintResults {
			if !r.Skipped {
				totalChecks++
				if r.Compliant {
					passedChecks++
				}
			}
		}
	}

	// Generate summary
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("                  PRINT SPOOLER HARDENING VALIDATION SUMMARY")
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	printCheckSummary("Spooler Service Status", serviceResult)

	if !serviceResult.Compliant {
		Endpoint.Say("")
		Endpoint.Say("Point and Print Restrictions (required when service is running):")
		for _, r := range pointAndPrintResults {
			if !r.Skipped {
				printCheckSummary("  "+r.Name, r)
			}
		}
	}

	if isDC {
		Endpoint.Say("")
		Endpoint.Say("[!] DOMAIN CONTROLLER NOTICE: Print Spooler should be DISABLED on all DCs")
	}

	Endpoint.Say("")
	Endpoint.Say("--------------------------------------------------------------------------------")

	if overallCompliant {
		Endpoint.Say("")
		Endpoint.Say("[COMPLIANT] %s", complianceReason)
		Endpoint.Say("            PrintNightmare mitigations are in place.")
		LogMessage("SUCCESS", "Compliance", fmt.Sprintf("System is COMPLIANT: %s", complianceReason))
		LogPhaseEnd(4, "success", complianceReason)
		SaveLog(126, fmt.Sprintf("System is COMPLIANT - %s", complianceReason))
		Endpoint.Stop(126)
	} else {
		Endpoint.Say("")
		Endpoint.Say("[NON-COMPLIANT] %s", complianceReason)
		Endpoint.Say("                System may be vulnerable to PrintNightmare (CVE-2021-34527).")
		Endpoint.Say("")
		Endpoint.Say("Remediation Options:")
		Endpoint.Say("")
		Endpoint.Say("  OPTION 1 (Recommended - Non-Print Servers):")
		Endpoint.Say("    Disable the Print Spooler service:")
		Endpoint.Say("      Stop-Service -Name Spooler -Force")
		Endpoint.Say("      Set-Service -Name Spooler -StartupType Disabled")
		Endpoint.Say("")
		Endpoint.Say("  OPTION 2 (Print Servers Only):")
		Endpoint.Say("    Enable all Point and Print restrictions:")

		// Show specific remediation for failed checks
		for _, r := range pointAndPrintResults {
			if !r.Compliant && !r.Skipped {
				showRemediation(r.Name)
			}
		}

		LogMessage("WARNING", "Compliance", fmt.Sprintf("System is NON-COMPLIANT: %s", complianceReason))
		LogPhaseEnd(4, "failed", complianceReason)
		SaveLog(101, fmt.Sprintf("System is NON-COMPLIANT - %s", complianceReason))
		Endpoint.Stop(101)
	}
}

// checkSpoolerService checks if the Print Spooler service is disabled or not running
func checkSpoolerService() CheckResult {
	result := CheckResult{
		Name:        "Spooler Service",
		Description: "Print Spooler service status",
		Expected:    "Disabled (4) OR not running",
	}

	Endpoint.Say("[*] Checking Print Spooler service status...")
	LogMessage("INFO", "SpoolerService", "Checking service status via sc query and registry")

	// Method 1: Check service state via sc query
	cmd := exec.Command("sc", "query", "Spooler")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	scOutput := stdout.String()
	saveServiceQueryOutput(scOutput, stderr.String())

	serviceRunning := false
	if err == nil {
		if strings.Contains(scOutput, "RUNNING") {
			serviceRunning = true
			result.Value = "Running"
			Endpoint.Say("    [*] Service state: RUNNING")
		} else if strings.Contains(scOutput, "STOPPED") {
			result.Value = "Stopped"
			Endpoint.Say("    [*] Service state: STOPPED")
		} else if strings.Contains(scOutput, "DISABLED") {
			result.Value = "Disabled"
			Endpoint.Say("    [*] Service state: DISABLED")
		} else {
			result.Value = "Unknown"
			Endpoint.Say("    [*] Service state: Unknown")
		}
	} else {
		// Service might not exist
		result.Value = "Not found"
		Endpoint.Say("    [*] Service query failed: %v", err)
	}

	// Method 2: Check registry for Start type
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Spooler`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		startType, _, err := key.GetIntegerValue("Start")
		if err == nil {
			startTypeStr := getStartTypeName(int(startType))
			LogMessage("INFO", "SpoolerService", fmt.Sprintf("Registry Start type: %d (%s)", startType, startTypeStr))
			Endpoint.Say("    [*] Service start type: %s (%d)", startTypeStr, startType)

			if startType == SERVICE_START_DISABLED {
				result.Compliant = true
				result.Details = "Service is disabled via registry (Start=4)"
				Endpoint.Say("    [+] Print Spooler service is DISABLED")
				LogMessage("SUCCESS", "SpoolerService", "Service is disabled")
				return result
			}
		}
	}

	// Final determination
	if !serviceRunning {
		// Service is not running (but might be set to Manual or Auto)
		result.Compliant = true
		result.Details = "Service is not currently running"
		Endpoint.Say("    [+] Print Spooler service is NOT RUNNING")
		LogMessage("SUCCESS", "SpoolerService", "Service is not running")
	} else {
		result.Compliant = false
		result.Details = "Service is running - Point and Print restrictions required"
		Endpoint.Say("    [-] Print Spooler service is RUNNING")
		LogMessage("WARNING", "SpoolerService", "Service is running")
	}

	return result
}

// checkPointAndPrintRestrictions checks all Point and Print registry settings
func checkPointAndPrintRestrictions(informationalOnly bool) []CheckResult {
	results := make([]CheckResult, 0, 3)

	// The Point and Print registry path
	pnpPath := `SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`

	Endpoint.Say("[*] Checking Point and Print restrictions...")
	LogMessage("INFO", "PointAndPrint", fmt.Sprintf("Checking registry: HKLM\\%s", pnpPath))

	// Open the registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, pnpPath, registry.QUERY_VALUE)
	keyExists := err == nil
	if keyExists {
		defer key.Close()
	}

	// Check 1: NoWarningNoElevationOnInstall
	result1 := CheckResult{
		Name:        "NoWarningNoElevationOnInstall",
		Description: "Prevents silent driver installation without UAC",
		Expected:    "0 (or not configured)",
		Skipped:     informationalOnly,
	}

	if !keyExists {
		result1.Value = "Not configured"
		result1.Compliant = true // Not configured = secure default
		result1.Details = "Point and Print policy key does not exist - using secure defaults"
		Endpoint.Say("    [+] NoWarningNoElevationOnInstall: Not configured (secure)")
		LogMessage("INFO", "PointAndPrint", "NoWarningNoElevationOnInstall not configured - secure default")
	} else {
		value, _, err := key.GetIntegerValue("NoWarningNoElevationOnInstall")
		if err != nil {
			result1.Value = "Not configured"
			result1.Compliant = true
			result1.Details = "Value not present - using secure default"
			Endpoint.Say("    [+] NoWarningNoElevationOnInstall: Not configured (secure)")
			LogMessage("INFO", "PointAndPrint", "NoWarningNoElevationOnInstall not configured")
		} else {
			result1.Value = fmt.Sprintf("%d", value)
			if value == 0 {
				result1.Compliant = true
				result1.Details = "Value is 0 - UAC elevation required"
				Endpoint.Say("    [+] NoWarningNoElevationOnInstall = %d (secure)", value)
				LogMessage("SUCCESS", "PointAndPrint", "NoWarningNoElevationOnInstall is secure (0)")
			} else {
				result1.Compliant = false
				result1.Details = fmt.Sprintf("Value is %d - allows silent installation without UAC (DANGEROUS)", value)
				Endpoint.Say("    [-] NoWarningNoElevationOnInstall = %d (INSECURE)", value)
				LogMessage("WARNING", "PointAndPrint", fmt.Sprintf("NoWarningNoElevationOnInstall is insecure (%d)", value))
			}
		}
	}
	results = append(results, result1)

	// Check 2: UpdatePromptSettings
	result2 := CheckResult{
		Name:        "UpdatePromptSettings",
		Description: "Controls driver update prompts",
		Expected:    "0 (or not configured)",
		Skipped:     informationalOnly,
	}

	if !keyExists {
		result2.Value = "Not configured"
		result2.Compliant = true
		result2.Details = "Point and Print policy key does not exist - using secure defaults"
		Endpoint.Say("    [+] UpdatePromptSettings: Not configured (secure)")
		LogMessage("INFO", "PointAndPrint", "UpdatePromptSettings not configured - secure default")
	} else {
		value, _, err := key.GetIntegerValue("UpdatePromptSettings")
		if err != nil {
			result2.Value = "Not configured"
			result2.Compliant = true
			result2.Details = "Value not present - using secure default"
			Endpoint.Say("    [+] UpdatePromptSettings: Not configured (secure)")
			LogMessage("INFO", "PointAndPrint", "UpdatePromptSettings not configured")
		} else {
			result2.Value = fmt.Sprintf("%d", value)
			if value == 0 {
				result2.Compliant = true
				result2.Details = "Value is 0 - prompts for updates"
				Endpoint.Say("    [+] UpdatePromptSettings = %d (secure)", value)
				LogMessage("SUCCESS", "PointAndPrint", "UpdatePromptSettings is secure (0)")
			} else {
				result2.Compliant = false
				result2.Details = fmt.Sprintf("Value is %d - allows silent updates (DANGEROUS)", value)
				Endpoint.Say("    [-] UpdatePromptSettings = %d (INSECURE)", value)
				LogMessage("WARNING", "PointAndPrint", fmt.Sprintf("UpdatePromptSettings is insecure (%d)", value))
			}
		}
	}
	results = append(results, result2)

	// Check 3: RestrictDriverInstallationToAdministrators
	result3 := CheckResult{
		Name:        "RestrictDriverInstallationToAdministrators",
		Description: "Limits driver installation to admins only",
		Expected:    "1",
		Skipped:     informationalOnly,
	}

	if !keyExists {
		result3.Value = "Not configured"
		result3.Compliant = true // Windows default after July 2021 patches
		result3.Details = "Not configured - Windows default is now secure (post-July 2021)"
		Endpoint.Say("    [+] RestrictDriverInstallationToAdministrators: Not configured (default secure)")
		LogMessage("INFO", "PointAndPrint", "RestrictDriverInstallationToAdministrators not configured - using secure Windows default")
	} else {
		value, _, err := key.GetIntegerValue("RestrictDriverInstallationToAdministrators")
		if err != nil {
			result3.Value = "Not configured"
			result3.Compliant = true
			result3.Details = "Value not present - using secure Windows default"
			Endpoint.Say("    [+] RestrictDriverInstallationToAdministrators: Not configured (default secure)")
			LogMessage("INFO", "PointAndPrint", "RestrictDriverInstallationToAdministrators not configured")
		} else {
			result3.Value = fmt.Sprintf("%d", value)
			if value == 1 {
				result3.Compliant = true
				result3.Details = "Value is 1 - only administrators can install drivers"
				Endpoint.Say("    [+] RestrictDriverInstallationToAdministrators = %d (secure)", value)
				LogMessage("SUCCESS", "PointAndPrint", "RestrictDriverInstallationToAdministrators is secure (1)")
			} else {
				result3.Compliant = false
				result3.Details = fmt.Sprintf("Value is %d - non-admins can install drivers (DANGEROUS)", value)
				Endpoint.Say("    [-] RestrictDriverInstallationToAdministrators = %d (INSECURE)", value)
				LogMessage("WARNING", "PointAndPrint", fmt.Sprintf("RestrictDriverInstallationToAdministrators is insecure (%d)", value))
			}
		}
	}
	results = append(results, result3)

	return results
}

// isDomainController checks if this machine is a Domain Controller
func isDomainController() bool {
	LogMessage("INFO", "DomainController", "Checking if system is a Domain Controller")

	// Method 1: Check for NTDS service
	cmd := exec.Command("sc", "query", "NTDS")
	err := cmd.Run()
	if err == nil {
		LogMessage("INFO", "DomainController", "NTDS service found - this is a Domain Controller")
		return true
	}

	// Method 2: Check registry for ProductType
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		productType, _, err := key.GetStringValue("ProductType")
		if err == nil {
			LogMessage("INFO", "DomainController", fmt.Sprintf("ProductType: %s", productType))
			if strings.EqualFold(productType, "LanmanNT") {
				return true
			}
		}
	}

	return false
}

// getStartTypeName returns the human-readable name for a service start type
func getStartTypeName(startType int) string {
	switch startType {
	case SERVICE_START_BOOT:
		return "Boot"
	case SERVICE_START_SYSTEM:
		return "System"
	case SERVICE_START_AUTO:
		return "Automatic"
	case SERVICE_START_MANUAL:
		return "Manual"
	case SERVICE_START_DISABLED:
		return "Disabled"
	default:
		return "Unknown"
	}
}

// saveServiceQueryOutput saves the sc query output for debugging
func saveServiceQueryOutput(stdout, stderr string) {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	outputPath := filepath.Join(targetDir, "spooler_service_output.txt")
	content := fmt.Sprintf("=== Print Spooler Service Query Output ===\n\nSTDOUT:\n%s\n\nSTDERR:\n%s\n", stdout, stderr)

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		LogMessage("WARNING", "SpoolerService", fmt.Sprintf("Failed to save output: %v", err))
	} else {
		LogMessage("INFO", "SpoolerService", fmt.Sprintf("Output saved to: %s", outputPath))
	}
}

// showRemediation shows specific remediation steps for a failed check
func showRemediation(checkName string) {
	switch checkName {
	case "NoWarningNoElevationOnInstall":
		Endpoint.Say("      Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Value 0 -Type DWord")
	case "UpdatePromptSettings":
		Endpoint.Say("      Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name 'UpdatePromptSettings' -Value 0 -Type DWord")
	case "RestrictDriverInstallationToAdministrators":
		Endpoint.Say("      Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Type DWord")
	}
}

// logCheckResult logs a check result to the structured log
func logCheckResult(phaseNum int, result CheckResult) {
	LogMessage("INFO", result.Name, fmt.Sprintf("Check: %s", result.Description))
	LogMessage("INFO", result.Name, fmt.Sprintf("Expected: %s", result.Expected))
	LogMessage("INFO", result.Name, fmt.Sprintf("Actual: %s", result.Value))
	LogMessage("INFO", result.Name, fmt.Sprintf("Compliant: %v (Skipped: %v)", result.Compliant, result.Skipped))
	LogMessage("INFO", result.Name, fmt.Sprintf("Details: %s", result.Details))
}

// printCheckSummary prints a formatted check summary
func printCheckSummary(name string, result CheckResult) {
	status := "FAIL"
	if result.Compliant {
		status = "PASS"
	}
	if result.Skipped {
		status = "SKIP"
	}
	Endpoint.Say("[%s] %-50s Value: %s", status, name, result.Value)
}

// main is the entry point
func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("  F0RT1KA CYBER HYGIENE TEST: Print Spooler Hardening Validator")
	Endpoint.Say("  Test ID: %s", TEST_UUID)
	Endpoint.Say("================================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("This is a READ-ONLY configuration validation test.")
	Endpoint.Say("")
	Endpoint.Say("CVE Reference: CVE-2021-34527 (PrintNightmare)")
	Endpoint.Say("CISA Directive: Emergency Directive 21-04")
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
