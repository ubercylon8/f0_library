//go:build windows
// +build windows

/*
ID: 19d1d49c-d278-41a3-bfad-8bb318bdde45
NAME: Windows Audit Logging Configuration Validator
TECHNIQUES: T1070.001, T1562.002
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: audit-logging, event-log, detection, cis-controls, nsa-top10
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID = "19d1d49c-d278-41a3-bfad-8bb318bdde45"
	TEST_NAME = "Windows Audit Logging Configuration Validator"
)

// AuditCheck represents a single audit policy check
type AuditCheck struct {
	Name             string
	Subcategory      string
	RequiredSettings []string // "Success", "Failure", or both
	CISReference     string
	Description      string
}

// AuditCheckResult stores the result of an audit check
type AuditCheckResult struct {
	Check         AuditCheck
	CurrentValue  string
	Compliant     bool
	Details       string
}

// Define all required audit checks per NSA/CISA Top 10 and CIS Benchmarks
var auditChecks = []AuditCheck{
	{
		Name:             "Credential Validation",
		Subcategory:      "Credential Validation",
		RequiredSettings: []string{"Success", "Failure"},
		CISReference:     "17.1.1",
		Description:      "Audit credential validation for detecting brute force attacks and invalid credentials",
	},
	{
		Name:             "Security Group Management",
		Subcategory:      "Security Group Management",
		RequiredSettings: []string{"Success"},
		CISReference:     "17.2.5",
		Description:      "Audit security group changes for detecting unauthorized privilege escalation",
	},
	{
		Name:             "User Account Management",
		Subcategory:      "User Account Management",
		RequiredSettings: []string{"Success", "Failure"},
		CISReference:     "17.2.6",
		Description:      "Audit user account changes for detecting unauthorized account creation/modification",
	},
	{
		Name:             "Logon",
		Subcategory:      "Logon",
		RequiredSettings: []string{"Success", "Failure"},
		CISReference:     "17.5.1",
		Description:      "Audit logon events for detecting unauthorized access attempts",
	},
	{
		Name:             "Special Logon",
		Subcategory:      "Special Logon",
		RequiredSettings: []string{"Success"},
		CISReference:     "17.5.6",
		Description:      "Audit special logon events (admin privileges assigned) for privilege escalation detection",
	},
	{
		Name:             "Sensitive Privilege Use",
		Subcategory:      "Sensitive Privilege Use",
		RequiredSettings: []string{"Success", "Failure"},
		CISReference:     "17.7.1",
		Description:      "Audit sensitive privilege use for detecting abuse of high-privilege operations",
	},
	{
		Name:             "Security State Change",
		Subcategory:      "Security State Change",
		RequiredSettings: []string{"Success"},
		CISReference:     "17.7.3",
		Description:      "Audit security state changes for detecting system security modifications",
	},
	{
		Name:             "Process Creation",
		Subcategory:      "Process Creation",
		RequiredSettings: []string{"Success"},
		CISReference:     "17.8.1",
		Description:      "Audit process creation for detecting malware execution and suspicious processes",
	},
}

// Check if running as administrator
func checkAdminPrivileges() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// Get all audit policy settings in one call
func getAuditPolicyOutput() (string, error) {
	cmd := exec.Command("auditpol", "/get", "/category:*")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute auditpol: %v", err)
	}
	return string(output), nil
}

// Parse audit policy output to find a specific subcategory setting
func parseSubcategorySetting(auditOutput, subcategory string) string {
	lines := strings.Split(auditOutput, "\n")

	// Build regex pattern to match the subcategory line
	// Format: "  Subcategory Name                      Setting"
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Check if this line contains our subcategory
		if strings.Contains(trimmedLine, subcategory) {
			// Extract the setting (last word/phrase on the line)
			// Settings are: "Success", "Failure", "Success and Failure", "No Auditing"

			// Use regex to extract the setting portion
			// The setting comes after the subcategory name and spaces
			pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(subcategory) + `\s+(.+)$`)
			matches := pattern.FindStringSubmatch(trimmedLine)
			if len(matches) > 1 {
				return strings.TrimSpace(matches[1])
			}
		}
	}

	return "Not Found"
}

// Check if the current setting meets the required settings
func isCompliant(currentSetting string, requiredSettings []string) bool {
	currentLower := strings.ToLower(currentSetting)

	// "No Auditing" never meets any requirement
	if strings.Contains(currentLower, "no auditing") {
		return false
	}

	// "Success and Failure" meets all requirements
	if strings.Contains(currentLower, "success and failure") {
		return true
	}

	// Check if we need both Success and Failure
	needsSuccess := false
	needsFailure := false
	for _, req := range requiredSettings {
		if strings.EqualFold(req, "Success") {
			needsSuccess = true
		}
		if strings.EqualFold(req, "Failure") {
			needsFailure = true
		}
	}

	// If we need both but only have one, fail
	if needsSuccess && needsFailure {
		return strings.Contains(currentLower, "success and failure")
	}

	// Check for individual settings
	if needsSuccess && strings.Contains(currentLower, "success") {
		return true
	}
	if needsFailure && strings.Contains(currentLower, "failure") {
		return true
	}

	return false
}

// Check command line auditing registry setting
func checkCommandLineAuditing() (bool, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`,
		registry.QUERY_VALUE)
	if err != nil {
		// Key doesn't exist - not configured
		return false, "Registry key not found (not configured)"
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("ProcessCreationIncludeCmdLine_Enabled")
	if err != nil {
		return false, "Registry value not found (not configured)"
	}

	if value == 1 {
		return true, "Enabled (value = 1)"
	}
	return false, fmt.Sprintf("Disabled (value = %d)", value)
}

func test() {
	// Initialize comprehensive logger with Schema v2.0
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "cyber_hygiene",
		Severity:   "high",
		Techniques: []string{}, // Defensive test - enables detection of attack techniques
		Tactics:    []string{}, // Defensive test
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Validates actual production security settings
			TechnicalSophistication: 2.0, // Uses auditpol and registry queries
			SafetyMechanisms:        2.0, // Read-only, no system modifications
			DetectionOpportunities:  0.5, // N/A for config validation
			LoggingObservability:    1.0, // Comprehensive logging
		},
		Tags: []string{"cyber-hygiene", "audit-logging", "compliance", "cis-benchmark", "nsa-cisa"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         60000, // 1 minute timeout
			CertificateMode:   "none", // No certificate needed for read-only test
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

	// Phase 0: Pre-flight Checks
	LogPhaseStart(0, "Pre-flight Checks")
	Endpoint.Say("=" + strings.Repeat("=", 70))
	Endpoint.Say("Windows Audit Logging Configuration Validator")
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=" + strings.Repeat("=", 70))
	Endpoint.Say("")

	// Check for admin privileges
	Endpoint.Say("[*] Checking administrator privileges...")
	if !checkAdminPrivileges() {
		Endpoint.Say("[-] ERROR: This test requires administrator privileges")
		Endpoint.Say("    auditpol command requires elevated access")
		LogMessage("ERROR", "Pre-flight", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Not running as administrator")
		SaveLog(999, "Administrator privileges required")
		Endpoint.Stop(999)
	}
	Endpoint.Say("[+] Running with administrator privileges")
	LogMessage("INFO", "Pre-flight", "Administrator privileges confirmed")
	LogPhaseEnd(0, "success", "Pre-flight checks passed")

	// Phase 1: Retrieve Audit Policy
	LogPhaseStart(1, "Audit Policy Retrieval")
	Endpoint.Say("")
	Endpoint.Say("[*] Retrieving Windows audit policy configuration...")

	auditOutput, err := getAuditPolicyOutput()
	if err != nil {
		Endpoint.Say("[-] ERROR: Failed to retrieve audit policy: %v", err)
		LogMessage("ERROR", "Audit Policy", fmt.Sprintf("Failed to retrieve: %v", err))
		LogPhaseEnd(1, "failed", fmt.Sprintf("auditpol failed: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to retrieve audit policy: %v", err))
		Endpoint.Stop(999)
	}

	Endpoint.Say("[+] Successfully retrieved audit policy")
	LogMessage("INFO", "Audit Policy", "Retrieved audit policy output")
	LogPhaseEnd(1, "success", "Audit policy retrieved successfully")

	// Phase 2: Validate Audit Subcategories
	LogPhaseStart(2, "Audit Subcategory Validation")
	Endpoint.Say("")
	Endpoint.Say("[*] Validating %d audit subcategories...", len(auditChecks))
	Endpoint.Say("")

	var results []AuditCheckResult
	passCount := 0
	failCount := 0

	for _, check := range auditChecks {
		currentSetting := parseSubcategorySetting(auditOutput, check.Subcategory)
		compliant := isCompliant(currentSetting, check.RequiredSettings)

		requiredStr := strings.Join(check.RequiredSettings, " and ")

		result := AuditCheckResult{
			Check:        check,
			CurrentValue: currentSetting,
			Compliant:    compliant,
		}

		if compliant {
			result.Details = "COMPLIANT"
			passCount++
			Endpoint.Say("  [PASS] %s", check.Name)
			Endpoint.Say("         Required: %s | Current: %s", requiredStr, currentSetting)
			LogMessage("SUCCESS", "Audit Check", fmt.Sprintf("%s: COMPLIANT (Required: %s, Current: %s)",
				check.Name, requiredStr, currentSetting))
		} else {
			result.Details = "NON-COMPLIANT"
			failCount++
			Endpoint.Say("  [FAIL] %s", check.Name)
			Endpoint.Say("         Required: %s | Current: %s", requiredStr, currentSetting)
			Endpoint.Say("         CIS Ref: %s - %s", check.CISReference, check.Description)
			LogMessage("ERROR", "Audit Check", fmt.Sprintf("%s: NON-COMPLIANT (Required: %s, Current: %s, CIS: %s)",
				check.Name, requiredStr, currentSetting, check.CISReference))
		}

		results = append(results, result)
	}

	Endpoint.Say("")
	LogPhaseEnd(2, "success", fmt.Sprintf("Validated %d subcategories: %d pass, %d fail",
		len(auditChecks), passCount, failCount))

	// Phase 3: Validate Command Line Auditing
	LogPhaseStart(3, "Command Line Auditing Validation")
	Endpoint.Say("[*] Checking Process Creation Command Line auditing...")

	cmdLineEnabled, cmdLineDetails := checkCommandLineAuditing()

	if cmdLineEnabled {
		passCount++
		Endpoint.Say("  [PASS] Command Line Auditing")
		Endpoint.Say("         Registry: ProcessCreationIncludeCmdLine_Enabled = 1")
		LogMessage("SUCCESS", "Command Line Audit", fmt.Sprintf("COMPLIANT: %s", cmdLineDetails))
	} else {
		failCount++
		Endpoint.Say("  [FAIL] Command Line Auditing")
		Endpoint.Say("         Status: %s", cmdLineDetails)
		Endpoint.Say("         CIS Ref: 17.9.1 - Required for complete process forensics")
		LogMessage("ERROR", "Command Line Audit", fmt.Sprintf("NON-COMPLIANT: %s (CIS 17.9.1)", cmdLineDetails))
	}

	Endpoint.Say("")
	LogPhaseEnd(3, "success", fmt.Sprintf("Command line auditing: %s", cmdLineDetails))

	// Phase 4: Results Summary
	LogPhaseStart(4, "Results Summary")

	totalChecks := len(auditChecks) + 1 // +1 for command line auditing
	Endpoint.Say("=" + strings.Repeat("=", 70))
	Endpoint.Say("AUDIT LOGGING VALIDATION SUMMARY")
	Endpoint.Say("=" + strings.Repeat("=", 70))
	Endpoint.Say("")
	Endpoint.Say("  Total Checks:      %d", totalChecks)
	Endpoint.Say("  Compliant:         %d", passCount)
	Endpoint.Say("  Non-Compliant:     %d", failCount)
	Endpoint.Say("  Compliance Rate:   %.1f%%", float64(passCount)/float64(totalChecks)*100)
	Endpoint.Say("")

	LogMessage("INFO", "Summary", fmt.Sprintf("Total: %d, Compliant: %d, Non-Compliant: %d, Rate: %.1f%%",
		totalChecks, passCount, failCount, float64(passCount)/float64(totalChecks)*100))

	// Determine final result
	if failCount == 0 {
		// All checks passed - COMPLIANT
		Endpoint.Say("  RESULT: ALL AUDIT LOGGING PROPERLY CONFIGURED")
		Endpoint.Say("")
		Endpoint.Say("  The system has all required audit logging categories enabled")
		Endpoint.Say("  per NSA/CISA Top 10 and CIS Benchmark recommendations.")
		Endpoint.Say("")
		Endpoint.Say("=" + strings.Repeat("=", 70))

		LogPhaseEnd(4, "success", "All audit logging checks passed")
		LogMessage("SUCCESS", "Final Result", "COMPLIANT - All 9 audit categories properly configured")
		SaveLog(126, "All audit logging properly configured - COMPLIANT")
		Endpoint.Stop(126)
	} else {
		// Some checks failed - NON-COMPLIANT
		Endpoint.Say("  RESULT: AUDIT LOGGING MISCONFIGURATION DETECTED")
		Endpoint.Say("")
		Endpoint.Say("  %d audit category/categories not properly configured.", failCount)
		Endpoint.Say("  This creates visibility gaps for incident detection and forensics.")
		Endpoint.Say("")
		Endpoint.Say("  REMEDIATION:")
		Endpoint.Say("  Configure via GPO: Computer Configuration > Windows Settings >")
		Endpoint.Say("  Security Settings > Advanced Audit Policy Configuration > Audit Policies")
		Endpoint.Say("")
		Endpoint.Say("  Or use auditpol commands:")

		// Show remediation commands for failed checks
		for _, result := range results {
			if !result.Compliant {
				requiredStr := strings.Join(result.Check.RequiredSettings, ",")
				Endpoint.Say("    auditpol /set /subcategory:\"%s\" /%s:enable",
					result.Check.Subcategory, strings.ToLower(strings.Replace(requiredStr, " and ", " /", -1)))
			}
		}

		if !cmdLineEnabled {
			Endpoint.Say("    reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f")
		}

		Endpoint.Say("")
		Endpoint.Say("=" + strings.Repeat("=", 70))

		LogPhaseEnd(4, "failed", fmt.Sprintf("%d audit logging checks failed", failCount))
		LogMessage("ERROR", "Final Result", fmt.Sprintf("NON-COMPLIANT - %d of %d checks failed", failCount, totalChecks))
		SaveLog(101, fmt.Sprintf("Audit logging misconfiguration - %d checks failed", failCount))
		Endpoint.Stop(101)
	}
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("")

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// 1 minute timeout for this read-only test
	timeout := 1 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test completed successfully")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(102, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(102)
	}
}
