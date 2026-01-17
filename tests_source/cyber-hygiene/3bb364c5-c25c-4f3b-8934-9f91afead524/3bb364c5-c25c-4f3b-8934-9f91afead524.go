//go:build windows
// +build windows

/*
ID: 3bb364c5-c25c-4f3b-8934-9f91afead524
NAME: Account Lockout and Password Policy Validator
TECHNIQUES: T1110, T1110.001, T1110.003
TACTICS: credential-access
SEVERITY: high
TARGET: windows-endpoint, active-directory
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: password-policy, account-lockout, brute-force-prevention, cis-controls
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "3bb364c5-c25c-4f3b-8934-9f91afead524"
	TEST_NAME = "Account Lockout and Password Policy Validator"
)

// CIS Level 1 compliant thresholds
const (
	MAX_LOCKOUT_THRESHOLD     = 5    // 1-5 attempts is compliant, 0 is disabled (fail)
	MIN_LOCKOUT_DURATION      = 15   // >= 15 minutes
	MIN_RESET_COUNTER         = 15   // >= 15 minutes
	MIN_PASSWORD_LENGTH       = 14   // >= 14 characters
	PASSWORD_COMPLEXITY_REQ   = true // Must be enabled
)

// PolicyResult holds the result of a single policy check
type PolicyResult struct {
	Name        string
	Value       interface{}
	Threshold   string
	Compliant   bool
	Method      string
	Description string
}

// PolicyValidationResults holds all policy validation results
type PolicyValidationResults struct {
	LockoutThreshold  PolicyResult
	LockoutDuration   PolicyResult
	ResetCounterAfter PolicyResult
	MinPasswordLength PolicyResult
	PasswordComplexity PolicyResult
	AllCompliant      bool
	TotalChecks       int
	PassedChecks      int
	FailedChecks      int
}

// ==============================================================================
// MAIN FUNCTION
// ==============================================================================

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Cyber Hygiene Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0 metadata
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "cyber_hygiene",
		Severity:   "high",
		Techniques: []string{"T1110", "T1110.001", "T1110.003"},
		Tactics:    []string{"credential-access"},
		Score:      7.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.0,
			TechnicalSophistication: 1.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cyber-hygiene", "password-policy", "account-lockout", "cis-benchmark", "brute-force-prevention"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	// Define execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         60000, // 1 minute
			CertificateMode:   "none", // Read-only test, no cert needed
			MultiStageEnabled: false,
		},
	}

	// Initialize logger
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(999)
		}
	}()

	// Run the test
	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	// Phase 1: Pre-flight checks
	LogPhaseStart(0, "Pre-flight Checks")
	Endpoint.Say("[*] Phase 1: Pre-flight Checks")

	// Verify admin privileges (required to run net accounts)
	if !isAdmin() {
		LogMessage("ERROR", "Pre-flight", "Administrator privileges required to query account policies")
		LogPhaseEnd(0, "failed", "Administrator privileges required")
		Endpoint.Say("")
		Endpoint.Say("ERROR: Administrator privileges required")
		Endpoint.Say("Please run this test as Administrator")
		Endpoint.Say("")
		SaveLog(999, "Administrator privileges required to query account policies")
		Endpoint.Stop(999)
	}

	LogMessage("INFO", "Pre-flight", "Running with administrator privileges")
	LogPhaseEnd(0, "success", "Pre-flight checks passed")
	Endpoint.Say("    [+] Administrator privileges confirmed")
	Endpoint.Say("")

	// Phase 2: Query account policies
	LogPhaseStart(1, "Query Account Policies")
	Endpoint.Say("[*] Phase 2: Querying Account Policies")

	results, err := validateAccountPolicies()
	if err != nil {
		LogMessage("ERROR", "Policy Query", fmt.Sprintf("Failed to query policies: %v", err))
		LogPhaseEnd(1, "failed", fmt.Sprintf("Policy query failed: %v", err))
		Endpoint.Say("")
		Endpoint.Say("ERROR: Failed to query account policies: %v", err)
		Endpoint.Say("")
		SaveLog(999, fmt.Sprintf("Failed to query account policies: %v", err))
		Endpoint.Stop(999)
	}

	LogPhaseEnd(1, "success", "Account policies queried successfully")
	Endpoint.Say("    [+] Account policies retrieved successfully")
	Endpoint.Say("")

	// Phase 3: Display results
	LogPhaseStart(2, "Policy Evaluation")
	Endpoint.Say("[*] Phase 3: Policy Evaluation Results")
	Endpoint.Say("")

	displayPolicyResults(results)
	logPolicyResults(results)

	LogPhaseEnd(2, "success", fmt.Sprintf("Evaluated %d policies: %d passed, %d failed",
		results.TotalChecks, results.PassedChecks, results.FailedChecks))

	// Phase 4: Determine outcome
	LogPhaseStart(3, "Final Evaluation")
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	if results.AllCompliant {
		// All checks passed - system is compliant (PROTECTED against brute force)
		LogPhaseEnd(3, "success", "All policy checks passed - CIS Level 1 compliant")

		Endpoint.Say("RESULT: COMPLIANT (Protected)")
		Endpoint.Say("")
		Endpoint.Say("All 5 account policy checks passed CIS Level 1 benchmarks:")
		Endpoint.Say("  + Lockout Threshold: %v (max 5 attempts)", results.LockoutThreshold.Value)
		Endpoint.Say("  + Lockout Duration: %v minutes (min 15)", results.LockoutDuration.Value)
		Endpoint.Say("  + Reset Counter After: %v minutes (min 15)", results.ResetCounterAfter.Value)
		Endpoint.Say("  + Minimum Password Length: %v characters (min 14)", results.MinPasswordLength.Value)
		Endpoint.Say("  + Password Complexity: %v (required)", results.PasswordComplexity.Value)
		Endpoint.Say("")
		Endpoint.Say("The system is protected against brute force attacks.")
		Endpoint.Say("Microsoft blocks 7,000 password attacks per second - proper")
		Endpoint.Say("account lockout policies are essential for defense.")
		Endpoint.Say("")
		Endpoint.Say("CIS Benchmark References:")
		Endpoint.Say("  - 1.1.1: Enforce password history")
		Endpoint.Say("  - 1.1.4: Minimum password length")
		Endpoint.Say("  - 1.1.5: Password complexity requirements")
		Endpoint.Say("  - 1.2.1: Account lockout duration")
		Endpoint.Say("  - 1.2.2: Account lockout threshold")
		Endpoint.Say("  - 1.2.3: Reset account lockout counter")
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(126, "All 5 CIS Level 1 policy checks passed - system is protected against brute force attacks")
		Endpoint.Stop(126) // ExecutionPrevented = policy is blocking attack vector

	} else {
		// One or more checks failed - system is non-compliant (VULNERABLE)
		LogPhaseEnd(3, "failed", fmt.Sprintf("%d policy checks failed - non-compliant", results.FailedChecks))

		Endpoint.Say("RESULT: NON-COMPLIANT (Vulnerable)")
		Endpoint.Say("")
		Endpoint.Say("Policy Failures Detected (%d of %d failed):", results.FailedChecks, results.TotalChecks)
		Endpoint.Say("")

		if !results.LockoutThreshold.Compliant {
			Endpoint.Say("  FAIL - Lockout Threshold: %v (should be 1-5)", results.LockoutThreshold.Value)
			if results.LockoutThreshold.Value == 0 {
				Endpoint.Say("         CRITICAL: Lockout is DISABLED (0 = never lock out)")
			}
		}
		if !results.LockoutDuration.Compliant {
			Endpoint.Say("  FAIL - Lockout Duration: %v min (should be >= 15)", results.LockoutDuration.Value)
		}
		if !results.ResetCounterAfter.Compliant {
			Endpoint.Say("  FAIL - Reset Counter After: %v min (should be >= 15)", results.ResetCounterAfter.Value)
		}
		if !results.MinPasswordLength.Compliant {
			Endpoint.Say("  FAIL - Min Password Length: %v chars (should be >= 14)", results.MinPasswordLength.Value)
		}
		if !results.PasswordComplexity.Compliant {
			Endpoint.Say("  FAIL - Password Complexity: %v (should be Enabled)", results.PasswordComplexity.Value)
		}

		Endpoint.Say("")
		Endpoint.Say("SECURITY RISK:")
		Endpoint.Say("  These settings leave the system vulnerable to:")
		Endpoint.Say("  - Brute force password attacks (T1110)")
		Endpoint.Say("  - Password guessing (T1110.001)")
		Endpoint.Say("  - Password spraying (T1110.003)")
		Endpoint.Say("")
		Endpoint.Say("RECOMMENDED REMEDIATION:")
		Endpoint.Say("  Run the following commands as Administrator:")
		Endpoint.Say("")
		Endpoint.Say("  net accounts /lockoutthreshold:5")
		Endpoint.Say("  net accounts /lockoutduration:15")
		Endpoint.Say("  net accounts /lockoutwindow:15")
		Endpoint.Say("  net accounts /minpwlen:14")
		Endpoint.Say("")
		Endpoint.Say("  For password complexity, use Group Policy:")
		Endpoint.Say("  Computer Configuration > Windows Settings > Security Settings")
		Endpoint.Say("  > Account Policies > Password Policy > Password must meet complexity")
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(101, fmt.Sprintf("%d of %d CIS Level 1 policy checks failed - system is vulnerable to brute force attacks", results.FailedChecks, results.TotalChecks))
		Endpoint.Stop(101) // Unprotected = attack vector is open
	}
}

// ==============================================================================
// POLICY VALIDATION FUNCTIONS
// ==============================================================================

// validateAccountPolicies queries and validates all account policies
func validateAccountPolicies() (*PolicyValidationResults, error) {
	results := &PolicyValidationResults{
		TotalChecks: 5,
	}

	// Run 'net accounts' command to get policy settings
	Endpoint.Say("    Executing: net accounts")
	cmd := exec.Command("net", "accounts")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("net accounts command failed: %v", err)
	}

	netAccountsOutput := string(output)
	LogMessage("DEBUG", "Policy Query", fmt.Sprintf("net accounts output:\n%s", netAccountsOutput))

	// Parse the output
	settings := parseNetAccountsOutput(netAccountsOutput)

	// Log what we parsed
	Endpoint.Say("    Parsed values from net accounts:")

	// 1. Lockout Threshold
	lockoutThreshold := settings["lockoutthreshold"]
	results.LockoutThreshold = PolicyResult{
		Name:        "Account Lockout Threshold",
		Value:       lockoutThreshold,
		Threshold:   "1-5 attempts (0 = disabled = FAIL)",
		Method:      "net accounts",
		Description: "Number of failed attempts before account lockout",
	}
	// Compliant if 1-5, non-compliant if 0 (disabled) or > 5
	if lockoutThreshold >= 1 && lockoutThreshold <= MAX_LOCKOUT_THRESHOLD {
		results.LockoutThreshold.Compliant = true
		results.PassedChecks++
	} else {
		results.LockoutThreshold.Compliant = false
		results.FailedChecks++
	}
	Endpoint.Say("      - Lockout Threshold: %d", lockoutThreshold)

	// 2. Lockout Duration
	lockoutDuration := settings["lockoutduration"]
	results.LockoutDuration = PolicyResult{
		Name:        "Account Lockout Duration",
		Value:       lockoutDuration,
		Threshold:   fmt.Sprintf(">= %d minutes", MIN_LOCKOUT_DURATION),
		Method:      "net accounts",
		Description: "How long account remains locked",
	}
	if lockoutDuration >= MIN_LOCKOUT_DURATION {
		results.LockoutDuration.Compliant = true
		results.PassedChecks++
	} else {
		results.LockoutDuration.Compliant = false
		results.FailedChecks++
	}
	Endpoint.Say("      - Lockout Duration: %d minutes", lockoutDuration)

	// 3. Reset Counter After (Lockout Observation Window)
	resetCounter := settings["resetcounter"]
	results.ResetCounterAfter = PolicyResult{
		Name:        "Reset Account Lockout Counter After",
		Value:       resetCounter,
		Threshold:   fmt.Sprintf(">= %d minutes", MIN_RESET_COUNTER),
		Method:      "net accounts",
		Description: "Time before failed attempt counter resets",
	}
	if resetCounter >= MIN_RESET_COUNTER {
		results.ResetCounterAfter.Compliant = true
		results.PassedChecks++
	} else {
		results.ResetCounterAfter.Compliant = false
		results.FailedChecks++
	}
	Endpoint.Say("      - Reset Counter After: %d minutes", resetCounter)

	// 4. Minimum Password Length
	minPwLen := settings["minpwlen"]
	results.MinPasswordLength = PolicyResult{
		Name:        "Minimum Password Length",
		Value:       minPwLen,
		Threshold:   fmt.Sprintf(">= %d characters", MIN_PASSWORD_LENGTH),
		Method:      "net accounts",
		Description: "Minimum required password length",
	}
	if minPwLen >= MIN_PASSWORD_LENGTH {
		results.MinPasswordLength.Compliant = true
		results.PassedChecks++
	} else {
		results.MinPasswordLength.Compliant = false
		results.FailedChecks++
	}
	Endpoint.Say("      - Minimum Password Length: %d characters", minPwLen)

	// 5. Password Complexity - requires secedit export
	complexity, complexityErr := checkPasswordComplexity()
	complexityStatus := "Unknown"
	if complexityErr != nil {
		LogMessage("WARN", "Policy Query", fmt.Sprintf("Could not check password complexity: %v", complexityErr))
		complexityStatus = "Unknown (query failed)"
		results.PasswordComplexity = PolicyResult{
			Name:        "Password Complexity",
			Value:       complexityStatus,
			Threshold:   "Enabled",
			Compliant:   false, // Assume non-compliant if we can't check
			Method:      "secedit",
			Description: "Password must meet complexity requirements",
		}
		results.FailedChecks++
	} else {
		if complexity {
			complexityStatus = "Enabled"
			results.PasswordComplexity = PolicyResult{
				Name:        "Password Complexity",
				Value:       complexityStatus,
				Threshold:   "Enabled",
				Compliant:   true,
				Method:      "secedit",
				Description: "Password must meet complexity requirements",
			}
			results.PassedChecks++
		} else {
			complexityStatus = "Disabled"
			results.PasswordComplexity = PolicyResult{
				Name:        "Password Complexity",
				Value:       complexityStatus,
				Threshold:   "Enabled",
				Compliant:   false,
				Method:      "secedit",
				Description: "Password must meet complexity requirements",
			}
			results.FailedChecks++
		}
	}
	Endpoint.Say("      - Password Complexity: %s", complexityStatus)

	// Determine overall compliance
	results.AllCompliant = results.FailedChecks == 0

	return results, nil
}

// parseNetAccountsOutput parses the output of 'net accounts' command
func parseNetAccountsOutput(output string) map[string]int {
	settings := make(map[string]int)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse each relevant line
		if strings.Contains(line, "Lockout threshold") {
			// Lockout threshold:                                    5
			// or "Never" for disabled
			value := extractIntValue(line)
			settings["lockoutthreshold"] = value
		} else if strings.Contains(line, "Lockout duration") {
			// Lockout duration (minutes):                          15
			value := extractIntValue(line)
			settings["lockoutduration"] = value
		} else if strings.Contains(line, "Lockout observation window") {
			// Lockout observation window (minutes):                15
			value := extractIntValue(line)
			settings["resetcounter"] = value
		} else if strings.Contains(line, "Minimum password length") {
			// Minimum password length:                             14
			value := extractIntValue(line)
			settings["minpwlen"] = value
		}
	}

	return settings
}

// extractIntValue extracts an integer value from a net accounts output line
func extractIntValue(line string) int {
	// Handle "Never" case (for lockout threshold disabled)
	if strings.Contains(strings.ToLower(line), "never") {
		return 0 // Never = disabled = 0
	}

	// Find the last number in the line
	parts := strings.Fields(line)
	for i := len(parts) - 1; i >= 0; i-- {
		value, err := strconv.Atoi(parts[i])
		if err == nil {
			return value
		}
	}

	return 0
}

// checkPasswordComplexity checks password complexity via secedit export
func checkPasswordComplexity() (bool, error) {
	// Create temp file for secedit export
	tempDir := os.TempDir()
	tempFile := fmt.Sprintf("%s\\secedit_%d.inf", tempDir, time.Now().UnixNano())
	defer os.Remove(tempFile)

	// Export security policy to temp file
	cmd := exec.Command("secedit", "/export", "/cfg", tempFile, "/quiet")
	err := cmd.Run()
	if err != nil {
		return false, fmt.Errorf("secedit export failed: %v", err)
	}

	// Read and parse the exported file
	content, err := os.ReadFile(tempFile)
	if err != nil {
		return false, fmt.Errorf("failed to read secedit output: %v", err)
	}

	// Look for PasswordComplexity setting
	// Format: PasswordComplexity = 1 (enabled) or 0 (disabled)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "PasswordComplexity") {
			// Parse: PasswordComplexity = 1
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				value := strings.TrimSpace(parts[1])
				return value == "1", nil
			}
		}
	}

	return false, fmt.Errorf("PasswordComplexity setting not found in policy export")
}

// ==============================================================================
// DISPLAY AND LOGGING FUNCTIONS
// ==============================================================================

// displayPolicyResults displays the policy validation results in a formatted table
func displayPolicyResults(results *PolicyValidationResults) {
	Endpoint.Say("+---------------------------------+------------+-------------------+----------+")
	Endpoint.Say("| Policy Check                    | Value      | CIS L1 Threshold  | Status   |")
	Endpoint.Say("+---------------------------------+------------+-------------------+----------+")

	// Lockout Threshold
	status := "[PASS]"
	if !results.LockoutThreshold.Compliant {
		status = "[FAIL]"
	}
	Endpoint.Say("| %-31s | %-10v | %-17s | %-8s |",
		"Lockout Threshold", results.LockoutThreshold.Value, "1-5 attempts", status)

	// Lockout Duration
	status = "[PASS]"
	if !results.LockoutDuration.Compliant {
		status = "[FAIL]"
	}
	Endpoint.Say("| %-31s | %-10v | %-17s | %-8s |",
		"Lockout Duration", fmt.Sprintf("%v min", results.LockoutDuration.Value), ">= 15 min", status)

	// Reset Counter After
	status = "[PASS]"
	if !results.ResetCounterAfter.Compliant {
		status = "[FAIL]"
	}
	Endpoint.Say("| %-31s | %-10v | %-17s | %-8s |",
		"Reset Counter After", fmt.Sprintf("%v min", results.ResetCounterAfter.Value), ">= 15 min", status)

	// Minimum Password Length
	status = "[PASS]"
	if !results.MinPasswordLength.Compliant {
		status = "[FAIL]"
	}
	Endpoint.Say("| %-31s | %-10v | %-17s | %-8s |",
		"Minimum Password Length", fmt.Sprintf("%v chars", results.MinPasswordLength.Value), ">= 14 chars", status)

	// Password Complexity
	status = "[PASS]"
	if !results.PasswordComplexity.Compliant {
		status = "[FAIL]"
	}
	Endpoint.Say("| %-31s | %-10v | %-17s | %-8s |",
		"Password Complexity", results.PasswordComplexity.Value, "Enabled", status)

	Endpoint.Say("+---------------------------------+------------+-------------------+----------+")
	Endpoint.Say("")
	Endpoint.Say("Summary: %d/%d checks passed", results.PassedChecks, results.TotalChecks)
}

// logPolicyResults logs the policy results to the structured log
func logPolicyResults(results *PolicyValidationResults) {
	// Log each policy result
	logPolicyResult("Lockout Threshold", results.LockoutThreshold)
	logPolicyResult("Lockout Duration", results.LockoutDuration)
	logPolicyResult("Reset Counter After", results.ResetCounterAfter)
	logPolicyResult("Minimum Password Length", results.MinPasswordLength)
	logPolicyResult("Password Complexity", results.PasswordComplexity)

	// Log summary
	LogMessage("INFO", "Summary", fmt.Sprintf("Policy checks: %d passed, %d failed, overall compliant: %v",
		results.PassedChecks, results.FailedChecks, results.AllCompliant))
}

// logPolicyResult logs a single policy result
func logPolicyResult(name string, result PolicyResult) {
	status := "PASS"
	level := "INFO"
	if !result.Compliant {
		status = "FAIL"
		level = "WARN"
	}

	LogMessage(level, "Policy Check", fmt.Sprintf("[%s] %s: %v (threshold: %s, method: %s)",
		status, name, result.Value, result.Threshold, result.Method))
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

// checkAdminPrivileges checks if running with administrator privileges
// Note: Uses isAdmin() from test_logger.go
