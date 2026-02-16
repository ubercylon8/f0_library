//go:build windows
// +build windows

/*
ID: 7659eeba-f315-440e-9882-4aa015d68b27
NAME: Identity Endpoint Posture Bundle
TECHNIQUES: T1078.004, T1556.007, T1556.006, T1528, T1550.001, T1588.004, T1005, T1111
TACTICS: credential-access, defense-evasion, persistence, initial-access
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: identity-endpoint
TAGS: cyber-hygiene, identity, entra-id, whfb, mdm, intune, bitlocker, prt, device-join
UNIT: response
CREATED: 2026-02-15
AUTHOR: sectest-builder
*/

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TEST_UUID = "7659eeba-f315-440e-9882-4aa015d68b27"
	TEST_NAME = "Identity Endpoint Posture Bundle"
	VERSION   = "1.0.0"

	// Exit codes
	EXIT_COMPLIANT     = 126 // All validators passed
	EXIT_NON_COMPLIANT = 101 // One or more validators failed
	EXIT_ERROR         = 999 // Test error (prerequisites not met)

	// Target directory
	TARGET_DIR = `c:\F0`
)

// Validator represents a single validation module
type Validator struct {
	Name string
	Run  func() ValidatorResult
}

func main() {
	// Display banner
	printBanner()

	// Check for admin privileges
	if !IsAdmin() {
		fmt.Println("\n[ERROR] This test requires administrator privileges.")
		fmt.Println("        Please run from an elevated command prompt.")
		os.Exit(EXIT_ERROR)
	}

	// Ensure target directory exists
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		fmt.Printf("\n[ERROR] Failed to create target directory %s: %v\n", TARGET_DIR, err)
		os.Exit(EXIT_ERROR)
	}

	// Resolve organization
	orgInfo := ResolveOrganization("")

	// Initialize Schema v2.0 logging
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "cyber-hygiene",
		Severity: "high",
		Techniques: []string{
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1556.007", // Modify Authentication Process: Hybrid Identity
			"T1556.006", // Modify Authentication Process: Multi-Factor Authentication Interception
			"T1528",     // Steal Application Access Token
			"T1550.001", // Use Alternate Authentication Material: Application Access Token
			"T1588.004", // Obtain Capabilities: Digital Certificates
			"T1005",     // Data from Local System
			"T1111",     // Multi-Factor Authentication Request Generation
		},
		Tactics: []string{
			"credential-access",
			"defense-evasion",
			"persistence",
			"initial-access",
		},
		Score: 8.7,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.7,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cyber-hygiene", "identity", "entra-id", "whfb", "mdm", "intune", "bitlocker", "prt", "device-join"},
	}

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000,
			CertificateMode:   "self-healing",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)
	LogPhaseStart(1, "Identity Endpoint Posture Validation")

	// Define all validators
	validators := []Validator{
		{"Device Join Status", RunDeviceJoinChecks},
		{"Windows Hello for Business", RunWHfBChecks},
		{"Intune/MDM Enrollment", RunMDMEnrollmentChecks},
		{"Cloud Credential Protection", RunCloudCredentialChecks},
		{"BitLocker Cloud Escrow", RunBitLockerEscrowChecks},
	}

	// Run all validators
	fmt.Println()
	results := runAllValidators(validators)

	// Calculate totals
	validatorsPassed := 0
	validatorsFailed := 0
	totalChecksPassed := 0
	totalChecksFailed := 0
	failedValidatorNames := []string{}

	for _, result := range results {
		if result.IsCompliant {
			validatorsPassed++
		} else {
			validatorsFailed++
			failedValidatorNames = append(failedValidatorNames, result.Name)
		}
		totalChecksPassed += result.PassedCount
		totalChecksFailed += result.FailedCount
	}

	// Print summary
	printSummary(validatorsPassed, validatorsFailed, totalChecksPassed, totalChecksFailed, failedValidatorNames)

	// Determine exit code and log outcome
	var exitCode int
	var outcome string
	var outcomeDescription string

	if validatorsFailed == 0 {
		exitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All validators passed - endpoint identity posture is properly hardened"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		outcomeDescription = fmt.Sprintf("%d validator(s) failed - identity posture gaps detected", validatorsFailed)
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators failed: %s",
			validatorsFailed, len(validators), strings.Join(failedValidatorNames, ", ")))
	}

	// Log detailed results
	for _, result := range results {
		status := "PASS"
		if !result.IsCompliant {
			status = "FAIL"
		}
		LogMessage("INFO", result.Name, fmt.Sprintf("[%s] %d/%d checks passed",
			status, result.PassedCount, result.TotalChecks))
	}

	// End phase and save log
	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)

	os.Exit(exitCode)
}

// printBanner displays the test banner
func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║     F0RT1KA Identity Endpoint Posture Bundle                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 5 identity configurations...")
}

// runAllValidators executes all validators and returns results
func runAllValidators(validators []Validator) []ValidatorResult {
	results := make([]ValidatorResult, 0, len(validators))

	for i, v := range validators {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(validators), v.Name)

		result := v.Run()
		results = append(results, result)

		// Print individual check results
		for j, check := range result.Checks {
			if j == len(result.Checks)-1 {
				fmt.Println(FormatLastCheckResult(check))
			} else {
				fmt.Println(FormatCheckResult(check))
			}
		}

		// Print validator summary
		if result.IsCompliant {
			fmt.Printf("       → COMPLIANT (%d/%d checks passed)\n", result.PassedCount, result.TotalChecks)
		} else {
			fmt.Printf("       → NON-COMPLIANT (%d/%d checks passed)\n", result.PassedCount, result.TotalChecks)
		}
	}

	return results
}

// printSummary displays the final summary
func printSummary(validatorsPassed, validatorsFailed, checksPassed, checksFailed int, failedNames []string) {
	fmt.Println("\n══════════════════════════════════════════════════════════════════")
	fmt.Println("                        SUMMARY")
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Printf("  Validators Passed: %d/%d\n", validatorsPassed, validatorsPassed+validatorsFailed)
	fmt.Printf("  Validators Failed: %d/%d", validatorsFailed, validatorsPassed+validatorsFailed)
	if validatorsFailed > 0 {
		fmt.Printf(" (%s)", strings.Join(failedNames, ", "))
	}
	fmt.Println()
	fmt.Printf("  Total Checks: %d passed, %d failed\n", checksPassed, checksFailed)
	fmt.Println()

	if validatorsFailed == 0 {
		fmt.Println("  RESULT: COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT (Exit Code: 101)")
	}
	fmt.Println("══════════════════════════════════════════════════════════════════")
}
