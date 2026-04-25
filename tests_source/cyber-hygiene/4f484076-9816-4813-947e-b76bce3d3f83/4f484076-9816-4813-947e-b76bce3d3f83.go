//go:build windows
// +build windows

/*
ID: 4f484076-9816-4813-947e-b76bce3d3f83
NAME: Entra ID Tenant Security Hygiene Bundle
TECHNIQUES: T1078.004, T1556.007, T1110.001, T1098.003, T1098.001, T1566, T1528, T1562.008
TACTICS: credential-access, persistence, initial-access, defense-evasion
SEVERITY: critical
TARGET: entra-id, microsoft-365
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: identity-tenant
INTEGRATIONS: azure
TAGS: entra-id, mfa, conditional-access, pim, scuba, cis-benchmark, cloud-identity, zero-trust, isaca, itgc
ISACA_CONTROLS: ITGC-AM-006
CISA_DOMAINS: D5
COBIT_OBJECTIVES: DSS05.04
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
	TEST_UUID = "4f484076-9816-4813-947e-b76bce3d3f83"
	TEST_NAME = "Entra ID Tenant Security Hygiene Bundle"
	VERSION   = "1.1.0"

	// Exit codes
	EXIT_COMPLIANT     = 126 // All validators passed
	EXIT_NON_COMPLIANT = 101 // One or more validators failed
	EXIT_ERROR         = 999 // Test error (prerequisites not met)

	// Target directory.
	// LOG_DIR is the canonical-template name (referenced by test_logger.go's
	// WriteStageBundleResults); TARGET_DIR is this bundle's local alias. They
	// point to the same path on Windows.
	TARGET_DIR = `c:\F0`
	LOG_DIR    = `c:\F0`
)

// Validator represents a single validation module
type Validator struct {
	Name string
	Run  func() ValidatorResult
}

func main() {
	// Display banner
	printBanner()

	// Ensure target directory exists
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		fmt.Printf("\n[ERROR] Failed to create target directory %s: %v\n", TARGET_DIR, err)
		os.Exit(EXIT_ERROR)
	}

	// Authenticate to Microsoft Graph
	fmt.Println("\nAuthenticating to Microsoft Graph...")
	tenantName, err := GraphPreFlight()
	if err != nil {
		fmt.Printf("\n[ERROR] Graph authentication failed:\n  %v\n", err)
		os.Exit(EXIT_ERROR)
	}
	fmt.Printf("  Connected to tenant: %s\n", tenantName)
	defer GraphDisconnect()

	// Resolve organization
	orgInfo := ResolveOrganization("")

	// Initialize Schema v2.0 logging
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "cyber-hygiene",
		Severity: "critical",
		Techniques: []string{
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1556.007", // Modify Authentication Process: Hybrid Identity
			"T1110.001", // Brute Force: Password Guessing
			"T1098.003", // Account Manipulation: Additional Cloud Roles
			"T1098.001", // Account Manipulation: Additional Cloud Credentials
			"T1566",     // Phishing
			"T1528",     // Steal Application Access Token
			"T1562.008", // Impair Defenses: Disable Cloud Logs
		},
		Tactics: []string{
			"credential-access",
			"persistence",
			"initial-access",
			"defense-evasion",
		},
		Score:         9.2,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    0.7,
		},
		Tags: []string{
			"entra-id", "mfa", "conditional-access", "pim",
			"scuba", "cis-benchmark", "cloud-identity", "zero-trust", "isaca", "itgc",
		},
		// ISACA ITGC cross-reference: this bundle now also covers ITGC-AM-006 MFA Enrollment.
		IsacaControlIDs: []string{"ITGC-AM-006"},
		CisaDomains:     []string{"D5"},
		CobitObjectives: []string{"DSS05.04"},
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
	LogPhaseStart(1, "Entra ID Tenant Security Validation")

	// Define all validators aligned to CISA SCuBA sections
	validators := []Validator{
		{"Legacy Authentication (SCuBA §1)", RunLegacyAuthChecks},
		{"Risk-Based Policies (SCuBA §2)", RunRiskPolicyChecks},
		{"Strong Authentication / MFA (SCuBA §3)", RunMFAChecks},
		{"Centralized Log Collection (SCuBA §4)", RunLoggingChecks},
		{"Application Governance (SCuBA §5)", RunAppGovernanceChecks},
		{"Password Policies (SCuBA §6)", RunPasswordChecks},
		{"Privileged Access Management (SCuBA §7)", RunPrivilegedChecks},
		{"Guest Access Controls (SCuBA §8)", RunGuestChecks},
	}

	// Run all validators
	startedAt := time.Now().UTC().Format(time.RFC3339)
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

	// Collect per-control results and write bundle_results.json
	allControls := make([]ControlResult, 0, totalChecksPassed+totalChecksFailed)
	for _, result := range results {
		controls := CollectControlResults(result.Name, "cyber-hygiene", "identity-tenant", result.Checks)
		allControls = append(allControls, controls...)
	}

	overallExitCode := EXIT_COMPLIANT
	if validatorsFailed > 0 {
		overallExitCode = EXIT_NON_COMPLIANT
	}

	bundleResults := &BundleResults{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "identity-tenant",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		OverallExitCode:   overallExitCode,
		TotalControls:     len(allControls),
		PassedControls:    totalChecksPassed,
		FailedControls:    totalChecksFailed,
		Controls:          allControls,
	}

	if err := WriteBundleResults(bundleResults); err != nil {
		fmt.Printf("\n[WARNING] Failed to write bundle_results.json: %v\n", err)
	} else {
		fmt.Printf("\n[INFO] Bundle results written to c:\\F0\\bundle_results.json (%d controls)\n", len(allControls))
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
		outcomeDescription = "All validators passed - tenant identity controls are properly configured"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		outcomeDescription = fmt.Sprintf("%d validator(s) failed - identity security gaps detected", validatorsFailed)
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
	fmt.Println("║   F0RT1KA Entra ID Tenant Security Hygiene Bundle (SCuBA)       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Baseline:  CISA SCuBA MS.AAD.1.x - MS.AAD.8.x\n")
	fmt.Println("\nValidating 8 Entra ID security domains (~26 checks)...")
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
	fmt.Println("                   ENTRA ID TENANT SUMMARY")
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
