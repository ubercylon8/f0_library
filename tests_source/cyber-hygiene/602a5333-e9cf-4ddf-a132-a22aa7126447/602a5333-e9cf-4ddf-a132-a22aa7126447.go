//go:build windows
// +build windows

/*
ID: 602a5333-e9cf-4ddf-a132-a22aa7126447
NAME: CIS Identity & Active Directory Level 1 Bundle
TECHNIQUES: T1078.002, T1098.001, T1098.003, T1558.003, T1558.004, T1078.004, T1556.007, T1484.001
TACTICS: credential-access, persistence, privilege-escalation, defense-evasion
SEVERITY: critical
TARGET: windows-endpoint, active-directory, entra-id
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: cis-identity-ad-l1
INTEGRATIONS: azure
TAGS: cis-benchmark, level-1, active-directory, entra-id, identity-hardening, compliance, gmsa, kerberos
UNIT: response
CREATED: 2026-03-11
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
	TEST_UUID = "602a5333-e9cf-4ddf-a132-a22aa7126447"
	TEST_NAME = "CIS Identity & Active Directory Level 1 Bundle"
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

// graphAvailable indicates whether Graph API authentication succeeded.
// If false, Entra ID checks will be skipped gracefully.
var graphAvailable bool

func main() {
	// Display banner
	printBanner()

	// Ensure target directory exists
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		fmt.Printf("\n[ERROR] Failed to create target directory %s: %v\n", TARGET_DIR, err)
		os.Exit(EXIT_ERROR)
	}

	// Step 1: AD pre-flight (always required -- domain-joined machine with RSAT)
	fmt.Println("\nValidating Active Directory prerequisites...")
	domainName, err := ADPreFlight()
	if err != nil {
		fmt.Printf("\n[ERROR] Active Directory pre-flight failed:\n  %v\n", err)
		os.Exit(EXIT_ERROR)
	}
	fmt.Printf("  Connected to domain: %s\n", domainName)

	// Step 2: Graph API pre-flight (optional -- for Entra ID checks)
	fmt.Println("\nChecking Microsoft Graph API availability...")
	tenantName, graphErr := GraphPreFlight()
	if graphErr != nil {
		graphAvailable = false
		fmt.Printf("  [WARN] Graph API not available: %v\n", graphErr)
		fmt.Println("  Entra ID checks (CH-CIA-022 to CH-CIA-028) will be SKIPPED")
		fmt.Println("  AD checks (CH-CIA-001 to CH-CIA-021) will proceed normally")
	} else {
		graphAvailable = true
		fmt.Printf("  Connected to tenant: %s\n", tenantName)
		defer GraphDisconnect()
	}

	// Resolve organization
	orgInfo := ResolveOrganization("")

	// Initialize Schema v2.0 logging
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "cyber-hygiene",
		Severity: "critical",
		Techniques: []string{
			"T1078.002", // Valid Accounts: Domain Accounts
			"T1098.001", // Account Manipulation: Additional Cloud Credentials
			"T1098.003", // Account Manipulation: Additional Cloud Roles
			"T1558.003", // Steal or Forge Kerberos Tickets: Kerberoasting
			"T1558.004", // Steal or Forge Kerberos Tickets: AS-REP Roasting
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1556.007", // Modify Authentication Process: Hybrid Identity
			"T1484.001", // Domain Policy Modification: Group Policy Modification
		},
		Tactics: []string{
			"credential-access",
			"persistence",
			"privilege-escalation",
			"defense-evasion",
		},
		Score:         9.3,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    1.0,
		},
		Tags: []string{
			"cis-benchmark", "level-1", "active-directory", "entra-id",
			"identity-hardening", "compliance", "gmsa", "kerberos",
		},
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
	LogPhaseStart(1, "CIS Identity & Active Directory Level 1 Validation")

	// Define all 6 validators
	validators := []Validator{
		{"Privileged Account Management", RunPrivAccountChecks},
		{"Service Account Security", RunServiceAcctChecks},
		{"Authentication Hardening", RunAuthHardenChecks},
		{"AD Infrastructure", RunADInfraChecks},
		{"Group Policy Security", RunGroupPolicyChecks},
		{"Entra ID Controls", RunEntraIDChecks},
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
	totalChecksSkipped := 0
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
	allControls := make([]ControlResult, 0, 28)
	for _, result := range results {
		controls := CollectControlResults(result.Name, "cyber-hygiene", "cis-identity-ad-l1", result.Checks)
		allControls = append(allControls, controls...)
	}

	// Count skipped
	for _, ctrl := range allControls {
		if ctrl.Skipped {
			totalChecksSkipped++
		}
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
		BundleSubcategory: "cis-identity-ad-l1",
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
	printSummary(validatorsPassed, validatorsFailed, totalChecksPassed, totalChecksFailed, totalChecksSkipped, failedValidatorNames)

	// Determine exit code and log outcome
	var exitCode int
	var outcome string
	var outcomeDescription string

	if validatorsFailed == 0 {
		exitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All validators passed - identity and AD controls are properly configured"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		outcomeDescription = fmt.Sprintf("%d validator(s) failed - identity/AD security gaps detected", validatorsFailed)
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
	fmt.Println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557")
	fmt.Println("\u2551   F0RT1KA CIS Identity & Active Directory Level 1 Bundle      \u2551")
	fmt.Println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Baseline:  CIS Identity & AD Level 1 (28 controls)\n")
	fmt.Println("\nValidating 6 security domains (28 checks)...")
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
			fmt.Printf("       -> COMPLIANT (%d/%d checks passed)\n", result.PassedCount, result.TotalChecks)
		} else {
			skippedCount := 0
			for _, c := range result.Checks {
				if c.Details == "Skipped: Graph API not available" {
					skippedCount++
				}
			}
			if skippedCount == result.TotalChecks {
				fmt.Printf("       -> SKIPPED (Graph API not available)\n")
			} else {
				fmt.Printf("       -> NON-COMPLIANT (%d/%d checks passed)\n", result.PassedCount, result.TotalChecks)
			}
		}
	}

	return results
}

// printSummary displays the final summary
func printSummary(validatorsPassed, validatorsFailed, checksPassed, checksFailed, checksSkipped int, failedNames []string) {
	fmt.Println("\n\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
	fmt.Println("           CIS IDENTITY & ACTIVE DIRECTORY SUMMARY")
	fmt.Println("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
	fmt.Printf("  Validators Passed: %d/%d\n", validatorsPassed, validatorsPassed+validatorsFailed)
	fmt.Printf("  Validators Failed: %d/%d", validatorsFailed, validatorsPassed+validatorsFailed)
	if validatorsFailed > 0 {
		fmt.Printf(" (%s)", strings.Join(failedNames, ", "))
	}
	fmt.Println()
	fmt.Printf("  Total Checks: %d passed, %d failed", checksPassed, checksFailed)
	if checksSkipped > 0 {
		fmt.Printf(", %d skipped", checksSkipped)
	}
	fmt.Println()
	fmt.Println()

	if validatorsFailed == 0 {
		fmt.Println("  RESULT: COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT (Exit Code: 101)")
	}
	fmt.Println("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
}
