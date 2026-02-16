//go:build windows
// +build windows

/*
ID: a3c923ae-1a46-4b1f-b696-be6c2731a628
NAME: Cyber-Hygiene Bundle (Windows Defender Edition)
TECHNIQUES: T1562.001, T1003.001, T1059.001, T1021.002, T1110, T1547.001, T1548.002, T1569.002
TACTICS: defense-evasion, credential-access, execution, lateral-movement, persistence, privilege-escalation
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: cyber-hygiene, defender, hardening, compliance, bundle, cis-benchmark
UNIT: response
CREATED: 2026-01-26
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
	TEST_UUID = "a3c923ae-1a46-4b1f-b696-be6c2731a628"
	TEST_NAME = "Cyber-Hygiene Bundle (Windows Defender Edition)"
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
			"T1562.001", // Impair Defenses: Disable or Modify Tools
			"T1003.001", // OS Credential Dumping: LSASS Memory
			"T1059.001", // Command and Scripting Interpreter: PowerShell
			"T1021.002", // Remote Services: SMB/Windows Admin Shares
			"T1110",     // Brute Force
			"T1547.001", // Boot or Logon Autostart Execution
			"T1548.002", // Abuse Elevation Control Mechanism
			"T1569.002", // System Services: Service Execution
		},
		Tactics: []string{
			"defense-evasion",
			"credential-access",
			"execution",
			"lateral-movement",
			"persistence",
			"privilege-escalation",
		},
		Score: 9.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cyber-hygiene", "defender", "hardening", "compliance", "bundle", "cis-benchmark"},
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
	LogPhaseStart(1, "Bundled Windows Cyber-Hygiene Validation")

	// Define all validators
	validators := []Validator{
		{"Microsoft Defender Configuration", RunDefenderChecks},
		{"LSASS Protection", RunLSASSChecks},
		{"Attack Surface Reduction Rules", RunASRChecks},
		{"SMB Hardening", RunSMBChecks},
		{"PowerShell Security", RunPowerShellChecks},
		{"Network Protocol Hardening", RunNetworkChecks},
		{"Windows Audit Logging", RunAuditChecks},
		{"Account Lockout Policy", RunLockoutChecks},
		{"LAPS", RunLAPSChecks},
		{"Print Spooler Hardening", RunPrintSpoolerChecks},
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
		controls := CollectControlResults(result.Name, "cyber-hygiene", "baseline", result.Checks)
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
		BundleSubcategory: "baseline",
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
		outcomeDescription = "All validators passed - endpoint is properly hardened"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		outcomeDescription = fmt.Sprintf("%d validator(s) failed - security gaps detected", validatorsFailed)
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
	fmt.Println("║     F0RT1KA Cyber-Hygiene Bundle - Windows Defender Edition      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 10 security configurations...")
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
