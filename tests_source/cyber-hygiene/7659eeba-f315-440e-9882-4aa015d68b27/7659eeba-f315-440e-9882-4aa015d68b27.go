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
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TEST_UUID = "7659eeba-f315-440e-9882-4aa015d68b27"
	TEST_NAME = "Identity Endpoint Posture Bundle"
	VERSION   = "2.0.0"

	// Exit codes
	EXIT_COMPLIANT     = 126 // All validators passed
	EXIT_NON_COMPLIANT = 101 // One or more validators failed
	EXIT_ERROR         = 999 // Test error (prerequisites not met)

	// Target directory
	TARGET_DIR = `c:\F0`

	// Quarantine detection delay (ms)
	QUARANTINE_DELAY = 1500 * time.Millisecond
)

// Embedded signed validator binaries (populated by build_all.sh)
var (
	//go:embed validator-devicejoin.exe
	validatorDevicejoinBin []byte
	//go:embed validator-whfb.exe
	validatorWhfbBin []byte
	//go:embed validator-mdm.exe
	validatorMdmBin []byte
	//go:embed validator-cloudcred.exe
	validatorCloudcredBin []byte
	//go:embed validator-bitlocker.exe
	validatorBitlockerBin []byte
)

func main() {
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
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)
	LogPhaseStart(1, "Multi-Binary Identity Endpoint Posture Validation")

	// Define all validators with embedded binaries and expected control IDs
	validators := []ValidatorDef{
		{
			Name: "devicejoin", DisplayName: "Device Join Status",
			Binary:     validatorDevicejoinBin,
			ControlIDs: []string{"CH-IEP-001", "CH-IEP-002", "CH-IEP-003", "CH-IEP-004", "CH-IEP-005"},
		},
		{
			Name: "whfb", DisplayName: "Windows Hello for Business",
			Binary:     validatorWhfbBin,
			ControlIDs: []string{"CH-IEP-006", "CH-IEP-007", "CH-IEP-008", "CH-IEP-009", "CH-IEP-010"},
		},
		{
			Name: "mdm", DisplayName: "Intune/MDM Enrollment",
			Binary:     validatorMdmBin,
			ControlIDs: []string{"CH-IEP-011", "CH-IEP-012", "CH-IEP-013", "CH-IEP-014"},
		},
		{
			Name: "cloudcred", DisplayName: "Cloud Credential Protection",
			Binary:     validatorCloudcredBin,
			ControlIDs: []string{"CH-IEP-015", "CH-IEP-016", "CH-IEP-017", "CH-IEP-018", "CH-IEP-019"},
		},
		{
			Name: "bitlocker", DisplayName: "BitLocker Cloud Escrow",
			Binary:     validatorBitlockerBin,
			ControlIDs: []string{"CH-IEP-020", "CH-IEP-021", "CH-IEP-022"},
		},
	}

	// Execute validators: extract -> quarantine check -> run -> collect results
	startedAt := time.Now().UTC().Format(time.RFC3339)
	fmt.Println()

	allControls := make([]ControlResult, 0, 22)
	validatorsPassed := 0
	validatorsFailed := 0
	validatorsSkipped := 0
	failedNames := []string{}
	skippedNames := []string{}

	for i, vd := range validators {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(validators), vd.DisplayName)

		// 1. Extract validator binary
		exePath, err := ExtractValidator(vd.Name, vd.Binary)
		if err != nil {
			fmt.Printf("       [ERROR] Extract failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "identity-endpoint", fmt.Sprintf("extraction failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 2. Brief delay for EDR/AV to react
		time.Sleep(QUARANTINE_DELAY)

		// 3. Check if quarantined
		if IsQuarantined(exePath) {
			fmt.Printf("       [SKIPPED] Validator quarantined by EDR/AV\n")
			LogMessage("WARNING", vd.DisplayName, "Validator binary quarantined by endpoint protection")
			controls := MakeSkippedControls(vd, "cyber-hygiene", "identity-endpoint", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 4. Execute validator subprocess
		exitCode, err := ExecuteValidator(exePath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "identity-endpoint", fmt.Sprintf("execution failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 5. Read validator output
		output, err := ReadValidatorOutput(vd.Name)
		if err != nil {
			fmt.Printf("       [ERROR] Failed to read results: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "identity-endpoint", fmt.Sprintf("output read failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 6. Convert to control results and track status
		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "identity-endpoint", output)
		allControls = append(allControls, controls...)

		if exitCode == EXIT_COMPLIANT || output.IsCompliant {
			validatorsPassed++
			fmt.Printf("       → COMPLIANT (%d/%d checks passed)\n", output.PassedCount, output.TotalChecks)
		} else {
			validatorsFailed++
			failedNames = append(failedNames, vd.DisplayName)
			fmt.Printf("       → NON-COMPLIANT (%d/%d checks passed)\n", output.PassedCount, output.TotalChecks)
		}

		CleanupValidator(vd.Name)
	}

	// Calculate totals from controls
	totalPassed := 0
	totalFailed := 0
	totalSkipped := 0
	for _, c := range allControls {
		if c.Skipped {
			totalSkipped++
		} else if c.Compliant {
			totalPassed++
		} else {
			totalFailed++
		}
	}

	// Build and write bundle_results.json
	overallExitCode := EXIT_COMPLIANT
	if validatorsFailed > 0 || validatorsSkipped > 0 {
		overallExitCode = EXIT_NON_COMPLIANT
	}

	bundleResults := &BundleResults{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "identity-endpoint",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		OverallExitCode:   overallExitCode,
		TotalControls:     len(allControls),
		PassedControls:    totalPassed,
		FailedControls:    totalFailed,
		SkippedControls:   totalSkipped,
		Controls:          allControls,
	}

	if err := WriteBundleResults(bundleResults); err != nil {
		fmt.Printf("\n[WARNING] Failed to write bundle_results.json: %v\n", err)
	} else {
		fmt.Printf("\n[INFO] Bundle results written to c:\\F0\\bundle_results.json (%d controls)\n", len(allControls))
	}

	// Print summary
	printSummary(validatorsPassed, validatorsFailed, validatorsSkipped, totalPassed, totalFailed, totalSkipped, failedNames, skippedNames)

	// Determine exit code and log outcome
	var exitCode int
	var outcome string
	var outcomeDescription string

	if validatorsFailed == 0 && validatorsSkipped == 0 {
		exitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All validators passed - endpoint identity posture is properly hardened"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		parts := []string{}
		if validatorsFailed > 0 {
			parts = append(parts, fmt.Sprintf("%d failed", validatorsFailed))
		}
		if validatorsSkipped > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped/quarantined", validatorsSkipped))
		}
		outcomeDescription = fmt.Sprintf("Validators: %s - identity posture gaps detected", strings.Join(parts, ", "))
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators OK (%s)",
			validatorsPassed, len(validators), strings.Join(parts, ", ")))
	}

	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)

	os.Exit(exitCode)
}

// printBanner displays the test banner
func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║   F0RT1KA Identity Endpoint Posture Bundle v2                    ║")
	fmt.Println("║   Multi-Binary Architecture (quarantine-resilient)               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 5 identity configurations (independent validator binaries)...")
}

// printSummary displays the final summary
func printSummary(passed, failed, skipped, checksPassed, checksFailed, checksSkipped int, failedNames, skippedNames []string) {
	total := passed + failed + skipped
	fmt.Println("\n══════════════════════════════════════════════════════════════════")
	fmt.Println("                        SUMMARY")
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Printf("  Validators Passed:   %d/%d\n", passed, total)
	fmt.Printf("  Validators Failed:   %d/%d", failed, total)
	if failed > 0 {
		fmt.Printf(" (%s)", strings.Join(failedNames, ", "))
	}
	fmt.Println()
	if skipped > 0 {
		fmt.Printf("  Validators Skipped:  %d/%d (%s)\n", skipped, total, strings.Join(skippedNames, ", "))
	}
	fmt.Printf("  Total Controls: %d passed, %d failed, %d skipped\n", checksPassed, checksFailed, checksSkipped)
	fmt.Println()

	if failed == 0 && skipped == 0 {
		fmt.Println("  RESULT: COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT (Exit Code: 101)")
	}
	fmt.Println("══════════════════════════════════════════════════════════════════")
}
