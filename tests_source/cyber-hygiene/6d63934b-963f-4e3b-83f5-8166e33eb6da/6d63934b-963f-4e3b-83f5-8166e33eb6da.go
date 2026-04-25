//go:build darwin
// +build darwin

/*
ID: 6d63934b-963f-4e3b-83f5-8166e33eb6da
NAME: CIS macOS Endpoint Level 1 Hardening Bundle
TECHNIQUES: T1562.001, T1059.004, T1071.001, T1021.004, T1548.004, T1553.001, T1070.002
TACTICS: defense-evasion, execution, command-and-control, lateral-movement, privilege-escalation
SEVERITY: high
TARGET: macos-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: cis-macos-l1
TAGS: cis-benchmark, level-1, macos-hardening, compliance, filevault, gatekeeper, sip, firewall, xprotect
UNIT: response
CREATED: 2026-03-11
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
	TEST_UUID = "6d63934b-963f-4e3b-83f5-8166e33eb6da"
	TEST_NAME = "CIS macOS Endpoint Level 1 Hardening Bundle"
	VERSION   = "1.0.0"

	// Exit codes
	EXIT_COMPLIANT     = 126 // All validators passed
	EXIT_NON_COMPLIANT = 101 // One or more validators failed
	EXIT_ERROR         = 999 // Test error (prerequisites not met)

	// Target directory
	TARGET_DIR = "/tmp/F0"

	// Quarantine detection delay
	QUARANTINE_DELAY = 1500 * time.Millisecond
)

// Embedded signed validator binaries (populated by build_all.sh)
var (
	//go:embed validator-sysprefs
	validatorSysprefsBin []byte
	//go:embed validator-auditlog
	validatorAuditlogBin []byte
	//go:embed validator-network
	validatorNetworkBin []byte
	//go:embed validator-accessctl
	validatorAccessctlBin []byte
	//go:embed validator-eprotect
	validatorEprotectBin []byte
)

func main() {
	printBanner()

	// Check for root privileges
	if !IsAdmin() {
		fmt.Println("\n[ERROR] This test requires root privileges.")
		fmt.Println("        Please run with: sudo /tmp/F0/6d63934b-963f-4e3b-83f5-8166e33eb6da")
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
			"T1059.004", // Command and Scripting Interpreter: Unix Shell
			"T1071.001", // Application Layer Protocol: Web Protocols
			"T1021.004", // Remote Services: SSH
			"T1548.004", // Abuse Elevation Control Mechanism: Elevated Execution with Prompt
			"T1553.001", // Subvert Trust Controls: Gatekeeper Bypass
			"T1070.002", // Indicator Removal: Clear Linux or Mac System Logs
		},
		Tactics: []string{
			"defense-evasion",
			"execution",
			"command-and-control",
			"lateral-movement",
			"privilege-escalation",
		},
		Score:         9.1,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.7,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.9,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cis-benchmark", "level-1", "macos-hardening", "compliance", "filevault", "gatekeeper", "sip", "firewall", "xprotect"},
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
	LogPhaseStart(1, "Multi-Binary CIS macOS L1 Validation")

	// Define all validators with embedded binaries and expected control IDs
	validators := []ValidatorDef{
		{
			Name: "sysprefs", DisplayName: "System Preferences & Security",
			Binary: validatorSysprefsBin,
			ControlIDs: []string{
				"CH-CM1-001", "CH-CM1-002", "CH-CM1-003", "CH-CM1-004",
				"CH-CM1-005", "CH-CM1-006", "CH-CM1-007", "CH-CM1-008",
			},
		},
		{
			Name: "auditlog", DisplayName: "Audit & Logging",
			Binary:     validatorAuditlogBin,
			ControlIDs: []string{"CH-CM1-009", "CH-CM1-010", "CH-CM1-011"},
		},
		{
			Name: "network", DisplayName: "Network Security",
			Binary:     validatorNetworkBin,
			ControlIDs: []string{"CH-CM1-012", "CH-CM1-013", "CH-CM1-014"},
		},
		{
			Name: "accessctl", DisplayName: "Access Control",
			Binary: validatorAccessctlBin,
			ControlIDs: []string{
				"CH-CM1-015", "CH-CM1-016", "CH-CM1-017", "CH-CM1-018", "CH-CM1-019",
			},
		},
		{
			Name: "eprotect", DisplayName: "Endpoint Protection",
			Binary:     validatorEprotectBin,
			ControlIDs: []string{"CH-CM1-020", "CH-CM1-021", "CH-CM1-022"},
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-macos-l1", fmt.Sprintf("extraction failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-macos-l1", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 4. Execute validator subprocess
		exitCode, err := ExecuteValidator(exePath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-macos-l1", fmt.Sprintf("execution failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-macos-l1", fmt.Sprintf("output read failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 6. Handle empty results
		if output.TotalChecks == 0 {
			reason := fmt.Sprintf("validator returned no checks (exit %d) - prerequisite not met", exitCode)
			fmt.Printf("       [SKIPPED] %s\n", reason)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-macos-l1", reason)
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 7. Convert to control results and track status
		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "cis-macos-l1", output)
		allControls = append(allControls, controls...)

		if exitCode == EXIT_COMPLIANT || output.IsCompliant {
			validatorsPassed++
			fmt.Printf("       -> COMPLIANT (%d/%d checks passed)\n", output.PassedCount, output.TotalChecks)
		} else {
			validatorsFailed++
			failedNames = append(failedNames, vd.DisplayName)
			fmt.Printf("       -> NON-COMPLIANT (%d/%d checks passed)\n", output.PassedCount, output.TotalChecks)
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

	bundleResults := &BundleResultsExt{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "cis-macos-l1",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		OverallExitCode:   overallExitCode,
		TotalControls:     len(allControls),
		PassedControls:    totalPassed,
		FailedControls:    totalFailed,
		SkippedControls:   totalSkipped,
		Controls:          allControls,
	}

	if err := WriteBundleResultsExt(bundleResults); err != nil {
		fmt.Printf("\n[WARNING] Failed to write bundle_results.json: %v\n", err)
	} else {
		fmt.Printf("\n[INFO] Bundle results written to /tmp/F0/bundle_results.json (%d controls)\n", len(allControls))
	}

	// Print summary
	printSummary(validatorsPassed, validatorsFailed, validatorsSkipped, totalPassed, totalFailed, totalSkipped, failedNames, skippedNames)

	// Determine exit code and log outcome
	var finalExitCode int
	var outcome string
	var outcomeDescription string

	if validatorsFailed == 0 && validatorsSkipped == 0 {
		finalExitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All validators passed - macOS endpoint is properly hardened per CIS Level 1"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: All %d validators passed", len(validators)))
	} else {
		finalExitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		parts := []string{}
		if validatorsFailed > 0 {
			parts = append(parts, fmt.Sprintf("%d failed", validatorsFailed))
		}
		if validatorsSkipped > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped/quarantined", validatorsSkipped))
		}
		outcomeDescription = fmt.Sprintf("Validators: %s - CIS Level 1 hardening gaps detected", strings.Join(parts, ", "))
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators OK (%s)",
			validatorsPassed, len(validators), strings.Join(parts, ", ")))
	}

	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(finalExitCode, outcomeDescription)

	os.Exit(finalExitCode)
}

// printBanner displays the test banner
func printBanner() {
	fmt.Println("================================================================")
	fmt.Println("  F0RT1KA CIS macOS Endpoint Level 1 Hardening Bundle v1.0")
	fmt.Println("  Multi-Binary Architecture (quarantine-resilient)")
	fmt.Println("================================================================")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 22 CIS Level 1 controls across 5 validators...")
}

// printSummary displays the final summary
func printSummary(passed, failed, skipped, checksPassed, checksFailed, checksSkipped int, failedNames, skippedNames []string) {
	total := passed + failed + skipped
	fmt.Println("\n================================================================")
	fmt.Println("                        SUMMARY")
	fmt.Println("================================================================")
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
	fmt.Println("================================================================")
}
