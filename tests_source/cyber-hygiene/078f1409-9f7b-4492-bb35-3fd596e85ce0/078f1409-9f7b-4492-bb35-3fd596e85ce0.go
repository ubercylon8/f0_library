//go:build windows
// +build windows

/*
ID: 078f1409-9f7b-4492-bb35-3fd596e85ce0
NAME: CIS Windows Endpoint Level 1 Hardening Bundle
TECHNIQUES: T1110, T1078.001, T1557.001, T1003.001, T1562.001, T1562.004, T1059.001, T1021.001
TACTICS: credential-access, defense-evasion, lateral-movement, execution, persistence
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: cis-windows-l1
TAGS: cis-benchmark, level-1, windows-hardening, compliance, password-policy, firewall, audit-logging
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
	TEST_UUID = "078f1409-9f7b-4492-bb35-3fd596e85ce0"
	TEST_NAME = "CIS Windows Endpoint Level 1 Hardening Bundle"
	VERSION   = "1.0.0"

	// Exit codes
	EXIT_COMPLIANT     = 126 // All validators passed
	EXIT_NON_COMPLIANT = 101 // One or more validators failed
	EXIT_ERROR         = 999 // Test error (prerequisites not met)

	// Target directory
	TARGET_DIR = `c:\F0`

	// Quarantine detection delay
	QUARANTINE_DELAY = 1500 * time.Millisecond
)

// Embedded signed validator binaries (populated by build_all.sh)
var (
	//go:embed validator-credpolicy.exe
	validatorCredpolicyBin []byte
	//go:embed validator-accounts.exe
	validatorAccountsBin []byte
	//go:embed validator-netauth.exe
	validatorNetauthBin []byte
	//go:embed validator-credprotect.exe
	validatorCredprotectBin []byte
	//go:embed validator-firewall.exe
	validatorFirewallBin []byte
	//go:embed validator-auditlog.exe
	validatorAuditlogBin []byte
	//go:embed validator-eprotect.exe
	validatorEprotectBin []byte
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
			"T1110",     // Brute Force
			"T1078.001", // Valid Accounts: Default Accounts
			"T1557.001", // Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
			"T1003.001", // OS Credential Dumping: LSASS Memory
			"T1562.001", // Impair Defenses: Disable or Modify Tools
			"T1562.004", // Impair Defenses: Disable or Modify System Firewall
			"T1059.001", // Command and Scripting Interpreter: PowerShell
			"T1021.001", // Remote Services: Remote Desktop Protocol
		},
		Tactics: []string{
			"credential-access",
			"defense-evasion",
			"lateral-movement",
			"execution",
			"persistence",
		},
		Score: 9.4,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.9,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cis-benchmark", "level-1", "windows-hardening", "compliance", "password-policy", "firewall", "audit-logging"},
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
	LogPhaseStart(1, "CIS Windows Level 1 Cyber-Hygiene Validation")

	// Define all validators with embedded binaries and expected control IDs
	validators := []ValidatorDef{
		{
			Name: "credpolicy", DisplayName: "Credential & Password Policy",
			Binary:     validatorCredpolicyBin,
			ControlIDs: []string{"CH-CW1-001", "CH-CW1-002", "CH-CW1-003", "CH-CW1-004", "CH-CW1-005", "CH-CW1-006", "CH-CW1-007", "CH-CW1-008", "CH-CW1-009", "CH-CW1-010"},
		},
		{
			Name: "accounts", DisplayName: "Account Management",
			Binary:     validatorAccountsBin,
			ControlIDs: []string{"CH-CW1-011", "CH-CW1-012", "CH-CW1-013", "CH-CW1-014", "CH-CW1-015", "CH-CW1-016", "CH-CW1-017", "CH-CW1-018"},
		},
		{
			Name: "netauth", DisplayName: "Network Authentication Hardening",
			Binary:     validatorNetauthBin,
			ControlIDs: []string{"CH-CW1-019", "CH-CW1-020", "CH-CW1-021", "CH-CW1-022", "CH-CW1-023", "CH-CW1-024", "CH-CW1-025", "CH-CW1-026"},
		},
		{
			Name: "credprotect", DisplayName: "Credential Protection",
			Binary:     validatorCredprotectBin,
			ControlIDs: []string{"CH-CW1-027", "CH-CW1-028", "CH-CW1-029"},
		},
		{
			Name: "firewall", DisplayName: "Windows Firewall",
			Binary:     validatorFirewallBin,
			ControlIDs: []string{"CH-CW1-030", "CH-CW1-031", "CH-CW1-032", "CH-CW1-033"},
		},
		{
			Name: "auditlog", DisplayName: "Audit & Logging Policy",
			Binary:     validatorAuditlogBin,
			ControlIDs: []string{"CH-CW1-034", "CH-CW1-035", "CH-CW1-036", "CH-CW1-037", "CH-CW1-038", "CH-CW1-039", "CH-CW1-040", "CH-CW1-041", "CH-CW1-042", "CH-CW1-043", "CH-CW1-044"},
		},
		{
			Name: "eprotect", DisplayName: "Endpoint Protection & Access",
			Binary:     validatorEprotectBin,
			ControlIDs: []string{"CH-CW1-045", "CH-CW1-046", "CH-CW1-047", "CH-CW1-048", "CH-CW1-049", "CH-CW1-050", "CH-CW1-051", "CH-CW1-052"},
		},
	}

	// Execute validators: extract -> quarantine check -> run -> collect results
	startedAt := time.Now().UTC().Format(time.RFC3339)
	fmt.Println()

	allControls := make([]ControlResult, 0, 52)
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-windows-l1", fmt.Sprintf("extraction failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-windows-l1", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 4. Execute validator subprocess
		exitCode, err := ExecuteValidator(exePath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-windows-l1", fmt.Sprintf("execution failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-windows-l1", fmt.Sprintf("output read failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 6. Convert to control results and track status
		if output.TotalChecks == 0 {
			reason := fmt.Sprintf("validator returned no checks (exit %d) - prerequisite not met", exitCode)
			fmt.Printf("       [SKIPPED] %s\n", reason)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-windows-l1", reason)
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "cis-windows-l1", output)
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

	bundleResults := &BundleResults{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "cis-windows-l1",
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
		outcomeDescription = "All validators passed - endpoint meets CIS Level 1 hardening requirements"
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
		outcomeDescription = fmt.Sprintf("Validators: %s - CIS Level 1 compliance gaps detected", strings.Join(parts, ", "))
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators OK (%s)",
			validatorsPassed, len(validators), strings.Join(parts, ", ")))
	}

	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)

	os.Exit(exitCode)
}

// printBanner displays the test banner
func printBanner() {
	fmt.Println("+=======================================================================+")
	fmt.Println("|  F0RT1KA CIS Windows Endpoint Level 1 Hardening Bundle                 |")
	fmt.Println("|  Multi-Binary Architecture (quarantine-resilient)                       |")
	fmt.Println("+=======================================================================+")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 7 CIS Level 1 security domains (52 controls)...")
}

// printSummary displays the final summary
func printSummary(passed, failed, skipped, checksPassed, checksFailed, checksSkipped int, failedNames, skippedNames []string) {
	total := passed + failed + skipped
	fmt.Println("\n=======================================================================")
	fmt.Println("                           SUMMARY")
	fmt.Println("=======================================================================")
	fmt.Printf("  Validators Passed:   %d/%d\n", passed, total)
	fmt.Printf("  Validators Failed:   %d/%d", failed, total)
	if failed > 0 {
		fmt.Printf(" (%s)", strings.Join(failedNames, ", "))
	}
	fmt.Println()
	if skipped > 0 {
		fmt.Printf("  Validators Skipped:  %d/%d (%s)\n", skipped, total, strings.Join(skippedNames, ", "))
	}
	fmt.Printf("  Total Controls: %d passed, %d failed, %d skipped (of 52)\n", checksPassed, checksFailed, checksSkipped)
	fmt.Println()

	if failed == 0 && skipped == 0 {
		fmt.Println("  RESULT: CIS LEVEL 1 COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT (Exit Code: 101)")
	}
	fmt.Println("=======================================================================")
}
