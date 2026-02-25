//go:build windows
// +build windows

/*
ID: b2cd3532-701d-4700-bbb2-f7c10ef0d717
NAME: Cyber-Hygiene Bundle (CrowdStrike Falcon Edition)
TECHNIQUES: T1562.001, T1562.004, T1070, T1003.001, T1059.001, T1021.002, T1110, T1547.001, T1548.002, T1569.002
TACTICS: defense-evasion, credential-access, execution, lateral-movement, persistence, privilege-escalation
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: cyber-hygiene, crowdstrike, falcon, edr, hardening, compliance, bundle, cis-benchmark
UNIT: response
CREATED: 2026-02-21
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
	TEST_UUID = "b2cd3532-701d-4700-bbb2-f7c10ef0d717"
	TEST_NAME = "Cyber-Hygiene Bundle (CrowdStrike Falcon Edition)"
	VERSION   = "1.0.0"

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
	//go:embed validator-crowdstrike.exe
	validatorCrowdstrikeBin []byte
	//go:embed validator-lsass.exe
	validatorLsassBin []byte
	//go:embed validator-asr.exe
	validatorAsrBin []byte
	//go:embed validator-smb.exe
	validatorSmbBin []byte
	//go:embed validator-powershell.exe
	validatorPowershellBin []byte
	//go:embed validator-network.exe
	validatorNetworkBin []byte
	//go:embed validator-audit.exe
	validatorAuditBin []byte
	//go:embed validator-lockout.exe
	validatorLockoutBin []byte
	//go:embed validator-laps.exe
	validatorLapsBin []byte
	//go:embed validator-printspooler.exe
	validatorPrintspoolerBin []byte
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
			"T1562.001", // Impair Defenses: Disable or Modify Tools
			"T1562.004", // Impair Defenses: Disable or Modify System Firewall
			"T1070",     // Indicator Removal
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
		Tags: []string{"cyber-hygiene", "crowdstrike", "falcon", "edr", "hardening", "compliance", "bundle", "cis-benchmark"},
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
	LogPhaseStart(1, "Multi-Binary Cyber-Hygiene Validation")

	// Define all validators with embedded binaries and expected control IDs
	validators := []ValidatorDef{
		{
			Name: "crowdstrike", DisplayName: "CrowdStrike Falcon Configuration",
			Binary:     validatorCrowdstrikeBin,
			ControlIDs: []string{"CH-CRW-001", "CH-CRW-002", "CH-CRW-003", "CH-CRW-004", "CH-CRW-005", "CH-CRW-006"},
		},
		{
			Name: "lsass", DisplayName: "LSASS Protection",
			Binary:     validatorLsassBin,
			ControlIDs: []string{"CH-LSS-001", "CH-LSS-002", "CH-LSS-003"},
		},
		{
			Name: "asr", DisplayName: "Attack Surface Reduction Rules",
			Binary:     validatorAsrBin,
			ControlIDs: []string{"CH-ASR-001", "CH-ASR-002", "CH-ASR-003", "CH-ASR-004", "CH-ASR-005", "CH-ASR-006", "CH-ASR-007", "CH-ASR-008"},
		},
		{
			Name: "smb", DisplayName: "SMB Hardening",
			Binary:     validatorSmbBin,
			ControlIDs: []string{"CH-SMB-001", "CH-SMB-002", "CH-SMB-003", "CH-SMB-004", "CH-SMB-005"},
		},
		{
			Name: "powershell", DisplayName: "PowerShell Security",
			Binary:     validatorPowershellBin,
			ControlIDs: []string{"CH-PWS-001", "CH-PWS-002", "CH-PWS-003", "CH-PWS-004"},
		},
		{
			Name: "network", DisplayName: "Network Protocol Hardening",
			Binary:     validatorNetworkBin,
			ControlIDs: []string{"CH-NET-001", "CH-NET-002", "CH-NET-003", "CH-NET-004"},
		},
		{
			Name: "audit", DisplayName: "Windows Audit Logging",
			Binary:     validatorAuditBin,
			ControlIDs: []string{"CH-AUD-001", "CH-AUD-002", "CH-AUD-003", "CH-AUD-004", "CH-AUD-005", "CH-AUD-006", "CH-AUD-007", "CH-AUD-008", "CH-AUD-009"},
		},
		{
			Name: "lockout", DisplayName: "Account Lockout Policy",
			Binary:     validatorLockoutBin,
			ControlIDs: []string{"CH-LOK-001", "CH-LOK-002", "CH-LOK-003", "CH-LOK-004", "CH-LOK-005"},
		},
		{
			Name: "laps", DisplayName: "LAPS",
			Binary:     validatorLapsBin,
			ControlIDs: []string{"CH-LAP-001", "CH-LAP-002"},
		},
		{
			Name: "printspooler", DisplayName: "Print Spooler Hardening",
			Binary:     validatorPrintspoolerBin,
			ControlIDs: []string{"CH-PRT-001", "CH-PRT-002"},
		},
	}

	// Execute validators: extract -> quarantine check -> run -> collect results
	startedAt := time.Now().UTC().Format(time.RFC3339)
	fmt.Println()

	allControls := make([]ControlResult, 0, 48)
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "baseline", fmt.Sprintf("extraction failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "baseline", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 4. Execute validator subprocess
		exitCode, err := ExecuteValidator(exePath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "baseline", fmt.Sprintf("execution failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "baseline", fmt.Sprintf("output read failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		// 6. Convert to control results and track status
		// If validator ran but produced 0 checks (e.g., prerequisite not met), mark controls as skipped
		if output.TotalChecks == 0 {
			reason := fmt.Sprintf("validator returned no checks (exit %d) - prerequisite not met", exitCode)
			fmt.Printf("       [SKIPPED] %s\n", reason)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "baseline", reason)
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "baseline", output)
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
		BundleSubcategory: "baseline",
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
		outcomeDescription = "All validators passed - endpoint is properly hardened"
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
		outcomeDescription = fmt.Sprintf("Validators: %s - security gaps detected", strings.Join(parts, ", "))
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators OK (%s)",
			validatorsPassed, len(validators), strings.Join(parts, ", ")))
	}

	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)

	os.Exit(exitCode)
}

// printBanner displays the test banner
func printBanner() {
	fmt.Println("==================================================================")
	fmt.Println("  F0RT1KA Cyber-Hygiene Bundle - CrowdStrike Falcon Edition v1")
	fmt.Println("  Multi-Binary Architecture (quarantine-resilient)")
	fmt.Println("==================================================================")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 10 security configurations (independent validator binaries)...")
}

// printSummary displays the final summary
func printSummary(passed, failed, skipped, checksPassed, checksFailed, checksSkipped int, failedNames, skippedNames []string) {
	total := passed + failed + skipped
	fmt.Println("\n==================================================================")
	fmt.Println("                        SUMMARY")
	fmt.Println("==================================================================")
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
	fmt.Println("==================================================================")
}
