//go:build linux
// +build linux

/*
ID: 7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8
NAME: CIS Linux Endpoint Level 1 Hardening Bundle
TECHNIQUES: T1562.001, T1021.004, T1548.001, T1059.004, T1070.002, T1543.002
TACTICS: defense-evasion, lateral-movement, privilege-escalation, execution, persistence
SEVERITY: high
TARGET: linux-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: cis-linux-l1
TAGS: cis-benchmark, level-1, linux-hardening, compliance, ssh, firewall, audit, pam
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
	TEST_UUID = "7f0d43e7-8a7b-48f3-9aff-cfa9703a51e8"
	TEST_NAME = "CIS Linux Endpoint Level 1 Hardening Bundle"
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
	//go:embed validator-filesystem
	validatorFilesystemBin []byte
	//go:embed validator-services
	validatorServicesBin []byte
	//go:embed validator-network
	validatorNetworkBin []byte
	//go:embed validator-auditlog
	validatorAuditlogBin []byte
	//go:embed validator-sshconfig
	validatorSshconfigBin []byte
	//go:embed validator-accessctl
	validatorAccessctlBin []byte
	//go:embed validator-sysmaint
	validatorSysmaintBin []byte
)

func main() {
	printBanner()

	// Check for root privileges
	if !IsAdmin() {
		fmt.Println("\n[ERROR] This test requires root privileges.")
		fmt.Println("        Please run with sudo or as root.")
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
			"T1021.004", // Remote Services: SSH
			"T1548.001", // Abuse Elevation Control Mechanism: Setuid and Setgid
			"T1059.004", // Command and Scripting Interpreter: Unix Shell
			"T1070.002", // Indicator Removal: Clear Linux or Mac System Logs
			"T1543.002", // Create or Modify System Process: Systemd Service
		},
		Tactics: []string{
			"defense-evasion",
			"lateral-movement",
			"privilege-escalation",
			"execution",
			"persistence",
		},
		Score: 9.2,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.9,
			LoggingObservability:    1.0,
		},
		Tags: []string{"cis-benchmark", "level-1", "linux-hardening", "compliance", "ssh", "firewall", "audit", "pam"},
	}

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000,
			CertificateMode:   "none",
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)
	LogPhaseStart(1, "Multi-Binary CIS Linux L1 Validation")

	// Define all validators with embedded binaries and expected control IDs
	validators := []ValidatorDef{
		{
			Name: "filesystem", DisplayName: "Filesystem Security",
			Binary:     validatorFilesystemBin,
			ControlIDs: []string{"CH-CL1-001", "CH-CL1-002", "CH-CL1-003", "CH-CL1-004"},
		},
		{
			Name: "services", DisplayName: "Service Hardening",
			Binary:     validatorServicesBin,
			ControlIDs: []string{"CH-CL1-005", "CH-CL1-006", "CH-CL1-007", "CH-CL1-008"},
		},
		{
			Name: "network", DisplayName: "Network Security",
			Binary:     validatorNetworkBin,
			ControlIDs: []string{"CH-CL1-009", "CH-CL1-010", "CH-CL1-011", "CH-CL1-012", "CH-CL1-013"},
		},
		{
			Name: "auditlog", DisplayName: "Audit & Logging",
			Binary:     validatorAuditlogBin,
			ControlIDs: []string{"CH-CL1-014", "CH-CL1-015", "CH-CL1-016", "CH-CL1-017", "CH-CL1-018"},
		},
		{
			Name: "sshconfig", DisplayName: "SSH Configuration",
			Binary:     validatorSshconfigBin,
			ControlIDs: []string{"CH-CL1-019", "CH-CL1-020", "CH-CL1-021", "CH-CL1-022", "CH-CL1-023", "CH-CL1-024"},
		},
		{
			Name: "accessctl", DisplayName: "Access Control",
			Binary:     validatorAccessctlBin,
			ControlIDs: []string{"CH-CL1-025", "CH-CL1-026", "CH-CL1-027", "CH-CL1-028", "CH-CL1-029", "CH-CL1-030"},
		},
		{
			Name: "sysmaint", DisplayName: "System Maintenance",
			Binary:     validatorSysmaintBin,
			ControlIDs: []string{"CH-CL1-031", "CH-CL1-032", "CH-CL1-033", "CH-CL1-034", "CH-CL1-035"},
		},
	}

	// Execute validators: extract -> quarantine check -> run -> collect results
	startedAt := time.Now().UTC().Format(time.RFC3339)
	fmt.Println()

	allControls := make([]ControlResult, 0, 35)
	validatorsPassed := 0
	validatorsFailed := 0
	validatorsSkipped := 0
	failedNames := []string{}
	skippedNames := []string{}

	for i, vd := range validators {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(validators), vd.DisplayName)

		// 1. Extract validator binary
		binPath, err := ExtractValidator(vd.Name, vd.Binary)
		if err != nil {
			fmt.Printf("       [ERROR] Extract failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-linux-l1", fmt.Sprintf("extraction failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 2. Brief delay for EDR/AV to react
		time.Sleep(QUARANTINE_DELAY)

		// 3. Check if quarantined
		if IsQuarantined(binPath) {
			fmt.Printf("       [SKIPPED] Validator quarantined by EDR/AV\n")
			LogMessage("WARNING", vd.DisplayName, "Validator binary quarantined by endpoint protection")
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-linux-l1", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		// 4. Execute validator subprocess
		exitCode, err := ExecuteValidator(binPath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-linux-l1", fmt.Sprintf("execution failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-linux-l1", fmt.Sprintf("output read failed: %v", err))
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
			controls := MakeSkippedControls(vd, "cyber-hygiene", "cis-linux-l1", reason)
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "cis-linux-l1", output)
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
		BundleSubcategory: "cis-linux-l1",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		OverallExitCode:   overallExitCode,
		TotalControls:     len(allControls),
		PassedControls:    totalPassed,
		FailedControls:    totalFailed,
		Controls:          allControls,
	}

	if err := WriteBundleResultsLocal(bundleResults); err != nil {
		fmt.Printf("\n[WARNING] Failed to write bundle_results.json: %v\n", err)
	} else {
		fmt.Printf("\n[INFO] Bundle results written to /tmp/F0/bundle_results.json (%d controls)\n", len(allControls))
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
		outcomeDescription = "All validators passed - endpoint is properly hardened per CIS Linux L1"
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
		outcomeDescription = fmt.Sprintf("Validators: %s - CIS L1 security gaps detected", strings.Join(parts, ", "))
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
	fmt.Println("  F0RT1KA CIS Linux Endpoint Level 1 Hardening Bundle v1.0")
	fmt.Println("  Multi-Binary Architecture (quarantine-resilient)")
	fmt.Println("==================================================================")
	fmt.Printf("\nTest UUID: %s\n", TEST_UUID)
	fmt.Printf("Version:   %s\n", VERSION)
	fmt.Printf("Time:      %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 7 CIS Linux L1 security categories (35 controls)...")
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
