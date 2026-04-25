//go:build windows
// +build windows

/*
ID: db0738eb-848e-442b-b43c-208029063fe9
NAME: ISACA ITGC Windows Endpoint Validation Bundle
TECHNIQUES: T1078, T1110, T1078.001, T1562.001, T1562.004, T1059.001, T1021.001, T1490, T1486
TACTICS: defense-evasion, credential-access, lateral-movement, execution, impact, persistence
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: isaca-itgc-windows
TAGS: isaca, itgc, cisa, cobit-2019, audit, compliance, ciso-evidence, workpaper
ISACA_CONTROLS: ITGC-AM-001, ITGC-AM-002, ITGC-AM-005, ITGC-CM-001, ITGC-CM-002, ITGC-CM-003, ITGC-CM-004, ITGC-CM-005, ITGC-LM-001, ITGC-LM-002, ITGC-LM-003, ITGC-LM-004, ITGC-LM-005, ITGC-EP-001, ITGC-EP-002, ITGC-EP-003, ITGC-EP-004, ITGC-EP-005, ITGC-EP-006, ITGC-BR-001, ITGC-BR-002, ITGC-BR-003, ITGC-NS-001, ITGC-NS-002, ITGC-NS-004, ITGC-GV-001, ITGC-GV-002, ITGC-GV-003, ITGC-GV-004, ITGC-GV-005, ITGC-GV-006
CISA_DOMAINS: D2, D4, D5
COBIT_OBJECTIVES: APO13.01, BAI06.01, BAI09.01, DSS01.05, DSS04.01, DSS05.01, DSS05.02, DSS05.04, DSS05.05, DSS05.06, DSS05.07
SOURCE_URL: https://www.isaca.org/credentialing/cisa
UNIT: response
CREATED: 2026-04-25
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
	TEST_UUID = "db0738eb-848e-442b-b43c-208029063fe9"
	TEST_NAME = "ISACA ITGC Windows Endpoint Validation Bundle"
	VERSION   = "0.1.0"

	EXIT_COMPLIANT     = 126
	EXIT_NON_COMPLIANT = 101
	EXIT_ERROR         = 999

	TARGET_DIR       = `c:\F0`
	QUARANTINE_DELAY = 1500 * time.Millisecond
)

// Embedded signed validator binaries (populated by build_all.sh).
// Each validator covers one ISACA ITGC control family for the Windows-endpoint scope.
var (
	//go:embed validator-am.exe
	validatorAMBin []byte
	//go:embed validator-cm.exe
	validatorCMBin []byte
	//go:embed validator-lm.exe
	validatorLMBin []byte
	//go:embed validator-ep.exe
	validatorEPBin []byte
	//go:embed validator-br.exe
	validatorBRBin []byte
	//go:embed validator-ns.exe
	validatorNSBin []byte
	//go:embed validator-gv.exe
	validatorGVBin []byte
)

func main() {
	printBanner()

	if !IsAdmin() {
		fmt.Println("\n[ERROR] This bundle requires administrator privileges.")
		fmt.Println("        ISACA ITGC validation reads protected registry keys, audit policy,")
		fmt.Println("        BitLocker state, and Security event logs. Re-run from elevated prompt.")
		os.Exit(EXIT_ERROR)
	}

	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		fmt.Printf("\n[ERROR] Failed to create target directory %s: %v\n", TARGET_DIR, err)
		os.Exit(EXIT_ERROR)
	}

	orgInfo := ResolveOrganization("")

	metadata := TestMetadata{
		Version:  VERSION,
		Category: "cyber-hygiene",
		Severity: "high",
		Techniques: []string{
			"T1078",     // Valid Accounts
			"T1110",     // Brute Force (password policy)
			"T1078.001", // Default Accounts
			"T1562.001", // Disable or Modify Tools (AV/EDR, audit log)
			"T1562.004", // Disable or Modify System Firewall
			"T1059.001", // PowerShell
			"T1021.001", // Remote Desktop Protocol
			"T1490",     // Inhibit System Recovery (VSS / backup)
			"T1486",     // Data Encrypted for Impact (CFA / ransomware)
		},
		Tactics: []string{
			"defense-evasion",
			"credential-access",
			"lateral-movement",
			"execution",
			"impact",
			"persistence",
		},
		Score:         8.5,
		RubricVersion: "v2.1",
		Tags:          []string{"isaca", "itgc", "cisa", "cobit-2019", "audit", "compliance", "workpaper"},
		IsacaControlIDs: []string{
			"ITGC-AM-001", "ITGC-AM-002", "ITGC-AM-005",
			"ITGC-CM-001", "ITGC-CM-002", "ITGC-CM-003", "ITGC-CM-004", "ITGC-CM-005",
			"ITGC-LM-001", "ITGC-LM-002", "ITGC-LM-003", "ITGC-LM-004", "ITGC-LM-005",
			"ITGC-EP-001", "ITGC-EP-002", "ITGC-EP-003", "ITGC-EP-004", "ITGC-EP-005", "ITGC-EP-006",
			"ITGC-BR-001", "ITGC-BR-002", "ITGC-BR-003",
			"ITGC-NS-001", "ITGC-NS-002", "ITGC-NS-004",
			"ITGC-GV-001", "ITGC-GV-002", "ITGC-GV-003", "ITGC-GV-004", "ITGC-GV-005", "ITGC-GV-006",
		},
		CisaDomains:     []string{"D2", "D4", "D5"},
		CobitObjectives: []string{"APO13.01", "BAI06.01", "BAI09.01", "DSS01.05", "DSS04.01", "DSS05.04"},
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
	LogPhaseStart(1, "ISACA ITGC Windows Endpoint Validation")

	validators := []ValidatorDef{
		{
			Name: "am", DisplayName: "Access Management",
			Binary:     validatorAMBin,
			ControlIDs: []string{"ITGC-AM-001", "ITGC-AM-002", "ITGC-AM-005"},
		},
		{
			Name: "cm", DisplayName: "Change Management",
			Binary:     validatorCMBin,
			ControlIDs: []string{"ITGC-CM-001", "ITGC-CM-002", "ITGC-CM-003", "ITGC-CM-004", "ITGC-CM-005"},
		},
		{
			Name: "lm", DisplayName: "Logging & Monitoring",
			Binary:     validatorLMBin,
			ControlIDs: []string{"ITGC-LM-001", "ITGC-LM-002", "ITGC-LM-003", "ITGC-LM-004", "ITGC-LM-005"},
		},
		{
			Name: "ep", DisplayName: "Endpoint Protection",
			Binary:     validatorEPBin,
			ControlIDs: []string{"ITGC-EP-001", "ITGC-EP-002", "ITGC-EP-003", "ITGC-EP-004", "ITGC-EP-005", "ITGC-EP-006"},
		},
		{
			Name: "br", DisplayName: "Backup & Recovery",
			Binary:     validatorBRBin,
			ControlIDs: []string{"ITGC-BR-001", "ITGC-BR-002", "ITGC-BR-003"},
		},
		{
			Name: "ns", DisplayName: "Network Security",
			Binary:     validatorNSBin,
			ControlIDs: []string{"ITGC-NS-001", "ITGC-NS-002", "ITGC-NS-004"},
		},
		{
			Name: "gv", DisplayName: "Governance & Policy",
			Binary:     validatorGVBin,
			ControlIDs: []string{"ITGC-GV-001", "ITGC-GV-002", "ITGC-GV-003", "ITGC-GV-004", "ITGC-GV-005", "ITGC-GV-006"},
		},
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)
	hostname, _ := os.Hostname()
	fmt.Println()

	allControls := make([]ControlResult, 0, 31)
	validatorsPassed := 0
	validatorsFailed := 0
	validatorsSkipped := 0
	failedNames := []string{}
	skippedNames := []string{}

	for i, vd := range validators {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(validators), vd.DisplayName)

		exePath, err := ExtractValidator(vd.Name, vd.Binary)
		if err != nil {
			fmt.Printf("       [ERROR] Extract failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "isaca-itgc-windows", fmt.Sprintf("extraction failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		time.Sleep(QUARANTINE_DELAY)

		if IsQuarantined(exePath) {
			fmt.Printf("       [SKIPPED] Validator quarantined by EDR/AV\n")
			LogMessage("WARNING", vd.DisplayName, "Validator binary quarantined by endpoint protection")
			controls := MakeSkippedControls(vd, "cyber-hygiene", "isaca-itgc-windows", "validator binary quarantined by endpoint protection")
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			continue
		}

		exitCode, err := ExecuteValidator(exePath)
		if err != nil {
			fmt.Printf("       [ERROR] Execution failed: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "isaca-itgc-windows", fmt.Sprintf("execution failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		output, err := ReadValidatorOutput(vd.Name)
		if err != nil {
			fmt.Printf("       [ERROR] Failed to read results: %v\n", err)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "isaca-itgc-windows", fmt.Sprintf("output read failed: %v", err))
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		if output.TotalChecks == 0 {
			reason := fmt.Sprintf("validator returned no checks (exit %d) - prerequisite not met", exitCode)
			fmt.Printf("       [SKIPPED] %s\n", reason)
			controls := MakeSkippedControls(vd, "cyber-hygiene", "isaca-itgc-windows", reason)
			allControls = append(allControls, controls...)
			validatorsSkipped++
			skippedNames = append(skippedNames, vd.DisplayName)
			CleanupValidator(vd.Name)
			continue
		}

		controls := ConvertOutputToControls(vd.DisplayName, "cyber-hygiene", "isaca-itgc-windows", output)
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

	overallExitCode := EXIT_COMPLIANT
	if validatorsFailed > 0 || validatorsSkipped > 0 {
		overallExitCode = EXIT_NON_COMPLIANT
	}

	bundleResults := &BundleResults{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "isaca-itgc-windows",
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
		fmt.Printf("\n[INFO] Bundle results written to %s\\bundle_results.json (%d controls)\n", TARGET_DIR, len(allControls))
	}

	// ITGC auditor workpaper output (per-control sidecars + aggregated workpaper)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	workpaper := &ITGCWorkpaper{
		BundleID:      TEST_UUID,
		BundleName:    TEST_NAME,
		ExecutionID:   executionContext.ExecutionID,
		Organization:  orgInfo.UUID,
		Hostname:      hostname,
		StartedAt:     startedAt,
		TotalControls: len(allControls),
		Passed:        totalPassed,
		Failed:        totalFailed,
		Skipped:       totalSkipped,
		Controls:      make([]ITGCEvidence, 0, len(allControls)),
	}
	for _, c := range allControls {
		ev := BuildITGCEvidence(c, hostname, timestamp)
		workpaper.Controls = append(workpaper.Controls, ev)
		if err := WriteITGCEvidence(ev); err != nil {
			fmt.Printf("[WARNING] Failed to write evidence for %s: %v\n", c.ControlID, err)
		}
	}
	if err := WriteITGCWorkpaper(workpaper); err != nil {
		fmt.Printf("[WARNING] Failed to write itgc_audit_workpaper.json: %v\n", err)
	} else {
		fmt.Printf("[INFO] Auditor workpaper written to %s\\itgc_audit_workpaper.json\n", TARGET_DIR)
	}

	printSummary(validatorsPassed, validatorsFailed, validatorsSkipped, totalPassed, totalFailed, totalSkipped, failedNames, skippedNames, len(allControls))

	var exitCode int
	var outcome string
	var outcomeDescription string

	if validatorsFailed == 0 && validatorsSkipped == 0 {
		exitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All ITGC controls compliant - endpoint meets ISACA ITGC validation baseline"
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
		outcomeDescription = fmt.Sprintf("Validators: %s - ITGC compliance gaps detected (auditor review required)", strings.Join(parts, ", "))
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d/%d validators OK (%s)",
			validatorsPassed, len(validators), strings.Join(parts, ", ")))
	}

	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)

	os.Exit(exitCode)
}

func printBanner() {
	fmt.Println("+=======================================================================+")
	fmt.Println("|  F0RT1KA ISACA ITGC Windows Endpoint Validation Bundle                 |")
	fmt.Println("|  Multi-Binary Architecture (quarantine-resilient, auditor evidence)    |")
	fmt.Println("+=======================================================================+")
	fmt.Printf("\nTest UUID:    %s\n", TEST_UUID)
	fmt.Printf("Version:      %s\n", VERSION)
	fmt.Printf("Time:         %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 7 ISACA ITGC control families (31 endpoint controls)...")
	fmt.Println("Output: bundle_results.json + itgc_audit_workpaper.json (auditor evidence)")
}

func printSummary(passed, failed, skipped, checksPassed, checksFailed, checksSkipped int, failedNames, skippedNames []string, totalControls int) {
	total := passed + failed + skipped
	fmt.Println("\n=======================================================================")
	fmt.Println("                       ISACA ITGC SUMMARY")
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
	fmt.Printf("  Total Controls: %d passed, %d failed, %d skipped (of %d)\n", checksPassed, checksFailed, checksSkipped, totalControls)
	fmt.Println()

	if failed == 0 && skipped == 0 {
		fmt.Println("  RESULT: ITGC COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT — auditor review required (Exit Code: 101)")
	}
	fmt.Println("=======================================================================")
}
