//go:build windows
// +build windows

/*
ID: a26a91b2-8d59-410b-9f5e-7ec5ffb6734c
NAME: ISACA ITGC AD Identity Validation Bundle
TECHNIQUES: T1078.002, T1078.001, T1558.003, T1078.003
TACTICS: defense-evasion, credential-access, persistence, privilege-escalation
SEVERITY: critical
TARGET: active-directory, windows-server
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: isaca-itgc-ad-identity
TAGS: isaca, itgc, cisa, cobit-2019, audit, compliance, active-directory, dormant-accounts, service-accounts, laps
ISACA_CONTROLS: ITGC-AM-003, ITGC-AM-004, ITGC-NS-003
CISA_DOMAINS: D5
COBIT_OBJECTIVES: DSS05.04
SOURCE_URL: https://www.isaca.org/credentialing/cisa
UNIT: response
CREATED: 2026-04-25
AUTHOR: sectest-builder
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TEST_UUID = "a26a91b2-8d59-410b-9f5e-7ec5ffb6734c"
	TEST_NAME = "ISACA ITGC AD Identity Validation Bundle"
	VERSION   = "0.1.0"

	EXIT_COMPLIANT     = 126
	EXIT_NON_COMPLIANT = 101
	EXIT_ERROR         = 999

	TARGET_DIR = `c:\F0`
)

func main() {
	printBanner()

	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		fmt.Printf("\n[ERROR] Failed to create target directory %s: %v\n", TARGET_DIR, err)
		os.Exit(EXIT_ERROR)
	}

	// AD pre-flight: domain-joined + RSAT + DC reachable
	fmt.Println("\nValidating Active Directory prerequisites...")
	domainName, err := ADPreFlight()
	if err != nil {
		fmt.Printf("\n[ERROR] Active Directory pre-flight failed:\n  %v\n", err)
		fmt.Println("\nThis bundle must run on a host that is:")
		fmt.Println("  1. Domain-joined to the AD forest you want to audit")
		fmt.Println("  2. Has the RSAT ActiveDirectory PowerShell module installed")
		fmt.Println("  3. Can reach a domain controller")
		os.Exit(EXIT_ERROR)
	}
	fmt.Printf("  Connected to domain: %s\n", domainName)

	orgInfo := ResolveOrganization("")

	metadata := TestMetadata{
		Version:  VERSION,
		Category: "cyber-hygiene",
		Severity: "critical",
		Techniques: []string{
			"T1078.002", // Valid Accounts: Domain Accounts
			"T1078.001", // Default Accounts (dormant)
			"T1558.003", // Kerberoasting (service accts via SPN)
			"T1078.003", // Local Accounts (LAPS managed)
		},
		Tactics: []string{
			"defense-evasion",
			"credential-access",
			"persistence",
			"privilege-escalation",
		},
		Score:         8.5,
		RubricVersion: "v2.1",
		Tags:          []string{"isaca", "itgc", "active-directory", "dormant-accounts", "service-accounts", "laps", "compliance"},
		IsacaControlIDs: []string{
			"ITGC-AM-003", // Dormant Accounts
			"ITGC-AM-004", // Service Account Permissions
			"ITGC-NS-003", // LAPS Deployment
		},
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
	LogPhaseStart(1, "ISACA ITGC AD Identity Validation")

	startedAt := time.Now().UTC().Format(time.RFC3339)
	hostname, _ := os.Hostname()

	// Run the single AD-Identity validator (3 checks rolled into one validator)
	fmt.Println("\n[1/1] AD Identity Controls (AM-003, AM-004, NS-003)")
	result := RunADIdentityChecks()

	for i, check := range result.Checks {
		if i == len(result.Checks)-1 {
			fmt.Println(FormatLastCheckResult(check))
		} else {
			fmt.Println(FormatCheckResult(check))
		}
	}

	// Convert to ControlResults for bundle_results.json
	controls := CollectControlResults(result.Name, "cyber-hygiene", "isaca-itgc-ad-identity", result.Checks)

	totalPassed := 0
	totalFailed := 0
	totalSkipped := 0
	for _, c := range controls {
		if c.Skipped {
			totalSkipped++
		} else if c.Compliant {
			totalPassed++
		} else {
			totalFailed++
		}
	}

	overallExitCode := EXIT_COMPLIANT
	if totalFailed > 0 {
		overallExitCode = EXIT_NON_COMPLIANT
	}

	bundleResults := &BundleResults{
		SchemaVersion:     "1.0",
		BundleID:          TEST_UUID,
		BundleName:        TEST_NAME,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "isaca-itgc-ad-identity",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		OverallExitCode:   overallExitCode,
		TotalControls:     len(controls),
		PassedControls:    totalPassed,
		FailedControls:    totalFailed,
		Controls:          controls,
	}
	if err := WriteBundleResults(bundleResults); err != nil {
		fmt.Printf("\n[WARNING] Failed to write bundle_results.json: %v\n", err)
	} else {
		fmt.Printf("\n[INFO] Bundle results written to %s\\bundle_results.json (%d controls)\n", TARGET_DIR, len(controls))
	}

	// ITGC auditor workpaper output (per-control sidecars + aggregated workpaper)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	workpaper := buildWorkpaper(controls, hostname, timestamp, executionContext.ExecutionID, orgInfo.UUID, startedAt)
	for _, ev := range workpaper.Controls {
		if err := writeITGCEvidence(ev); err != nil {
			fmt.Printf("[WARNING] Failed to write evidence for %s: %v\n", ev.ControlID, err)
		}
	}
	if err := writeITGCWorkpaper(workpaper); err != nil {
		fmt.Printf("[WARNING] Failed to write itgc_audit_workpaper.json: %v\n", err)
	} else {
		fmt.Printf("[INFO] Auditor workpaper written to %s\\itgc_audit_workpaper.json\n", TARGET_DIR)
	}

	// Print summary + outcome
	printSummary(totalPassed, totalFailed, totalSkipped, len(controls))

	var exitCode int
	var outcome string
	var outcomeDescription string
	if totalFailed == 0 && totalSkipped == 0 {
		exitCode = EXIT_COMPLIANT
		outcome = "compliant"
		outcomeDescription = "All ITGC AD-identity controls compliant"
		LogMessage("INFO", "Result", fmt.Sprintf("COMPLIANT: %d/%d controls passed", totalPassed, len(controls)))
	} else {
		exitCode = EXIT_NON_COMPLIANT
		outcome = "non_compliant"
		outcomeDescription = fmt.Sprintf("%d failed, %d skipped — auditor review required", totalFailed, totalSkipped)
		LogMessage("WARNING", "Result", fmt.Sprintf("NON-COMPLIANT: %d failed, %d skipped", totalFailed, totalSkipped))
	}
	LogPhaseEnd(1, outcome, outcomeDescription)
	SaveLog(exitCode, outcomeDescription)
	os.Exit(exitCode)
}

func printBanner() {
	fmt.Println("+=======================================================================+")
	fmt.Println("|  F0RT1KA ISACA ITGC AD Identity Validation Bundle                      |")
	fmt.Println("|  Single-binary AD audit (RSAT + domain join required)                  |")
	fmt.Println("+=======================================================================+")
	fmt.Printf("\nTest UUID:    %s\n", TEST_UUID)
	fmt.Printf("Version:      %s\n", VERSION)
	fmt.Printf("Time:         %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("\nValidating 3 ISACA ITGC AD-identity controls (AM-003, AM-004, NS-003)...")
	fmt.Println("Output: bundle_results.json + itgc_audit_workpaper.json")
}

func printSummary(passed, failed, skipped, total int) {
	fmt.Println("\n=======================================================================")
	fmt.Println("                    ISACA ITGC AD-IDENTITY SUMMARY")
	fmt.Println("=======================================================================")
	fmt.Printf("  Controls Passed:    %d/%d\n", passed, total)
	fmt.Printf("  Controls Failed:    %d/%d\n", failed, total)
	if skipped > 0 {
		fmt.Printf("  Controls Skipped:   %d/%d\n", skipped, total)
	}
	fmt.Println()
	if failed == 0 && skipped == 0 {
		fmt.Println("  RESULT: ITGC COMPLIANT (Exit Code: 126)")
	} else {
		fmt.Println("  RESULT: NON-COMPLIANT — auditor review required (Exit Code: 101)")
	}
	fmt.Println("=======================================================================")
}

// ITGC evidence sidecar (per-control + aggregated workpaper).
// Mirrors orchestrator_utils.go in the Windows-Endpoint bundle.

type ITGCEvidence struct {
	ControlID      string                 `json:"control_id"`
	ControlName    string                 `json:"control_name"`
	Description    string                 `json:"description"`
	Status         string                 `json:"status"` // PASS | FAIL | SKIPPED
	Severity       string                 `json:"severity"`
	CisaDomain     string                 `json:"cisa_domain,omitempty"`
	CobitObjective string                 `json:"cobit_objective,omitempty"`
	CisV8Mapping   string                 `json:"cis_v8_mapping,omitempty"`
	MitreAttack    []string               `json:"mitre_attack,omitempty"`
	ManualResidual string                 `json:"manual_residual,omitempty"`
	Expected       string                 `json:"expected,omitempty"`
	Actual         string                 `json:"actual,omitempty"`
	Details        string                 `json:"details,omitempty"`
	Evidence       map[string]interface{} `json:"evidence,omitempty"`
	Hostname       string                 `json:"hostname"`
	Timestamp      string                 `json:"timestamp"`
}

type ITGCWorkpaper struct {
	BundleID      string         `json:"bundle_id"`
	BundleName    string         `json:"bundle_name"`
	ExecutionID   string         `json:"execution_id"`
	Organization  string         `json:"organization"`
	Hostname      string         `json:"hostname"`
	StartedAt     string         `json:"started_at"`
	CompletedAt   string         `json:"completed_at"`
	TotalControls int            `json:"total_controls"`
	Passed        int            `json:"passed"`
	Failed        int            `json:"failed"`
	Skipped       int            `json:"skipped"`
	Controls      []ITGCEvidence `json:"controls"`
}

func mapWorkpaperStatus(c ControlResult) string {
	if c.Skipped {
		return "SKIPPED"
	}
	if c.Compliant {
		return "PASS"
	}
	return "FAIL"
}

func buildWorkpaper(controls []ControlResult, hostname, timestamp, executionID, org, startedAt string) *ITGCWorkpaper {
	wp := &ITGCWorkpaper{
		BundleID:     TEST_UUID,
		BundleName:   TEST_NAME,
		ExecutionID:  executionID,
		Organization: org,
		Hostname:     hostname,
		StartedAt:    startedAt,
		CompletedAt:  time.Now().UTC().Format(time.RFC3339),
		Controls:     make([]ITGCEvidence, 0, len(controls)),
	}
	for _, c := range controls {
		wp.Controls = append(wp.Controls, ITGCEvidence{
			ControlID:      c.ControlID,
			ControlName:    c.ControlName,
			Description:    c.Details,
			Status:         mapWorkpaperStatus(c),
			Severity:       c.Severity,
			CisaDomain:     c.CisaDomain,
			CobitObjective: c.CobitObjective,
			CisV8Mapping:   c.CisV8Mapping,
			MitreAttack:    c.Techniques,
			ManualResidual: c.ManualResidual,
			Expected:       c.Expected,
			Actual:         c.Actual,
			Details:        c.Details,
			Evidence:       c.Evidence,
			Hostname:       hostname,
			Timestamp:      timestamp,
		})
		switch mapWorkpaperStatus(c) {
		case "PASS":
			wp.Passed++
		case "FAIL":
			wp.Failed++
		case "SKIPPED":
			wp.Skipped++
		}
	}
	wp.TotalControls = len(controls)
	return wp
}

func writeITGCEvidence(ev ITGCEvidence) error {
	safeID := strings.ReplaceAll(strings.ReplaceAll(ev.ControlID, "/", "_"), "\\", "_")
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ITGC evidence for %s: %v", ev.ControlID, err)
	}
	outputPath := filepath.Join(TARGET_DIR, fmt.Sprintf("itgc_evidence_%s.json", safeID))
	return os.WriteFile(outputPath, data, 0644)
}

func writeITGCWorkpaper(wp *ITGCWorkpaper) error {
	data, err := json.MarshalIndent(wp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ITGC workpaper: %v", err)
	}
	outputPath := filepath.Join(TARGET_DIR, "itgc_audit_workpaper.json")
	return os.WriteFile(outputPath, data, 0644)
}
