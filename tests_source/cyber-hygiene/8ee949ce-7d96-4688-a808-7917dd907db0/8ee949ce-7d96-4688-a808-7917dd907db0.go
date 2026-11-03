//go:build windows

/*
ID: 8ee949ce-7d96-4688-a808-7917dd907db0
NAME: Cyber-Hygiene Bundle (Sophos Intercept X Edition)
TECHNIQUES: T1562.001, T1003.001, T1059.001, T1021.002, T1110, T1557.001, T1572, T1078.003, T1569.002, T1547.012, T1078, T1136, T1098
TACTICS: defense-evasion, credential-access, execution, lateral-movement, command-and-control, persistence, privilege-escalation
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: baseline
TAGS: cyber-hygiene, sophos, intercept-x, edr, hardening, compliance, bundle
INTEGRATIONS: sophos
SOURCE_URL: N/A
UNIT: response
CREATED: 2026-11-03
AUTHOR: sectest-builder
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cyberhygiene "f0_library/tests_source/cyber-hygiene/shared"
	"github.com/google/uuid"
)

const (
	TestUUID          = "8ee949ce-7d96-4688-a808-7917dd907db0"
	TestName          = "Cyber-Hygiene Bundle (Sophos Intercept X Edition)"
	TestVersion       = "1.0.0"
	ExitTestError     = 999
	ExitTimeout       = 102
	AssessmentTimeout = 10 * time.Minute
)

func main() {
	defer func() {
		if recovered := recover(); recovered != nil {
			SaveLog(ExitTestError, fmt.Sprintf("test panic: %v", recovered))
			os.Exit(ExitTestError)
		}
	}()
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		fmt.Printf("failed to create %s: %v\n", LOG_DIR, err)
		os.Exit(ExitTestError)
	}
	orgInfo := ResolveOrganization("")
	endpointContext, contextErr := cyberhygiene.DiscoverEndpointContext()
	metadata := TestMetadata{
		Version:       TestVersion,
		Category:      "cyber-hygiene",
		Severity:      "high",
		Techniques:    []string{"T1562.001", "T1003.001", "T1059.001", "T1021.002", "T1110", "T1557.001", "T1572", "T1078.003", "T1569.002", "T1547.012", "T1078", "T1136", "T1098"},
		Tactics:       []string{"defense-evasion", "credential-access", "execution", "lateral-movement", "command-and-control", "persistence", "privilege-escalation"},
		Score:         8.5,
		RubricVersion: "v2.1",
		Tags:          []string{"cyber-hygiene", "sophos", "intercept-x", "edr", "hardening", "compliance", "bundle"},
	}
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration:  &ExecutionConfiguration{TimeoutMs: 600000, CertificateMode: "self-healing"},
	}
	InitLogger(TestUUID, TestName, metadata, executionContext)
	watchdog := time.AfterFunc(AssessmentTimeout, func() {
		LogMessage("ERROR", "Timeout", "Assessment exceeded the 10-minute watchdog")
		LogPhaseEnd(1, "failed", "Assessment watchdog expired")
		SaveLog(ExitTimeout, "Assessment watchdog expired")
		os.Exit(ExitTimeout)
	})
	defer watchdog.Stop()
	LogPhaseStart(1, "Sophos Endpoint and Windows Baseline Validation")
	startedAt := time.Now().UTC().Format(time.RFC3339)

	controls := cyberhygiene.WindowsBaselineChecks(endpointContext)
	controls = append(controls, RunSophosChecks()...)
	for i := range controls {
		controls[i].Category = "cyber-hygiene"
		controls[i].Subcategory = "baseline"
		cyberhygiene.FinalizeControlResult(&controls[i])
		fmt.Printf("[%s] %s — %s\n", controls[i].Status, controls[i].ControlName, controls[i].Actual)
	}
	contextError := ""
	if contextErr != nil {
		contextError = contextErr.Error()
		LogMessage("WARNING", "System Context", contextError)
	}
	bundle := &cyberhygiene.BundleResults{
		SchemaVersion:     "1.1",
		BundleID:          TestUUID,
		BundleName:        TestName,
		BundleCategory:    "cyber-hygiene",
		BundleSubcategory: "baseline",
		ExecutionID:       executionContext.ExecutionID,
		StartedAt:         startedAt,
		EndpointContext:   &endpointContext,
		ContextError:      contextError,
		Controls:          controls,
	}
	cyberhygiene.FinalizeBundleResults(bundle)
	if err := writeBundleResults(bundle); err != nil {
		LogMessage("ERROR", "Results", err.Error())
		SaveLog(ExitTestError, err.Error())
		os.Exit(ExitTestError)
	}
	fmt.Printf("Summary: %d passed, %d failed, %d unknown; compliance=%s, execution=%s\n",
		bundle.PassedControls, bundle.FailedControls, bundle.UnknownControls, bundle.ComplianceStatus, bundle.ExecutionStatus)
	phaseStatus := "failed"
	if bundle.ComplianceStatus == "compliant" {
		phaseStatus = "success"
	}
	LogPhaseEnd(1, phaseStatus, fmt.Sprintf("%s: %d of %d controls compliant", bundle.ComplianceStatus, bundle.PassedControls, bundle.PassedControls+bundle.FailedControls))
	SaveLog(bundle.OverallExitCode, bundle.ComplianceStatus)
	os.Exit(bundle.OverallExitCode)
}

func writeBundleResults(bundle *cyberhygiene.BundleResults) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle results: %w", err)
	}
	path := filepath.Join(LOG_DIR, "bundle_results.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write bundle results: %w", err)
	}
	return nil
}
