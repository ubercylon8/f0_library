package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ExitNonCompliant = 101
	ExitCompliant    = 126
	ExitTestError    = 999
)

type probeStatus string

const (
	probeAccepted probeStatus = "accepted"
	probeRejected probeStatus = "rejected"
	probeError    probeStatus = "error"
)

type probeResult struct {
	Runtime  string      `json:"runtime"`
	Case     string      `json:"case"`
	Status   probeStatus `json:"status"`
	Evidence string      `json:"evidence"`
}

func makeControl(id, name, validator string, probes []probeResult, techniques []string) ControlResult {
	control := ControlResult{
		ControlID: id, ControlName: name, Validator: validator,
		Severity: "critical", Category: "cyber-hygiene", Subcategory: "baseline",
		Techniques: techniques, Tactics: []string{"credential-access", "defense-evasion"},
		Expected: "Every compromised certificate chain is rejected",
		Evidence: map[string]interface{}{"probes": probes},
	}
	if len(probes) == 0 {
		control.Skipped = true
		control.Actual = "Not applicable"
		control.Details = "The runtime or validation facility was not found"
		return control
	}

	accepted, rejected, errors := summarizeProbes(probes)
	control.Actual = fmt.Sprintf("%d accepted, %d rejected, %d inconclusive", accepted, rejected, errors)
	control.Evidence["accepted"] = accepted
	control.Evidence["rejected"] = rejected
	control.Evidence["inconclusive"] = errors
	switch {
	case accepted > 0:
		control.ExitCode = ExitNonCompliant
		control.Compliant = false
		control.Details = "At least one compromised chain was accepted by this validation path"
	case errors > 0:
		control.ExitCode = ExitTestError
		control.Compliant = false
		control.Details = "No chain was accepted, but at least one probe could not establish a certificate-based rejection"
		control.ErrorMessage = firstProbeError(probes)
	default:
		control.ExitCode = ExitCompliant
		control.Compliant = true
		control.Details = "All tested compromised chains were rejected with certificate-validation evidence"
	}
	return control
}

func summarizeProbes(probes []probeResult) (accepted, rejected, errors int) {
	for _, probe := range probes {
		switch probe.Status {
		case probeAccepted:
			accepted++
		case probeRejected:
			rejected++
		default:
			errors++
		}
	}
	return
}

func firstProbeError(probes []probeResult) string {
	for _, probe := range probes {
		if probe.Status == probeError {
			return probe.Runtime + " " + probe.Case + ": " + probe.Evidence
		}
	}
	return ""
}

func writeBundle(executionID, startedAt string, controls []ControlResult, overallExit int) error {
	passed, failed := 0, 0
	for _, control := range controls {
		if control.Skipped {
			continue
		}
		if control.Compliant {
			passed++
		} else {
			failed++
		}
	}
	bundle := &BundleResults{
		SchemaVersion: "1.0", BundleID: TEST_UUID, BundleName: TEST_NAME,
		BundleCategory: "cyber-hygiene", BundleSubcategory: "baseline",
		ExecutionID: executionID, StartedAt: startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339), OverallExitCode: overallExit,
		TotalControls: len(controls), PassedControls: passed, FailedControls: failed,
		Controls: controls,
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bundle results: %v", err)
	}
	path := filepath.Join(LOG_DIR, "bundle_results.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write bundle results: %v", err)
	}
	return nil
}

func overallResult(controls []ControlResult) (int, string) {
	assessed, errors, accepted := 0, 0, 0
	for _, control := range controls {
		if control.Skipped {
			continue
		}
		assessed++
		switch control.ExitCode {
		case ExitNonCompliant:
			accepted++
		case ExitTestError:
			errors++
		}
	}
	if accepted > 0 {
		return ExitNonCompliant, fmt.Sprintf("%d validation paths accepted compromised eMudhra chains", accepted)
	}
	if errors > 0 || assessed == 0 {
		return ExitTestError, fmt.Sprintf("Assessment incomplete: %d assessed paths, %d inconclusive paths", assessed, errors)
	}
	return ExitCompliant, fmt.Sprintf("All %d assessed validation paths rejected compromised eMudhra chains", assessed)
}

func printControls(controls []ControlResult) {
	for _, control := range controls {
		status := "PROTECTED"
		switch {
		case control.Skipped:
			status = "NOT ASSESSED"
		case control.ExitCode == ExitNonCompliant:
			status = "EXPOSED"
		case control.ExitCode == ExitTestError:
			status = "INCONCLUSIVE"
		}
		fmt.Printf("[%-12s] %s — %s\n", status, control.ControlName, control.Actual)
		if control.ExitCode == ExitNonCompliant || control.ExitCode == ExitTestError {
			fmt.Printf("               %s\n", strings.TrimSpace(control.Details))
		}
	}
}
