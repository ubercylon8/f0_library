//go:build windows
// +build windows

/*
ID: 208ef54b-06bc-4610-87b6-520aea57517e
NAME: ScreenConnect Unsanctioned RMM Abuse for Third-Party Access
TECHNIQUES: T1199, T1219, T1543.003, T1567.002
TACTICS: command-and-control, persistence, exfiltration
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Black Basta
SUBCATEGORY: c2
TAGS: rmm, screenconnect, connectwise, remote-access, service-install, exfiltration, living-off-trusted-software
SOURCE_URL: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
UNIT: response
CREATED: 2026-07-07
AUTHOR: sectest-builder
*/

// Multi-stage orchestrator for the ScreenConnect (ConnectWise) RMM abuse test.
//
// This test validates whether AV/EDR flags a LEGITIMATE, VENDOR-SIGNED remote
// monitoring & management (RMM) agent being installed and used for unsanctioned
// third-party access — the "living off trusted software" tradecraft used by
// Black Basta and access brokers (mass-exploited post CVE-2024-1709).
//
// The embedded ScreenConnect MSI is genuinely benign and vendor-signed; the
// detection target is the ANOMALOUS install + service creation + relay of an
// unsanctioned RMM, NOT the agent's hash. No live relay is stood up — the agent
// is pointed at an unreachable/controlled URL and no relay secrets are shipped.

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "208ef54b-06bc-4610-87b6-520aea57517e"
	TEST_NAME = "ScreenConnect Unsanctioned RMM Abuse for Third-Party Access"
)

// Embed gzip-compressed, vendor/F0RT1KA-signed stage binaries.
// Compressed at build time (~35% smaller orchestrator); decompressed in memory
// during extraction — files written to disk are normal signed PEs.
// NEVER use UPX or runtime packers (they trigger EDR heuristic/packer detections).
//
//go:embed 208ef54b-06bc-4610-87b6-520aea57517e-T1219.exe.gz
var stage1Compressed []byte

//go:embed 208ef54b-06bc-4610-87b6-520aea57517e-T1543.003.exe.gz
var stage2Compressed []byte

//go:embed 208ef54b-06bc-4610-87b6-520aea57517e-T1567.002.exe.gz
var stage3Compressed []byte

// Embed the cleanup utility (uninstalls the agent + removes the service post-run).
//
//go:embed cleanup_utility.exe.gz
var cleanupCompressed []byte

// KillchainStage represents one technique in the attack chain.
// NOTE: named KillchainStage (not "Stage") to avoid the test_logger.go conflict.
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	// Schema v2.0 metadata + execution context.
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "command_and_control",
		Severity:      "high",
		Techniques:    []string{"T1199", "T1219", "T1543.003", "T1567.002"},
		Tactics:       []string{"command-and-control", "persistence", "exfiltration"},
		Score:         8.4,
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"multi-stage", "rmm", "screenconnect", "connectwise", "remote-access", "living-off-trusted-software"},
	}

	orgInfo := ResolveOrganization("") // default org from registry

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000, // 10 minutes (MSI install can be slow)
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Multi-stage architecture for technique-level detection")
	Endpoint.Say("Threat actor: Black Basta (unsanctioned RMM abuse)")
	Endpoint.Say("")

	test(metadata)
}

func test(metadata TestMetadata) {
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Silent RMM Install",
			Technique:   "T1219",
			BinaryName:  fmt.Sprintf("%s-T1219.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Silently install the embedded vendor-signed ScreenConnect MSI via msiexec /qn",
		},
		{
			ID:          2,
			Name:        "Service Creation + Relay Attempt",
			Technique:   "T1543.003",
			BinaryName:  fmt.Sprintf("%s-T1543.003.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Verify the ScreenConnect Client Windows service is created/running and attempt the outbound relay",
		},
		{
			ID:          3,
			Name:        "Follow-on Data Exfiltration",
			Technique:   "T1567.002",
			BinaryName:  fmt.Sprintf("%s-T1567.002.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Collect decoy data staged in ARTIFACT_DIR and exfiltrate over the RMM foothold to a benign endpoint",
		},
	}

	// Phase 0: extract stage binaries + cleanup utility.
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("Phase 0: Extracting %d stage binaries...", len(killchain))

	for _, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("  [!] FATAL: Failed to extract %s: %v", stage.BinaryName, err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Extraction failed: %v", err))
			finalize()
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		Endpoint.Say("  [+] Extracted: %s", stage.BinaryName)
	}

	// Extract cleanup utility (best-effort; non-fatal).
	if cleanupData, err := decompressGzip(cleanupCompressed); err == nil {
		cleanupPath := filepath.Join(LOG_DIR, "screenconnect_cleanup.exe")
		if werr := os.WriteFile(cleanupPath, cleanupData, 0755); werr == nil {
			Endpoint.Say("  [+] Extracted: screenconnect_cleanup.exe (cleanup utility)")
			LogFileDropped("screenconnect_cleanup.exe", cleanupPath, int64(len(cleanupData)), false)
		} else {
			LogMessage("WARNING", "Extraction", fmt.Sprintf("Failed to write cleanup utility: %v", werr))
		}
	} else {
		LogMessage("WARNING", "Extraction", fmt.Sprintf("Failed to decompress cleanup utility: %v", err))
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("")

	// Per-stage bundle fan-out (one ES doc per technique).
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  metadata.Severity,
			Tactics:   metadata.Tactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain sequentially.
	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d: %s", stage.ID, stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")

		exitCode := executeStage(stage)

		if exitCode == 126 || exitCode == 105 {
			// Positive-evidence block reported by the stage.
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Protection blocked %s (exit %d)", stage.Technique, exitCode)
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("Protection blocked %s (exit %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("A protection layer blocked technique %s at stage %d", stage.Technique, stage.ID)
			Endpoint.Say("Attack chain interrupted.")
			Endpoint.Say("Cleanup: run 'C:\\F0\\screenconnect_cleanup.exe' as Administrator.")
			Endpoint.Say("=================================================================")

			blockCode := Endpoint.ExecutionPrevented
			if exitCode == 105 {
				blockCode = Endpoint.FileQuarantinedOnExtraction
			}
			SaveLog(blockCode, fmt.Sprintf("Blocked at %s (exit %d)", stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			finalize()
			Endpoint.Stop(blockCode)

		} else if exitCode != 0 {
			// Benign / ambiguous failure — NEVER a block (Bug Prevention Rules 5 & 8).
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage error: exit code %d", exitCode))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %s failed with code %d", stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Stage %d ended with error code %d (prerequisite/benign failure — not a block).", stage.ID, exitCode)
			Endpoint.Say("Cleanup: run 'C:\\F0\\screenconnect_cleanup.exe' as Administrator if the agent installed.")
			finalize()
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("%s completed successfully", stage.Technique))
		Endpoint.Say("  Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages succeeded => endpoint did not stop the unsanctioned RMM chain.
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: UNPROTECTED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("The complete unsanctioned-RMM chain executed without prevention:")
	for _, stage := range killchain {
		Endpoint.Say("  - %s: %s", stage.Technique, stage.Name)
	}
	Endpoint.Say("")
	Endpoint.Say("The endpoint allowed:")
	Endpoint.Say("  1. Silent install of a vendor-signed RMM agent (ScreenConnect)")
	Endpoint.Say("  2. Creation + start of the RMM Windows service")
	Endpoint.Say("  3. Outbound relay attempt to an external control endpoint")
	Endpoint.Say("  4. Collection + exfiltration of staged data over the foothold")
	Endpoint.Say("")
	Endpoint.Say("RECOMMENDED ACTIONS:")
	Endpoint.Say("  - Application control / RMM allow-listing (block unsanctioned RMM installs)")
	Endpoint.Say("  - Alert on new service names matching 'ScreenConnect Client (*'")
	Endpoint.Say("  - Egress monitoring for RMM relay destinations")
	Endpoint.Say("  - Run cleanup: C:\\F0\\screenconnect_cleanup.exe")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, "Complete unsanctioned-RMM chain succeeded — all techniques executed")
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
	finalize()
	Endpoint.Stop(Endpoint.Unprotected)
}

// finalize gives monitoring platforms time to read the exit code before process exit.
func finalize() {
	Endpoint.Say("")
	Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
	time.Sleep(5 * time.Second)
}

// extractStage decompresses and writes a gzip-embedded stage binary to LOG_DIR.
func extractStage(stage KillchainStage) error {
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %v", LOG_DIR, err)
	}

	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)
	return nil
}

// decompressGzip decompresses gzip data in memory.
func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %v", err)
	}
	return decompressed, nil
}

// executeStage runs a stage binary and returns its exit code.
func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)

	cmd := exec.Command(stagePath)
	cmd.Dir = LOG_DIR
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, exitErr.Error())
			return code
		}
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
