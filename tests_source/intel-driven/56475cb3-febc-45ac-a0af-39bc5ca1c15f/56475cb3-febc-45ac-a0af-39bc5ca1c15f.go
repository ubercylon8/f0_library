//go:build windows
// +build windows

/*
ID: 56475cb3-febc-45ac-a0af-39bc5ca1c15f
NAME: 3CX 3CXDesktopApp Cascading Supply-Chain Compromise
TECHNIQUES: T1195.002, T1574.002, T1497, T1027.003, T1071.001, T1555.003
TACTICS: initial-access, defense-evasion, command-and-control, credential-access
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Lazarus
SUBCATEGORY: supply-chain
TAGS: 3cx, lazarus, unc4736, supply-chain, dll-sideloading, sandbox-evasion, steganography, ico-stego, browser-credential-theft, iconic, trusted-binary
SOURCE_URL: https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise
UNIT: response
CREATED: 2026-07-07
AUTHOR: sectest-builder
*/

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

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TEST_NAME = "3CX 3CXDesktopApp Cascading Supply-Chain Compromise"
)

// Embed gzip-compressed signed stage binaries.
// Compressed at build time to reduce orchestrator size (~35% smaller).
// Decompressed in memory during extraction — files on disk are normal signed PEs.
//
// This orchestrator is F0RT1KA-signed and plays the role of the trusted, validly
// code-signed 3CXDesktopApp. No real 3CX binary or certificate is used — our own
// signing cert stands in for 3CX's, so the "trusted signed vendor app" premise holds
// without shipping or forging anything from 3CX.
//
//go:embed 56475cb3-febc-45ac-a0af-39bc5ca1c15f-T1574.002.exe.gz
var stage1Compressed []byte

//go:embed 56475cb3-febc-45ac-a0af-39bc5ca1c15f-T1497.exe.gz
var stage2Compressed []byte

//go:embed 56475cb3-febc-45ac-a0af-39bc5ca1c15f-T1027.003.exe.gz
var stage3Compressed []byte

//go:embed 56475cb3-febc-45ac-a0af-39bc5ca1c15f-T1555.003.exe.gz
var stage4Compressed []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique in the attack killchain.
// Named to avoid conflict with the test_logger.go Stage struct.
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

// ==============================================================================
// MAIN FUNCTION
// ==============================================================================

func main() {
	// Initialize logger with Schema v2.0 metadata
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "supply_chain",
		Severity:      "critical",
		Techniques:    []string{"T1195.002", "T1574.002", "T1497", "T1027.003", "T1071.001", "T1555.003"},
		Tactics:       []string{"initial-access", "defense-evasion", "command-and-control", "credential-access"},
		Score:         7.6,    // v2.1 — Realism 5.0/7.0 (API 2.0/2.5 [Stage 1 now emits a real LoadLibrary/image-load event], Identifier 1.2/1.5, Telemetry Signal Quality 1.3/2.0 capped pending lab run, Execution-Context 0.5/1.0) + Structure 2.6/3.0 (Schema 1.0/1.0, Docs 1.0/1.0, Logging 0.25/0.5, Op Hygiene 0.35/0.5). Not yet lab-detonated. See info.md Score Breakdown.
		RubricVersion: "v2.1", // Tiered realism-first rubric (active). Safety gate + Realism 0-7 + Structure 0-3.
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct don't match v2.1's tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
		Tags: []string{"3cx", "lazarus", "unc4736", "supply-chain", "dll-sideloading", "sandbox-evasion", "steganography", "ico-stego", "browser-credential-theft", "iconic", "multi-stage", "killchain"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000,
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Threat Actor: Lazarus / UNC4736 (DPRK)")
	Endpoint.Say("Scenario: trusted, validly-signed vendor app behaving anomalously")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "DLL Side-Loading",
			Technique:   "T1574.002",
			BinaryName:  fmt.Sprintf("%s-T1574.002.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Signed parent (3CXDesktopApp role) drops and side-loads a companion DLL (d3dcompiler_47.dll / ffmpeg.dll) from a user-writable app-dir path",
		},
		{
			ID:          2,
			Name:        "Sandbox / Dormancy Evasion",
			Technique:   "T1497",
			BinaryName:  fmt.Sprintf("%s-T1497.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "VM-artifact, uptime and domain-join checks representing the real 7-day dormancy (intended sleep logged, not slept)",
		},
		{
			ID:          3,
			Name:        "Steganographic C2 Config",
			Technique:   "T1027.003",
			BinaryName:  fmt.Sprintf("%s-T1027.003.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Real DNS + HTTPS GET shaped like the raw.githubusercontent.com ICO URL; benign ICO-with-appended-AES config decoded/decrypted locally (T1071.001 egress)",
		},
		{
			ID:          4,
			Name:        "Credentials from Web Browsers",
			Technique:   "T1555.003",
			BinaryName:  fmt.Sprintf("%s-T1555.003.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "ICONIC-style browser credential-store / history collection against decoys pre-staged in ARTIFACT_DIR (never real credentials)",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractKillchainStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			Endpoint.Say("    Error: %v", err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Initialize per-stage bundle results for ES fan-out
	stageSeverity := "critical"
	stageTactics := []string{"initial-access", "defense-evasion", "command-and-control", "credential-access"}
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  stageSeverity,
			Tactics:   stageTactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain
	Endpoint.Say("[*] Executing %d-stage 3CX cascading supply-chain killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogPhaseStart(stage.ID, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exitCode := executeKillchainStage(stage)

		if exitCode == 126 || exitCode == 105 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("FINAL EVALUATION: Stage %d Blocked", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("")
			Endpoint.Say("A protection layer stopped the 3CX supply-chain chain at stage %d:", stage.ID)
			Endpoint.Say("  Technique: %s", stage.Technique)
			Endpoint.Say("  Stage: %s", stage.Name)
			Endpoint.Say("  Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Attack Chain Interrupted:")
			Endpoint.Say("  Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  Blocked Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Security Status: ENDPOINT IS SECURE")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protection blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d encountered an error", stage.ID)
			Endpoint.Say("    Technique: %s", stage.Technique)
			Endpoint.Say("    Exit Code: %d", exitCode)
			Endpoint.Say("    (Prerequisite not met or ambiguous failure — NOT classified as a block)")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed successfully", stage.Technique))
		Endpoint.Say("    Stage %d completed successfully", stage.ID)
		Endpoint.Say("")

		// Brief pause between stages for realistic timing
		if idx < len(killchain)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// All stages completed - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete 3CX cascading supply-chain chain executed without prevention")
	Endpoint.Say("")
	Endpoint.Say("Attack Chain Summary:")
	Endpoint.Say("  Total Stages: %d", len(killchain))
	Endpoint.Say("  Successful Stages: %d", len(killchain))
	Endpoint.Say("  Blocked Stages: 0")
	Endpoint.Say("")
	Endpoint.Say("Executed Techniques:")
	for _, stage := range killchain {
		Endpoint.Say("  Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Security Impact: CRITICAL")
	Endpoint.Say("  Trusted signed binary side-loaded an untrusted DLL")
	Endpoint.Say("  Sandbox/dormancy evasion completed")
	Endpoint.Say("  Steganographic C2 config decoded from ICO-shaped payload")
	Endpoint.Say("  Browser credential-store collection pattern executed (decoys)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete 3CX cascading supply-chain chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

func extractKillchainStage(stage KillchainStage) error {
	targetDir := "c:\\F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", targetDir, err)
	}

	// Decompress gzip-compressed binary data
	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)

	// Check for quarantine using os.Stat (Rule 3: avoid Endpoint.Quarantined)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), true)
		return fmt.Errorf("stage binary %s missing after extraction (possible quarantine)", stage.BinaryName)
	}

	return nil
}

// decompressGzip decompresses gzip-compressed data in memory
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

func executeKillchainStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	// Check if binary was quarantined before execution (Rule 3)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary missing before execution (possible quarantine): %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Binary missing pre-exec: %s", stage.BinaryName))
		return 105
	}

	cmd := exec.Command(stagePath)

	// Capture stdout/stderr to both console and file (MANDATORY)
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	// Save raw output to file
	outputFilePath := filepath.Join("c:\\F0", fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes, %v)", outputFilePath, outputBuffer.Len(), executionDuration))
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			Endpoint.Say("  Stage %d exited with code: %d", stage.ID, exitCode)
			return exitCode
		}
		// Failed to start
		errMsg := fmt.Sprintf("Failed to execute stage %s: %v", stage.Technique, err)
		Endpoint.Say("  %s", errMsg)
		LogMessage("ERROR", stage.Technique, errMsg)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
