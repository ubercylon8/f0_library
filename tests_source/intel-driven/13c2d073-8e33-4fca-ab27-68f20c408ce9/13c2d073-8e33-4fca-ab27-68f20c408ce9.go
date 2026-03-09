//go:build windows
// +build windows

/*
ID: 13c2d073-8e33-4fca-ab27-68f20c408ce9
NAME: APT33 Tickler Backdoor DLL Sideloading
TECHNIQUES: T1566.001, T1574.002, T1547.001, T1053.005, T1036, T1071.001
TACTICS: initial-access, persistence, defense-evasion, command-and-control
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: APT33
SUBCATEGORY: apt
TAGS: apt33, peach-sandstorm, tickler, dll-sideloading, registry-persistence, scheduled-task, masquerading, http-c2, spearphishing
UNIT: response
CREATED: 2026-03-08
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
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
	TEST_UUID = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TEST_NAME = "APT33 Tickler Backdoor DLL Sideloading"
)

// Embed signed stage binaries (MUST be signed before embedding!)
//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1566.001.exe
var stage1Binary []byte

//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1574.002.exe
var stage2Binary []byte

//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1547.001.exe
var stage3Binary []byte

//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1053.005.exe
var stage4Binary []byte

//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1036.exe
var stage5Binary []byte

//go:embed 13c2d073-8e33-4fca-ab27-68f20c408ce9-T1071.001.exe
var stage6Binary []byte

//go:embed cleanup_utility.exe
var cleanupBinary []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique in the attack killchain
// Named to avoid conflict with test_logger.go Stage struct
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
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "high",
		Techniques: []string{"T1566.001", "T1574.002", "T1547.001", "T1053.005", "T1036", "T1071.001"},
		Tactics:    []string{"initial-access", "persistence", "defense-evasion", "command-and-control"},
		Score:      8.7,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.7,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        1.5,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.5,
		},
		Tags: []string{"apt33", "peach-sandstorm", "tickler", "dll-sideloading", "multi-stage", "killchain"},
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
	Endpoint.Say("Threat Actor: APT33 (Elfin / Peach Sandstorm / Refined Kitten)")
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
			Name:        "Spearphishing Attachment",
			Technique:   "T1566.001",
			BinaryName:  fmt.Sprintf("%s-T1566.001.exe", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Simulate ZIP archive delivery masquerading as PDF containing Tickler payload and legitimate DLLs",
		},
		{
			ID:          2,
			Name:        "DLL Side-Loading",
			Technique:   "T1574.002",
			BinaryName:  fmt.Sprintf("%s-T1574.002.exe", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Simulate DLL sideloading via renamed Microsoft binary loading msvcp140.dll/vcruntime140.dll",
		},
		{
			ID:          3,
			Name:        "Registry Run Keys",
			Technique:   "T1547.001",
			BinaryName:  fmt.Sprintf("%s-T1547.001.exe", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Add registry Run key persistence as SharePoint.exe in non-standard path",
		},
		{
			ID:          4,
			Name:        "Scheduled Task",
			Technique:   "T1053.005",
			BinaryName:  fmt.Sprintf("%s-T1053.005.exe", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Create scheduled task for redundant Tickler persistence",
		},
		{
			ID:          5,
			Name:        "Masquerading",
			Technique:   "T1036",
			BinaryName:  fmt.Sprintf("%s-T1036.exe", TEST_UUID),
			BinaryData:  stage5Binary,
			Description: "Rename binary to Microsoft.SharePoint.NativeMessaging.exe to blend with legitimate software",
		},
		{
			ID:          6,
			Name:        "Web Protocols C2",
			Technique:   "T1071.001",
			BinaryName:  fmt.Sprintf("%s-T1071.001.exe", TEST_UUID),
			BinaryData:  stage6Binary,
			Description: "Simulate HTTP POST exfiltration to Azure-hosted C2 on non-standard ports (808/880)",
		},
	}

	// Phase 0: Extract all stage binaries + cleanup utility
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries + cleanup utility...", len(killchain))

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

	// Extract cleanup utility
	cleanupPath := filepath.Join("c:\\F0", "cleanup_utility.exe")
	if err := os.WriteFile(cleanupPath, cleanupBinary, 0755); err != nil {
		LogMessage("WARNING", "Extraction", fmt.Sprintf("Failed to extract cleanup utility: %v", err))
	} else {
		LogFileDropped("cleanup_utility.exe", cleanupPath, int64(len(cleanupBinary)), false)
		Endpoint.Say("    [+] Extracted cleanup_utility.exe (%d bytes)", len(cleanupBinary))
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries + cleanup", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Initialize per-stage bundle results for ES fan-out
	stageSeverity := "high"
	stageTactics := []string{"initial-access", "persistence", "defense-evasion", "command-and-control"}
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
	Endpoint.Say("[*] Executing %d-stage APT33 Tickler attack killchain...", len(killchain))
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
			Endpoint.Say("EDR successfully blocked the APT33 Tickler attack at stage %d:", stage.ID)
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

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
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
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
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
	Endpoint.Say("CRITICAL: Complete APT33 Tickler attack chain executed without prevention")
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
	Endpoint.Say("Security Impact: HIGH")
	Endpoint.Say("  Spearphishing payload delivered and extracted")
	Endpoint.Say("  DLL sideloading via legitimate Microsoft binary")
	Endpoint.Say("  Dual persistence via registry Run key and scheduled task")
	Endpoint.Say("  Binary masquerading as SharePoint component")
	Endpoint.Say("  HTTP POST C2 to Azure endpoints")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete APT33 Tickler attack chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
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

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, stage.BinaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), false)

	// Check for quarantine using os.Stat (Rule 3: avoid Endpoint.Quarantined)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), true)
		return fmt.Errorf("file quarantined after extraction")
	}

	return nil
}

func executeKillchainStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	// Check if binary was quarantined before execution (Rule 3)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary quarantined before execution: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Binary quarantined: %s", stage.BinaryName))
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
