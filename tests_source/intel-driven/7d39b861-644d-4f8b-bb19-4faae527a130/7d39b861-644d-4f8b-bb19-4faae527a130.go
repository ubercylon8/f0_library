//go:build windows
// +build windows

/*
ID: 7d39b861-644d-4f8b-bb19-4faae527a130
NAME: Agrius Multi-Wiper Deployment Against Banking Infrastructure
TECHNIQUES: T1505.003, T1543.003, T1562.001, T1485, T1070.001
TACTICS: persistence, defense-evasion, impact
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: Agrius
SUBCATEGORY: apt
TAGS: wiper, destructive, multi-wiper, edr-bypass, event-log-deletion, banking-infrastructure, agrius, pink-sandstorm, iranian-apt, multi-stage
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	_ "embed"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TEST_NAME = "Agrius Multi-Wiper Deployment Against Banking Infrastructure"
)

// Embed signed stage binaries (MUST be signed before embedding!)
//go:embed 7d39b861-644d-4f8b-bb19-4faae527a130-T1505.003.exe
var stage1Binary []byte

//go:embed 7d39b861-644d-4f8b-bb19-4faae527a130-T1543.003.exe
var stage2Binary []byte

//go:embed 7d39b861-644d-4f8b-bb19-4faae527a130-T1562.001.exe
var stage3Binary []byte

//go:embed 7d39b861-644d-4f8b-bb19-4faae527a130-T1485.exe
var stage4Binary []byte

//go:embed 7d39b861-644d-4f8b-bb19-4faae527a130-T1070.001.exe
var stage5Binary []byte

// KillchainStage definition for multi-stage execution
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
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "impact",
		Severity:   "critical",
		Techniques: []string{"T1505.003", "T1543.003", "T1562.001", "T1485", "T1070.001"},
		Tactics:    []string{"persistence", "defense-evasion", "impact"},
		Score:      9.2,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.7,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.7,
		},
		Tags: []string{"wiper", "destructive", "multi-wiper", "edr-bypass", "agrius", "pink-sandstorm", "iranian-apt", "banking-infrastructure", "multi-stage"},
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
	Endpoint.Say("Threat Actor: Agrius / Pink Sandstorm / Agonizing Serpens")
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
			Name:        "ASPXSpy Webshell Deployment",
			Technique:   "T1505.003",
			BinaryName:  fmt.Sprintf("%s-T1505.003.exe", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Deploy simulated ASPXSpy webshell to staging directory",
		},
		{
			ID:          2,
			Name:        "IPsec Helper Service Persistence",
			Technique:   "T1543.003",
			BinaryName:  fmt.Sprintf("%s-T1543.003.exe", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Create malicious Windows service for persistence (IPsec Helper)",
		},
		{
			ID:          3,
			Name:        "EDR Tampering via Driver Load",
			Technique:   "T1562.001",
			BinaryName:  fmt.Sprintf("%s-T1562.001.exe", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Attempt to disable EDR via GMER64.sys driver loading and service tampering",
		},
		{
			ID:          4,
			Name:        "Multi-Wiper Deployment (MultiLayer + PartialWasher + BFG Agonizer)",
			Technique:   "T1485",
			BinaryName:  fmt.Sprintf("%s-T1485.exe", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Simulate simultaneous deployment of three wiper variants against test files",
		},
		{
			ID:          5,
			Name:        "Anti-Forensics and Evidence Destruction",
			Technique:   "T1070.001",
			BinaryName:  fmt.Sprintf("%s-T1070.001.exe", TEST_UUID),
			BinaryData:  stage5Binary,
			Description: "Clear Windows Event Logs and trigger self-deletion mechanism",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)

		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Check if EDR quarantined the extracted binary
		if Endpoint.Quarantined(fmt.Sprintf("c:\\F0\\%s", stage.BinaryName)) {
			LogMessage("BLOCKED", stage.Technique, fmt.Sprintf("Stage binary quarantined: %s", stage.BinaryName))
			LogPhaseEnd(0, "blocked", fmt.Sprintf("EDR quarantined %s during extraction", stage.BinaryName))
			Endpoint.Say("    [!] QUARANTINED: %s — EDR removed stage binary", stage.BinaryName)
			SaveLog(Endpoint.FileQuarantinedOnExtraction, fmt.Sprintf("Stage binary %s quarantined during extraction", stage.BinaryName))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Initialize per-stage bundle results for ES fan-out
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  "critical",
			Tactics:   []string{"persistence", "defense-evasion", "impact"},
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing %d-stage Agrius attack killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogPhaseStart(stage.ID, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exitCode := executeStage(stage)

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
			Endpoint.Say("EDR successfully blocked the attack at stage %d:", stage.ID)
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

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed successfully", stage.Technique))
		Endpoint.Say("    Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages completed - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete Agrius wiper attack chain executed without prevention")
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
	Endpoint.Say("  Webshell deployed for remote access")
	Endpoint.Say("  Persistent service installed")
	Endpoint.Say("  EDR tampering succeeded")
	Endpoint.Say("  Multi-wiper deployment completed (data destruction)")
	Endpoint.Say("  Event logs cleared (anti-forensics)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED - Banking infrastructure at risk")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete Agrius wiper chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

func extractStage(stage KillchainStage) error {
	targetDir := "c:\\F0"

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", targetDir, err)
	}

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, stage.BinaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), false)
	return nil
}

func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	cmd := exec.Command(stagePath)

	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	if err := cmd.Start(); err != nil {
		errMsg := fmt.Sprintf("Failed to start stage %s: %v", stage.Technique, err)
		Endpoint.Say("  Failed to start stage: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		return 999
	}

	stageStart := time.Now()
	err := cmd.Wait()
	stageDuration := time.Since(stageStart)

	Endpoint.Say("    [Timing] Stage %d (%s) completed in %s", stage.ID, stage.Technique, stageDuration.Round(time.Millisecond))
	LogMessage("INFO", stage.Technique, fmt.Sprintf("Stage duration: %s", stageDuration.Round(time.Millisecond)))

	// Save raw output
	outputFilePath := filepath.Join("c:\\F0", fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputFilePath, outputBuffer.Len()))
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		errMsg := fmt.Sprintf("Stage execution error for %s: %v", stage.Technique, err)
		Endpoint.Say("  Stage execution error: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
