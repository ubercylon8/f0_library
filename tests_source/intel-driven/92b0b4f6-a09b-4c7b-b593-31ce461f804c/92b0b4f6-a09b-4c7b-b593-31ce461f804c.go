//go:build windows

/*
ID: 92b0b4f6-a09b-4c7b-b593-31ce461f804c
NAME: APT42 TAMECAT Fileless Backdoor with Browser Credential Theft
TECHNIQUES: T1204.002, T1059.001, T1547.001, T1555.003, T1102
TACTICS: execution, persistence, credential-access, command-and-control
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: APT42
SUBCATEGORY: apt
TAGS: fileless, powershell, browser-credentials, credential-theft, telegram-c2, persistence, apt42, magic-hound, iranian-apt, tamecat, multi-stage
UNIT: response
CREATED: 2026-03-07
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
	TEST_UUID = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TEST_NAME = "APT42 TAMECAT Fileless Backdoor with Browser Credential Theft"
)

// Embed signed stage binaries (signed BEFORE embedding)
//go:embed 92b0b4f6-a09b-4c7b-b593-31ce461f804c-T1204.002.exe
var stage1Binary []byte

//go:embed 92b0b4f6-a09b-4c7b-b593-31ce461f804c-T1059.001.exe
var stage2Binary []byte

//go:embed 92b0b4f6-a09b-4c7b-b593-31ce461f804c-T1547.001.exe
var stage3Binary []byte

//go:embed 92b0b4f6-a09b-4c7b-b593-31ce461f804c-T1555.003.exe
var stage4Binary []byte

//go:embed 92b0b4f6-a09b-4c7b-b593-31ce461f804c-T1102.exe
var stage5Binary []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique in the attack killchain
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
		Category:   "credential_access",
		Severity:   "critical",
		Techniques: []string{"T1204.002", "T1059.001", "T1547.001", "T1555.003", "T1102"},
		Tactics:    []string{"execution", "persistence", "credential-access", "command-and-control"},
		Score:      9.4,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.9,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.7,
		},
		Tags: []string{"multi-stage", "fileless", "powershell", "browser-credentials", "credential-theft", "telegram-c2", "persistence", "apt42", "magic-hound", "tamecat"},
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
		// Safety: always clean up any persistence mechanisms that Stage 3 may have created
		cleanupPersistenceFromOrchestrator()

		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Threat Actor: APT42 / Magic Hound / Educated Manticore")
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
			Name:        "Initial Access via LNK + VBScript",
			Technique:   "T1204.002",
			BinaryName:  fmt.Sprintf("%s-T1204.002.exe", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Simulate malicious LNK file delivery with VBScript downloader and WMI AV enumeration",
		},
		{
			ID:          2,
			Name:        "TAMECAT PowerShell Backdoor Deployment",
			Technique:   "T1059.001",
			BinaryName:  fmt.Sprintf("%s-T1059.001.exe", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Deploy fileless TAMECAT backdoor via in-memory PowerShell execution from conhost context",
		},
		{
			ID:          3,
			Name:        "Dual Persistence Mechanism",
			Technique:   "T1547.001",
			BinaryName:  fmt.Sprintf("%s-T1547.001.exe", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Establish dual persistence via Registry Run key (Renovation) and UserInitMprLogonScript",
		},
		{
			ID:          4,
			Name:        "Browser Credential Theft Simulation",
			Technique:   "T1555.003",
			BinaryName:  fmt.Sprintf("%s-T1555.003.exe", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Simulate Edge remote debugging + Chrome Login Data access with Runs.dll chunking behavior",
		},
		{
			ID:          5,
			Name:        "Multi-Channel Exfiltration via Telegram",
			Technique:   "T1102",
			BinaryName:  fmt.Sprintf("%s-T1102.exe", TEST_UUID),
			BinaryData:  stage5Binary,
			Description: "Simulate exfiltration over Telegram API, FTP, and HTTPS POST channels",
		},
	}

	// Initialize per-stage results for bundle fan-out (before extraction so quarantine path can use it)
	stageSeverity := "critical"
	stageTactics := []string{"execution", "persistence", "credential-access", "command-and-control"}
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

		// Check if EDR quarantined the extracted binary
		// Note: We use os.Stat instead of Endpoint.Quarantined() because Quarantined()
		// internally calls Pwd(filename) which does filepath.Join(cwd, filename), producing
		// an invalid doubled path (e.g. C:\F0\tasks\task-xxx\c:\F0\binary.exe) when given
		// an absolute path. Direct stat check on the known extraction path is more reliable.
		time.Sleep(3 * time.Second)
		if _, statErr := os.Stat(filepath.Join("c:\\F0", stage.BinaryName)); os.IsNotExist(statErr) {
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

	// Execute killchain
	Endpoint.Say("[*] Executing %d-stage APT42 TAMECAT attack killchain...", len(killchain))
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
			Endpoint.Say("EDR successfully blocked the APT42 attack at stage %d:", stage.ID)
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
	Endpoint.Say("CRITICAL: Complete APT42 TAMECAT attack chain executed without prevention")
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
	Endpoint.Say("  Initial access via LNK/VBScript achieved")
	Endpoint.Say("  Fileless TAMECAT backdoor deployed in memory")
	Endpoint.Say("  Dual persistence mechanisms established")
	Endpoint.Say("  Browser credentials accessed")
	Endpoint.Say("  Multi-channel exfiltration via Telegram API completed")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete APT42 attack chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// SAFETY: ORCHESTRATOR-LEVEL PERSISTENCE CLEANUP
// ==============================================================================

// cleanupPersistenceFromOrchestrator removes any persistence mechanisms that
// Stage 3 (T1547.001) may have created, even if the orchestrator exits early
// or panics. This is a safety backstop — Stage 3 also cleans up internally,
// but this ensures no persistence survives an unexpected orchestrator exit.
func cleanupPersistenceFromOrchestrator() {
	// Attempt to remove Registry Run key "Renovation" (Stage 3 artifact)
	cleanupCmd1 := exec.Command("reg.exe", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "Renovation", "/f")
	if output, err := cleanupCmd1.CombinedOutput(); err == nil {
		LogMessage("INFO", "Safety", fmt.Sprintf("Orchestrator cleanup: removed Run key 'Renovation': %s", string(output)))
	}

	// Attempt to remove UserInitMprLogonScript (Stage 3 artifact)
	cleanupCmd2 := exec.Command("reg.exe", "delete",
		`HKCU\Environment`,
		"/v", "UserInitMprLogonScript", "/f")
	if output, err := cleanupCmd2.CombinedOutput(); err == nil {
		LogMessage("INFO", "Safety", fmt.Sprintf("Orchestrator cleanup: removed UserInitMprLogonScript: %s", string(output)))
	}
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
	return nil
}

func executeKillchainStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	cmd := exec.Command(stagePath)
	cmd.Dir = "c:\\F0"

	// Capture stdout/stderr to both console and file via io.MultiWriter
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

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

	// Save raw output to file
	outputFilePath := filepath.Join("c:\\F0", fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputFilePath, outputBuffer.Len()))
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			Endpoint.Say("  Stage %d exit code: %d", stage.ID, exitCode)
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		errMsg := fmt.Sprintf("Failed to execute stage %s: %v", stage.Technique, err)
		Endpoint.Say("  Stage execution error: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
