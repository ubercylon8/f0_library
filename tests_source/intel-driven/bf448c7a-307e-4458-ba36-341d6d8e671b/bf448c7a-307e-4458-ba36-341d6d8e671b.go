//go:build windows
// +build windows

/*
ID: bf448c7a-307e-4458-ba36-341d6d8e671b
NAME: TclBanker Brazilian Banking Trojan Full Killchain
TECHNIQUES: T1218.007, T1566.001, T1574.002, T1140, T1027, T1497.001, T1497.003, T1053.005, T1056.003, T1010, T1185, T1071.001, T1102
TACTICS: initial-access, defense-evasion, execution, persistence, credential-access, command-and-control, discovery
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: TclBanker
SUBCATEGORY: banking-trojan
TAGS: tclbanker, brazil, banking-trojan, dll-sideloading, scheduled-task, com, cloudflare-workers, websocket, overlay-fraud, hmac, uia, multi-stage, killchain
SOURCE_URL: https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan
UNIT: response
CREATED: 2026-05-11
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
	TEST_UUID = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TEST_NAME = "TclBanker Brazilian Banking Trojan Full Killchain"
)

// Embed gzip-compressed signed stage binaries. Decompressed in memory at
// extraction time; files on disk are normal signed PEs.
//
//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1218.007.exe.gz
var stage1Compressed []byte

//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1574.002.exe.gz
var stage2Compressed []byte

//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1140.exe.gz
var stage3Compressed []byte

//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1053.005.exe.gz
var stage4Compressed []byte

//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1056.003.exe.gz
var stage5Compressed []byte

//go:embed bf448c7a-307e-4458-ba36-341d6d8e671b-T1071.001.exe.gz
var stage6Compressed []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique in the attack killchain.
// Named to avoid conflict with test_logger.go Stage struct.
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
	// Schema v2.0 metadata
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "banking-trojan",
		Severity: "high",
		Techniques: []string{
			"T1218.007", "T1566.001", "T1574.002", "T1140", "T1027",
			"T1497.001", "T1497.003", "T1053.005", "T1056.003", "T1010",
			"T1185", "T1071.001", "T1102",
		},
		Tactics: []string{
			"initial-access", "defense-evasion", "execution", "persistence",
			"credential-access", "command-and-control", "discovery",
		},
		Score:         9.25,
		RubricVersion: "v2.1",
		Tags: []string{
			"tclbanker", "brazil", "banking-trojan", "dll-sideloading",
			"scheduled-task", "com", "cloudflare-workers", "websocket",
			"overlay-fraud", "hmac", "uia", "multi-stage", "killchain",
		},
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
	Endpoint.Say("Threat Actor: TclBanker (Brazilian Banking Trojan)")
	Endpoint.Say("Source: Elastic Security Labs")
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
			Name:        "Delivery — Logitech_Update MSI in ZIP",
			Technique:   "T1218.007",
			BinaryName:  fmt.Sprintf("%s-T1218.007.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Drop signed-looking Logitech_Update MSI artifact + ZIP wrapper (TclBanker initial-access pattern)",
		},
		{
			ID:          2,
			Name:        "DLL Side-Loading — screen_retriever_plugin",
			Technique:   "T1574.002",
			BinaryName:  fmt.Sprintf("%s-T1574.002.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Real LoadLibrary on renamed Microsoft DLL via sandbox LogiAiPromptBuilder.exe host (LIFT 1)",
		},
		{
			ID:          3,
			Name:        "Deobfuscate + Brazilian Locale Gate",
			Technique:   "T1140",
			BinaryName:  fmt.Sprintf("%s-T1140.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "AES-256-CBC decrypt of simulated Tcl.Agent + pt-BR locale + RDTSC/QPC timing observation",
		},
		{
			ID:          4,
			Name:        "Persistence — RuntimeOptimizeService COM Task",
			Technique:   "T1053.005",
			BinaryName:  fmt.Sprintf("%s-T1053.005.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Real CoCreateInstance(CLSID_TaskScheduler) + RegisterTaskDefinition for RuntimeOptimizeService (LIFT 2, triple cleanup)",
		},
		{
			ID:          5,
			Name:        "Overlay + Browser Address-Bar Monitoring",
			Technique:   "T1056.003",
			BinaryName:  fmt.Sprintf("%s-T1056.003.exe", TEST_UUID),
			BinaryData:  stage5Compressed,
			Description: "Auto-dismiss overlay + UI Automation COM + brief no-data WH_KEYBOARD_LL hook",
		},
		{
			ID:          6,
			Name:        "C2 Beacon — Cloudflare Workers ef971a42",
			Technique:   "T1071.001",
			BinaryName:  fmt.Sprintf("%s-T1071.001.exe", TEST_UUID),
			BinaryData:  stage6Compressed,
			Description: "DNS observation for *.workers.dev + loopback WebSocket handshake with HMAC-SHA256(campaignGUID)",
		},
	}

	// Phase 0: extract stage binaries
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
	Endpoint.Say("    All stage binaries extracted")
	Endpoint.Say("")

	// Initialize per-stage bundle results for ES fan-out
	stageSeverity := "high"
	stageTactics := []string{
		"initial-access", "defense-evasion", "execution", "persistence",
		"credential-access", "command-and-control",
	}
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

	Endpoint.Say("[*] Executing %d-stage TclBanker killchain...", len(killchain))
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
			Endpoint.Say("EDR blocked the TclBanker chain at stage %d:", stage.ID)
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

			SaveLog(Endpoint.ExecutionPrevented,
				fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "banking-trojan", stageResults)
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

			SaveLog(Endpoint.UnexpectedTestError,
				fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "banking-trojan", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed successfully", stage.Technique))
		Endpoint.Say("    Stage %d completed successfully", stage.ID)
		Endpoint.Say("")

		if idx < len(killchain)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// All stages completed — chain executed without prevention
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete TclBanker attack chain executed without prevention")
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
	Endpoint.Say("  Logitech-impersonating MSI dropped")
	Endpoint.Say("  Real DLL sideloading via renamed Microsoft DLL")
	Endpoint.Say("  Persistence via COM-based scheduled task (RuntimeOptimizeService)")
	Endpoint.Say("  UI Automation + overlay + keyboard-hook surface produced")
	Endpoint.Say("  Cloudflare Workers C2 (loopback handshake with HMAC)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected,
		fmt.Sprintf("All %d stages completed — TclBanker chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "banking-trojan", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

func extractKillchainStage(stage KillchainStage) error {
	targetDir := LOG_DIR
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", targetDir, err)
	}

	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)

	// Quarantine detection via os.Stat (per CLAUDE.md Bug Prevention Rule 3)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), true)
		return fmt.Errorf("file quarantined after extraction")
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
	return io.ReadAll(reader)
}

func executeKillchainStage(stage KillchainStage) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)

	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary quarantined before execution: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID),
			fmt.Sprintf("Binary quarantined: %s", stage.BinaryName))
		return 105
	}

	cmd := exec.Command(stagePath)

	// stdout/stderr capture per CLAUDE.md MANDATORY pattern
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID),
		fmt.Sprintf("Executing %s", stage.BinaryName))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	outputFilePath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture",
			fmt.Sprintf("Raw output saved to: %s (%d bytes, %v)",
				outputFilePath, outputBuffer.Len(), executionDuration))
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			Endpoint.Say("  Stage %d exited with code: %d", stage.ID, exitCode)
			return exitCode
		}
		errMsg := fmt.Sprintf("Failed to execute stage %s: %v", stage.Technique, err)
		Endpoint.Say("  %s", errMsg)
		LogMessage("ERROR", stage.Technique, errMsg)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
