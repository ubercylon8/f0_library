//go:build windows
// +build windows

/*
ID: 0a749b39-409e-46f5-9338-ee886b439cfa
NAME: PROMPTFLUX v1 — LLM-Assisted VBScript Dropper
TECHNIQUES: T1071.001, T1027.001, T1547.001, T1091
TACTICS: command-and-control, defense-evasion, persistence, lateral-movement
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: apt
TAGS: promptflux, llm-abuse, gemini-api, vbscript, wscript, metamorphic, thinging, startup-folder, wmi-enum, github-raw, multi-stage
SOURCE_URL: https://cloud.google.com/blog/topics/threat-intelligence
UNIT: response
CREATED: 2026-04-13
AUTHOR: sectest-builder
*/

// NOTE: SUBCATEGORY=apt — the framework's current `sectest-builder` enum set does
// not include a dedicated "llm-abuse" category, so this test is filed under `apt`
// to remain catalogue-compatible with PA's MetadataExtractor. When the category
// enum is extended (see CLAUDE.md §Test Metadata Header → PA propagation checklist),
// this test should be re-tagged SUBCATEGORY=llm-abuse.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// Per-stage execution timeout. Hard cap on any single stage. v1.1 added this
// after a Session-0 wscript.exe MessageBox hang in stage 1 (5m51s before
// manual kill). 30s is generous: stages 1+2 are HTTPS GET (≤15s timeout) +
// wscript file-only (<2s); stage 3 is a single file write; stage 4 is one
// wmic CSV query (typically <5s). A timeout = test-infra failure (999),
// NOT an EDR block (126).
const stageExecTimeout = 30 * time.Second

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "0a749b39-409e-46f5-9338-ee886b439cfa"
	TEST_NAME = "PROMPTFLUX v1 — LLM-Assisted VBScript Dropper"
)

// Embed gzip-compressed signed stage binaries.
// Stages: T1071.001 (C2 + VBS staging), T1027.001 (metamorphic rewrite),
//         T1547.001 (startup persistence), T1091 (propagation enumeration).
//go:embed 0a749b39-409e-46f5-9338-ee886b439cfa-T1071.001.exe.gz
var stage1Compressed []byte

//go:embed 0a749b39-409e-46f5-9338-ee886b439cfa-T1027.001.exe.gz
var stage2Compressed []byte

//go:embed 0a749b39-409e-46f5-9338-ee886b439cfa-T1547.001.exe.gz
var stage3Compressed []byte

//go:embed 0a749b39-409e-46f5-9338-ee886b439cfa-T1091.exe.gz
var stage4Compressed []byte

// Artefacts created by the orchestrator and its stages. The cleanup routine
// walks this list on every exit path (normal return, panic, signal).
// The two persistent log outputs (test_execution_log.json and
// bundle_results.json) are intentionally NOT listed here — those are the
// test's deliverables, not PROMPTFLUX artefacts.
var promptfluxArtefacts = []string{
	`c:\F0\crypted_ScreenRec_webinstall.vbs`,
	`c:\F0\promptflux_stage1_marker.txt`,
	`c:\F0\promptflux_stage2_marker.txt`,
	`c:\F0\stage1_wscript_output.txt`,
	`c:\F0\stage2_wscript_output.txt`,
	`c:\F0\stage1_network.log`,
	`c:\F0\stage2_network.log`,
	`c:\F0\stage4_propagation_targets.json`,
	`c:\F0\T1071.001_output.txt`,
	`c:\F0\T1027.001_output.txt`,
	`c:\F0\T1547.001_output.txt`,
	`c:\F0\T1091_output.txt`,
}

// Stage binaries dropped to c:\F0 during extraction — cleaned up on exit.
var promptfluxStageBinaries = []string{
	fmt.Sprintf(`c:\F0\%s-T1071.001.exe`, TEST_UUID),
	fmt.Sprintf(`c:\F0\%s-T1027.001.exe`, TEST_UUID),
	fmt.Sprintf(`c:\F0\%s-T1547.001.exe`, TEST_UUID),
	fmt.Sprintf(`c:\F0\%s-T1091.exe`, TEST_UUID),
}

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:    "1.2.0",
		Category:   "command_and_control",
		Severity:   "high",
		Techniques: []string{"T1071.001", "T1027.001", "T1547.001", "T1091"},
		Tactics:    []string{"command-and-control", "defense-evasion", "persistence", "lateral-movement"},
		Score:      9.4,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.9,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        1.8,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.7,
		},
		Tags: []string{"promptflux", "llm-abuse", "gemini-api", "vbscript", "wscript", "metamorphic", "thinging", "startup-folder", "wmi-enum", "github-raw", "multi-stage"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000,
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Install cleanup on every exit path: normal return, panic, or signal.
	installCleanupHandlers()

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			cleanupAll("panic")
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Reference: GTIG PROMPTFLUX disclosure (Nov 2025)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

// ==============================================================================
// TEST FLOW
// ==============================================================================

func test() {
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Application Layer Protocol: Web Protocols",
			Technique:   "T1071.001",
			BinaryName:  fmt.Sprintf("%s-T1071.001.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "HTTPS GET a Gemini-shaped JSON envelope from raw.githubusercontent.com, extract an obfuscated VBS body, write it as c:\\F0\\crypted_ScreenRec_webinstall.vbs, and invoke wscript.exe on it",
		},
		{
			ID:          2,
			Name:        "Obfuscated Files or Information: Binary Padding",
			Technique:   "T1027.001",
			BinaryName:  fmt.Sprintf("%s-T1027.001.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Fetch variant_thinging.vbs from raw.githubusercontent.com and overwrite the stage-1 VBS on disk, simulating the PROMPTFLUX Thinging module's hourly metamorphic rewrite, then invoke wscript.exe on the new variant",
		},
		{
			ID:          3,
			Name:        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
			Technique:   "T1547.001",
			BinaryName:  fmt.Sprintf("%s-T1547.001.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Drop an obfuscated benign VBS into %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup as ScreenRecUpdater.vbs for at-logon persistence (drop only; not executed at test time)",
		},
		{
			ID:          4,
			Name:        "Replication Through Removable Media (enumeration-only)",
			Technique:   "T1091",
			BinaryName:  fmt.Sprintf("%s-T1091.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Enumerate removable (DriveType=2) and network (DriveType=4) volumes via WMI Win32_LogicalDisk and log targets — enumeration only, no copy/propagation",
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
			cleanupAll("extract-failed")
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Per-stage bundle results for ES fan-out
	stageSeverity := "high"
	stageTactics := []string{"command-and-control", "defense-evasion", "persistence", "lateral-movement"}
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

	Endpoint.Say("[*] Executing %d-stage PROMPTFLUX attack killchain...", len(killchain))
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
			Endpoint.Say("EDR successfully blocked the PROMPTFLUX attack at stage %d:", stage.ID)
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

			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			cleanupAll("blocked")
			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
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

			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			cleanupAll("error")
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

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

	// All stages completed — endpoint unprotected
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete PROMPTFLUX attack chain executed without prevention")
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
	Endpoint.Say("  LLM-sourced VBS fetched via HTTPS to raw.githubusercontent.com")
	Endpoint.Say("  wscript.exe executed the staged dropper body")
	Endpoint.Say("  Metamorphic variant successfully overwrote stage-1 VBS on disk")
	Endpoint.Say("  Persistence VBS dropped to user Startup folder")
	Endpoint.Say("  Propagation targets enumerated via WMI Win32_LogicalDisk")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	cleanupAll("unprotected")
	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete PROMPTFLUX attack chain successful", len(killchain)))
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// STAGE EXTRACTION / EXECUTION
// ==============================================================================

func extractKillchainStage(stage KillchainStage) error {
	targetDir := `c:\F0`
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

	// Rule 3: os.Stat quarantine check, not Endpoint.Quarantined.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), true)
		return fmt.Errorf("file quarantined after extraction")
	}
	return nil
}

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
	stagePath := filepath.Join(`c:\F0`, stage.BinaryName)

	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary quarantined before execution: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Binary quarantined: %s", stage.BinaryName))
		return 105
	}

	// v1.1: 30s hard timeout per stage. Prevents the orchestrator from
	// hanging if a stage's child process (e.g. wscript.exe) blocks on an
	// invisible modal dialog under Session 0 / non-interactive contexts.
	ctx, cancel := context.WithTimeout(context.Background(), stageExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, stagePath)

	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s (timeout=%v)", stage.BinaryName, stageExecTimeout))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	outputFilePath := filepath.Join(`c:\F0`, fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes, %v)", outputFilePath, outputBuffer.Len(), executionDuration))
	}

	if err != nil {
		// v1.1: if the context deadline was exceeded, the stage hung and
		// was killed by us — treat as test-infra error (999), NOT an EDR
		// block (126). Hangs are timing failures, not protection signals.
		if ctx.Err() == context.DeadlineExceeded {
			errMsg := fmt.Sprintf("Stage %s timed out after %v — killed by orchestrator (test-infra failure, NOT EDR block)", stage.Technique, stageExecTimeout)
			Endpoint.Say("  %s", errMsg)
			LogMessage("ERROR", stage.Technique, errMsg)
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, "context deadline exceeded")
			return 999
		}
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

// ==============================================================================
// CLEANUP — fires on every exit path (normal return, panic, signal)
// ==============================================================================

var cleanupOnce = make(chan struct{}, 1)

func installCleanupHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		LogMessage("WARNING", "Runtime", fmt.Sprintf("Received signal %v - running cleanup", sig))
		cleanupAll("signal")
		os.Exit(999)
	}()
}

func cleanupAll(reason string) {
	// Guard against double-fire.
	select {
	case cleanupOnce <- struct{}{}:
	default:
		return
	}

	LogMessage("INFO", "Cleanup", fmt.Sprintf("Cleanup triggered: reason=%s", reason))
	Endpoint.Say("[*] Cleaning up PROMPTFLUX artefacts (reason=%s)...", reason)

	// Stage-dropped binaries in c:\F0
	for _, p := range promptfluxStageBinaries {
		if err := os.Remove(p); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed stage binary: %s", p))
		}
	}

	// PROMPTFLUX simulation artefacts
	for _, p := range promptfluxArtefacts {
		if err := os.Remove(p); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed artefact: %s", p))
		}
	}

	// Startup folder VBS — covers both APPDATA and PUBLIC profiles so cleanup
	// works regardless of whether stage 3 ran in user or SYSTEM context.
	startupVbsCandidates := []string{}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		startupVbsCandidates = append(startupVbsCandidates,
			filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup\ScreenRecUpdater.vbs`))
	}
	if public := os.Getenv("PUBLIC"); public != "" {
		startupVbsCandidates = append(startupVbsCandidates,
			filepath.Join(public, `..\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ScreenRecUpdater.vbs`))
	}
	startupVbsCandidates = append(startupVbsCandidates,
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\ScreenRecUpdater.vbs`)

	for _, p := range startupVbsCandidates {
		if err := os.Remove(p); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed Startup VBS: %s", p))
		}
	}

	// Thinking-trail log documented by GTIG
	if tmp := os.Getenv("TEMP"); tmp != "" {
		thinking := filepath.Join(tmp, "thinking_robot_log.txt")
		if err := os.Remove(thinking); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed Thinging log: %s", thinking))
		}
	}

	Endpoint.Say("[*] Cleanup complete")
}
