//go:build darwin
// +build darwin

/*
ID: 244dfb88-9068-4db4-9fa8-dbc49517f63d
NAME: DPRK BlueNoroff Financial Sector Attack Chain
TECHNIQUES: T1553.001, T1543.004, T1059.002, T1071.001, T1041
TACTICS: initial-access, persistence, credential-access, command-and-control, exfiltration, defense-evasion
SEVERITY: critical
TARGET: macos-endpoint
COMPLEXITY: high
THREAT_ACTOR: BlueNoroff/Lazarus
SUBCATEGORY: apt
TAGS: dprk, lazarus, bluenoroff, rustbucket, hidden-risk, launchagent, zshenv, osascript, keychain, crypto-wallet, sliver, macos, financial-sector, gatekeeper-bypass
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"context"
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
	TEST_UUID = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
	TEST_NAME = "DPRK BlueNoroff Financial Sector Attack Chain"
)

// Embed signed stage binaries (MUST be signed before embedding!)
//go:embed 244dfb88-9068-4db4-9fa8-dbc49517f63d-T1553.001
var stage1Binary []byte

//go:embed 244dfb88-9068-4db4-9fa8-dbc49517f63d-T1543.004
var stage2Binary []byte

//go:embed 244dfb88-9068-4db4-9fa8-dbc49517f63d-T1059.002
var stage3Binary []byte

//go:embed 244dfb88-9068-4db4-9fa8-dbc49517f63d-T1071.001
var stage4Binary []byte

//go:embed 244dfb88-9068-4db4-9fa8-dbc49517f63d-T1041
var stage5Binary []byte

// Embed cleanup utility
//go:embed cleanup_utility
var cleanupBinary []byte

// KillchainStage definition for multi-stage execution
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Multi-stage architecture: 5 stages (DPRK/BlueNoroff killchain)")
	Endpoint.Say("")
	Endpoint.Say("Threat Intelligence:")
	Endpoint.Say("  Threat Actor: BlueNoroff/Lazarus (DPRK)")
	Endpoint.Say("  Campaigns: RustBucket, Hidden Risk, TodoSwift, KANDYKORN, BeaverTail")
	Endpoint.Say("  Target Sector: Financial / Cryptocurrency")
	Endpoint.Say("  Target Platform: macOS")
	Endpoint.Say("")

	// Initialize Schema v2.0 metadata
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "initial_access",
		Severity: "critical",
		Techniques: []string{
			"T1553.001", "T1543.004", "T1059.002",
			"T1071.001", "T1041",
		},
		Tactics: []string{
			"initial-access", "persistence", "credential-access",
			"command-and-control", "exfiltration", "defense-evasion",
		},
		Score: 9.2,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        1.8,
			DetectionOpportunities:  0.8,
			LoggingObservability:    0.8,
		},
		Tags: []string{
			"multi-stage", "dprk", "lazarus", "bluenoroff",
			"rustbucket", "hidden-risk", "launchagent", "zshenv",
			"osascript", "keychain", "crypto-wallet", "sliver",
			"macos", "financial-sector", "gatekeeper-bypass",
		},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         600000, // 10 minutes
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Run the test
	test()
}

func test() {
	// Define the 5-stage killchain based on BlueNoroff attack intelligence
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Gatekeeper Bypass & Payload Delivery",
			Technique:   "T1553.001",
			BinaryName:  fmt.Sprintf("%s-T1553.001", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Simulate curl-based download (no quarantine), notarized malware with hijacked developer ID, xattr removal",
		},
		{
			ID:          2,
			Name:        "LaunchAgent Persistence",
			Technique:   "T1543.004",
			BinaryName:  fmt.Sprintf("%s-T1543.004", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Install RustBucket LaunchAgent, BeaverTail LaunchAgent, Hidden Risk .zshenv, LaunchDaemon",
		},
		{
			ID:          3,
			Name:        "Credential Harvesting",
			Technique:   "T1059.002",
			BinaryName:  fmt.Sprintf("%s-T1059.002", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Simulate osascript password dialog, Keychain dump, browser creds, crypto wallet theft",
		},
		{
			ID:          4,
			Name:        "Multi-Protocol C2 Communication",
			Technique:   "T1071.001",
			BinaryName:  fmt.Sprintf("%s-T1071.001", TEST_UUID),
			BinaryData:  stage4Binary,
			Description: "Establish Sliver mTLS beacon, HTTPS fallback, DNS tunnel, Google Drive staging",
		},
		{
			ID:          5,
			Name:        "Financial Data Exfiltration",
			Technique:   "T1041",
			BinaryName:  fmt.Sprintf("%s-T1041", TEST_UUID),
			BinaryData:  stage5Binary,
			Description: "Archive data (AMOS pattern), exfiltrate via AWS S3, Google Drive, HTTP POST",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for _, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s", stage.BinaryName))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Extraction failed: %v", err))
			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		Endpoint.Say("  [+] Extracted: %s (%d bytes)", stage.BinaryName, len(stage.BinaryData))
	}

	// Extract cleanup utility
	cleanupPath := filepath.Join("/tmp/F0", "bluenoroff_cleanup")
	if err := os.WriteFile(cleanupPath, cleanupBinary, 0755); err != nil {
		LogMessage("ERROR", "Extraction", fmt.Sprintf("Failed to extract cleanup utility: %v", err))
	} else {
		Endpoint.Say("  [+] Extracted: bluenoroff_cleanup (cleanup utility)")
		LogFileDropped("bluenoroff_cleanup", cleanupPath, int64(len(cleanupBinary)), false)
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries + cleanup utility", len(killchain)))
	Endpoint.Say("")

	// Track per-stage results for bundle fan-out
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  "critical",
			Tactics:   []string{"initial-access", "persistence", "credential-access", "command-and-control", "exfiltration", "defense-evasion"},
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing 5-stage BlueNoroff attack killchain...")
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exitCode := executeStage(stage)

		if exitCode == 126 || exitCode == 105 {
			// Stage blocked by EDR
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (%s)", stage.Technique, stage.Name)
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("EDR successfully blocked technique %s at stage %d", stage.Technique, stage.ID)
			Endpoint.Say("  Stage: %s", stage.Name)
			Endpoint.Say("  Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Attack Chain Interrupted:")
			Endpoint.Say("  Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  Blocked Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Cleanup: Run '/tmp/F0/bluenoroff_cleanup'")
			Endpoint.Say("=================================================================")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			// Stage error
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage error: exit code %d", exitCode))

			Endpoint.Say("")
			Endpoint.Say("Stage %d encountered error (exit code %d)", stage.ID, exitCode)
			Endpoint.Say("Cleanup: Run '/tmp/F0/bluenoroff_cleanup'")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("%s completed successfully", stage.Technique))
		Endpoint.Say("  Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages completed - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete BlueNoroff attack chain succeeded")
	Endpoint.Say("")
	Endpoint.Say("All %d techniques executed successfully:", len(killchain))
	for _, stage := range killchain {
		Endpoint.Say("  Stage %d: %s (%s)", stage.ID, stage.Technique, stage.Name)
	}
	Endpoint.Say("")
	Endpoint.Say("The system allowed:")
	Endpoint.Say("  1. Gatekeeper bypass with fake notarized payload")
	Endpoint.Say("  2. LaunchAgent and .zshenv persistence installation")
	Endpoint.Say("  3. Credential harvesting (Keychain, browser, crypto wallets)")
	Endpoint.Say("  4. Multi-protocol C2 channel establishment")
	Endpoint.Say("  5. Financial data exfiltration via multiple channels")
	Endpoint.Say("")
	Endpoint.Say("THREAT IMPACT: CRITICAL")
	Endpoint.Say("  - DPRK/BlueNoroff targets financial sector for revenue")
	Endpoint.Say("  - Cryptocurrency theft is a primary objective")
	Endpoint.Say("  - Complete credential compromise achieved")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
	Endpoint.Say("  - Review endpoint detection for macOS-specific threats")
	Endpoint.Say("  - Implement LaunchAgent monitoring")
	Endpoint.Say("  - Monitor .zshenv modifications")
	Endpoint.Say("  - Enable network-level C2 detection")
	Endpoint.Say("  - Cleanup: /tmp/F0/bluenoroff_cleanup")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, "Complete BlueNoroff killchain succeeded - all 5 stages executed")
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)

	Endpoint.Say("")
	Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
	time.Sleep(5 * time.Second)
	Endpoint.Stop(Endpoint.Unprotected)
}

func extractStage(stage KillchainStage) error {
	targetDir := "/tmp/F0"
	os.MkdirAll(targetDir, 0755)

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, stage.BinaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(stage.BinaryData)), false)
	return nil
}

func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("/tmp/F0", stage.BinaryName)

	// Standard 5-minute timeout per stage
	timeout := 5 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = "/tmp/F0"

	// Capture stdout/stderr to both console and buffer
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

	// Heartbeat goroutine
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		startTime := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := int(time.Since(startTime).Seconds())
				Endpoint.Say("  [Progress] Stage executing... (%d seconds elapsed)", elapsed)
			}
		}
	}()

	err := cmd.Wait()
	close(done)

	// Save raw output to file
	outputFilePath := filepath.Join("/tmp/F0", fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputFilePath, outputBuffer.Len()))
	}

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		Endpoint.Say("  Stage execution timeout (5 minutes exceeded)")
		LogMessage("ERROR", "Stage Execution", fmt.Sprintf("Stage %d (%s) timeout", stage.ID, stage.Technique))
		return 999
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
