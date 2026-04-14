//go:build windows
// +build windows

/*
ID: e5472cd5-c799-4b07-b455-8c02665ca4cf
NAME: HONESTCUE LLM-Assisted Runtime C# Compilation (v2)
TECHNIQUES: T1071.001, T1027.004, T1027.010, T1620, T1105, T1204.002, T1059.001
TACTICS: command-and-control, defense-evasion, execution
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: apt
TAGS: honestcue, llm-abuse, gemini-api, ai-as-runtime, runtime-compilation, reflective-load, github-raw, roslyn, dotnet-8, real-tls, exact-gtig-prompts, multi-stage, killchain
SOURCE_URL: https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use
UNIT: response
CREATED: 2026-04-13
AUTHOR: sectest-builder

v2 CHANGES (2026-04-13):
  - Stage 1 POST -> GET against raw.githubusercontent.com (real TLS+DNS IOCs)
  - Stage 2 Go+powershell+CSharpCodeProvider -> native C# .NET 8 self-contained
    + Roslyn in-memory compile + Assembly.Load(byte[])
  - Stage 3 Discord-CDN hosts-file spoof removed; simple GitHub-raw PE fetch + exec
  - Admin prerequisite removed (no hosts-file modification needed)
  - T1583.006 (Discord CDN) + T1565.001 (hosts file) removed; T1204.002 added
  - See _info.md "Changes from v1" and "Roslyn vs CSharpCodeProvider"

NOTE ON SUBCATEGORY:
  Using `apt` for compatibility with existing CLAUDE.md enum. A new
  subcategory value `llm-abuse` is PROPOSED for AI-as-runtime-component
  threats where an LLM API is a *live dependency at runtime* rather than
  a development assistant. Operators should consider extending the
  official SUBCATEGORY enum to include `llm-abuse`.
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
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TEST_NAME = "HONESTCUE LLM-Assisted Runtime C# Compilation (v2)"
)

// Embed gzip-compressed signed stage binaries
//
//go:embed e5472cd5-c799-4b07-b455-8c02665ca4cf-T1071.001.exe.gz
var stage1Compressed []byte

//go:embed e5472cd5-c799-4b07-b455-8c02665ca4cf-T1027.004.exe.gz
var stage2Compressed []byte

//go:embed e5472cd5-c799-4b07-b455-8c02665ca4cf-T1105.exe.gz
var stage3Compressed []byte

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

// Temp files we drop across the chain; cleaned best-effort on exit.
var tempFiles = []string{
	`c:\F0\honestcue_stage2_source.cs`,
	`c:\F0\stage1_network.log`,
	`c:\F0\stage2_roslyn.log`,
	`c:\F0\stage3_network.log`,
	`c:\F0\T1071.001_output.txt`,
	`c:\F0\T1027.004_output.txt`,
	`c:\F0\T1105_output.txt`,
	`C:\Windows\Temp\honestcue_payload.exe`,
}

// ==============================================================================
// MAIN FUNCTION
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:    "2.1.0",
		Category:   "defense_evasion",
		Severity:   "high",
		Techniques: []string{"T1071.001", "T1027.004", "T1027.010", "T1620", "T1105", "T1204.002", "T1059.001"},
		Tactics:    []string{"command-and-control", "defense-evasion", "execution"},
		Score:      9.4,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.9,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        1.8,
			DetectionOpportunities:  1.0,
			LoggingObservability:    0.7,
		},
		Tags: []string{"honestcue", "llm-abuse", "gemini-api", "ai-as-runtime", "github-raw", "roslyn", "dotnet-8", "real-tls", "exact-gtig-prompts", "multi-stage", "killchain"},
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

	// Install panic recovery with best-effort cleanup of temp files.
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	// Install signal handler for Ctrl+C / termination.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		LogMessage("WARN", "Runtime", "Received termination signal - exiting")
		os.Exit(999)
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test (v2): %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Reference: GTIG AI Threat Tracker (Feb 2026) - HONESTCUE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	// Prerequisite: powershell.exe available (stage-2 Roslyn is self-contained,
	// but Roslyn runtime on some Windows SKUs reaches powershell via AppContext
	// probe in rare edge cases; also useful for optional diagnostic commands).
	// NOTE: the stage-2 C# binary itself is SELF-CONTAINED .NET 8 — it does NOT
	// require an external .NET runtime. The powershell prereq is kept only as
	// a sanity check for the target host being a real Windows box.
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		Endpoint.Say("[!] Prerequisite failed: powershell.exe not available")
		LogMessage("ERROR", "Prerequisites", "powershell.exe not in PATH - target host may not be Windows")
		SaveLog(Endpoint.UnexpectedTestError, "Missing prerequisite: powershell.exe")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
		return
	}
	LogMessage("INFO", "Prerequisites", "powershell.exe located (Windows host confirmed)")

	killchain := []KillchainStage{
		{
			ID:         1,
			Name:       "LLM API Fetch (GitHub-Raw GET)",
			Technique:  "T1071.001",
			BinaryName: fmt.Sprintf("%s-T1071.001.exe", TEST_UUID),
			BinaryData: stage1Compressed,
			Description: "Real HTTPS GET to raw.githubusercontent.com for pre-staged " +
				"Gemini-shaped JSON response containing C# source; produces real TLS+DNS IOCs; " +
				"hands off C# source to stage 2 via disk",
		},
		{
			ID:         2,
			Name:       "Roslyn In-Memory Compile & Reflective Load",
			Technique:  "T1027.004",
			BinaryName: fmt.Sprintf("%s-T1027.004.exe", TEST_UUID),
			BinaryData: stage2Compressed,
			Description: "Native C# .NET 8 self-contained executable uses Microsoft.CodeAnalysis.CSharp " +
				"(Roslyn) CSharpCompilation.Create + Emit(MemoryStream) to compile the LLM-sourced " +
				"C# in-memory, Assembly.Load(byte[]) reflective load, invokes Run() which reads " +
				"Defender registry subkey and writes marker to ARTIFACT_DIR; covers T1027.004 + " +
				"T1027.010 + T1620",
		},
		{
			ID:         3,
			Name:       "GitHub-Raw PE Fetch & Execute",
			Technique:  "T1105",
			BinaryName: fmt.Sprintf("%s-T1105.exe", TEST_UUID),
			BinaryData: stage3Compressed,
			Description: "Real HTTPS GET to raw.githubusercontent.com for pre-staged F0RT1KA-signed " +
				"benign marker PE; drop to c:\\Windows\\Temp; execute; covers T1105 + T1204.002",
		},
	}

	// Phase 0: Extract stage binaries
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
	stageSeverity := "high"
	stageTactics := []string{"command-and-control", "defense-evasion", "execution"}
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
	Endpoint.Say("[*] Executing %d-stage HONESTCUE v2 killchain...", len(killchain))
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
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("  Technique: %s", stage.Technique)
			Endpoint.Say("  Stage: %s", stage.Name)
			Endpoint.Say("  Exit Code: %d", exitCode)
			Endpoint.Say("  Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			cleanupTempFiles()
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

			cleanupTempFiles()
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

		if idx < len(killchain)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// All stages completed - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete HONESTCUE v2 chain executed without prevention")
	Endpoint.Say("  Stages Completed: %d/%d", len(killchain), len(killchain))
	for _, stage := range killchain {
		Endpoint.Say("  Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Security Impact: HIGH")
	Endpoint.Say("  LLM API abused as runtime C# source provider (Gemini-shaped JSON on GitHub raw)")
	Endpoint.Say("  In-memory Roslyn compile + reflective .NET 8 assembly load")
	Endpoint.Say("  Trusted-hosting (GitHub raw) abused for signed-PE staging")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	cleanupTempFiles()
	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete HONESTCUE v2 chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPER FUNCTIONS
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

	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), true)
		return fmt.Errorf("file removed after extraction")
	}

	return nil
}

// decompressGzip decompresses gzip-compressed data in memory.
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
		Endpoint.Say("  Stage binary removed before execution: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Binary removed: %s", stage.BinaryName))
		return 105
	}

	cmd := exec.Command(stagePath)

	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

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
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			Endpoint.Say("  Stage %d exited with code: %d", stage.ID, exitCode)
			return exitCode
		}
		errMsg := fmt.Sprintf("Failed to spawn stage %s: %v", stage.Technique, err)
		Endpoint.Say("  %s", errMsg)
		LogMessage("ERROR", stage.Technique, errMsg)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}

// cleanupTempFiles removes handoff & log files created by the stages.
// Best-effort; no errors are surfaced. The dropped payload PE under
// c:\Windows\Temp is intentionally LEFT BEHIND as evidence of the attack
// chain's file-drop IOC; operators can remove it after forensic review.
func cleanupTempFiles() {
	for _, p := range tempFiles {
		if p == `C:\Windows\Temp\honestcue_payload.exe` {
			// Leave the dropped PE as evidence.
			continue
		}
		_ = os.Remove(p)
	}
}
