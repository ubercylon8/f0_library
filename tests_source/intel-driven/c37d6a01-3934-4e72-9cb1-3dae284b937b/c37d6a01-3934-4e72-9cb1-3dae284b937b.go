// Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration — Multi-Stage Orchestrator
// F0RT1KA Security Testing Framework
//
// This orchestrator drives a 3-stage Kothamine-RAT killchain built on tailcat
// (Tailscale's control-plane-less netcat over the WireGuard data plane):
//   Stage 1 (T1105)            — ingress tool transfer: download the pinned
//                                tailcat v0.7.0 binary from GitHub releases
//   Stage 2 (T1572, T1021.004) — protocol tunneling + SSH: launch
//                                `tailcat serve no-auth-ssh` and prove shell
//                                access back over the encrypted tunnel
//   Stage 3 (T1005, T1041)     — collection + exfiltration: drop synthetic
//                                decoy user files under ARTIFACT_DIR and
//                                exfiltrate them to an in-test `tailcat recv`
//                                drop box (hash-verified)
//
// Cross-platform: Windows + Linux. Platform-specific embed/name logic lives in
// orchestrator_embed_windows.go / orchestrator_embed_linux.go; LOG_DIR and
// ARTIFACT_DIR come from the per-platform test_logger_<os>.go files.

/*
ID: c37d6a01-3934-4e72-9cb1-3dae284b937b
NAME: Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration
TECHNIQUES: T1105, T1572, T1021.004, T1005, T1041
TACTICS: command-and-control, lateral-movement, collection, exfiltration
SEVERITY: high
TARGET: windows-endpoint, linux-endpoint
COMPLEXITY: high
THREAT_ACTOR: Kothamine (unattributed)
SUBCATEGORY: c2
TAGS: kothamine, tailcat, tailscale, wireguard, derp, c2, tunneling, ssh, exfiltration, npm-supply-chain
SOURCE_URL: N/A
UNIT: response
CREATED: 2026-10-14
AUTHOR: sectest-builder
*/

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
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "c37d6a01-3934-4e72-9cb1-3dae284b937b"
	TEST_NAME = "Kothamine Tailcat Encrypted C2 Channel and Data Exfiltration"
)

// stageTimeout bounds each stage binary. Stage 1 downloads ~7 MB from GitHub
// (180s internal budget) and stages 2/3 wait on DERP bootstrap (90s) — 240s
// covers the slowest legitimate path without letting a hung child run forever.
const stageTimeout = 240 * time.Second

// ExitTestError is the F0RT1KA convention for test errors (999). The vendored
// endpoint library maps UnexpectedTestError to 1 — do not use it.
const ExitTestError = 999

// Embedded gzip-compressed (and, on Windows, signed) stage binaries live in the
// per-platform orchestrator_embed_*.go files:
//   - stage1Compressed / stage2Compressed / stage3Compressed
//   - stageBinaryName(technique string) string

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillchainStage represents one technique-stage in the attack killchain.
// NOTE: deliberately NOT named "Stage" — that name is owned by test_logger.go.
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Tactics     []string
	Description string
}

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "command_and_control",
		Severity:      "high",
		Techniques:    []string{"T1105", "T1572", "T1021.004", "T1005", "T1041"},
		Tactics:       []string{"command-and-control", "lateral-movement", "collection", "exfiltration"},
		RubricVersion: "v2.1",
		// Score assigned by the Phase-2 documentation agent under rubric v2.1
		// (post-lab: lab-verified 2026-10-14, all stages reached on Windows
		// with CrowdStrike Falcon active and on Debian 13; exit 101).
		Score: 8.7,
		Tags:  []string{"multi-stage", "kothamine", "tailcat", "tailscale", "wireguard", "derp", "c2", "tunneling", "ssh", "exfiltration"},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         900000,
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(ExitTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(ExitTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Purpose: validate AV/EDR/egress coverage of tailcat-based C2 and exfil")
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
			Name:        "Ingress Tool Transfer (tailcat download)",
			Technique:   "T1105",
			BinaryName:  stageBinaryName("T1105"),
			BinaryData:  stage1Compressed,
			Tactics:     []string{"command-and-control"},
			Description: "Download the pinned tailcat v0.7.0 binary from GitHub releases into LOG_DIR, checksum-verify, extract, and execute",
		},
		{
			ID:          2,
			Name:        "Protocol Tunneling + SSH over tailcat",
			Technique:   "T1572",
			BinaryName:  stageBinaryName("T1572"),
			BinaryData:  stage2Compressed,
			Tactics:     []string{"command-and-control", "lateral-movement"},
			Description: "Launch `tailcat serve no-auth-ssh` (T1572) and prove shell access back over the encrypted tunnel (T1021.004), then kill the server",
		},
		{
			ID:          3,
			Name:        "Data Collection + Exfiltration over tailcat C2",
			Technique:   "T1005",
			BinaryName:  stageBinaryName("T1005"),
			BinaryData:  stage3Compressed,
			Tactics:     []string{"collection", "exfiltration"},
			Description: "Create synthetic decoy user files in ARTIFACT_DIR (T1005) and exfiltrate them via `tailcat cp` to an in-test receiver (T1041), hash-verified",
		},
	}

	// Preflight: ARTIFACT_DIR must exist AND be writable before any stage runs —
	// an unmet prerequisite is reported before Phase 0 drops three signed stage
	// binaries into LOG_DIR (no file-drop telemetry for a non-viable run).
	Endpoint.Say("[*] Preflight: provisioning ARTIFACT_DIR (%s) ...", ARTIFACT_DIR)
	if err := EnsureArtifactDir(); err != nil {
		LogMessage("ERROR", "Preflight", fmt.Sprintf("ARTIFACT_DIR prerequisite not met: %v", err))
		Endpoint.Say("    [!] %v", err)
		Endpoint.Say("")
		Endpoint.Say("FATAL: prerequisite not met — INCONCLUSIVE, not a protection verdict.")
		Endpoint.Say("")
		Endpoint.Say("Remediation (run once, elevated):")
		for _, cmd := range ArtifactDirRemediation() {
			Endpoint.Say("    %s", cmd)
		}
		Endpoint.Say("")

		SaveLog(ExitTestError, fmt.Sprintf("ARTIFACT_DIR prerequisite not met: %v", err))
		Endpoint.Stop(ExitTestError)
	}
	Endpoint.Say("    [+] %s is provisioned and writable", ARTIFACT_DIR)
	Endpoint.Say("")

	// Phase 0: extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries to %s ...", len(killchain), LOG_DIR)

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			Endpoint.Say("    Error: %v", err)
			SaveLog(ExitTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(ExitTestError)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Per-stage results for bundle fan-out
	stageSeverity := "high"
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique:   stage.Technique,
			Name:        stage.Name,
			Description: stage.Description,
			Severity:    stageSeverity,
			Tactics:     stage.Tactics,
			ExitCode:    0,
			Status:      "skipped",
		}
	}

	Endpoint.Say("[*] Executing %d-stage Kothamine tailcat killchain...", len(killchain))
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

		// Exit-code semantics (see stage sources):
		//   0        → stage's technique executed unimpeded
		//   126/105/127 → positive protection evidence — PROTECTED
		//   102      → stage exceeded its time budget — TIMEOUT
		//   999      → prerequisite/ambiguous error — inconclusive
		if exitCode == 126 || exitCode == 105 || exitCode == 127 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Protection layer intervened at %s (exit code: %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("Protection layer intervened at %s (exit code: %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("FINAL EVALUATION: Stage %d Intercepted", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("")
			Endpoint.Say("A protection layer intervened at stage %d:", stage.ID)
			Endpoint.Say("  - Technique: %s", stage.Technique)
			Endpoint.Say("  - Stage: %s", stage.Name)
			Endpoint.Say("  - Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Killchain Interrupted:")
			Endpoint.Say("  - Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  - Intercepted Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  - Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Security Status: ENDPOINT IS SECURE")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protection layer intervened at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "c2", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode == 102 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage %d timed out after %v", stage.ID, stageTimeout)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s exceeded its time budget", stage.Technique))

			Endpoint.Say("")
			Endpoint.Say("TIMEOUT: Stage %d exceeded its time budget (%v)", stage.ID, stageTimeout)
			Endpoint.Say("")

			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Stage %d (%s) timed out", stage.ID, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "c2", stageResults)
			Endpoint.Stop(Endpoint.TimeoutExceeded)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d could not complete (exit code %d)", stage.ID, exitCode)
			Endpoint.Say("    Technique: %s", stage.Technique)
			Endpoint.Say("")
			Endpoint.Say("This is inconclusive — NOT a protection verdict. Likely causes:")
			Endpoint.Say("  - No internet egress (GitHub / Tailscale DERP relays unreachable)")
			Endpoint.Say("  - Missing system OpenSSH client (ssh/scp) required by tailcat ssh/cp")
			Endpoint.Say("  - ARTIFACT_DIR (%s) not provisioned/writable", ARTIFACT_DIR)
			Endpoint.Say("")

			SaveLog(ExitTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "c2", stageResults)
			Endpoint.Stop(ExitTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s executed", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s executed", stage.Technique))
		Endpoint.Say("    Stage %d executed", stage.ID)
		Endpoint.Say("")
	}

	// All stages executed without a protection layer intervening.
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: UNPROTECTED (C2 ESTABLISHED, DATA EXFILTRATED)")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: The full Kothamine tailcat killchain completed:")
	Endpoint.Say("  - tailcat tooling pulled from GitHub and executed")
	Endpoint.Say("  - Encrypted WireGuard C2 channel established via DERP relays")
	Endpoint.Say("  - Unauthenticated SSH shell proven over the tunnel")
	Endpoint.Say("  - Decoy user data exfiltrated over the encrypted channel")
	Endpoint.Say("")
	Endpoint.Say("No AV/EDR/egress control intervened at any stage.")
	Endpoint.Say("")
	Endpoint.Say("RECOMMENDED ACTION: alert on tailcat/Tailscale data-plane tooling and")
	Endpoint.Say("unauthorized DERP-relay egress; restrict inbound tool transfer.")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - tailcat C2 established and decoy data exfiltrated", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "c2", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPERS
// ==============================================================================

// extractStage decompresses and writes a gzip-compressed stage binary to LOG_DIR.
func extractStage(stage KillchainStage) error {
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", LOG_DIR, err)
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

// executeStage runs a stage binary under a per-stage timeout and returns its
// exit code (102 if the stage exceeded stageTimeout). Stage stdout/stderr is
// captured to both the console and LOG_DIR/<binary>_output.txt via
// io.MultiWriter (CLAUDE.md mandatory stdout/stderr capture pattern).
func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)

	ctx, cancel := context.WithTimeout(context.Background(), stageTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, stagePath)

	outPath := filepath.Join(LOG_DIR, stage.BinaryName+"_output.txt")
	if outFile, ferr := os.Create(outPath); ferr == nil {
		defer outFile.Close()
		cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
		cmd.Stderr = io.MultiWriter(os.Stderr, outFile)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, 102, "stage timeout")
			return 102
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		code, why := classifyStageLaunchError(err, stagePath)
		Endpoint.Say("  Stage launch failed: %s", why)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, err.Error())
		return code
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
