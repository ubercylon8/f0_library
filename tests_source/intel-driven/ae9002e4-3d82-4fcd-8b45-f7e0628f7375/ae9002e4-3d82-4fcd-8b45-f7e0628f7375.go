//go:build linux
// +build linux

/*
ID: ae9002e4-3d82-4fcd-8b45-f7e0628f7375
NAME: Mini Shai-Hulud npm Supply Chain Kill Chain (@redhat-cloud-services)
TECHNIQUES: T1195.002, T1059.007, T1480.001, T1497.001, T1105, T1552.001, T1552.004, T1552.005, T1071.001, T1041, T1567.001, T1080
TACTICS: initial-access, execution, defense-evasion, credential-access, command-and-control, exfiltration, lateral-movement
SEVERITY: critical
TARGET: linux-endpoint
COMPLEXITY: high
THREAT_ACTOR: Shai-Hulud
SUBCATEGORY: supply-chain
TAGS: multi-stage, supply-chain, npm, preinstall-hook, deobfuscation, bun, execution-guardrails, credential-theft, decoy-credentials, beacon, worm, ci-runner, developer-workstation, linux
SOURCE_URL: https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages
UNIT: response
CREATED: 2026-06-01
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

const (
	TEST_UUID = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TEST_NAME = "Mini Shai-Hulud npm Supply Chain Kill Chain (@redhat-cloud-services)"
)

// Embed gzip-compressed stage binaries (compressed at build time, decompressed
// in memory at extraction). Files written to disk are normal ELF binaries.
// Linux ELF code signing is a no-op (Authenticode is Windows-only).
//
//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1195.002.gz
var stage1Compressed []byte

//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1480.001.gz
var stage2Compressed []byte

//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1105.gz
var stage3Compressed []byte

//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1552.001.gz
var stage4Compressed []byte

//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1071.001.gz
var stage5Compressed []byte

//go:embed ae9002e4-3d82-4fcd-8b45-f7e0628f7375-T1567.001.gz
var stage6Compressed []byte

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
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Multi-stage architecture: 6-stage npm supply-chain compromise killchain")
	Endpoint.Say("Threat: 'mini Shai-Hulud' via compromised @redhat-cloud-services npm packages")
	Endpoint.Say("Platform: Linux developer workstation / CI runner (SIMULATION ONLY)")
	Endpoint.Say("")

	// Initialize shared logger with Schema v2.0 metadata and execution context
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "supply-chain",
		Severity:      "critical",
		Techniques:    []string{"T1195.002", "T1059.007", "T1480.001", "T1497.001", "T1105", "T1552.001", "T1552.004", "T1552.005", "T1071.001", "T1041", "T1567.001", "T1080"},
		Tactics:       []string{"initial-access", "execution", "defense-evasion", "credential-access", "command-and-control", "exfiltration", "lateral-movement"},
		Score:         9.3,
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.8,
			LoggingObservability:    1.0,
		},
		Tags: []string{"multi-stage", "supply-chain", "npm", "preinstall-hook", "deobfuscation", "bun", "execution-guardrails", "credential-theft", "decoy-credentials", "beacon", "worm", "ci-runner", "linux"},
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

	// Define killchain. Technique IDs are assigned accurately here (the source
	// article's own ATT&CK mapping is loose; e.g. it labels the npm hook T1053).
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "npm Install-Hook Execution & Staged Deobfuscation",
			Technique:   "T1195.002",
			BinaryName:  fmt.Sprintf("%s-T1195.002", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Simulate preinstall hook (node index.js) + multi-layer deobfuscation of a BENIGN embedded payload (char-code map -> AES-GCM blobs)",
		},
		{
			ID:          2,
			Name:        "Execution Guardrails & Sandbox Evasion",
			Technique:   "T1480.001",
			BinaryName:  fmt.Sprintf("%s-T1480.001", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Simulate locale check (skip if ru-*), CI/CD detection (GITHUB_ACTIONS/RUNNER_OS), daemonization decision, and lock-file canary",
		},
		{
			ID:          3,
			Name:        "JS Runtime Acquisition (Bun) — Stubbed",
			Technique:   "T1105",
			BinaryName:  fmt.Sprintf("%s-T1105", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Simulate 'download + unzip Bun runtime' staging behavior WITHOUT any real network fetch (curl/unzip command strings logged only)",
		},
		{
			ID:          4,
			Name:        "Credential & Secret Discovery (Decoy Artifacts)",
			Technique:   "T1552.001",
			BinaryName:  fmt.Sprintf("%s-T1552.001", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Plant DECOY credential files under the artifact dir, then enumerate/read ONLY those decoys (never real ~/.aws, ~/.ssh, gh auth token, etc.)",
		},
		{
			ID:          5,
			Name:        "C2 Beacon & Synthetic Exfiltration (Loopback Sink)",
			Technique:   "T1071.001",
			BinaryName:  fmt.Sprintf("%s-T1071.001", TEST_UUID),
			BinaryData:  stage5Compressed,
			Description: "Gzip+AES-wrap a SYNTHETIC envelope and POST it to a benign loopback sink (127.0.0.1) — no real attacker infrastructure contacted",
		},
		{
			ID:          6,
			Name:        "Worm Propagation via Code Repositories — Log-Only",
			Technique:   "T1567.001",
			BinaryName:  fmt.Sprintf("%s-T1567.001", TEST_UUID),
			BinaryData:  stage6Compressed,
			Description: "Represent self-propagation (repo/workflow modification, downstream npm publish, GitHub-commit exfil fallback) as a LOGGED SIMULATED step ONLY — no real repos or registries touched",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("Phase 0: Extracting %d stage binaries...", len(killchain))

	for _, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s", stage.BinaryName))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Extraction failed: %v", err))
			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
		Endpoint.Say("  [+] Extracted: %s", stage.BinaryName)
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("")

	// Track per-stage results for bundle fan-out (per-stage ES documents)
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  "critical",
			Tactics:   metadata.Tactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing 6-stage Mini Shai-Hulud npm Supply Chain Kill Chain...")
	Endpoint.Say("")

	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")

		exitCode := executeStage(stage)

		if exitCode == 126 || exitCode == 105 {
			// Stage blocked by EDR
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (%s)", stage.Technique, stage.Name)
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("EDR blocked %s", stage.Technique))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("EDR successfully blocked technique %s at stage %d", stage.Technique, stage.ID)
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

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)

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
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %s failed with code %d", stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)

			Endpoint.Say("")
			Endpoint.Say("Stage %d failed with error code %d", stage.ID, exitCode)
			Endpoint.Say("")
			Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
			time.Sleep(5 * time.Second)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded - continue to next stage
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("%s completed successfully", stage.Technique))
		Endpoint.Say("  Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages succeeded = vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("CRITICAL: Complete npm supply-chain kill chain succeeded without prevention")
	Endpoint.Say("")
	Endpoint.Say("All %d techniques executed successfully:", len(killchain))
	for _, stage := range killchain {
		Endpoint.Say("  - Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("The system allowed (all SIMULATED, benign):")
	Endpoint.Say("  1. npm preinstall hook execution + staged deobfuscation")
	Endpoint.Say("  2. Sandbox/locale/CI guardrail evaluation")
	Endpoint.Say("  3. JS runtime (Bun) acquisition staging (stubbed, no download)")
	Endpoint.Say("  4. Decoy credential discovery and reads")
	Endpoint.Say("  5. C2 beacon + synthetic exfiltration to loopback sink")
	Endpoint.Say("  6. Worm propagation (log-only simulated step)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
	Endpoint.Say("  - Audit npm install-time script execution policy (ignore-scripts)")
	Endpoint.Say("  - Monitor node/bun spawning curl/unzip and reading credential paths")
	Endpoint.Say("  - Deploy egress controls on developer workstations and CI runners")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, "Complete npm supply-chain killchain succeeded - all 6 techniques executed")
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "supply-chain", stageResults)

	Endpoint.Say("")
	Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
	time.Sleep(5 * time.Second)
	Endpoint.Stop(Endpoint.Unprotected)
}

// extractStage decompresses a gzip-embedded stage binary and writes it to /tmp/F0
func extractStage(stage KillchainStage) error {
	targetDir := "/tmp/F0"
	os.MkdirAll(targetDir, 0755)

	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)
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

// executeStage executes a stage binary and returns its exit code
func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("/tmp/F0", stage.BinaryName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = "/tmp/F0"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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

	if ctx.Err() == context.DeadlineExceeded {
		Endpoint.Say("  Stage execution timeout (5 minutes exceeded)")
		LogMessage("ERROR", "Stage Execution", fmt.Sprintf("Stage %d (%s) timeout after 5 minutes", stage.ID, stage.Technique))
		return 999
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		errMsg := fmt.Sprintf("Stage execution error for %s: %v", stage.Technique, err)
		Endpoint.Say("  Stage execution error: %v", err)
		LogMessage("ERROR", stage.Technique, errMsg)
		return 999
	}

	return 0
}
