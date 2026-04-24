// F0RT1KA Multi-Stage Test Orchestrator
// BlueHammer Early-Stage Behavioral Simulation (Nightmare-Eclipse, 2026)
//
// Simulates only the OBSERVABLE primitives of BlueHammer's initial phases:
//   Stage 1 (T1211): Cloud Files sync-root registration + fetch-placeholder callback + EICAR drop
//   Stage 2 (T1562.001): Batch-oplock primitive on a sandbox file (5s timeout, always released)
//   Stage 3 (T1211): VSS device enumeration (read-only) + transacted-open attempt on sandbox file
//
// EXPLICITLY OUT OF SCOPE (never implemented):
//   - SAM hive access (any hive, anywhere)
//   - VSS shadow-copy file opens
//   - offreg, samlib.dll, LSA boot-key reads
//   - password/hash derivation, token manipulation, privilege enablement
//   - service creation, cross-session process spawning
//   - Real Defender freeze (oplock released within 5s regardless)
//   - Real Defender definition update download

//go:build windows

/*
ID: 5e59dd6a-6c87-4377-942c-ea9b5e054cb9
NAME: BlueHammer Early-Stage Behavioral Pattern
TECHNIQUES: T1211, T1562.001
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Nightmare-Eclipse
SUBCATEGORY: apt
TAGS: cloud-files, oplock, vss-enum, eicar, transacted-open, defender-evasion
SOURCE_URL: https://github.com/Nightmare-Eclipse/BlueHammer
UNIT: response
CREATED: 2026-04-24
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

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
	TEST_NAME = "BlueHammer Early-Stage Behavioral Pattern"
)

// Embedded gzip-compressed SIGNED stage binaries
// Build process: build_all.sh — builds stages, signs, gzips, embeds, signs orchestrator

//go:embed 5e59dd6a-6c87-4377-942c-ea9b5e054cb9-T1211-cfapi.exe.gz
var stage1Compressed []byte

//go:embed 5e59dd6a-6c87-4377-942c-ea9b5e054cb9-T1562.001-oplock.exe.gz
var stage2Compressed []byte

//go:embed 5e59dd6a-6c87-4377-942c-ea9b5e054cb9-T1211-vssenum.exe.gz
var stage3Compressed []byte

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "high",
		Techniques: []string{"T1211", "T1562.001"},
		Tactics:    []string{"defense-evasion"},
		Score:      9.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.7,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.7,
			LoggingObservability:    0.8,
		},
		Tags: []string{"cloud-files", "oplock", "vss-enum", "eicar", "transacted-open", "bluehammer", "nightmare-eclipse"},
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

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Source:    https://github.com/Nightmare-Eclipse/BlueHammer")
	Endpoint.Say("Scope:     Observable primitives of phases 1-3 ONLY")
	Endpoint.Say("           (SAM/VSS-file access and later phases NOT simulated)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

type stageDef struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func test() {
	killchain := []stageDef{
		{
			ID:          1,
			Name:        "Cloud Files Sync-Root + Fetch-Placeholder Callback + EICAR Drop",
			Technique:   "T1211",
			BinaryName:  fmt.Sprintf("%s-T1211-cfapi.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Register a non-standard Cloud Files provider with a fetch-placeholder callback, drop EICAR in the sync-root sandbox",
		},
		{
			ID:          2,
			Name:        "Batch Oplock on Sandbox File",
			Technique:   "T1562.001",
			BinaryName:  fmt.Sprintf("%s-T1562.001-oplock.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Request FSCTL_REQUEST_BATCH_OPLOCK on a sandbox file; always release within 5 seconds",
		},
		{
			ID:          3,
			Name:        "VSS Device Enumeration + Transacted-Open on Sandbox File",
			Technique:   "T1211",
			BinaryName:  fmt.Sprintf("%s-T1211-vssenum.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Enumerate \\Device for HarddiskVolumeShadowCopy* (read-only recon) + transacted CreateFileTransacted against a sandbox file",
		},
	}

	// Phase 0: Extract stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Extraction failed for %s: %v", stage.BinaryName, err))
			Endpoint.Say("FATAL: Extraction failed for %s: %v", stage.BinaryName, err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted")
	Endpoint.Say("")

	stageSeverity := "high"
	stageTactics := []string{"defense-evasion"}
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

	Endpoint.Say("[*] Executing %d-stage behavioral simulation...", len(killchain))
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
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (exit %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("EDR blocked %s (exit %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED — EDR blocked at stage %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("=================================================================")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s", stage.ID, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s errored (exit %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d errored (exit %d)", stage.ID, exitCode)

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) errored (exit %d)", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed without prevention", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed without prevention", stage.Technique))
		Endpoint.Say("    Stage %d completed without prevention", stage.ID)
		Endpoint.Say("")
	}

	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: UNPROTECTED — all 3 observable primitives executed without prevention")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("EDR did not raise a detection on any of:")
	Endpoint.Say("  - Cloud Files sync-root + fetch-placeholder callback registration")
	Endpoint.Say("  - Batch oplock request on sandbox file (FSCTL_REQUEST_BATCH_OPLOCK)")
	Endpoint.Say("  - VSS device enumeration + transacted-open on sandbox file")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d observable primitives executed without detection", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPERS
// ==============================================================================

func extractStage(stage stageDef) error {
	targetDir := LOG_DIR
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %v", targetDir, err)
	}
	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("decompress %s: %v", stage.BinaryName, err)
	}
	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("write %s: %v", stage.BinaryName, err)
	}
	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)
	return nil
}

func decompressGzip(compressed []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %v", err)
	}
	defer r.Close()
	return io.ReadAll(r)
}

func executeStage(stage stageDef) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	cmd := exec.Command(stagePath)
	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, exitErr.Error())
			return code
		}
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}
	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
