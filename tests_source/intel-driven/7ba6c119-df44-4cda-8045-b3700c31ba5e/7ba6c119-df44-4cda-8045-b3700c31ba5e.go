// KslKatz Credential Dumping Framework Simulation — Multi-Stage Orchestrator
// F0RT1KA Security Testing Framework
//
// Simulates the prerequisite chain and access primitives of the KslKatz framework
// (vergamota/KslKatz), which combines KslDump + GhostKatz to read LSASS memory via
// a no-fix, Microsoft-signed Defender kernel driver (KslD.sys), bypassing PPL with
// kernel-mode MmCopyMemory physical reads.
//
// SAFETY POSTURE (realism-first with safety gate):
//   - Stage 1 writes the EXACT KslD service value names (AllowedProcessName, ImagePath)
//     the detection logic keys on, but under a SANDBOX-OWNED service key — never the
//     real Defender-associated KslD service. Telemetry/detection surface is identical.
//   - Stage 3 OPENS \\.\KslD (the access event is the detection signal) but issues NO
//     memory-read IOCTL. No kernel physical reads.
//   - Stage 4 exercises the LSASS access primitive (handle enumeration + OpenProcess
//     VM_READ) but reads NO memory and parses NO secrets.
// No real credentials are ever exposed. All mutations are reversible and sandbox-scoped.

//go:build windows

/*
ID: 7ba6c119-df44-4cda-8045-b3700c31ba5e
NAME: KslKatz LSASS Credential Dumping Framework (BYOVD PPL Bypass)
TECHNIQUES: T1543.003, T1112, T1068, T1003.001
TACTICS: persistence, defense-evasion, privilege-escalation, credential-access
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: N/A
SUBCATEGORY: apt
TAGS: byovd, lsass, ppl-bypass, ksld, credential-theft, kernel-driver, mimikatz
SOURCE_URL: https://detect.fyi/ghost-in-lsass-detecting-kslkatz-credential-dumping-framework-8645f246aec9
UNIT: response
CREATED: 2026-06-01
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
	TEST_UUID = "7ba6c119-df44-4cda-8045-b3700c31ba5e"
	TEST_NAME = "KslKatz LSASS Credential Dumping Framework (BYOVD PPL Bypass)"
)

// Embed gzip-compressed, signed stage binaries. Decompressed in memory at
// extraction time — files written to disk are normal signed PEs.
// NEVER use UPX/runtime packers (trigger EDR entropy/packer heuristics).

//go:embed 7ba6c119-df44-4cda-8045-b3700c31ba5e-T1543.003.exe.gz
var stage1Compressed []byte

//go:embed 7ba6c119-df44-4cda-8045-b3700c31ba5e-T1112.exe.gz
var stage2Compressed []byte

//go:embed 7ba6c119-df44-4cda-8045-b3700c31ba5e-T1068.exe.gz
var stage3Compressed []byte

//go:embed 7ba6c119-df44-4cda-8045-b3700c31ba5e-T1003.001.exe.gz
var stage4Compressed []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// KillStage models one technique step in the orchestrated killchain. Named
// KillStage (not Stage) to avoid colliding with test_logger.go's Stage type
// per the CLAUDE.md bug-prevention rule on struct naming.
type KillStage struct {
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
		Version:       "1.0.0",
		Category:      "credential_access",
		Severity:      "critical",
		Techniques:    []string{"T1543.003", "T1112", "T1068", "T1003.001"},
		Tactics:       []string{"persistence", "defense-evasion", "privilege-escalation", "credential-access"},
		Score:         9.0,
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"byovd", "lsass", "ppl-bypass", "ksld", "credential-theft", "kernel-driver", "multi-stage"},
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
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Simulates: KslKatz BYOVD LSASS dumping prerequisite chain")
	Endpoint.Say("Source: detect.fyi - Ghost in LSASS (Omar Tarek Zayed)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	killchain := []KillStage{
		{
			ID:          1,
			Name:        "Defender Kernel Service Reconfiguration (KslD)",
			Technique:   "T1543.003",
			BinaryName:  fmt.Sprintf("%s-T1543.003.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Rewire a KslD-shaped Defender kernel service ImagePath toward a vulnerable driver (sandbox-owned key)",
		},
		{
			ID:          2,
			Name:        "Driver Trust Tampering via AllowedProcessName",
			Technique:   "T1112",
			BinaryName:  fmt.Sprintf("%s-T1112.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Write AllowedProcessName under the KslD service key to defeat the driver's plain-string actor check",
		},
		{
			ID:          3,
			Name:        "Vulnerable Driver Load & Device Open (\\\\.\\KslD)",
			Technique:   "T1068",
			BinaryName:  fmt.Sprintf("%s-T1068.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Drop a vKslD.sys artifact and attempt to open the \\\\.\\KslD kernel device (open-only, no memory IOCTL)",
		},
		{
			ID:          4,
			Name:        "LSASS Memory Access for Credential Extraction",
			Technique:   "T1003.001",
			BinaryName:  fmt.Sprintf("%s-T1003.001.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Enumerate handles to lsass.exe and open it for VM_READ (access primitive only, no memory read)",
		},
	}

	// Phase 0: Extract stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s (%v)", stage.BinaryName, err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	stageSeverity := "critical"
	stageTactics := []string{"persistence", "defense-evasion", "privilege-escalation", "credential-access"}
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

	Endpoint.Say("[*] Executing %d-stage KslKatz attack killchain...", len(killchain))
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
			Endpoint.Say("EDR interrupted the KslKatz chain at stage %d:", stage.ID)
			Endpoint.Say("  - Technique: %s", stage.Technique)
			Endpoint.Say("  - Stage: %s", stage.Name)
			Endpoint.Say("  - Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Attack Chain Interrupted:")
			Endpoint.Say("  - Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  - Blocked Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  - Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Security Status: ENDPOINT IS SECURE")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("ERROR: Stage %d encountered an error (exit %d, technique %s)", stage.ID, exitCode, stage.Technique)
			Endpoint.Say("Possible causes: prerequisites not met, insufficient privileges, or test issue")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed successfully", stage.Technique))
		Endpoint.Say("    Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete KslKatz prerequisite chain executed without prevention")
	Endpoint.Say("")
	Endpoint.Say("Executed Techniques:")
	for _, stage := range killchain {
		Endpoint.Say("  - Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Security Impact: CRITICAL")
	Endpoint.Say("  - Defender kernel service trust could be subverted")
	Endpoint.Say("  - BYOVD driver load path unprotected")
	Endpoint.Say("  - LSASS access primitive unprotected (PPL bypass surface)")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d KslKatz stages completed - prerequisite chain unprotected", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPERS
// ==============================================================================

func extractStage(stage KillStage) error {
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

func executeStage(stage KillStage) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	cmd := exec.Command(stagePath)
	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
