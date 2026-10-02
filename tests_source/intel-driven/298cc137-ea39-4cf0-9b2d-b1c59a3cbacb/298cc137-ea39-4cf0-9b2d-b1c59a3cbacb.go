//go:build windows
// +build windows

/*
ID: 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb
NAME: LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)
TECHNIQUES: T1059.001, T1562.001, T1112, T1003.001, T1003.002, T1021.002, T1570, T1567.002, T1486, T1490, T1070.001
TACTICS: execution, defense-evasion, credential-access, lateral-movement, exfiltration, impact
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: LockBit 3.0
SUBCATEGORY: ransomware
TAGS: lockbit, ransomware, double-extortion, sb-pc-2026-001, assume-breach
SOURCE_URL: N/A
UNIT: response
CREATED: 2026-10-01
AUTHOR: sectest-builder
*/

// Orchestrator — LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)
// F0RT1KA Security Testing Framework
//
// Post-compromise (assume-breach) emulation of the five attacker objectives
// defined by Superintendencia de Bancos supervisory document SB-PC-2026-001
// (Arquetipo A — Ransomware con doble extorsión, reference actor LockBit 3.0):
//
//   Stage 1  T1059.001/T1562.001/T1112   Execution & defense degradation
//   Stage 2  T1003.001/T1003.002         Privileged credential access
//   Stage 3  T1021.002/T1570             Lateral movement (loopback SMB only)
//   Stage 4  T1567.002                   Pre-encryption exfiltration (loopback)
//   Stage 5  T1486/T1490/T1070.001       Impact: encryption & recovery inhibition
//
// Each objective is a separate SIGNED, GZIP-COMPRESSED stage binary embedded
// below. Stage binaries are extracted (decompressed to normal signed PEs) to
// LOG_DIR and executed sequentially; per-stage stdout/stderr is captured to
// LOG_DIR/<binary>_output.txt via io.MultiWriter. Quarantine is detected via
// time.Sleep(3s) + os.Stat (Bug Prevention Rule 3). WriteStageBundleResults()
// is called before EVERY Endpoint.Stop().
//
// Exit mapping: any stage blocked/quarantined (126/105) -> 126; all stages
// succeed -> 101; stage error -> 999.

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
	TEST_UUID = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TEST_NAME = "LockBit 3.0 Double Extortion Kill Chain (SB-PC-2026-001)"
)

// ExitTestError is the F0RT1KA convention for test errors (999). The vendored
// endpoint library maps ExitTestError to 1 — do not use it.
const ExitTestError = 999

// Embed SIGNED + GZIP-COMPRESSED stage binaries (signed BEFORE compression
// and embedding — see build_all.sh). Decompressed in memory at extraction;
// files on disk are normal signed PEs. NEVER use UPX/runtime packers.

//go:embed 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb-T1059.001.exe.gz
var stage1Compressed []byte

//go:embed 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb-T1003.001.exe.gz
var stage2Compressed []byte

//go:embed 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb-T1021.002.exe.gz
var stage3Compressed []byte

//go:embed 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb-T1567.002.exe.gz
var stage4Compressed []byte

//go:embed 298cc137-ea39-4cf0-9b2d-b1c59a3cbacb-T1486.exe.gz
var stage5Compressed []byte

// StageDef describes one killchain stage. (Named StageDef — the shared logger
// already defines a type named Stage; see CLAUDE.md naming-conflict rule.)
type StageDef struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
	Timeout     time.Duration
}

// stageResults holds the per-stage ES fan-out records. Package-level so the
// panic-recovery path can also flush them before Endpoint.Stop().
var stageResults []StageBundleDef

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("Bundle: SB-PC-2026-001 [LOCKBIT] - Arquetipo A (doble extorsion)")
	Endpoint.Say("Scope: post-compromise / assume-breach, 5 objectives, loopback-only lateral+exfil")
	Endpoint.Say("=================================================================")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))

	// Schema v2.0 metadata
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "ransomware",
		Severity: "critical",
		Techniques: []string{
			"T1059.001", "T1562.001", "T1112",
			"T1003.001", "T1003.002",
			"T1021.002", "T1570",
			"T1567.002",
			"T1486", "T1490", "T1070.001",
		},
		Tactics: []string{
			"execution", "defense-evasion", "credential-access",
			"lateral-movement", "exfiltration", "impact",
		},
		Score:         8.8,
		RubricVersion: "v2.1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.4,
			TechnicalSophistication: 2.4,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  1.0,
			LoggingObservability:    1.0,
		},
		Tags: []string{"lockbit", "ransomware", "double-extortion", "sb-pc-2026-001", "assume-breach", "multi-stage"},
	}

	// Resolve organization from registry (empty = default org)
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         900000, // 15 minutes total budget
			CertificateMode:   "self-healing",
			MultiStageEnabled: true,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Panic recovery — flush bundle results before stopping (mandatory).
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			if stageResults != nil {
				WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", stageResults)
			}
			Endpoint.Stop(ExitTestError)
		}
	}()

	test(metadata)
}

func test(metadata TestMetadata) {
	// Define the killchain — one stage per SB-PC-2026-001 objective.
	killchain := []StageDef{
		{
			ID:          1,
			Name:        "Execution & Defense Degradation",
			Technique:   "T1059.001",
			BinaryName:  fmt.Sprintf("%s-T1059.001.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "PowerShell recon (T1059.001), security-service stop/disable attempts (T1562.001), registry modification (T1112)",
			Timeout:     4 * time.Minute,
		},
		{
			ID:          2,
			Name:        "Privileged Credential Access",
			Technique:   "T1003.001",
			BinaryName:  fmt.Sprintf("%s-T1003.001.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "LSASS access primitive + comsvcs.dll MiniDump attempt (T1003.001), SAM hive save attempt (T1003.002)",
			Timeout:     4 * time.Minute,
		},
		{
			ID:          3,
			Name:        "Lateral Movement & Propagation",
			Technique:   "T1021.002",
			BinaryName:  fmt.Sprintf("%s-T1021.002.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Loopback SMB session to ADMIN$ (T1021.002) + benign tool transfer (T1570) - 127.0.0.1 only",
			Timeout:     3 * time.Minute,
		},
		{
			ID:          4,
			Name:        "Pre-Encryption Exfiltration",
			Technique:   "T1567.002",
			BinaryName:  fmt.Sprintf("%s-T1567.002.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Synthetic PII staging, Compress-Archive, loopback HTTP POST with rclone signature (T1567.002)",
			Timeout:     5 * time.Minute,
		},
		{
			ID:          5,
			Name:        "Impact: Encryption & Recovery Inhibition",
			Technique:   "T1486",
			BinaryName:  fmt.Sprintf("%s-T1486.exe", TEST_UUID),
			BinaryData:  stage5Compressed,
			Description: "AES-256-GCM encryption of sandbox documents (T1486), fail-harmless vssadmin/bcdedit (T1490), wevtutil attempt (T1070.001)",
			Timeout:     4 * time.Minute,
		},
	}

	// Initialize per-stage bundle results (skipped until executed)
	stageTactics := map[int][]string{
		1: {"execution", "defense-evasion"},
		2: {"credential-access"},
		3: {"lateral-movement"},
		4: {"exfiltration"},
		5: {"impact"},
	}
	stageResults = make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  metadata.Severity,
			Tactics:   stageTactics[stage.ID],
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	// Phase 0: Extract all stage binaries (decompress -> normal signed PEs)
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries to %s...", len(killchain), LOG_DIR)

	for i, stage := range killchain {
		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("FATAL: Failed to extract stage binary %s: %v", stage.BinaryName, err)
			finalize(ExitTestError,
				fmt.Sprintf("Stage extraction failed for %s: %v", stage.BinaryName, err),
				stageResults)
		}
		Endpoint.Say("  [+] Extracted %d/%d: %s", i+1, len(killchain), stage.BinaryName)
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("")

	// Execute the killchain sequentially. ALL stages run regardless of
	// individual outcomes: SB-PC-2026-001 coverage requires every objective
	// to be attempted (NOT_RUN does not count for coverage), and a real
	// actor does not stop after a single failed primitive.
	Endpoint.Say("[*] Executing %d-stage LockBit 3.0 double-extortion kill chain...", len(killchain))
	Endpoint.Say("")

	anyBlocked := false
	anyError := false

	for idx, stage := range killchain {
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique family: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")

		// Quarantine check (Bug Prevention Rule 3): Sleep + os.Stat.
		stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
		time.Sleep(3 * time.Second)
		if _, err := os.Stat(stagePath); os.IsNotExist(err) {
			stageResults[idx].ExitCode = 105
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Stage binary %s quarantined before execution (os.Stat evidence)", stage.BinaryName)
			LogStageBlocked(stage.ID, stage.Technique, "Stage binary quarantined before execution")
			LogMessage("CRITICAL", stage.Technique, fmt.Sprintf("Stage binary %s missing after extraction - quarantine evidence", stage.BinaryName))
			anyBlocked = true
			Endpoint.Say("  [!] Stage %d binary quarantined before execution (105)", stage.ID)
			Endpoint.Say("")
			continue
		}

		exitCode := executeStage(stage)

		switch {
		case exitCode == 126 || exitCode == 105 || exitCode == 127:
			// Stage positively prevented — recorded, chain continues.
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Protection layer prevented %s at stage %d (exit code %d)", stage.Technique, stage.ID, exitCode)
			LogStageBlocked(stage.ID, stage.Technique, fmt.Sprintf("Stage prevented, exit code %d", exitCode))
			anyBlocked = true
			Endpoint.Say("  [!] Stage %d PREVENTED by endpoint protection (exit code %d)", stage.ID, exitCode)
			Endpoint.Say("")

		case exitCode != 0:
			// Stage error - not attributable to a protection action.
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage error: exit code %d", exitCode))
			anyError = true
			Endpoint.Say("  [x] Stage %d (%s) returned error code %d - inconclusive, continuing chain", stage.ID, stage.Technique, exitCode)
			Endpoint.Say("")

		default:
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "success"
			stageResults[idx].Details = fmt.Sprintf("%s completed without prevention", stage.Technique)
			LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("Stage %d completed", stage.ID))
			Endpoint.Say("  [+] Stage %d completed without prevention", stage.ID)
			Endpoint.Say("")
		}
	}

	// Final verdict across all five SB-PC-2026-001 objectives.
	printStageSummary(killchain, stageResults)

	switch {
	case anyBlocked:
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("At least one critical protection layer prevented a kill-chain stage.")
		Endpoint.Say("=================================================================")
		finalize(Endpoint.ExecutionPrevented,
			"Endpoint protection prevented at least one LockBit kill-chain stage (see per-stage results)",
			stageResults)

	case anyError:
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: INCONCLUSIVE - test error in at least one stage")
		Endpoint.Say("=================================================================")
		finalize(ExitTestError,
			"One or more stages returned an error - kill chain could not be fully evaluated",
			stageResults)

	default:
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: VULNERABLE")
		Endpoint.Say("=================================================================")
		Endpoint.Say("CRITICAL: Complete LockBit 3.0 double-extortion kill chain executed without prevention")
		Endpoint.Say("=================================================================")
		finalize(Endpoint.Unprotected,
			fmt.Sprintf("All %d stages completed - complete LockBit double-extortion kill chain succeeded", len(killchain)),
			stageResults)
	}
}

// printStageSummary renders the per-stage results table for all five objectives.
func printStageSummary(killchain []StageDef, results []StageBundleDef) {
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("KILL CHAIN RESULTS (SB-PC-2026-001 objectives)")
	Endpoint.Say("=================================================================")
	for i, stage := range killchain {
		Endpoint.Say("  Stage %d  %-11s %-45s %-8s exit=%d",
			stage.ID, stage.Technique, stage.Name, results[i].Status, results[i].ExitCode)
	}
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
}

// extractStage decompresses a gzip-embedded stage binary and writes it to LOG_DIR.
func extractStage(stage StageDef) error {
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
	return io.ReadAll(reader)
}

// executeStage runs one stage binary with a per-stage watchdog timeout and
// captures stdout/stderr via io.MultiWriter to console + LOG_DIR/<binary>_output.txt.
func executeStage(stage StageDef) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)

	ctx, cancel := context.WithTimeout(context.Background(), stage.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = LOG_DIR

	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s (watchdog %v)", stage.BinaryName, stage.Timeout))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	// Save raw stage output to LOG_DIR (mandatory capture pattern).
	outputFilePath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_output.txt", stage.BinaryName))
	if werr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); werr != nil {
		LogMessage("WARNING", stage.Technique, fmt.Sprintf("Failed to write stage output capture: %v", werr))
	}

	if ctx.Err() == context.DeadlineExceeded {
		LogMessage("ERROR", stage.Technique, fmt.Sprintf("Stage %d watchdog timeout after %v", stage.ID, stage.Timeout))
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, "watchdog timeout")
		return 999
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode,
				fmt.Sprintf("exit code %d after %v", exitCode, executionDuration))
			return exitCode
		}
		LogMessage("ERROR", stage.Technique, fmt.Sprintf("Stage process returned: %v", err))
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}

// finalize writes the result log + per-stage bundle results, waits for
// platform sync, and stops with the given exit code. WriteStageBundleResults
// is guaranteed to run before EVERY Endpoint.Stop() via this single path.
func finalize(exitCode int, reason string, results []StageBundleDef) {
	SaveLog(exitCode, reason)
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", results)
	Endpoint.Say("")
	Endpoint.Say("Finalizing test results (waiting 5 seconds for platform sync)...")
	time.Sleep(5 * time.Second)
	Endpoint.Stop(exitCode)
}
