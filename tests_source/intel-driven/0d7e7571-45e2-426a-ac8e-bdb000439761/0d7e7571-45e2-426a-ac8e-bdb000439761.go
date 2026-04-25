//go:build windows
// +build windows

/*
ID: 0d7e7571-45e2-426a-ac8e-bdb000439761
NAME: Nightmare-Eclipse RedSun Cloud Files Rewrite Primitive Chain
TECHNIQUES: T1211, T1006, T1574, T1559.001
TACTICS: defense-evasion, collection, persistence, execution
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Nightmare-Eclipse
SUBCATEGORY: apt
TAGS: cloud-files-api, cfapi, vss-enumeration, batch-oplock, mount-point-reparse, reparse-readback, file-supersede, ntqueryinformationfile, com-activation, tieringengine-precheck, eicar, redsun, primitive-chain
SOURCE_URL: https://github.com/Nightmare-Eclipse/RedSun
UNIT: response
CREATED: 2026-04-24
AUTHOR: sectest-builder
*/

// This test exercises the OBSERVABLE API-surface primitives from the
// Nightmare-Eclipse "RedSun" PoC against sandboxed targets under
// c:\Users\fortika-test. The test NEVER writes to or reparses real system
// directories. Stage 4's COM activation has a HARD pre-check that aborts
// without activation if TieringEngineService is in any state other than
// STOPPED — preventing inadvertent service-start behavior.
//
// The primitives exercised characterize the RedSun detection opportunity
// surface:
//   Stage 1 (T1211):     non-OneDrive Cloud Files sync-root + EICAR drop
//   Stage 2 (T1006):     NtOpenDirectoryObject over \Device + batch oplock
//                        on a sandbox file
//   Stage 3 (T1574):     mount-point reparse (sandbox -> sandbox) + reparse
//                        read-back via FSCTL_GET_REPARSE_POINT (R3) +
//                        NtQueryInformationFile pre-race probe (R4) +
//                        FILE_SUPERSEDE race loop against a sandbox file
//   Stage 4 (T1559.001): TieringEngineService state pre-check + CoCreateInstance
//                        against the CFAPI Sync Root Manager broker CLSID
//                        (only fires when service is STOPPED — guard in stage)
//
// Safety hard-stops enforced in every stage (Tier 1 v2 gate):
//   - all writes under ARTIFACT_DIR (c:\Users\fortika-test)
//   - no reparse target points anywhere outside ARTIFACT_DIR
//   - CoCreateInstance only runs when TieringEngineService is STOPPED
//     (stage 4 pre-check); post-activation safety verifies state didn't change
//   - oplocks are released within the same stage function
//   - VSS handles are opened read-only
//   - no service start/stop ever attempted

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "0d7e7571-45e2-426a-ac8e-bdb000439761"
	TEST_NAME = "Nightmare-Eclipse RedSun Cloud Files Rewrite Primitive Chain"
)

// Embedded gzip-compressed signed stage binaries (signed BEFORE embed)
//
//go:embed 0d7e7571-45e2-426a-ac8e-bdb000439761-T1211.exe.gz
var stage1Compressed []byte

//go:embed 0d7e7571-45e2-426a-ac8e-bdb000439761-T1006.exe.gz
var stage2Compressed []byte

//go:embed 0d7e7571-45e2-426a-ac8e-bdb000439761-T1574.exe.gz
var stage3Compressed []byte

//go:embed 0d7e7571-45e2-426a-ac8e-bdb000439761-T1559.001-com.exe.gz
var stage4Compressed []byte

// KillchainStage avoids name collision with test_logger.go's Stage struct.
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "defense_evasion",
		Severity: "high",
		Techniques: []string{
			"T1211",
			"T1006",
			"T1574",
		},
		Tactics: []string{
			"defense-evasion",
			"collection",
			"persistence",
		},
		Score:         8.0, // v2.1 — lab-verified 2026-04-25 (all 4 stages reached, exit 101). See info.md Score Breakdown.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2 — v1 dimensions in struct
		// don't match v2's tiered structure. Breakdown lives in info.md.
		Tags: []string{
			"redsun",
			"nightmare-eclipse",
			"cloud-files-api",
			"cfapi",
			"vss-enumeration",
			"batch-oplock",
			"mount-point-reparse",
			"reparse-readback",
			"file-supersede",
			"ntqueryinformationfile",
			"com-activation",
			"tieringengine-precheck",
			"eicar",
			"multi-stage",
			"killchain",
		},
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
	Endpoint.Say("Threat Actor: Nightmare-Eclipse (RedSun PoC, 2026)")
	Endpoint.Say("Source: https://github.com/Nightmare-Eclipse/RedSun")
	Endpoint.Say("Sandbox Root: %s", ARTIFACT_DIR)
	Endpoint.Say("Rubric: v2 (realism-first, tiered)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// X1 — pre-test system snapshot (best-effort; failure is logged, never aborts)
	captureSystemSnapshot("pre")

	test()
	// NOTE: test() always calls Endpoint.Stop() (which invokes os.Exit()),
	// so any code after this line is unreachable. The post-snapshot is
	// captured INSIDE test() before each Endpoint.Stop() site.
}

func test() {
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "Cloud Files Sync Root + EICAR Provocation",
			Technique:   "T1211",
			BinaryName:  fmt.Sprintf("%s-T1211.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Register non-OneDrive Cloud Files sync root under sandbox dir and drop EICAR test string (industry-standard AV provoke)",
		},
		{
			ID:          2,
			Name:        "VSS Device Enumeration + Batch Oplock",
			Technique:   "T1006",
			BinaryName:  fmt.Sprintf("%s-T1006.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Enumerate \\Device for HarddiskVolumeShadowCopy* via NtOpenDirectoryObject and request FSCTL_REQUEST_BATCH_OPLOCK on a sandbox file",
		},
		{
			ID:          3,
			Name:        "Mount-Point Reparse + Reparse Read-Back + NtQueryInformationFile + FILE_SUPERSEDE Race",
			Technique:   "T1574",
			BinaryName:  fmt.Sprintf("%s-T1574.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Create mount-point reparse (sandbox->sandbox), read-back via FSCTL_GET_REPARSE_POINT (R3 lift), NtQueryInformationFile pre-race probe (R4 lift), then loop NtCreateFile with FILE_SUPERSEDE against a sandbox target file",
		},
		{
			ID:          4,
			Name:        "TieringEngineService Pre-Check + CFAPI Broker COM Activation",
			Technique:   "T1559.001",
			BinaryName:  fmt.Sprintf("%s-T1559.001-com.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "Hard pre-check on TieringEngineService state — only proceeds if STOPPED. CoCreateInstance against the CFAPI Sync Root Manager broker CLSID for activation telemetry. Post-activation safety check verifies service didn't start.",
		},
	}

	// Phase 0: Extraction
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)
		if err := extractKillchainStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			Endpoint.Say("    Reason: %v", err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			captureSystemSnapshot("post")
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    All stage binaries extracted successfully")
	Endpoint.Say("")

	// Bundle results for ES fan-out
	stageSeverity := "high"
	stageTactics := []string{"defense-evasion", "collection", "persistence", "execution"}
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
	Endpoint.Say("[*] Executing %d-stage RedSun primitive chain...", len(killchain))
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
			Endpoint.Say("FINAL EVALUATION: Stage %d Flagged/Blocked", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("  Technique: %s", stage.Technique)
			Endpoint.Say("  Stage: %s", stage.Name)
			Endpoint.Say("  Exit Code: %d", exitCode)
			Endpoint.Say("  Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("=================================================================")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			captureSystemSnapshot("post")
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("ERROR: Stage %d (%s) exited with %d", stage.ID, stage.Technique, exitCode)

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
			captureSystemSnapshot("post")
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed", stage.Technique))
		Endpoint.Say("    Stage %d completed without prevention", stage.ID)
		Endpoint.Say("")

		if idx < len(killchain)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All RedSun Primitives Observed Without Prevention")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("The endpoint allowed every API-surface primitive that characterizes")
	Endpoint.Say("the RedSun Cloud Files rewrite exploit. A real attacker could chain")
	Endpoint.Say("these primitives together to target system files. This simulation")
	Endpoint.Say("only touched sandbox paths under %s.", ARTIFACT_DIR)
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d RedSun primitives executed without prevention", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	captureSystemSnapshot("post")
	Endpoint.Stop(Endpoint.Unprotected)
}

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

	// Rule 3: use os.Stat, not Endpoint.Quarantined, for quarantine detection
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
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)

	// Quarantine check BEFORE execution (Rule 3)
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary quarantined before execution: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Binary quarantined: %s", stage.BinaryName))
		return 105
	}

	cmd := exec.Command(stagePath)

	// Capture stdout/stderr to both console and file (MANDATORY pattern)
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	outputFilePath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_output.txt", stage.Technique))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Output saved: %s (%d bytes, %v)", outputFilePath, outputBuffer.Len(), executionDuration))
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

// captureSystemSnapshot writes a JSON dump of system-state probes to
// LOG_DIR/<uuid>_system_snapshot_<phase>.json. phase is "pre" or "post".
// Best-effort — failures are logged but never abort the test. (v2 lift X1)
type systemSnapshot struct {
	Phase                  string            `json:"phase"`
	Timestamp              string            `json:"timestamp"`
	DefenderStatus         map[string]string `json:"defenderStatus,omitempty"`
	ASRRulesEnabled        []string          `json:"asrRulesEnabled,omitempty"`
	AVExclusionPaths       []string          `json:"avExclusionPaths,omitempty"`
	AVExclusionExtensions  []string          `json:"avExclusionExtensions,omitempty"`
	AVExclusionProcesses   []string          `json:"avExclusionProcesses,omitempty"`
	HotfixesInstalledCount int               `json:"hotfixesInstalledCount"`
	TieringEngineState     string            `json:"tieringEngineState,omitempty"` // RedSun-specific: relevant to stage 4 pre-check audit trail
	Errors                 []string          `json:"errors,omitempty"`
}

func captureSystemSnapshot(phase string) {
	snap := systemSnapshot{
		Phase:     phase,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if status, err := powerShellMap("Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,AMServiceEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated | Format-List"); err == nil {
		snap.DefenderStatus = status
	} else {
		snap.Errors = append(snap.Errors, fmt.Sprintf("Get-MpComputerStatus: %v", err))
	}

	if asr, err := powerShellList("(Get-MpPreference).AttackSurfaceReductionRules_Ids"); err == nil {
		snap.ASRRulesEnabled = asr
	}
	if paths, err := powerShellList("(Get-MpPreference).ExclusionPath"); err == nil {
		snap.AVExclusionPaths = paths
	}
	if exts, err := powerShellList("(Get-MpPreference).ExclusionExtension"); err == nil {
		snap.AVExclusionExtensions = exts
	}
	if procs, err := powerShellList("(Get-MpPreference).ExclusionProcess"); err == nil {
		snap.AVExclusionProcesses = procs
	}
	if hcount, err := powerShellInt("(Get-HotFix | Measure-Object).Count"); err == nil {
		snap.HotfixesInstalledCount = hcount
	}

	// RedSun-specific: capture TieringEngineService state for audit. Stage 4
	// reads this independently for its pre-check.
	if state, err := powerShellRun("(Get-Service -Name TieringEngineService -ErrorAction SilentlyContinue).Status"); err == nil {
		snap.TieringEngineState = state
	}

	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		LogMessage("WARN", "Snapshot", fmt.Sprintf("MkdirAll(%s) failed: %v", LOG_DIR, err))
		return
	}
	snapPath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_system_snapshot_%s.json", TEST_UUID, phase))
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		LogMessage("WARN", "Snapshot", fmt.Sprintf("JSON marshal: %v", err))
		return
	}
	if err := os.WriteFile(snapPath, data, 0644); err != nil {
		LogMessage("WARN", "Snapshot", fmt.Sprintf("Write %s: %v", snapPath, err))
		return
	}
	LogMessage("INFO", "Snapshot", fmt.Sprintf("System snapshot (%s) written to %s", phase, snapPath))
}

func powerShellRun(command string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), err
	}
	return strings.TrimSpace(string(out)), nil
}

func powerShellMap(command string) (map[string]string, error) {
	out, err := powerShellRun(command)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			result[key] = val
		}
	}
	return result, nil
}

func powerShellList(command string) ([]string, error) {
	out, err := powerShellRun(command)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return []string{}, nil
	}
	var items []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			items = append(items, line)
		}
	}
	return items, nil
}

func powerShellInt(command string) (int, error) {
	out, err := powerShellRun(command)
	if err != nil {
		return 0, err
	}
	var n int
	_, scanErr := fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
	if scanErr != nil {
		return 0, scanErr
	}
	return n, nil
}
