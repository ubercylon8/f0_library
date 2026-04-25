// F0RT1KA Multi-Stage Test Orchestrator
// BlueHammer Early-Stage Behavioral Simulation (Nightmare-Eclipse, 2026)
//
// Simulates only the OBSERVABLE primitives of BlueHammer's initial phases:
//   Stage 1 (T1211):     Cloud Files sync-root + fetch-placeholder callback + Mimikatz-named EICAR drop
//   Stage 2 (T1562.001): Batch-oplock primitive on a sandbox file (5s timeout, always released)
//   Stage 3 (T1211):     NT Object enumeration of \Device + WMI shadow-copy enumeration + transacted-open on sandbox file
//   Stage 4 (T1003.002): Privilege-enable telemetry + synthetic SAM-named hive load/read (sandbox-only, watchdog-protected)
//
// SAFETY GUARANTEES (Tier 1 v2 gate):
//   - All file writes confined to ARTIFACT_DIR or LOG_DIR.
//   - No real SAM/SECURITY/SYSTEM hive ever opened. Stage 4 loads a SYNTHETIC
//     sandbox file generated at runtime via RegSaveKey from a temp HKLM key
//     we created. The temp key and the loaded mount point are removed on
//     cleanup; a watchdog goroutine force-unloads on panic/timeout.
//   - No VSS shadow-copy creation (Win32_ShadowCopy.Create is NEVER called —
//     stage 3 only enumerates with a read-only WQL query).
//   - No COM activation against production brokers; no service start/stop.
//   - All oplocks released within 5s; all transactions rolled back; all
//     handles closed in defer.
//
// EXPLICITLY OUT OF SCOPE:
//   - Real SAM, SECURITY, or SYSTEM hive access of any kind
//   - Real VSS shadow-copy file opens
//   - Real Defender freeze (oplocks always released within 5s)
//   - offreg use, samlib.dll, LSA boot-key reads
//   - Password/hash derivation, credential extraction
//   - Cross-session or service-context process spawning

//go:build windows

/*
ID: 5e59dd6a-6c87-4377-942c-ea9b5e054cb9
NAME: BlueHammer Early-Stage Behavioral Pattern
TECHNIQUES: T1211, T1562.001, T1003.002, T1134.001
TACTICS: defense-evasion, credential-access, privilege-escalation
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Nightmare-Eclipse
SUBCATEGORY: apt
TAGS: cloud-files, oplock, vss-enum, wmi-shadow-enum, mimikatz-signature, sam-sim, sebackup-privilege, transacted-open, defender-evasion, watchdog
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

//go:embed 5e59dd6a-6c87-4377-942c-ea9b5e054cb9-T1003.002-samsim.exe.gz
var stage4Compressed []byte

// ==============================================================================
// MAIN
// ==============================================================================

func main() {
	metadata := TestMetadata{
		Version:       "2.0.0",
		Category:      "defense_evasion",
		Severity:      "high",
		Techniques:    []string{"T1211", "T1562.001", "T1003.002", "T1134.001"},
		Tactics:       []string{"defense-evasion", "credential-access", "privilege-escalation"},
		Score:         7.0, // v2 — pre-lab cap 7.5; Detection Firing capped at 0.5 until lab evidence lands. Re-score post-lab.
		RubricVersion: "v2",
		// ScoreBreakdown intentionally nil under v2 — the v1 dimensions in
		// the struct don't match v2's tiered structure. The v2 breakdown lives
		// in the info.md scorecard table.
		Tags: []string{"cloud-files", "oplock", "vss-enum", "wmi-shadow-enum", "mimikatz-signature", "sam-sim", "sebackup-privilege", "transacted-open", "bluehammer", "nightmare-eclipse"},
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
	Endpoint.Say("Rubric:    v2 (realism-first, tiered)")
	Endpoint.Say("Scope:     Observable primitives of BlueHammer phases 1-4")
	Endpoint.Say("           Stage 4 SAM-sim is sandbox-only, watchdog-protected")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// X1 — pre-test system snapshot (v2 lift). Captured as best-effort; failure
	// is logged but never aborts the test.
	captureSystemSnapshot("pre")

	test()
	// NOTE: test() always calls Endpoint.Stop() which invokes os.Exit(),
	// so any code after this line is unreachable. The post-snapshot is
	// captured INSIDE test() before each Endpoint.Stop() site. (Fix for
	// the v2 dead-code bug surfaced by the 2026-04-25 lab run.)
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
			Name:        "Cloud Files Sync-Root + Fetch-Placeholder Callback + Mimikatz-Named EICAR Drop",
			Technique:   "T1211",
			BinaryName:  fmt.Sprintf("%s-T1211-cfapi.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Register a non-standard Cloud Files provider with a fetch-placeholder callback; drop EICAR content in the sync-root sandbox under a Mimikatz-suggestive filename so path-based detection rules also fire",
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
			Name:        "NT Object Enum + WMI Shadow Enum + Transacted-Open on Sandbox File",
			Technique:   "T1211",
			BinaryName:  fmt.Sprintf("%s-T1211-vssenum.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Enumerate \\Device for HarddiskVolumeShadowCopy* (read-only recon) + WQL Win32_ShadowCopy enumeration via PowerShell + transacted CreateFileTransacted against a sandbox file",
		},
		{
			ID:          4,
			Name:        "Privilege-Enable Telemetry + Synthetic SAM-Hive Load (sandbox-only)",
			Technique:   "T1003.002",
			BinaryName:  fmt.Sprintf("%s-T1003.002-samsim.exe", TEST_UUID),
			BinaryData:  stage4Compressed,
			Description: "AdjustTokenPrivileges on SeBackupPrivilege/SeRestorePrivilege as B4 telemetry; if elevated, RegLoadKey a SYNTHETIC sandbox hive under a unique mount name and RegOpenKeyEx-read it (BlueHammer SAM-load API signature). Watchdog force-unloads on timeout/panic. NEVER touches real SAM/SECURITY/SYSTEM hives.",
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
			captureSystemSnapshot("post")
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
			captureSystemSnapshot("post")
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
			captureSystemSnapshot("post")
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
	Endpoint.Say("RESULT: UNPROTECTED — all %d observable primitives executed without prevention", len(killchain))
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("EDR did not raise a detection on any of:")
	Endpoint.Say("  - Cloud Files sync-root + fetch-placeholder callback + Mimikatz-named EICAR drop")
	Endpoint.Say("  - Batch oplock request on sandbox file (FSCTL_REQUEST_BATCH_OPLOCK)")
	Endpoint.Say("  - NT Object enum of \\Device + WMI Win32_ShadowCopy enum + transacted-open")
	Endpoint.Say("  - SeBackupPrivilege/SeRestorePrivilege enable + synthetic SAM-hive RegLoadKey + RegOpenKey")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d observable primitives executed without detection", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "apt", stageResults)
	captureSystemSnapshot("post")
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

	// Quarantine pre-check (Bug Prevention Rule #3 + 2026-04-25 lab finding):
	// EDR/AV may quarantine a stage binary between extraction (Phase 0) and
	// the moment we try to launch it. cmd.Run() against a missing file gives
	// "file does not exist" which would otherwise be misclassified as exit
	// 999 (test error). os.Stat() lets us detect quarantine and return the
	// correct exit 105 (Endpoint.FileQuarantinedOnExtraction) so the
	// orchestrator records the event as a Protected outcome rather than an
	// error.
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		Endpoint.Say("  Stage binary quarantined before launch: %s", stage.BinaryName)
		LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID),
			fmt.Sprintf("Binary missing at launch (quarantined): %s", stage.BinaryName))
		LogFileDropped(stage.BinaryName, stagePath, 0, true)
		return 105
	}

	cmd := exec.Command(stagePath)
	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, exitErr.Error())
			return code
		}
		// Re-check for quarantine: cmd.Run() can also fail with file-not-found
		// if the binary was removed between os.Stat and exec.
		if _, statErr := os.Stat(stagePath); os.IsNotExist(statErr) {
			LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID),
				fmt.Sprintf("Binary disappeared during launch (quarantined mid-run): %s", stage.BinaryName))
			LogFileDropped(stage.BinaryName, stagePath, 0, true)
			return 105
		}
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
	Errors                 []string          `json:"errors,omitempty"`
}

func captureSystemSnapshot(phase string) {
	snap := systemSnapshot{
		Phase:     phase,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Defender computer status via PowerShell. Wraps Get-MpComputerStatus
	// and parses the key/value pairs we care about. Errors are non-fatal.
	if status, err := powerShellMap("Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,AMServiceEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated | Format-List"); err == nil {
		snap.DefenderStatus = status
	} else {
		snap.Errors = append(snap.Errors, fmt.Sprintf("Get-MpComputerStatus: %v", err))
	}

	// ASR rules currently enabled. The IDs are GUIDs.
	if asr, err := powerShellList("(Get-MpPreference).AttackSurfaceReductionRules_Ids"); err == nil {
		snap.ASRRulesEnabled = asr
	} else {
		snap.Errors = append(snap.Errors, fmt.Sprintf("ASR rules: %v", err))
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

	// Hotfix count — quick summary; full list would be too verbose for a snapshot.
	if hcount, err := powerShellInt("(Get-HotFix | Measure-Object).Count"); err == nil {
		snap.HotfixesInstalledCount = hcount
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
