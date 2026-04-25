//go:build windows
// +build windows

/*
ID: 6a2351ac-654a-4112-b378-e6919beef70d
NAME: UnDefend - Defender Signature/Engine Update DoS via File-Lock Race
TECHNIQUES: T1562.001, T1083
TACTICS: defense-evasion, discovery
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: Nightmare-Eclipse
SUBCATEGORY: defender-evasion
TAGS: defender-evasion, file-lock-race, read-directory-changes, signature-update-dos, standard-user, ntcreatefile, lockfileex, service-notification, mpavbase-name, productappdatapath, file-disposition-delete-pending, etw-correlation
SOURCE_URL: https://github.com/Nightmare-Eclipse/UnDefend
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

const (
	TEST_UUID = "6a2351ac-654a-4112-b378-e6919beef70d"
	TEST_NAME = "UnDefend - Defender Signature/Engine Update DoS via File-Lock Race"
)

// Embedded gzip-compressed signed stage binaries.
// Built and compressed by build_all.sh (never use UPX / runtime packers).

//go:embed 6a2351ac-654a-4112-b378-e6919beef70d-T1083.exe.gz
var stage1Compressed []byte

//go:embed 6a2351ac-654a-4112-b378-e6919beef70d-T1562.001-lock.exe.gz
var stage2Compressed []byte

//go:embed 6a2351ac-654a-4112-b378-e6919beef70d-T1562.001-svcnotify.exe.gz
var stage3Compressed []byte

// UnDefendStage describes one detection-opportunity stage in the killchain.
// Named UnDefendStage to avoid collision with test_logger.go's Stage struct.
type UnDefendStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "defense_evasion",
		Severity:      "high",
		Techniques:    []string{"T1562.001", "T1083"},
		Tactics:       []string{"defense-evasion", "discovery"},
		Score:         7.0, // v2 — pre-lab cap 7.5; Detection Firing capped at 0.5 until lab evidence lands. Re-score post-lab.
		RubricVersion: "v2",
		// ScoreBreakdown intentionally nil under v2 — v1 dimensions don't match
		// v2's tiered structure. Breakdown lives in info.md.
		Tags: []string{
			"defender-evasion",
			"file-lock-race",
			"read-directory-changes",
			"signature-update-dos",
			"standard-user",
			"ntcreatefile",
			"service-notification",
			"mpavbase-name",
			"productappdatapath",
			"file-disposition-delete-pending",
			"etw-correlation",
			"nightmare-eclipse",
			"undefend",
		},
	}

	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000, // 3 minutes
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
	Endpoint.Say("Threat Actor: Nightmare-Eclipse (UnDefend PoC)")
	Endpoint.Say("Rubric: v2 (realism-first, tiered)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Simulation reproduces the UnDefend file-lock-race primitives")
	Endpoint.Say("WITHOUT touching real Defender files. Sandbox files use Defender-")
	Endpoint.Say("pattern names (mpavbase.vdm, mpengine.dll) so path-rule sensors")
	Endpoint.Say("fire alongside behavior-rule sensors. Real Defender paths are")
	Endpoint.Say("read from registry as telemetry only.")
	Endpoint.Say("")

	// X1 — pre-test system snapshot
	captureSystemSnapshot("pre")

	// U4 — emit a synthetic ETW correlation marker for stage boundary "test_start"
	emitEtwMarker("test_start", "UnDefend orchestrator entering killchain")

	runKillchain()

	emitEtwMarker("test_end", "UnDefend orchestrator killchain complete")
	captureSystemSnapshot("post")
}

func runKillchain() {
	killchain := []UnDefendStage{
		{
			ID:          1,
			Name:        "Defender Update-Path Discovery",
			Technique:   "T1083",
			BinaryName:  fmt.Sprintf("%s-T1083.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Registry recon + ReadDirectoryChangesW watch on Defender Definition Updates directory",
		},
		{
			ID:          2,
			Name:        "UnDefend File-Lock Primitive (Benign Target)",
			Technique:   "T1562.001",
			BinaryName:  fmt.Sprintf("%s-T1562.001-lock.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "NtCreateFile + LockFile/LockFileEx against a sandbox file under ARTIFACT_DIR (benign)",
		},
		{
			ID:          3,
			Name:        "WinDefend Service-Stop Notification Subscription",
			Technique:   "T1562.001",
			BinaryName:  fmt.Sprintf("%s-T1562.001-svcnotify.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "NotifyServiceStatusChangeW subscription on WinDefend (read-only, unregistered immediately)",
		},
	}

	// Phase 0: extract stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))
	for i, s := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), s.BinaryName, s.Technique)
		if err := extractStage(s); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Extract failed for %s: %v", s.BinaryName, err))
			Endpoint.Say("[!] FATAL: Failed to extract stage %s", s.BinaryName)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}
	LogPhaseEnd(0, "success", fmt.Sprintf("Extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    [OK] All stage binaries extracted")
	Endpoint.Say("")

	// Per-stage result tracking for bundle fan-out
	stageSeverity := "high"
	stageTactics := []string{"defense-evasion", "discovery"}
	stageResults := make([]StageBundleDef, len(killchain))
	for i, s := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: s.Technique,
			Name:      s.Name,
			Severity:  stageSeverity,
			Tactics:   stageTactics,
			ExitCode:  0,
			Status:    "skipped",
		}
	}

	Endpoint.Say("[*] Executing %d-stage UnDefend simulation...", len(killchain))
	Endpoint.Say("")

	for idx, s := range killchain {
		LogPhaseStart(s.ID, fmt.Sprintf("%s (%s)", s.Name, s.Technique))
		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", s.ID, len(killchain), s.Name)
		Endpoint.Say("Technique: %s", s.Technique)
		Endpoint.Say("Description: %s", s.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		exit := executeStage(s)

		switch {
		case exit == 126 || exit == 105:
			stageResults[idx].ExitCode = exit
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked stage %d (%s), exit=%d", s.ID, s.Technique, exit)
			LogPhaseEnd(s.ID, "blocked", stageResults[idx].Details)

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("RESULT: PROTECTED")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("EDR blocked UnDefend primitive at stage %d:", s.ID)
			Endpoint.Say("  Technique: %s", s.Technique)
			Endpoint.Say("  Stage:     %s", s.Name)
			Endpoint.Say("  ExitCode:  %d", exit)
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented,
				fmt.Sprintf("EDR blocked stage %d: %s (%s)", s.ID, s.Name, s.Technique))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "defender-evasion", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		case exit != 0:
			stageResults[idx].ExitCode = exit
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage %d error (exit %d)", s.ID, exit)
			LogPhaseEnd(s.ID, "error", stageResults[idx].Details)

			Endpoint.Say("")
			Endpoint.Say("[!] Stage %d encountered an error (exit=%d)", s.ID, exit)
			Endpoint.Say("    Likely prerequisites missing (Defender not present, registry unreadable, etc.)")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, stageResults[idx].Details)
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "defender-evasion", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// success
		stageResults[idx].ExitCode = 0
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s primitive executed without prevention", s.Technique)
		LogPhaseEnd(s.ID, "success", stageResults[idx].Details)
		Endpoint.Say("    [OK] Stage %d completed without EDR intervention", s.ID)
		Endpoint.Say("")
	}

	// All stages succeeded
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("All %d UnDefend primitives ran without EDR intervention:", len(killchain))
	for _, s := range killchain {
		Endpoint.Say("  Stage %d: %s (%s)", s.ID, s.Name, s.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Impact: an attacker running as standard user could chain these")
	Endpoint.Say("primitives against REAL Defender signature/engine files to cause")
	Endpoint.Say("silent signature-update failure (persistent outdated AV state).")
	Endpoint.Say("=================================================================")

	SaveLog(Endpoint.Unprotected,
		fmt.Sprintf("All %d UnDefend primitives executed without prevention", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "defender-evasion", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// extractStage decompresses an embedded gzip'd stage and writes the signed PE to C:\F0.
func extractStage(s UnDefendStage) error {
	if err := os.MkdirAll(LOG_DIR, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %v", LOG_DIR, err)
	}
	data, err := decompressGzip(s.BinaryData)
	if err != nil {
		return fmt.Errorf("gunzip %s: %v", s.BinaryName, err)
	}
	outPath := filepath.Join(LOG_DIR, s.BinaryName)
	if err := os.WriteFile(outPath, data, 0o755); err != nil {
		return fmt.Errorf("write %s: %v", outPath, err)
	}
	LogFileDropped(s.BinaryName, outPath, int64(len(data)), false)
	return nil
}

func decompressGzip(b []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %v", err)
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// executeStage runs a stage binary and returns its exit code (0 success, 126 blocked, 999 error).
func executeStage(s UnDefendStage) int {
	stagePath := filepath.Join(LOG_DIR, s.BinaryName)
	cmd := exec.Command(stagePath)
	LogMessage("INFO", fmt.Sprintf("Stage %d", s.ID), fmt.Sprintf("Executing %s", s.BinaryName))

	emitEtwMarker(fmt.Sprintf("stage_%d_start", s.ID), fmt.Sprintf("technique=%s", s.Technique))
	err := cmd.Run()
	emitEtwMarker(fmt.Sprintf("stage_%d_end", s.ID), fmt.Sprintf("technique=%s", s.Technique))

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(s.BinaryName, stagePath, 0, false, code, exitErr.Error())
			return code
		}
		LogProcessExecution(s.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	LogProcessExecution(s.BinaryName, stagePath, 0, true, 0, "")
	return 0
}

// emitEtwMarker writes a synthetic ETW correlation marker via Event Tracing for
// Windows. Implementation: shell out to PowerShell `Write-EventLog` against
// the Application log under a unique source. The user-mode signal an ETW
// collector / SIEM picks up is the value — the test's UUID is in the message,
// so events can be correlated with the test's bundle results. (v2 lift U4)
//
// This is a synthetic-event emission. We register the source on first use
// (best-effort; failure is logged but never fatal).
//
// The Application event log is the closest approximation of a user-mode ETW
// provider event we can emit without registering a custom ETW manifest. A
// real ETW provider would use TraceLogging, but that requires significant
// scaffolding for marginal benefit; PowerShell Write-EventLog gives us the
// SIEM-ingestion property we need in ~5 lines.
func emitEtwMarker(phase, details string) {
	const sourceName = "F0RT1KA-UnDefend-Sim"
	msg := fmt.Sprintf("[F0RT1KA UnDefend] phase=%s test_uuid=%s details=%s", phase, TEST_UUID, details)

	// Best-effort source registration. Idempotent.
	regCmd := fmt.Sprintf(`if (-not [System.Diagnostics.EventLog]::SourceExists("%s")) { New-EventLog -LogName Application -Source "%s" -ErrorAction SilentlyContinue }`, sourceName, sourceName)
	_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", regCmd).Run()

	writeCmd := fmt.Sprintf(`Write-EventLog -LogName Application -Source "%s" -EventId 7777 -EntryType Information -Message %q`, sourceName, msg)
	if err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", writeCmd).Run(); err != nil {
		LogMessage("INFO", "ETW", fmt.Sprintf("Write-EventLog phase=%s failed (likely standard-user without source registration): %v", phase, err))
	} else {
		LogMessage("INFO", "ETW", fmt.Sprintf("Synthetic event emitted: phase=%s", phase))
	}
}

// captureSystemSnapshot writes a JSON dump of system-state probes to
// LOG_DIR/<uuid>_system_snapshot_<phase>.json. (v2 lift X1)
type systemSnapshot struct {
	Phase                  string            `json:"phase"`
	Timestamp              string            `json:"timestamp"`
	DefenderStatus         map[string]string `json:"defenderStatus,omitempty"`
	ASRRulesEnabled        []string          `json:"asrRulesEnabled,omitempty"`
	AVExclusionPaths       []string          `json:"avExclusionPaths,omitempty"`
	AVExclusionExtensions  []string          `json:"avExclusionExtensions,omitempty"`
	AVExclusionProcesses   []string          `json:"avExclusionProcesses,omitempty"`
	HotfixesInstalledCount int               `json:"hotfixesInstalledCount"`
	WinDefendServiceState  string            `json:"winDefendServiceState,omitempty"` // UnDefend-specific: relevant to all stages
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
	if state, err := powerShellRun("(Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status"); err == nil {
		snap.WinDefendServiceState = state
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
