//go:build windows
// +build windows

/*
ID: 8f68dda1-94be-430f-8f35-d8af3f9b5d2e
NAME: Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain
TECHNIQUES: T1518.001, T1082, T1562.001, T1211, T1055, T1003.001, T1490, T1486
TACTICS: discovery, defense-evasion, credential-access, impact
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: Qilin
SUBCATEGORY: ransomware
TAGS: qilin, agenda, ransomware, byovd, edr-killer, process-injection, vulnerable-driver, lsass
SOURCE_URL: https://blog.talosintelligence.com/qilin-edr-killer/
UNIT: response
CREATED: 2026-11-02
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
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
	TEST_UUID     = "8f68dda1-94be-430f-8f35-d8af3f9b5d2e"
	TEST_NAME     = "Qilin (Agenda): BYOVD EDR-Killer & svchost Injection Chain"
	ExitTestError = 999
)

//go:embed 8f68dda1-94be-430f-8f35-d8af3f9b5d2e-T1518.001.exe.gz
var stage1Compressed []byte

//go:embed 8f68dda1-94be-430f-8f35-d8af3f9b5d2e-T1562.001.exe.gz
var stage2Compressed []byte

//go:embed 8f68dda1-94be-430f-8f35-d8af3f9b5d2e-T1055.exe.gz
var stage3Compressed []byte

//go:embed 8f68dda1-94be-430f-8f35-d8af3f9b5d2e-T1003.001.exe.gz
var stage4Compressed []byte

//go:embed 8f68dda1-94be-430f-8f35-d8af3f9b5d2e-T1486.exe.gz
var stage5Compressed []byte

type StageDef struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
	Timeout     time.Duration
}

type systemSnapshot struct {
	Timestamp string            `json:"timestamp"`
	System    SystemInfo        `json:"systemInfo"`
	Services  map[string]string `json:"services"`
}

var stageResults []StageBundleDef

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Scope: five independent post-compromise detection objectives")
	Endpoint.Say("Kernel callback modification is simulated; no vulnerable driver is loaded")
	Endpoint.Say("=================================================================")

	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "ransomware",
		Severity:      "critical",
		Techniques:    []string{"T1518.001", "T1082", "T1562.001", "T1211", "T1055", "T1003.001", "T1490", "T1486"},
		Tactics:       []string{"discovery", "defense-evasion", "credential-access", "impact"},
		Score:         8.7,
		RubricVersion: "v2.1",
		Tags:          []string{"qilin", "agenda", "ransomware", "byovd", "edr-killer", "process-injection", "vulnerable-driver", "lsass", "multi-stage"},
	}
	orgInfo := ResolveOrganization("")
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         1200000,
			CertificateMode:   "self-healing",
			MultiStageEnabled: true,
		},
	}
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)
	writeSystemSnapshot("pre")

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			if stageResults != nil {
				finalize(ExitTestError, fmt.Sprintf("Panic: %v", r), stageResults)
			}
			writeSystemSnapshot("post")
			SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			Endpoint.Stop(ExitTestError)
		}
	}()

	test(metadata)
}

func test(metadata TestMetadata) {
	killchain := []StageDef{
		{ID: 1, Name: "Security Discovery & Side-Load", Technique: "T1518.001", BinaryName: fmt.Sprintf("%s-T1518.001.exe", TEST_UUID), BinaryData: stage1Compressed, Description: "SecurityCenter2, process/service and system discovery; test-owned FoxitPDFReader.exe plus msimg32.dll LoadLibraryW telemetry", Timeout: 3 * time.Minute},
		{ID: 2, Name: "BYOVD EDR-Killer", Technique: "T1562.001", BinaryName: fmt.Sprintf("%s-T1562.001.exe", TEST_UUID), BinaryData: stage2Compressed, Description: "rwdrv.sys signature drop, nonfunctional driver service/native-load attempts, callback-list simulation and test-owned security-process termination", Timeout: 6 * time.Minute},
		{ID: 3, Name: "svchost Process Injection", Technique: "T1055", BinaryName: fmt.Sprintf("%s-T1055.exe", TEST_UUID), BinaryData: stage3Compressed, Description: "VirtualAllocEx, WriteProcessMemory and CreateRemoteThread LoadLibraryW injection into a test-owned svchost.exe", Timeout: 4 * time.Minute},
		{ID: 4, Name: "LSASS Access Attempt", Technique: "T1003.001", BinaryName: fmt.Sprintf("%s-T1003.001.exe", TEST_UUID), BinaryData: stage4Compressed, Description: "SeDebugPrivilege plus OpenProcess(PROCESS_VM_READ) against LSASS; no read or dump", Timeout: 3 * time.Minute},
		{ID: 5, Name: "Minimal Impact", Technique: "T1486", BinaryName: fmt.Sprintf("%s-T1486.exe", TEST_UUID), BinaryData: stage5Compressed, Description: "Synthetic decoy encryption and fail-harmless recovery-inhibition commands", Timeout: 3 * time.Minute},
	}

	stageTactics := map[int][]string{
		1: {"discovery", "defense-evasion"},
		2: {"defense-evasion"},
		3: {"defense-evasion"},
		4: {"credential-access"},
		5: {"impact"},
	}
	stageResults = make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{Technique: stage.Technique, Name: stage.Name, Description: stage.Description, Severity: metadata.Severity, Tactics: stageTactics[stage.ID], Status: "skipped"}
	}

	LogPhaseStart(0, "Independent Stage Extraction")
	for i, stage := range killchain {
		if err := extractStage(stage); err != nil {
			stageResults[i].ExitCode = ExitTestError
			stageResults[i].Status = "error"
			stageResults[i].Details = fmt.Sprintf("Stage extraction failed: %v", err)
			LogMessage("ERROR", stage.Technique, stageResults[i].Details)
			Endpoint.Say("  [x] %s extraction failed; remaining stages will continue: %v", stage.BinaryName, err)
			continue
		}
		Endpoint.Say("  [+] Extracted %s", stage.BinaryName)
	}
	LogPhaseEnd(0, "success", "Independent stage extraction attempts completed")

	anyBlocked, anyError := false, false
	for idx, stage := range killchain {
		if stageResults[idx].Status == "error" {
			anyError = true
			continue
		}
		LogStageStart(stage.ID, stage.Technique, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))
		Endpoint.Say("=================================================================")
		Endpoint.Say("STAGE %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("=================================================================")

		stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
		time.Sleep(3 * time.Second)
		if _, err := os.Stat(stagePath); os.IsNotExist(err) {
			stageResults[idx].ExitCode = 105
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = "Stage binary quarantined before execution (os.Stat evidence)"
			LogStageBlocked(stage.ID, stage.Technique, stageResults[idx].Details)
			anyBlocked = true
			continue
		}

		exitCode := executeStage(stage)
		if stage.ID == 2 || stage.ID == 3 {
			cleanupQilinResiduals()
		}
		switch {
		case exitCode == 126 || exitCode == 105 || exitCode == 127:
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("Protection layer prevented stage %d (exit code %d)", stage.ID, exitCode)
			LogStageBlocked(stage.ID, stage.Technique, stageResults[idx].Details)
			anyBlocked = true
		case exitCode != 0:
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogStageEnd(stage.ID, stage.Technique, "error", stageResults[idx].Details)
			anyError = true
		default:
			stageResults[idx].ExitCode = 0
			stageResults[idx].Status = "success"
			stageResults[idx].Details = "Stage completed without prevention"
			LogStageEnd(stage.ID, stage.Technique, "success", stageResults[idx].Details)
		}
		Endpoint.Say("  Stage %d result: %s (%d); continuing independent objectives", stage.ID, stageResults[idx].Status, exitCode)
	}

	printStageSummary(killchain, stageResults)
	switch {
	case anyBlocked:
		finalize(Endpoint.ExecutionPrevented, "Endpoint protection prevented at least one Qilin emulation stage; see per-stage evidence", stageResults)
	case anyError:
		finalize(ExitTestError, "One or more independent Qilin stages returned an error", stageResults)
	default:
		finalize(Endpoint.Unprotected, "All five Qilin emulation objectives completed without prevention; kernel callback removal was simulated", stageResults)
	}
}

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

func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func executeStage(stage StageDef) int {
	stagePath := filepath.Join(LOG_DIR, stage.BinaryName)
	ctx, cancel := context.WithTimeout(context.Background(), stage.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, stagePath)
	cmd.Dir = LOG_DIR
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)
	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)
	outputFilePath := filepath.Join(LOG_DIR, fmt.Sprintf("%s_output.txt", stage.BinaryName))
	if writeErr := os.WriteFile(outputFilePath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", stage.Technique, fmt.Sprintf("Failed to write stage output capture: %v", writeErr))
	}
	if ctx.Err() == context.DeadlineExceeded {
		LogMessage("ERROR", stage.Technique, fmt.Sprintf("Stage %d watchdog timeout after %v", stage.ID, stage.Timeout))
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 102, "watchdog timeout")
		return 102
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, fmt.Sprintf("exit code %d after %v", code, executionDuration))
			return code
		}
		code, why := classifyStageLaunchError(err, stagePath)
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, code, why)
		return code
	}
	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}

func writeSystemSnapshot(label string) {
	services := map[string]string{}
	for _, name := range []string{"CSFalconService", "WinDefend", "Sense", "Sophos Endpoint Defense Service", "Sophos File Scanner Service", "Sophos MCS Agent"} {
		out, err := exec.Command("sc.exe", "query", name).CombinedOutput()
		if err != nil {
			services[name] = fmt.Sprintf("query returned %v: %s", err, string(out))
		} else {
			services[name] = string(out)
		}
	}
	payload, err := json.MarshalIndent(systemSnapshot{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), System: captureSystemInfo(), Services: services}, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(LOG_DIR, fmt.Sprintf("%s_system_snapshot_%s.json", TEST_UUID, label))
	_ = os.WriteFile(path, payload, 0644)
}

func printStageSummary(killchain []StageDef, results []StageBundleDef) {
	Endpoint.Say("=================================================================")
	for i, stage := range killchain {
		Endpoint.Say("  Stage %d %-11s %-42s %-8s exit=%d", stage.ID, stage.Technique, stage.Name, results[i].Status, results[i].ExitCode)
	}
	Endpoint.Say("=================================================================")
}

func cleanupDriverServices() {
	for _, service := range []string{"qilin_rwdrv_f0", "qilin_hlpdrv_f0"} {
		if out, err := exec.Command("sc.exe", "delete", service).CombinedOutput(); err == nil {
			LogMessage("INFO", "T1562.001", fmt.Sprintf("orchestrator cleanup deleted driver service %s", service))
		} else {
			LogMessage("DEBUG", "T1562.001", fmt.Sprintf("orchestrator service cleanup %s returned %v: %s", service, err, string(out)))
		}
	}
}

func cleanupQilinResiduals() {
	cleanupDriverServices()
	script := `$owned = @('C:\F0\MsMpEng.exe','C:\F0\CSFalconService.exe','C:\F0\CrowdStrike.exe'); Get-CimInstance Win32_Process | Where-Object { $owned -contains $_.ExecutablePath -or $_.ExecutablePath -like 'C:\Users\fortika-test\Qilin\*' } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput(); err != nil {
		LogMessage("DEBUG", "Cleanup", fmt.Sprintf("test-owned descendant cleanup returned %v: %s", err, string(out)))
	}
	if err := os.RemoveAll(filepath.Join(ARTIFACT_DIR, "Qilin")); err != nil {
		LogMessage("WARNING", "Cleanup", fmt.Sprintf("Qilin sandbox cleanup returned: %v", err))
	}
	for _, path := range []string{filepath.Join(LOG_DIR, "MsMpEng.exe"), filepath.Join(LOG_DIR, "CSFalconService.exe"), filepath.Join(LOG_DIR, "CrowdStrike.exe"), filepath.Join(LOG_DIR, "rwdrv.sys"), filepath.Join(LOG_DIR, "hlpdrv.sys")} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			LogMessage("WARNING", "Cleanup", fmt.Sprintf("residual file cleanup %s returned: %v", path, err))
		}
	}
}

func mergePersistedStageMessages() {
	data, err := os.ReadFile(filepath.Join(LOG_DIR, "test_execution_log.json"))
	if err != nil || globalLog == nil {
		return
	}
	var persisted TestLog
	if err := json.Unmarshal(data, &persisted); err != nil {
		return
	}
	existing := make(map[string]bool, len(globalLog.Messages))
	for _, message := range globalLog.Messages {
		key := message.Timestamp.Time.UTC().Format(time.RFC3339Nano) + "|" + message.Phase + "|" + message.Message
		existing[key] = true
	}
	for _, message := range persisted.Messages {
		key := message.Timestamp.Time.UTC().Format(time.RFC3339Nano) + "|" + message.Phase + "|" + message.Message
		if !existing[key] {
			globalLog.Messages = append(globalLog.Messages, message)
			existing[key] = true
		}
	}
}

func finalize(exitCode int, reason string, results []StageBundleDef) {
	cleanupQilinResiduals()
	writeSystemSnapshot("post")
	mergePersistedStageMessages()
	SaveLog(exitCode, reason)
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "ransomware", results)
	Endpoint.Say("Finalizing independent stage results")
	time.Sleep(2 * time.Second)
	Endpoint.Stop(exitCode)
}
