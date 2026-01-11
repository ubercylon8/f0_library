//go:build windows
// +build windows

/*
ID: c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03
NAME: RDP Lateral Movement Simulation
TECHNIQUES: T1021.001, T1555.004
UNIT: response
CREATED: 2026-01-11
*/
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID  = "c9f5d0e3-8a4b-5f2c-9d6e-3b4c5d6e7f03"
	TEST_NAME  = "RDP Lateral Movement Simulation"
	TARGET_DIR = "c:\\F0"
)

// SharpRDP binary is loaded at runtime from c:\F0\tools\SharpRDP.exe
// User must place the binary there before running the test
// See tools/README.md for instructions on obtaining SharpRDP
var sharpRDPBinary []byte // Will be populated if SharpRDP is found at runtime

// Test credential for cmdkey simulation (immediately removed after test)
var (
	testServerName = "TESTSERVER"
	testUsername   = "testuser"
	testPassword   = "testpass123!"
)

// checkTermServiceStatus checks if RDP service (TermService) is running
func checkTermServiceStatus() (bool, string) {
	cmd := exec.Command("sc", "query", "TermService")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Sprintf("Failed to query TermService: %v", err)
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "RUNNING") {
		return true, "TermService is RUNNING"
	} else if strings.Contains(outputStr, "STOPPED") {
		return false, "TermService is STOPPED"
	}
	return false, "TermService status unknown"
}

// checkRDPRegistryConfig checks RDP configuration in registry
func checkRDPRegistryConfig() (bool, string, map[string]string) {
	config := make(map[string]string)

	// Check if RDP is enabled (fDenyTSConnections)
	cmd := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return false, fmt.Sprintf("Failed to query registry: %v", err), config
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "0x0") {
		config["fDenyTSConnections"] = "0 (RDP Enabled)"
	} else if strings.Contains(outputStr, "0x1") {
		config["fDenyTSConnections"] = "1 (RDP Disabled)"
	}

	// Check NLA (Network Level Authentication) setting
	cmd = exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"/v", "UserAuthentication")
	output, _ = cmd.CombinedOutput()
	outputStr = string(output)

	if strings.Contains(outputStr, "0x1") {
		config["UserAuthentication"] = "1 (NLA Required)"
	} else if strings.Contains(outputStr, "0x0") {
		config["UserAuthentication"] = "0 (NLA Not Required)"
	}

	// Check listening port
	cmd = exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"/v", "PortNumber")
	output, _ = cmd.CombinedOutput()
	outputStr = string(output)

	if strings.Contains(outputStr, "REG_DWORD") {
		// Extract port number (default 0xd3d = 3389)
		config["PortNumber"] = "Configured"
	}

	enabled := strings.Contains(config["fDenyTSConnections"], "RDP Enabled")
	return enabled, "Registry query completed", config
}

// enumerateRDPSessions uses qwinsta to enumerate RDP sessions
func enumerateRDPSessions() (bool, bool, string, int) {
	Endpoint.Say("  Executing: qwinsta")

	cmd := exec.Command("qwinsta")

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	output := outputBuffer.String()

	if err != nil {
		errorStr := err.Error()

		// Check for blocking indicators
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "access is denied") {

			LogProcessExecution("qwinsta.exe", "qwinsta", pid, false, 126, "Blocked by security controls")
			LogMessage("INFO", "Session Enumeration", fmt.Sprintf("Command blocked after %v", duration))
			return false, true, "Session enumeration blocked by EDR", 0
		}

		LogProcessExecution("qwinsta.exe", "qwinsta", pid, false, cmd.ProcessState.ExitCode(), errorStr)
		return false, false, fmt.Sprintf("Failed: %s", errorStr), 0
	}

	LogProcessExecution("qwinsta.exe", "qwinsta", pid, true, 0, "")

	// Count sessions (excluding header)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	sessionCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "SESSIONNAME") {
			sessionCount++
		}
	}

	// Save output to file
	outputPath := filepath.Join(TARGET_DIR, "qwinsta_output.txt")
	os.WriteFile(outputPath, []byte(output), 0644)
	LogFileDropped("qwinsta_output.txt", outputPath, int64(len(output)), false)

	LogMessage("INFO", "Session Enumeration", fmt.Sprintf("Enumerated %d sessions in %v", sessionCount, duration))
	return true, false, fmt.Sprintf("Enumerated %d RDP sessions", sessionCount), sessionCount
}

// testCmdkeyCredentialManager tests cmdkey manipulation (T1555.004)
// Creates and immediately deletes a test credential
func testCmdkeyCredentialManager() (bool, bool, string) {
	Endpoint.Say("  Testing cmdkey credential manipulation (T1555.004)")

	// Step 1: Add test credential
	addCmd := exec.Command("cmdkey",
		fmt.Sprintf("/add:%s", testServerName),
		fmt.Sprintf("/user:%s", testUsername),
		fmt.Sprintf("/pass:%s", testPassword))

	var addOutput bytes.Buffer
	addCmd.Stdout = &addOutput
	addCmd.Stderr = &addOutput

	startTime := time.Now()
	err := addCmd.Run()
	addDuration := time.Since(startTime)

	addPid := 0
	if addCmd.Process != nil {
		addPid = addCmd.Process.Pid
	}

	addOutputStr := addOutput.String()

	if err != nil {
		errorStr := err.Error()

		// Check for blocking
		if strings.Contains(strings.ToLower(addOutputStr), "blocked") ||
			strings.Contains(strings.ToLower(addOutputStr), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "access is denied") ||
			strings.Contains(strings.ToLower(addOutputStr), "not allowed") {

			LogProcessExecution("cmdkey.exe", "cmdkey /add:"+testServerName, addPid, false, 126, "Blocked by security controls")
			LogMessage("INFO", "Cmdkey Test", "Credential creation blocked by EDR")
			return false, true, "Cmdkey credential creation blocked by EDR"
		}

		LogProcessExecution("cmdkey.exe", "cmdkey /add:"+testServerName, addPid, false, addCmd.ProcessState.ExitCode(), errorStr)
		return false, false, fmt.Sprintf("Failed to add credential: %s", errorStr)
	}

	LogProcessExecution("cmdkey.exe", "cmdkey /add:"+testServerName, addPid, true, 0, "")
	LogMessage("INFO", "Cmdkey Test", fmt.Sprintf("Test credential created in %v", addDuration))

	// Step 2: Immediately delete the test credential
	Endpoint.Say("  Removing test credential immediately...")

	deleteCmd := exec.Command("cmdkey", fmt.Sprintf("/delete:%s", testServerName))

	var deleteOutput bytes.Buffer
	deleteCmd.Stdout = &deleteOutput
	deleteCmd.Stderr = &deleteOutput

	startTime = time.Now()
	err = deleteCmd.Run()
	deleteDuration := time.Since(startTime)

	deletePid := 0
	if deleteCmd.Process != nil {
		deletePid = deleteCmd.Process.Pid
	}

	if err != nil {
		LogProcessExecution("cmdkey.exe", "cmdkey /delete:"+testServerName, deletePid, false, deleteCmd.ProcessState.ExitCode(), err.Error())
		LogMessage("WARN", "Cmdkey Test", fmt.Sprintf("Failed to delete test credential: %v", err))
		// Still return success for the add operation since we're testing detection
	} else {
		LogProcessExecution("cmdkey.exe", "cmdkey /delete:"+testServerName, deletePid, true, 0, "")
		LogMessage("INFO", "Cmdkey Test", fmt.Sprintf("Test credential deleted in %v", deleteDuration))
	}

	return true, false, "Cmdkey credential manipulation succeeded (credential created and removed)"
}

// checkSharpRDPAvailable checks if SharpRDP binary is available
// It looks for SharpRDP.exe in c:\F0\tools\ directory
func checkSharpRDPAvailable() bool {
	// Check if SharpRDP binary was loaded at runtime
	if len(sharpRDPBinary) > 0 {
		return true
	}

	// Check for SharpRDP in the tools directory
	sharpRDPPath := filepath.Join(TARGET_DIR, "tools", "SharpRDP.exe")
	if _, err := os.Stat(sharpRDPPath); err == nil {
		// Load the binary for later use
		data, err := os.ReadFile(sharpRDPPath)
		if err == nil && len(data) > 0 {
			sharpRDPBinary = data
			return true
		}
	}

	return false
}

// loadSharpRDP attempts to load SharpRDP from tools directory
func loadSharpRDP() (bool, string) {
	sharpRDPToolPath := filepath.Join(TARGET_DIR, "tools", "SharpRDP.exe")

	if _, err := os.Stat(sharpRDPToolPath); err != nil {
		return false, fmt.Sprintf("SharpRDP.exe not found in %s", filepath.Join(TARGET_DIR, "tools"))
	}

	data, err := os.ReadFile(sharpRDPToolPath)
	if err != nil {
		return false, fmt.Sprintf("Failed to read SharpRDP.exe: %v", err)
	}

	if len(data) == 0 {
		return false, "SharpRDP.exe is empty"
	}

	sharpRDPBinary = data
	return true, sharpRDPToolPath
}

// extractSharpRDP copies SharpRDP from tools directory to c:\F0 for execution
func extractSharpRDP() (string, error) {
	// First try to load from tools directory
	if len(sharpRDPBinary) == 0 {
		available, msg := loadSharpRDP()
		if !available {
			return "", fmt.Errorf("SharpRDP not available: %s - see tools/README.md for instructions", msg)
		}
	}

	// Copy to target directory for execution
	sharpRDPPath := filepath.Join(TARGET_DIR, "SharpRDP.exe")
	err := os.WriteFile(sharpRDPPath, sharpRDPBinary, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write SharpRDP: %v", err)
	}

	LogFileDropped("SharpRDP.exe", sharpRDPPath, int64(len(sharpRDPBinary)), false)
	return sharpRDPPath, nil
}

// testSharpRDPExecution tests SharpRDP execution (local only, safe mode)
// This executes SharpRDP with localhost as target for detection testing
func testSharpRDPExecution(sharpRDPPath string) (bool, bool, string) {
	Endpoint.Say("  Testing SharpRDP execution (local-only, safe mode)")

	// Check if file was quarantined before execution
	if _, err := os.Stat(sharpRDPPath); os.IsNotExist(err) {
		LogMessage("INFO", "SharpRDP", "SharpRDP.exe was quarantined before execution")
		return false, true, "SharpRDP.exe quarantined on extraction"
	}

	// Wait a moment for AV to react
	Endpoint.Wait(3)

	// Check again after delay
	if _, err := os.Stat(sharpRDPPath); os.IsNotExist(err) {
		LogMessage("INFO", "SharpRDP", "SharpRDP.exe was quarantined after brief delay")
		LogFileDropped("SharpRDP.exe", sharpRDPPath, int64(len(sharpRDPBinary)), true)
		return false, true, "SharpRDP.exe quarantined after extraction"
	}

	// Execute SharpRDP in safe mode (localhost, help/version check)
	// Real SharpRDP arguments for local test: computername=localhost command=whoami
	cmd := exec.Command(sharpRDPPath, "computername=localhost", "command=whoami")

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	output := outputBuffer.String()

	// Save output to file
	outputPath := filepath.Join(TARGET_DIR, "sharprdp_output.txt")
	os.WriteFile(outputPath, []byte(output), 0644)
	LogFileDropped("sharprdp_output.txt", outputPath, int64(len(output)), false)

	if err != nil {
		errorStr := err.Error()

		// Check for execution prevention
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "not recognized") ||
			strings.Contains(strings.ToLower(errorStr), "operation is not allowed") ||
			strings.Contains(strings.ToLower(errorStr), "blocked by") {

			LogProcessExecution("SharpRDP.exe", "SharpRDP computername=localhost command=whoami", pid, false, 126, "Execution blocked")
			LogMessage("INFO", "SharpRDP", "SharpRDP execution blocked by EDR")
			return false, true, "SharpRDP execution blocked by EDR"
		}

		// Check for exit code indicating EDR block
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Some EDRs return specific exit codes
		if exitCode == -1073741502 || // STATUS_DLL_NOT_FOUND (common for blocked executables)
			exitCode == -1073740760 { // STATUS_NONCONTINUABLE_EXCEPTION

			LogProcessExecution("SharpRDP.exe", "SharpRDP computername=localhost command=whoami", pid, false, 126, "Execution prevented")
			LogMessage("INFO", "SharpRDP", fmt.Sprintf("SharpRDP execution prevented (exit code: %d)", exitCode))
			return false, true, "SharpRDP execution prevented by EDR"
		}

		// Normal execution failure (tool ran but operation failed)
		LogProcessExecution("SharpRDP.exe", "SharpRDP computername=localhost command=whoami", pid, false, exitCode, errorStr)
		LogMessage("INFO", "SharpRDP", fmt.Sprintf("SharpRDP execution completed with error: %s (duration: %v)", errorStr, duration))

		// If the tool executed (not blocked), it's still a detection opportunity
		// Return success=true since the binary wasn't blocked
		return true, false, fmt.Sprintf("SharpRDP executed but operation failed: %s", errorStr)
	}

	LogProcessExecution("SharpRDP.exe", "SharpRDP computername=localhost command=whoami", pid, true, 0, "")
	LogMessage("INFO", "SharpRDP", fmt.Sprintf("SharpRDP execution completed successfully in %v", duration))
	return true, false, "SharpRDP executed successfully"
}

// cleanup removes test artifacts
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	filesToRemove := []string{
		"qwinsta_output.txt",
		"sharprdp_output.txt",
		"rdp_test_summary.txt",
		"rdp_registry_config.txt",
		"SharpRDP.exe",
	}

	for _, file := range filesToRemove {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}

	// Ensure test credential is removed (safety cleanup)
	exec.Command("cmdkey", fmt.Sprintf("/delete:%s", testServerName)).Run()
}

func test() {
	// Ensure log is saved on exit
	defer func() {
		if r := recover(); r != nil {
			if globalLog != nil {
				LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
				SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
			}
		}
	}()

	// Results tracking
	var blockedPatterns []string
	var successfulPatterns []string
	sharpRDPQuarantined := false

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		LogPhaseError(0, fmt.Sprintf("Dropper initialization failed: %v", err))
		LogPhaseEnd(0, "failed", "Dropper initialization failed")
		SaveLog(Endpoint.UnexpectedTestError, "Dropper initialization failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Create target directory
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(Endpoint.UnexpectedTestError, "Failed to create target directory")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Check RDP Service Status
	LogPhaseStart(2, "RDP Service Status Check")
	Endpoint.Say("\nPhase 2: Checking RDP service status (sc query TermService)")

	rdpRunning, statusMsg := checkTermServiceStatus()
	Endpoint.Say("  %s", statusMsg)
	LogMessage("INFO", "RDP Service", statusMsg)

	if !rdpRunning {
		LogPhaseEnd(1, "failed", "RDP service not running")
		Endpoint.Say("\n[WARNING] RDP service (TermService) is not running")
		Endpoint.Say("          Some tests may have limited results")
		LogMessage("WARN", "RDP Service", "TermService not running - continuing with limited testing")
	} else {
		LogPhaseEnd(1, "success", "RDP service is running")
	}

	// Phase 3: Registry Configuration Check
	LogPhaseStart(3, "RDP Registry Configuration")
	Endpoint.Say("\nPhase 3: Checking RDP registry configuration")

	rdpEnabled, regMsg, config := checkRDPRegistryConfig()
	Endpoint.Say("  %s", regMsg)

	// Save registry config to file
	configContent := "RDP Registry Configuration\n===========================\n"
	for key, value := range config {
		configContent += fmt.Sprintf("%s: %s\n", key, value)
		Endpoint.Say("    %s: %s", key, value)
		LogMessage("INFO", "Registry Config", fmt.Sprintf("%s: %s", key, value))
	}

	configPath := filepath.Join(TARGET_DIR, "rdp_registry_config.txt")
	os.WriteFile(configPath, []byte(configContent), 0644)
	LogFileDropped("rdp_registry_config.txt", configPath, int64(len(configContent)), false)

	if rdpEnabled {
		LogPhaseEnd(2, "success", "RDP is enabled in registry")
	} else {
		LogPhaseEnd(2, "success", "RDP configuration retrieved")
	}

	Endpoint.Wait(2)

	// Phase 4: Session Enumeration (qwinsta)
	LogPhaseStart(4, "RDP Session Enumeration")
	Endpoint.Say("\nPhase 4: Enumerating RDP sessions (qwinsta)")

	success, blocked, msg, sessionCount := enumerateRDPSessions()
	if blocked {
		Endpoint.Say("  [BLOCKED] Session enumeration was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "RDP Session Enumeration (qwinsta)")
		LogPhaseEnd(3, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] Session enumeration succeeded (%d sessions)", sessionCount)
		successfulPatterns = append(successfulPatterns, "RDP Session Enumeration (qwinsta)")
		LogPhaseEnd(3, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] Session enumeration failed: %s", msg)
		LogPhaseEnd(3, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 5: Cmdkey Credential Manager Test (T1555.004)
	LogPhaseStart(5, "Cmdkey Credential Manager")
	Endpoint.Say("\nPhase 5: Testing cmdkey credential manipulation (T1555.004)")

	successCmdkey, blockedCmdkey, msgCmdkey := testCmdkeyCredentialManager()
	if blockedCmdkey {
		Endpoint.Say("  [BLOCKED] Cmdkey manipulation was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "Cmdkey Credential Manager")
		LogPhaseEnd(4, "blocked", msgCmdkey)
	} else if successCmdkey {
		Endpoint.Say("  [VULNERABLE] Cmdkey manipulation succeeded")
		successfulPatterns = append(successfulPatterns, "Cmdkey Credential Manager")
		LogPhaseEnd(4, "success", msgCmdkey)
	} else {
		Endpoint.Say("  [ERROR] Cmdkey test failed: %s", msgCmdkey)
		LogPhaseEnd(4, "failed", msgCmdkey)
	}

	Endpoint.Wait(2)

	// Phase 6: SharpRDP Test (if available)
	LogPhaseStart(6, "SharpRDP Execution Test")
	Endpoint.Say("\nPhase 6: Testing SharpRDP execution (PLACEHOLDER)")

	if checkSharpRDPAvailable() {
		Endpoint.Say("  SharpRDP binary is embedded - extracting...")

		sharpRDPPath, err := extractSharpRDP()
		if err != nil {
			Endpoint.Say("  [ERROR] Failed to extract SharpRDP: %v", err)
			LogMessage("ERROR", "SharpRDP", fmt.Sprintf("Extraction failed: %v", err))
			LogPhaseEnd(5, "failed", err.Error())
		} else {
			Endpoint.Say("  [+] SharpRDP extracted to: %s", sharpRDPPath)

			// Wait for potential quarantine
			Endpoint.Wait(3)

			// Check if quarantined
			if Endpoint.Quarantined("SharpRDP.exe", sharpRDPBinary) {
				Endpoint.Say("  [QUARANTINED] SharpRDP.exe was quarantined on extraction")
				LogFileDropped("SharpRDP.exe", sharpRDPPath, int64(len(sharpRDPBinary)), true)
				sharpRDPQuarantined = true
				blockedPatterns = append(blockedPatterns, "SharpRDP (Quarantined on Extraction)")
				LogPhaseEnd(5, "blocked", "SharpRDP quarantined on extraction")
			} else {
				// Try to execute SharpRDP
				successSharp, blockedSharp, msgSharp := testSharpRDPExecution(sharpRDPPath)
				if blockedSharp {
					Endpoint.Say("  [BLOCKED] SharpRDP execution was blocked by EDR")
					blockedPatterns = append(blockedPatterns, "SharpRDP Execution")
					LogPhaseEnd(5, "blocked", msgSharp)
				} else if successSharp {
					Endpoint.Say("  [VULNERABLE] SharpRDP executed without detection")
					successfulPatterns = append(successfulPatterns, "SharpRDP Execution")
					LogPhaseEnd(5, "success", msgSharp)
				} else {
					Endpoint.Say("  [ERROR] SharpRDP test failed: %s", msgSharp)
					LogPhaseEnd(5, "failed", msgSharp)
				}
			}
		}
	} else {
		Endpoint.Say("  [INFO] SharpRDP not embedded - see tools/README.md for instructions")
		LogMessage("INFO", "SharpRDP", "Binary not embedded - skipping execution test")
		LogPhaseEnd(5, "skipped", "SharpRDP binary not available")
	}

	// Phase 7: Final Assessment
	LogPhaseStart(7, "Final Assessment")
	Endpoint.Say("\nPhase 7: Final assessment and summary")

	// Create summary
	summaryPath := filepath.Join(TARGET_DIR, "rdp_test_summary.txt")
	summary := fmt.Sprintf(`RDP Lateral Movement Simulation Test Summary
=============================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1021.001: Remote Services - Remote Desktop Protocol
- T1555.004: Credentials from Password Stores - Windows Credential Manager

Test Components:
1. RDP Service Status (sc query TermService)
2. RDP Registry Configuration Check
3. Session Enumeration (qwinsta)
4. Cmdkey Credential Manager Manipulation
5. SharpRDP Execution (if embedded)

Results:
- Patterns Blocked: %d
- Patterns Successful: %d
- SharpRDP Available: %v
- SharpRDP Quarantined: %v

Blocked Patterns:
%s

Successful Patterns (VULNERABLE):
%s

Detection Opportunities:
1. sc.exe querying TermService
2. reg.exe querying Terminal Server keys
3. qwinsta.exe session enumeration
4. cmdkey.exe credential manipulation
5. SharpRDP.exe execution (if present)
6. RDP-related registry access

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(blockedPatterns),
		len(successfulPatterns),
		checkSharpRDPAvailable(),
		sharpRDPQuarantined,
		formatPatternList(blockedPatterns),
		formatPatternList(successfulPatterns),
		generateAssessment(len(blockedPatterns), len(successfulPatterns), sharpRDPQuarantined))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("rdp_test_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(6, "success", fmt.Sprintf("Assessment complete: %d blocked, %d successful", len(blockedPatterns), len(successfulPatterns)))

	// Final result
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("RDP Patterns Blocked: %d", len(blockedPatterns))
	Endpoint.Say("RDP Patterns Successful: %d", len(successfulPatterns))
	Endpoint.Say("SharpRDP Available: %v", checkSharpRDPAvailable())
	Endpoint.Say("SharpRDP Quarantined: %v", sharpRDPQuarantined)

	// Determine exit code
	if sharpRDPQuarantined {
		// SharpRDP was quarantined on extraction - exit 105
		Endpoint.Say("\n[RESULT] PROTECTED - SharpRDP quarantined on extraction")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - SharpRDP quarantined")
		SaveLog(Endpoint.FileQuarantinedOnExtraction, "SharpRDP.exe quarantined on extraction")
		cleanup()
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction) // Exit 105
	} else if len(blockedPatterns) > 0 {
		// At least one pattern was blocked - system has protection
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked RDP attack patterns")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - RDP controls active")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d RDP patterns blocked", len(blockedPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if len(successfulPatterns) > 0 {
		// All patterns executed successfully - system is unprotected
		Endpoint.Say("\n[RESULT] UNPROTECTED - RDP attack patterns executed without detection")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - RDP patterns undetected")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d RDP patterns executed", len(successfulPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else if !rdpRunning {
		// RDP service not running and no clear results
		Endpoint.Say("\n[RESULT] ERROR - RDP service not running, test incomplete")
		LogMessage("WARN", "Final Assessment", "Test incomplete - RDP service not running")
		SaveLog(999, "RDP service not running - test incomplete")
		cleanup()
		Endpoint.Stop(999)
	} else {
		// No clear result
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Test did not produce clear results")
		LogMessage("WARN", "Final Assessment", "Test inconclusive")
		SaveLog(Endpoint.UnexpectedTestError, "Test inconclusive")
		cleanup()
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
}

// formatPatternList formats a list of patterns for display
func formatPatternList(patterns []string) string {
	if len(patterns) == 0 {
		return "  (none)"
	}
	var result string
	for _, p := range patterns {
		result += fmt.Sprintf("  - %s\n", p)
	}
	return result
}

// generateAssessment creates an assessment string based on results
func generateAssessment(blocked, successful int, quarantined bool) string {
	if quarantined {
		return "PROTECTED - SharpRDP binary was quarantined on extraction, indicating strong AV/EDR protection."
	} else if blocked > 0 && successful == 0 {
		return "PROTECTED - All RDP lateral movement patterns were blocked by security controls."
	} else if blocked > 0 && successful > 0 {
		return "PARTIAL PROTECTION - Some RDP patterns were blocked, but others succeeded."
	} else if successful > 0 {
		return "UNPROTECTED - RDP lateral movement patterns executed successfully without detection."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1021.001 (RDP), T1555.004 (Cmdkey)")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "lateral_movement",
		Severity:   "high",
		Techniques: []string{"T1021.001", "T1555.004"},
		Tactics:    []string{"lateral-movement", "credential-access"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Real tool potential (SharpRDP), actual cmdkey manipulation
			TechnicalSophistication: 2.0, // Multiple techniques, service/registry checks
			SafetyMechanisms:        2.0, // Local only, immediate credential cleanup
			DetectionOpportunities:  1.0, // 5+ detection points
			LoggingObservability:    0.5, // Comprehensive logging
		},
		Tags: []string{"rdp", "lateral-movement", "credential-manager", "native", "sharprdp"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Run test with timeout
	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	timeout := 3 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
