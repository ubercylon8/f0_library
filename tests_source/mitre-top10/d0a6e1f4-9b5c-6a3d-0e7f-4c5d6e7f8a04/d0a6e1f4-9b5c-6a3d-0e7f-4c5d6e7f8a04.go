//go:build windows
// +build windows

/*
ID: d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04
NAME: WMI Execution Simulation
TECHNIQUES: T1047, T1546.003
TACTICS: execution, persistence
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: execution
TAGS: wmi, wmic, event-subscription, lateral-tool-transfer
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
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
	TEST_UUID  = "d0a6e1f4-9b5c-6a3d-0e7f-4c5d6e7f8a04"
	TEST_NAME  = "WMI Execution Simulation"
	TARGET_DIR = "c:\\F0"
)

// WMI command patterns for testing
var (
	// Pattern 1: Process enumeration using wmic
	wmicProcessListCmd = []string{"wmic", "process", "list", "brief"}

	// Pattern 2: Process creation using wmic - creates a marker file
	// We use cmd.exe to echo to a file as a safe process creation test
	wmicProcessCreateCmd = []string{"wmic", "process", "call", "create", "cmd.exe /c echo F0RT1KA-WMI-ProcessCreate > c:\\F0\\wmi_marker.txt"}

	// Pattern 3: Shadow copy enumeration (reconnaissance)
	wmicShadowListCmd = []string{"wmic", "shadowcopy", "list", "brief"}

	// Pattern 4: OS information enumeration
	wmicOSInfoCmd = []string{"wmic", "os", "get", "caption,version,buildnumber", "/format:list"}
)

// WMI Event Subscription registry paths to check (T1546.003)
var wmiEventSubscriptionPaths = []struct {
	Key  string
	Path string
	Desc string
}{
	{
		Key:  "HKLM",
		Path: `SOFTWARE\Microsoft\Wbem\ESS`,
		Desc: "WMI Event Subscription Service",
	},
	{
		Key:  "HKLM",
		Path: `SOFTWARE\Microsoft\WBEM\CIMOM`,
		Desc: "WMI CIMOM Repository",
	},
}

// checkWMIServiceAvailable verifies WMI service is running
func checkWMIServiceAvailable() bool {
	cmd := exec.Command("sc", "query", "winmgmt")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

// checkWmicAvailable verifies wmic.exe is available
func checkWmicAvailable() bool {
	cmd := exec.Command("wmic", "/?")
	err := cmd.Run()
	return err == nil
}

// executeWmicCommand executes a wmic command and returns results
// Returns: success, blocked, output, errorMsg
func executeWmicCommand(args []string, description string) (bool, bool, string, string) {
	Endpoint.Say("  Executing: wmic %s", strings.Join(args[1:], " "))

	cmd := exec.Command(args[0], args[1:]...)
	cmdLine := strings.Join(args, " ")

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

		// Check for EDR/AV blocking indicators
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(output), "prevented") ||
			strings.Contains(strings.ToLower(errorStr), "access is denied") ||
			strings.Contains(strings.ToLower(errorStr), "operation is not allowed") ||
			strings.Contains(strings.ToLower(output), "0x80041003") || // WMI Access Denied
			strings.Contains(strings.ToLower(output), "0x80070005") { // Access Denied

			LogProcessExecution("wmic.exe", cmdLine, pid, false, 126, "Blocked by security controls")
			LogMessage("INFO", description, fmt.Sprintf("Command blocked after %v: %s", duration, errorStr))
			return false, true, output, fmt.Sprintf("Blocked: %s", errorStr)
		}

		LogProcessExecution("wmic.exe", cmdLine, pid, false, cmd.ProcessState.ExitCode(), errorStr)
		LogMessage("WARN", description, fmt.Sprintf("Command failed after %v: %s", duration, errorStr))
		return false, false, output, errorStr
	}

	LogProcessExecution("wmic.exe", cmdLine, pid, true, 0, "")
	LogMessage("INFO", description, fmt.Sprintf("Command completed in %v", duration))
	return true, false, output, ""
}

// testWmicProcessList tests process enumeration via WMI
func testWmicProcessList() (bool, bool, string) {
	Endpoint.Say("\n  Testing: wmic process list brief")

	success, blocked, output, errMsg := executeWmicCommand(wmicProcessListCmd, "Process Enumeration")

	if blocked {
		return false, true, "Process enumeration blocked by EDR"
	}

	if success {
		// Check if we got valid process data
		if strings.Contains(output, "Handle") || strings.Contains(output, "Name") {
			lineCount := strings.Count(output, "\n")
			LogMessage("INFO", "Process Enumeration", fmt.Sprintf("Retrieved %d lines of process data", lineCount))

			// Save output to file for analysis
			outputPath := filepath.Join(TARGET_DIR, "wmic_process_output.txt")
			os.WriteFile(outputPath, []byte(output), 0644)
			LogFileDropped("wmic_process_output.txt", outputPath, int64(len(output)), false)

			return true, false, fmt.Sprintf("Enumerated processes (%d lines)", lineCount)
		}
	}

	return false, false, errMsg
}

// testWmicProcessCreate tests process creation via WMI
func testWmicProcessCreate() (bool, bool, string) {
	Endpoint.Say("\n  Testing: wmic process call create (marker file creation)")

	success, blocked, output, errMsg := executeWmicCommand(wmicProcessCreateCmd, "Process Creation")

	if blocked {
		return false, true, "Process creation blocked by EDR"
	}

	if success {
		// Wait for process to complete and check marker file
		Endpoint.Wait(2)

		markerPath := filepath.Join(TARGET_DIR, "wmi_marker.txt")
		if _, err := os.Stat(markerPath); err == nil {
			// Read marker content
			content, _ := os.ReadFile(markerPath)
			LogFileDropped("wmi_marker.txt", markerPath, int64(len(content)), false)
			LogMessage("INFO", "Process Creation", "WMI successfully created process that wrote marker file")
			return true, false, "Process created and executed successfully"
		}

		// Check if wmic reported success but marker wasn't created (possible silent block)
		if strings.Contains(output, "ReturnValue = 0") {
			LogMessage("WARN", "Process Creation", "WMI reported success but marker file not found - possible silent block")
			return false, true, "Silent block - WMI reported success but execution blocked"
		}
	}

	return false, false, errMsg
}

// testWmicShadowList tests shadow copy enumeration
func testWmicShadowList() (bool, bool, string) {
	Endpoint.Say("\n  Testing: wmic shadowcopy list brief (reconnaissance)")

	success, blocked, output, errMsg := executeWmicCommand(wmicShadowListCmd, "Shadow Copy Enumeration")

	if blocked {
		return false, true, "Shadow copy enumeration blocked by EDR"
	}

	if success {
		// This might return empty results if no shadow copies exist, but command succeeded
		LogMessage("INFO", "Shadow Copy Enumeration", "Shadow copy enumeration completed")

		// Save output for analysis
		outputPath := filepath.Join(TARGET_DIR, "wmic_shadowcopy_output.txt")
		os.WriteFile(outputPath, []byte(output), 0644)
		LogFileDropped("wmic_shadowcopy_output.txt", outputPath, int64(len(output)), false)

		return true, false, "Shadow copy enumeration successful"
	}

	return false, false, errMsg
}

// testWmicOSInfo tests OS information enumeration
func testWmicOSInfo() (bool, bool, string) {
	Endpoint.Say("\n  Testing: wmic os get (system reconnaissance)")

	success, blocked, output, errMsg := executeWmicCommand(wmicOSInfoCmd, "OS Information")

	if blocked {
		return false, true, "OS information query blocked by EDR"
	}

	if success {
		LogMessage("INFO", "OS Information", fmt.Sprintf("Retrieved OS info: %s", strings.TrimSpace(output)[:min(100, len(output))]))
		return true, false, "OS information retrieved"
	}

	return false, false, errMsg
}

// checkWMIEventSubscriptionRegistry checks for WMI event subscription artifacts (read-only)
func checkWMIEventSubscriptionRegistry() (bool, string) {
	Endpoint.Say("\n  Checking WMI Event Subscription registry keys (T1546.003 - read-only)...")

	var findings []string

	for _, regPath := range wmiEventSubscriptionPaths {
		// Use reg query to check if the path exists
		cmd := exec.Command("reg", "query", fmt.Sprintf("%s\\%s", regPath.Key, regPath.Path))
		output, err := cmd.CombinedOutput()

		if err == nil {
			findings = append(findings, fmt.Sprintf("%s: Key exists", regPath.Desc))
			LogMessage("INFO", "WMI Event Subscription", fmt.Sprintf("Found %s at %s\\%s", regPath.Desc, regPath.Key, regPath.Path))

			// Check for specific event subscription indicators
			if strings.Contains(string(output), "EventConsumer") ||
				strings.Contains(string(output), "EventFilter") ||
				strings.Contains(string(output), "__FilterToConsumerBinding") {
				findings = append(findings, "  - Potential event subscription artifacts detected")
				LogMessage("WARN", "WMI Event Subscription", "Potential event subscription artifacts found")
			}
		} else {
			LogMessage("DEBUG", "WMI Event Subscription", fmt.Sprintf("Path not found or access denied: %s\\%s", regPath.Key, regPath.Path))
		}
	}

	// Save findings to file
	resultsPath := filepath.Join(TARGET_DIR, "wmi_event_subscription_check.txt")
	resultsContent := fmt.Sprintf("WMI Event Subscription Check (T1546.003)\n"+
		"==========================================\n"+
		"Note: This is a READ-ONLY check for existing WMI persistence\n"+
		"No event subscriptions were created by this test\n\n"+
		"Findings:\n%s\n", strings.Join(findings, "\n"))

	os.WriteFile(resultsPath, []byte(resultsContent), 0644)
	LogFileDropped("wmi_event_subscription_check.txt", resultsPath, int64(len(resultsContent)), false)

	return len(findings) > 0, strings.Join(findings, "; ")
}

// checkWmiexecProAvailable checks if wmiexec-Pro tool is available
func checkWmiexecProAvailable() (bool, string) {
	// Check for Python availability first
	pythonCmd := exec.Command("python", "--version")
	if err := pythonCmd.Run(); err != nil {
		pythonCmd = exec.Command("python3", "--version")
		if err := pythonCmd.Run(); err != nil {
			return false, "Python not available"
		}
	}

	// Check for wmiexec-Pro in tools directory
	toolPath := filepath.Join(TARGET_DIR, "tools", "wmiexec-Pro.py")
	if _, err := os.Stat(toolPath); err != nil {
		return false, "wmiexec-Pro.py not found in c:\\F0\\tools\\"
	}

	return true, toolPath
}

// testWmiexecProPlaceholder is a placeholder for wmiexec-Pro testing
// This logs the availability status but does not execute remote WMI
func testWmiexecProPlaceholder() (bool, string) {
	Endpoint.Say("\n  Checking wmiexec-Pro availability (PLACEHOLDER)...")

	available, status := checkWmiexecProAvailable()

	if available {
		LogMessage("INFO", "wmiexec-Pro", fmt.Sprintf("Tool available at: %s", status))
		LogMessage("INFO", "wmiexec-Pro", "Note: Remote WMI execution not performed in this test (requires network target)")

		// Log that the tool is present for detection testing
		detectionNote := `wmiexec-Pro Detection Notes:
- Tool detected at c:\F0\tools\wmiexec-Pro.py
- This test does NOT perform remote WMI execution
- To test remote WMI patterns, run wmiexec-Pro manually against a test target
- Common indicators: DCE/RPC traffic on port 135, WMI provider host spawning processes`

		notePath := filepath.Join(TARGET_DIR, "wmiexec_pro_notes.txt")
		os.WriteFile(notePath, []byte(detectionNote), 0644)
		LogFileDropped("wmiexec_pro_notes.txt", notePath, int64(len(detectionNote)), false)

		return true, "Tool available - manual execution required for remote testing"
	}

	LogMessage("INFO", "wmiexec-Pro", fmt.Sprintf("Tool not available: %s", status))
	LogMessage("INFO", "wmiexec-Pro", "See c:\\F0\\tools\\README.md for installation instructions")

	return false, status
}

// cleanup removes test artifacts
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	filesToRemove := []string{
		"wmic_process_output.txt",
		"wmic_shadowcopy_output.txt",
		"wmi_marker.txt",
		"wmi_event_subscription_check.txt",
		"wmiexec_pro_notes.txt",
		"wmi_test_summary.txt",
	}

	for _, file := range filesToRemove {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

	// Phase 1: Initialization and Prerequisites
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

	// Check WMI service availability
	if !checkWMIServiceAvailable() {
		LogMessage("ERROR", "Initialization", "WMI service (winmgmt) is not running")
		LogPhaseEnd(0, "failed", "WMI service not available")
		SaveLog(999, "WMI service not available - cannot run test")
		Endpoint.Stop(999)
	}
	LogMessage("INFO", "Initialization", "WMI service is running")

	// Check wmic availability
	if !checkWmicAvailable() {
		LogMessage("ERROR", "Initialization", "wmic.exe is not available (may be deprecated in newer Windows)")
		LogPhaseEnd(0, "failed", "wmic.exe not available")
		SaveLog(999, "wmic.exe not available on system")
		Endpoint.Stop(999)
	}
	LogMessage("INFO", "Initialization", "wmic.exe is available")

	LogPhaseEnd(0, "success", "Environment initialized, WMI available")

	// Phase 2: Process Enumeration (T1047)
	LogPhaseStart(2, "Process Enumeration via WMI")
	Endpoint.Say("\nPhase 2: Testing WMI process enumeration (T1047)")

	success, blocked, msg := testWmicProcessList()
	if blocked {
		Endpoint.Say("  [BLOCKED] Process enumeration was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "WMI Process Enumeration")
		LogPhaseEnd(1, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] Process enumeration succeeded")
		successfulPatterns = append(successfulPatterns, "WMI Process Enumeration")
		LogPhaseEnd(1, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] Process enumeration failed: %s", msg)
		LogPhaseEnd(1, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 3: Process Creation via WMI (T1047)
	LogPhaseStart(3, "Process Creation via WMI")
	Endpoint.Say("\nPhase 3: Testing WMI process creation (T1047)")

	success, blocked, msg = testWmicProcessCreate()
	if blocked {
		Endpoint.Say("  [BLOCKED] WMI process creation was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "WMI Process Creation")
		LogPhaseEnd(2, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] WMI process creation succeeded")
		successfulPatterns = append(successfulPatterns, "WMI Process Creation")
		LogPhaseEnd(2, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] WMI process creation failed: %s", msg)
		LogPhaseEnd(2, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 4: Shadow Copy Enumeration (T1047 - Reconnaissance)
	LogPhaseStart(4, "Shadow Copy Enumeration")
	Endpoint.Say("\nPhase 4: Testing WMI shadow copy enumeration (reconnaissance)")

	success, blocked, msg = testWmicShadowList()
	if blocked {
		Endpoint.Say("  [BLOCKED] Shadow copy enumeration was blocked")
		blockedPatterns = append(blockedPatterns, "WMI Shadow Copy Enumeration")
		LogPhaseEnd(3, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] Shadow copy enumeration succeeded")
		successfulPatterns = append(successfulPatterns, "WMI Shadow Copy Enumeration")
		LogPhaseEnd(3, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] Shadow copy enumeration failed: %s", msg)
		LogPhaseEnd(3, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 5: WMI Event Subscription Check (T1546.003 - Read Only)
	LogPhaseStart(5, "WMI Event Subscription Check")
	Endpoint.Say("\nPhase 5: Checking WMI event subscription artifacts (T1546.003 - read-only)")

	foundArtifacts, findings := checkWMIEventSubscriptionRegistry()
	if foundArtifacts {
		Endpoint.Say("  [INFO] WMI Event Subscription artifacts found: %s", findings)
		LogMessage("INFO", "WMI Event Subscription", "Registry check completed - artifacts found")
		LogPhaseEnd(4, "success", "WMI ESS artifacts found (read-only check)")
	} else {
		Endpoint.Say("  [INFO] No WMI Event Subscription artifacts detected")
		LogMessage("INFO", "WMI Event Subscription", "No event subscription artifacts found")
		LogPhaseEnd(4, "success", "No WMI ESS artifacts (read-only check)")
	}

	Endpoint.Wait(1)

	// Phase 6: wmiexec-Pro Placeholder Check
	LogPhaseStart(6, "wmiexec-Pro Availability")
	Endpoint.Say("\nPhase 6: Checking wmiexec-Pro tool availability (PLACEHOLDER)")

	toolAvailable, toolMsg := testWmiexecProPlaceholder()
	if toolAvailable {
		Endpoint.Say("  [INFO] wmiexec-Pro is available - manual testing required for remote WMI")
		LogPhaseEnd(5, "success", toolMsg)
	} else {
		Endpoint.Say("  [INFO] wmiexec-Pro not available: %s", toolMsg)
		LogPhaseEnd(5, "skipped", toolMsg)
	}

	// Phase 7: Final Assessment
	LogPhaseStart(7, "Final Assessment")
	Endpoint.Say("\nPhase 7: Final assessment and summary")

	// Create summary
	summaryPath := filepath.Join(TARGET_DIR, "wmi_test_summary.txt")
	summary := fmt.Sprintf(`WMI Execution Simulation Test Summary
======================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1047: Windows Management Instrumentation
- T1546.003: WMI Event Subscription (read-only check)

Patterns Tested: 4 (native WMI)
Patterns Blocked: %d
Patterns Successful: %d

Blocked Patterns:
%s

Successful Patterns (VULNERABLE):
%s

wmiexec-Pro Status: %s

Detection Opportunities:
1. wmic.exe process creation
2. WMI Win32_Process::Create method calls
3. Shadow copy enumeration attempts
4. WMI provider host (wmiprvse.exe) spawning child processes
5. Port 135 (DCE/RPC) traffic for remote WMI

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(blockedPatterns),
		len(successfulPatterns),
		formatPatternList(blockedPatterns),
		formatPatternList(successfulPatterns),
		toolMsg,
		generateAssessment(len(blockedPatterns), len(successfulPatterns)))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("wmi_test_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(6, "success", fmt.Sprintf("Assessment complete: %d blocked, %d successful", len(blockedPatterns), len(successfulPatterns)))

	// Final result
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("WMI Patterns Blocked: %d", len(blockedPatterns))
	Endpoint.Say("WMI Patterns Successful: %d", len(successfulPatterns))

	// Exit code logic based on results
	if len(blockedPatterns) > 0 {
		// At least one WMI pattern was blocked - system has protection
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked at least one WMI attack pattern")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - WMI controls active")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d WMI patterns blocked", len(blockedPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if len(successfulPatterns) > 0 {
		// All patterns executed successfully - system is unprotected against WMI
		Endpoint.Say("\n[RESULT] UNPROTECTED - All WMI attack patterns executed successfully")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - WMI patterns undetected")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d WMI patterns executed", len(successfulPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// No clear result
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Test did not produce clear results")
		LogMessage("WARN", "Final Assessment", "Test inconclusive")
		SaveLog(Endpoint.UnexpectedTestError, "Test inconclusive - no clear result")
		cleanup()
		Endpoint.Stop(Endpoint.UnexpectedTestError) // Exit 1
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
func generateAssessment(blocked, successful int) string {
	if blocked > 0 && successful == 0 {
		return "PROTECTED - All WMI attack patterns were blocked by security controls."
	} else if blocked > 0 && successful > 0 {
		return "PARTIAL PROTECTION - Some WMI attack patterns were blocked, but others succeeded."
	} else if successful > 0 {
		return "UNPROTECTED - WMI attack patterns executed successfully without detection."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1047 (WMI), T1546.003 (WMI Event Subscription)")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "execution",
		Severity:   "high",
		Techniques: []string{"T1047", "T1546.003"},
		Tactics:    []string{"execution", "persistence"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Uses real WMI commands, potential for wmiexec-Pro
			TechnicalSophistication: 2.0, // Multiple WMI patterns tested
			SafetyMechanisms:        2.0, // Local operations only, benign markers
			DetectionOpportunities:  1.0, // 5+ detection points documented
			LoggingObservability:    0.5, // Comprehensive logging
		},
		Tags: []string{"wmi", "wmic", "process-creation", "native", "stealthy"},
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
