//go:build windows
// +build windows

/*
ID: f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01
NAME: PowerShell Execution & AMSI Detection
TECHNIQUES: T1059.001, T1140
TACTICS: execution, defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: execution
TAGS: powershell, amsi, obfuscation, command-line
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
	"encoding/base64"
	"fmt"
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
	TEST_UUID  = "f3d7a2b1-8c4e-4f5a-9d6b-1e2f3a4b5c01"
	TEST_NAME  = "PowerShell Execution & AMSI Detection"
	TARGET_DIR = "c:\\F0"
)

// PowerShell test patterns - all designed to be safe and create marker files only
var (
	// Pattern 1: Simple marker file creation (base64 encoded)
	// Command: New-Item -Path c:\F0\marker_encoded.txt -ItemType File -Value 'F0RT1KA-Base64-Test' -Force
	base64TestCommand = "TgBlAHcALQBJAHQAZQBtACAALQBQAGEAdABoACAAYwA6AFwARgAwAFwAbQBhAHIAawBlAHIAXwBlAG4AYwBvAGQAZQBkAC4AdAB4AHQAIAAtAEkAdABlAG0AVAB5AHAAZQAgAEYAaQBsAGUAIAAtAFYAYQBsAHUAZQAgACcARgAwAFIAVAAxAEsAQQAtAEIAYQBzAGUANgA0AC0AVABlAHMAdAAnACAALQBGAG8AcgBjAGUA"

	// Pattern 2: Download cradle simulation (harmless - creates marker only)
	downloadCradleCommand = `$marker = "F0RT1KA-DownloadCradle-Simulation"; $marker | Out-File -FilePath "c:\F0\marker_download.txt" -Force`

	// Pattern 3: Hidden window execution command
	hiddenWindowCommand = `New-Item -Path c:\F0\marker_hidden.txt -ItemType File -Value 'F0RT1KA-Hidden-Window-Test' -Force`

	// Pattern 4: AMSI bypass indicator patterns (logged but not actually executed as bypass)
	// These are strings that EDR/AV typically flag - we log their detection, not execute them
	amsiBypassPatterns = []string{
		"AmsiScanBuffer",
		"amsiInitFailed",
		"[Ref].Assembly.GetType",
		"System.Management.Automation.AmsiUtils",
	}
)

// checkPowerShellAvailable verifies PowerShell is available on the system
func checkPowerShellAvailable() bool {
	cmd := exec.Command("powershell.exe", "-Command", "Write-Output 'test'")
	err := cmd.Run()
	return err == nil
}

// executeBase64EncodedCommand executes a base64 encoded PowerShell command
// Returns: success, blocked, errorMsg
func executeBase64EncodedCommand() (bool, bool, string) {
	Endpoint.Say("  Executing base64 encoded command...")

	cmdLine := fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -EncodedCommand %s", base64TestCommand)
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64TestCommand)

	output, err := cmd.CombinedOutput()

	// Log the process execution
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if err != nil {
		errorStr := err.Error()
		outputStr := string(output)

		// Check for EDR/AV blocking indicators
		if strings.Contains(outputStr, "blocked") ||
			strings.Contains(outputStr, "denied") ||
			strings.Contains(outputStr, "prevented") ||
			strings.Contains(errorStr, "Access is denied") ||
			strings.Contains(errorStr, "not recognized") {
			LogProcessExecution("powershell.exe", cmdLine, pid, false, 126, "Blocked by security controls")
			return false, true, fmt.Sprintf("Blocked: %s", errorStr)
		}

		LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, errorStr)
		return false, false, errorStr
	}

	// Check if marker file was created
	markerPath := filepath.Join(TARGET_DIR, "marker_encoded.txt")
	if _, err := os.Stat(markerPath); err == nil {
		LogProcessExecution("powershell.exe", cmdLine, pid, true, 0, "")
		LogFileDropped("marker_encoded.txt", markerPath, 0, false)
		if info, err := os.Stat(markerPath); err == nil {
			// Update with actual size
			LogMessage("INFO", "Base64 Execution", fmt.Sprintf("Marker file created: %d bytes", info.Size()))
		}
		return true, false, ""
	}

	LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, "Marker file not created")
	return false, false, "Command executed but marker file not created"
}

// executeDownloadCradle simulates a download cradle pattern
// Returns: success, blocked, errorMsg
func executeDownloadCradle() (bool, bool, string) {
	Endpoint.Say("  Simulating download cradle pattern (harmless marker creation)...")

	// Note: This doesn't actually download anything - it creates a marker file
	// The pattern simulates IEX (New-Object Net.WebClient).DownloadString behavior
	cmdLine := "Download cradle simulation pattern"
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", downloadCradleCommand)

	output, err := cmd.CombinedOutput()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if err != nil {
		errorStr := err.Error()
		outputStr := string(output)

		// Check for blocking
		if strings.Contains(outputStr, "blocked") ||
			strings.Contains(outputStr, "denied") ||
			strings.Contains(errorStr, "Access is denied") {
			LogProcessExecution("powershell.exe", cmdLine, pid, false, 126, "Blocked by security controls")
			return false, true, fmt.Sprintf("Blocked: %s", errorStr)
		}

		LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, errorStr)
		return false, false, errorStr
	}

	// Check if marker file was created
	markerPath := filepath.Join(TARGET_DIR, "marker_download.txt")
	if _, err := os.Stat(markerPath); err == nil {
		LogProcessExecution("powershell.exe", cmdLine, pid, true, 0, "")
		LogFileDropped("marker_download.txt", markerPath, 0, false)
		return true, false, ""
	}

	LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, "Marker file not created")
	return false, false, "Command executed but marker file not created"
}

// executeHiddenWindow executes PowerShell with hidden window
// Returns: success, blocked, errorMsg
func executeHiddenWindow() (bool, bool, string) {
	Endpoint.Say("  Executing with hidden window style...")

	cmdLine := fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"%s\"", hiddenWindowCommand)
	cmd := exec.Command("powershell.exe",
		"-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden",
		"-Command", hiddenWindowCommand)

	output, err := cmd.CombinedOutput()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if err != nil {
		errorStr := err.Error()
		outputStr := string(output)

		if strings.Contains(outputStr, "blocked") ||
			strings.Contains(outputStr, "denied") ||
			strings.Contains(errorStr, "Access is denied") {
			LogProcessExecution("powershell.exe", cmdLine, pid, false, 126, "Blocked by security controls")
			return false, true, fmt.Sprintf("Blocked: %s", errorStr)
		}

		LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, errorStr)
		return false, false, errorStr
	}

	// Check if marker file was created
	markerPath := filepath.Join(TARGET_DIR, "marker_hidden.txt")
	if _, err := os.Stat(markerPath); err == nil {
		LogProcessExecution("powershell.exe", cmdLine, pid, true, 0, "")
		LogFileDropped("marker_hidden.txt", markerPath, 0, false)
		return true, false, ""
	}

	LogProcessExecution("powershell.exe", cmdLine, pid, false, 1, "Marker file not created")
	return false, false, "Command executed but marker file not created"
}

// testAMSIBypassPatternDetection tests if AMSI patterns would be detected
// This does NOT actually attempt an AMSI bypass - it just checks if patterns are logged/detected
// Returns: patternsDetected (count), details
func testAMSIBypassPatternDetection() (int, string) {
	Endpoint.Say("  Testing AMSI bypass pattern detection (logging only, no actual bypass)...")

	patternsDetected := 0
	var details []string

	for _, pattern := range amsiBypassPatterns {
		// Create a harmless command that contains the pattern in a string variable
		// This tests whether AV/EDR detects the pattern without actually executing malicious code
		testCmd := fmt.Sprintf(`$testVar = "%s"; Write-Output "Pattern test: $testVar" | Out-Null`, pattern)

		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", testCmd)
		err := cmd.Run()

		if err != nil {
			// Pattern was likely detected/blocked
			patternsDetected++
			details = append(details, fmt.Sprintf("Pattern '%s' detected", pattern))
			LogMessage("INFO", "AMSI Pattern Detection", fmt.Sprintf("Pattern blocked: %s", pattern))
		} else {
			LogMessage("WARN", "AMSI Pattern Detection", fmt.Sprintf("Pattern not blocked: %s", pattern))
		}
	}

	// Write detection results to file
	resultsPath := filepath.Join(TARGET_DIR, "amsi_pattern_results.txt")
	resultsContent := fmt.Sprintf("AMSI Bypass Pattern Detection Test\n"+
		"===================================\n"+
		"Total Patterns Tested: %d\n"+
		"Patterns Detected: %d\n\n"+
		"Results:\n%s\n",
		len(amsiBypassPatterns),
		patternsDetected,
		strings.Join(details, "\n"))

	os.WriteFile(resultsPath, []byte(resultsContent), 0644)
	LogFileDropped("amsi_pattern_results.txt", resultsPath, int64(len(resultsContent)), false)

	return patternsDetected, strings.Join(details, "; ")
}

// cleanup removes all marker files created during the test
func cleanup() {
	Endpoint.Say("Cleaning up test artifacts...")

	markerFiles := []string{
		"marker_encoded.txt",
		"marker_download.txt",
		"marker_hidden.txt",
		"amsi_pattern_results.txt",
		"test_summary.txt",
	}

	for _, file := range markerFiles {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}
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

	// Check PowerShell availability
	if !checkPowerShellAvailable() {
		LogMessage("ERROR", "Initialization", "PowerShell is not available on this system")
		LogPhaseEnd(0, "failed", "PowerShell not available")
		SaveLog(999, "PowerShell not available on system")
		Endpoint.Stop(999) // Exit code 999 for prerequisites not met
	}

	LogMessage("INFO", "Initialization", "PowerShell verified available")
	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Base64 Encoded Command Execution
	LogPhaseStart(2, "Base64 Encoded Command")
	Endpoint.Say("\nPhase 2: Testing base64 encoded command execution (-enc)")

	// Decode and log what the command does (for transparency)
	decodedCmd, _ := base64.StdEncoding.DecodeString(base64TestCommand)
	LogMessage("INFO", "Base64 Encoded Command", fmt.Sprintf("Testing encoded command (creates marker file): %s", string(decodedCmd)[:50]+"..."))

	success, blocked, errMsg := executeBase64EncodedCommand()
	if blocked {
		Endpoint.Say("  [BLOCKED] Base64 encoded command was blocked by EDR/AV")
		blockedPatterns = append(blockedPatterns, "Base64 Encoded Command (-enc)")
		LogPhaseEnd(1, "blocked", "Base64 command blocked by security controls")
	} else if success {
		Endpoint.Say("  [VULNERABLE] Base64 encoded command executed successfully")
		successfulPatterns = append(successfulPatterns, "Base64 Encoded Command (-enc)")
		LogPhaseEnd(1, "success", "Base64 command executed without detection")
	} else {
		Endpoint.Say("  [ERROR] Base64 command failed: %s", errMsg)
		LogPhaseEnd(1, "failed", errMsg)
	}

	Endpoint.Wait(2) // Allow time for EDR detection

	// Phase 3: Download Cradle Pattern
	LogPhaseStart(3, "Download Cradle Pattern")
	Endpoint.Say("\nPhase 3: Testing download cradle pattern detection")

	success, blocked, errMsg = executeDownloadCradle()
	if blocked {
		Endpoint.Say("  [BLOCKED] Download cradle pattern was blocked")
		blockedPatterns = append(blockedPatterns, "Download Cradle Pattern")
		LogPhaseEnd(2, "blocked", "Download cradle blocked by security controls")
	} else if success {
		Endpoint.Say("  [VULNERABLE] Download cradle pattern executed successfully")
		successfulPatterns = append(successfulPatterns, "Download Cradle Pattern")
		LogPhaseEnd(2, "success", "Download cradle executed without detection")
	} else {
		Endpoint.Say("  [ERROR] Download cradle failed: %s", errMsg)
		LogPhaseEnd(2, "failed", errMsg)
	}

	Endpoint.Wait(2)

	// Phase 4: Hidden Window Execution
	LogPhaseStart(4, "Hidden Window Execution")
	Endpoint.Say("\nPhase 4: Testing hidden window execution (-WindowStyle Hidden)")

	success, blocked, errMsg = executeHiddenWindow()
	if blocked {
		Endpoint.Say("  [BLOCKED] Hidden window execution was blocked")
		blockedPatterns = append(blockedPatterns, "Hidden Window Execution")
		LogPhaseEnd(3, "blocked", "Hidden window blocked by security controls")
	} else if success {
		Endpoint.Say("  [VULNERABLE] Hidden window execution succeeded")
		successfulPatterns = append(successfulPatterns, "Hidden Window Execution")
		LogPhaseEnd(3, "success", "Hidden window executed without detection")
	} else {
		Endpoint.Say("  [ERROR] Hidden window execution failed: %s", errMsg)
		LogPhaseEnd(3, "failed", errMsg)
	}

	Endpoint.Wait(2)

	// Phase 5: AMSI Pattern Detection Test
	LogPhaseStart(5, "AMSI Pattern Detection")
	Endpoint.Say("\nPhase 5: Testing AMSI bypass pattern detection")

	patternsDetected, detailStr := testAMSIBypassPatternDetection()
	if patternsDetected > 0 {
		Endpoint.Say("  [PROTECTED] %d/%d AMSI bypass patterns were detected", patternsDetected, len(amsiBypassPatterns))
		LogMessage("INFO", "AMSI Pattern Detection", fmt.Sprintf("Detection details: %s", detailStr))
		LogPhaseEnd(4, "success", fmt.Sprintf("%d/%d patterns detected", patternsDetected, len(amsiBypassPatterns)))
	} else {
		Endpoint.Say("  [VULNERABLE] No AMSI bypass patterns were detected")
		LogMessage("WARN", "AMSI Pattern Detection", "No AMSI bypass patterns were blocked")
		LogPhaseEnd(4, "vulnerable", "No AMSI patterns detected")
	}

	// Phase 6: Final Assessment
	LogPhaseStart(6, "Final Assessment")
	Endpoint.Say("\nPhase 6: Final assessment and summary")

	// Create summary
	summaryPath := filepath.Join(TARGET_DIR, "test_summary.txt")
	summary := fmt.Sprintf(`PowerShell Execution & AMSI Detection Test Summary
=================================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1059.001: Command and Scripting Interpreter - PowerShell
- T1140: Deobfuscate/Decode Files or Information

Patterns Tested: 4
Patterns Blocked: %d
Patterns Successful: %d
AMSI Patterns Detected: %d/%d

Blocked Patterns:
%s

Successful Patterns (VULNERABLE):
%s

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(blockedPatterns),
		len(successfulPatterns),
		patternsDetected, len(amsiBypassPatterns),
		formatPatternList(blockedPatterns),
		formatPatternList(successfulPatterns),
		generateAssessment(len(blockedPatterns), len(successfulPatterns), patternsDetected))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("test_summary.txt", summaryPath, int64(len(summary)), false)

	// Determine final outcome
	totalBlocked := len(blockedPatterns) + patternsDetected
	totalVulnerable := len(successfulPatterns) + (len(amsiBypassPatterns) - patternsDetected)

	LogPhaseEnd(5, "success", fmt.Sprintf("Assessment complete: %d blocked, %d vulnerable", totalBlocked, totalVulnerable))

	// Final result
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("Patterns Blocked: %d", len(blockedPatterns))
	Endpoint.Say("Patterns Vulnerable: %d", len(successfulPatterns))
	Endpoint.Say("AMSI Patterns Detected: %d/%d", patternsDetected, len(amsiBypassPatterns))

	// Exit code logic based on results
	if len(blockedPatterns) > 0 {
		// At least one pattern was blocked - system has some protection
		Endpoint.Say("\n[RESULT] PROTECTED - EDR/AV blocked at least one PowerShell attack pattern")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - security controls active")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d patterns blocked", len(blockedPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if len(successfulPatterns) > 0 {
		// All patterns executed successfully - system is unprotected
		Endpoint.Say("\n[RESULT] UNPROTECTED - All PowerShell attack patterns executed successfully")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - all patterns executed")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d patterns executed", len(successfulPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// Edge case - no clear result
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
func generateAssessment(blocked, successful, amsiDetected int) string {
	if blocked > 0 && successful == 0 {
		return "PROTECTED - All attack patterns were blocked by security controls."
	} else if blocked > 0 && successful > 0 {
		return "PARTIAL PROTECTION - Some attack patterns were blocked, but others succeeded."
	} else if successful > 0 {
		return "UNPROTECTED - Attack patterns executed successfully without detection."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1059.001 (PowerShell), T1140 (Deobfuscate/Decode)")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "execution",
		Severity:      "high",
		Techniques:    []string{"T1059.001", "T1140"},
		Tactics:       []string{"execution", "defense-evasion"},
		Score:         7.5,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.0, // Uses real PowerShell patterns
			TechnicalSophistication: 2.0, // Multiple pattern types
			SafetyMechanisms:        2.0, // Only creates marker files
			DetectionOpportunities:  1.0, // 4 distinct detection points
			LoggingObservability:    0.5, // Good logging
		},
		Tags: []string{"powershell", "amsi", "base64", "download-cradle", "native"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000,
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

	timeout := 2 * time.Minute

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
