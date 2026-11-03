//go:build windows
// +build windows

/*
ID: f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06
NAME: LOLBIN Download Detection
TECHNIQUES: T1105, T1059.001
TACTICS: command-and-control, execution
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: ingress-tool-transfer
TAGS: lolbin, certutil, bitsadmin, powershell-download
SOURCE_URL: https://top-attack-techniques.mitre-engenuity.org/
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID  = "f2c8a3b6-1d7e-8c5f-2a9b-6e7f8a9b0c06"
	TEST_NAME  = "LOLBIN Download Detection"
	TARGET_DIR = "c:\\F0"
	// ARTIFACT_DIR is defined in test_logger_windows.go. Downloaded payload
	// stand-ins are simulation artifacts and belong in the NON-whitelisted dir
	// so EDR file operations are visible (CLAUDE.md rule 2).
	ARTIFACT_SUBDIR = ARTIFACT_DIR + "\\downloads"
	// NOTE (2026-11-03): example.com/robots.txt now returns 404 (example.com
	// no longer serves robots.txt and asks not to be used for monitoring);
	// curl also needs --fail so HTTP errors are real failures, not "success".
	TEST_URL   = "https://raw.githubusercontent.com/torvalds/linux/master/README"
	TEST_URL_2 = "https://httpbin.org/robots.txt"

	// ExitTestError is the framework test-error exit code. The vendored prelude
	// endpoint lib maps UnexpectedTestError to exit 1 — do not use it (CLAUDE.md).
	ExitTestError = 999
)

// isExplicitAVActionText returns true ONLY for explicit security-product action
// text (Defender/AV-specific messages). Generic words ("denied", "dangerous",
// proxy 403s, PATH errors) are NOT protection evidence (Bug Prevention Rule 8).
func isExplicitAVActionText(s string) bool {
	markers := []string{
		"contains a virus",                                                    // Defender: "...did not complete successfully because the file contains a virus"
		"Operation did not complete successfully because the file contains a virus",
		"This program is blocked by group policy",                             // AppLocker/GPO
		"was blocked by your administrator",                                   // policy block
		"Threat found",                                                        // vendor-specific
	}
	l := strings.ToLower(s)
	for _, m := range markers {
		if strings.Contains(l, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// isBenignDownloadFailure returns true for known-benign network/environment
// failure text (such an outcome must never count as a block or quarantine).
func isBenignDownloadFailure(s string) bool {
	benign := []string{
		"unable to complete download", // certutil network failure
		"could not connect",           // network unreachable
		"timed out",
		"name or service not known",
		"no such host",
		"connection refused",
		"proxy",
		"http 403",
		"http 407",
	}
	l := strings.ToLower(s)
	for _, b := range benign {
		if strings.Contains(l, b) {
			return true
		}
	}
	return false
}

// fileExists is a small os.Stat wrapper
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LOLBINTest represents a single LOLBIN download test
type LOLBINTest struct {
	Name        string
	Binary      string
	CommandArgs []string
	OutputFile  string
	Technique   string
}

// getLOLBINTests returns all LOLBIN download patterns to test
func getLOLBINTests() []LOLBINTest {
	return []LOLBINTest{
		{
			Name:        "certutil URL cache download",
			Binary:      "certutil.exe",
			CommandArgs: []string{"-urlcache", "-split", "-f", TEST_URL, filepath.Join(ARTIFACT_SUBDIR, "test_certutil.txt")},
			OutputFile:  "test_certutil.txt",
			Technique:   "T1105",
		},
		{
			Name:        "bitsadmin transfer download",
			Binary:      "bitsadmin.exe",
			CommandArgs: []string{"/transfer", "F0TestJob", "/download", "/priority", "FOREGROUND", TEST_URL, filepath.Join(ARTIFACT_SUBDIR, "test_bitsadmin.txt")},
			OutputFile:  "test_bitsadmin.txt",
			Technique:   "T1105",
		},
		{
			Name:   "PowerShell Invoke-WebRequest",
			Binary: "powershell.exe",
			CommandArgs: []string{"-ExecutionPolicy", "Bypass", "-Command",
				fmt.Sprintf("Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing", TEST_URL, filepath.Join(ARTIFACT_SUBDIR, "test_iwr.txt"))},
			OutputFile: "test_iwr.txt",
			Technique:  "T1059.001",
		},
		{
			Name:   "PowerShell WebClient.DownloadFile",
			Binary: "powershell.exe",
			CommandArgs: []string{"-ExecutionPolicy", "Bypass", "-Command",
				fmt.Sprintf("(New-Object System.Net.WebClient).DownloadFile('%s', '%s')", TEST_URL, filepath.Join(ARTIFACT_SUBDIR, "test_webclient.txt"))},
			OutputFile: "test_webclient.txt",
			Technique:  "T1059.001",
		},
		{
			Name:        "curl.exe download",
			Binary:      "curl.exe",
			CommandArgs: []string{"--fail", "-o", filepath.Join(ARTIFACT_SUBDIR, "test_curl.txt"), TEST_URL, "--silent"},
			OutputFile:  "test_curl.txt",
			Technique:   "T1105",
		},
	}
}

// checkNetworkConnectivity verifies network access is available
func checkNetworkConnectivity() bool {
	Endpoint.Say("Checking network connectivity...")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(TEST_URL)
	if err != nil {
		// Try alternate URL
		resp, err = client.Head(TEST_URL_2)
		if err != nil {
			LogMessage("ERROR", "Network Check", fmt.Sprintf("Network unavailable: %v", err))
			return false
		}
	}
	defer resp.Body.Close()

	LogMessage("INFO", "Network Check", fmt.Sprintf("Network available, status: %d", resp.StatusCode))
	return true
}

// checkBinaryExists verifies if a LOLBIN exists on the system
func checkBinaryExists(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// executeLOLBINTest executes a single LOLBIN download test
// Returns: success, blocked, quarantined, errorMsg
func executeLOLBINTest(test LOLBINTest) (bool, bool, bool, string) {
	Endpoint.Say("  Testing: %s", test.Name)

	// Check if binary exists
	if !checkBinaryExists(test.Binary) {
		LogMessage("WARN", test.Name, fmt.Sprintf("Binary not found: %s", test.Binary))
		return false, false, false, fmt.Sprintf("Binary not found: %s", test.Binary)
	}

	outputPath := filepath.Join(ARTIFACT_SUBDIR, test.OutputFile)

	// Build command
	cmd := exec.Command(test.Binary, test.CommandArgs...)

	// Capture stdout/stderr using MultiWriter pattern
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	cmdLine := fmt.Sprintf("%s %s", test.Binary, strings.Join(test.CommandArgs, " "))
	LogMessage("INFO", test.Name, fmt.Sprintf("Executing: %s", cmdLine))

	startTime := time.Now()
	err := cmd.Run()
	executionDuration := time.Since(startTime)

	pid := 0
	exitCode := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	// Save command output to file
	outputLogPath := filepath.Join(TARGET_DIR, fmt.Sprintf("%s_output.txt", strings.TrimSuffix(test.OutputFile, ".txt")))
	if writeErr := os.WriteFile(outputLogPath, outputBuffer.Bytes(), 0644); writeErr != nil {
		LogMessage("WARNING", "Output Capture", fmt.Sprintf("Failed to save raw output: %v", writeErr))
	} else {
		LogMessage("INFO", "Output Capture", fmt.Sprintf("Raw output saved to: %s (%d bytes)", outputLogPath, outputBuffer.Len()))
	}

	// Check for execution error
	if err != nil {
		errorStr := err.Error()
		outputStr := outputBuffer.String()

		// Process-Creation denial: "fork/exec <path>: Access is denied." is an
		// OS-emitted denial on the test's own operation (spawning a system
		// binary that normally starts) — affirmative protection evidence
		// (observed: Sophos Intercept X blocking certutil.exe, 2026-11-03).
		if strings.Contains(errorStr, "fork/exec") && strings.Contains(errorStr, "Access is denied") {
			LogProcessExecution(test.Binary, cmdLine, pid, false, 126, "Blocked at process creation (OS denial)")
			LogMessage("INFO", test.Name, "BLOCKED: process creation denied (fork/exec Access is denied)")
			return false, true, false, "Blocked: security product denied process creation"
		}

		// Block ONLY on explicit security-product action text AND the artifact
		// is absent (Rule 8: positive evidence only; proxy denials, PATH errors
		// and generic words are NOT protection).
		if isExplicitAVActionText(outputStr) || isExplicitAVActionText(errorStr) {
			if !fileExists(outputPath) {
				LogProcessExecution(test.Binary, cmdLine, pid, false, 126, "Blocked by security controls (explicit AV action text)")
				LogMessage("INFO", test.Name, fmt.Sprintf("BLOCKED: explicit AV action text (duration: %v)", executionDuration))
				return false, true, false, "Blocked: security product action"
			}
			LogProcessExecution(test.Binary, cmdLine, pid, false, exitCode, "AV text present but artifact exists — logged for triage, not counted as block")
			return false, false, false, "Ambiguous: AV text present but artifact exists"
		}

		// Benign network/environment failure — skipped, never a block
		if isBenignDownloadFailure(outputStr) || isBenignDownloadFailure(errorStr) {
			LogProcessExecution(test.Binary, cmdLine, pid, false, exitCode, "benign network/environment failure (skipped)")
			LogMessage("WARN", test.Name, fmt.Sprintf("Benign download failure (skipped): %v", err))
			return false, false, false, fmt.Sprintf("Benign failure: %s", errorStr)
		}

		LogProcessExecution(test.Binary, cmdLine, pid, false, exitCode, errorStr)
		LogMessage("ERROR", test.Name, fmt.Sprintf("Execution failed (skipped): %v", err))
		return false, false, false, errorStr
	}

	// Give EDR time to react (file system monitoring), then check the artifact
	Endpoint.Wait(2)

	if fileExists(outputPath) {
		fileInfo, _ := os.Stat(outputPath)
		fileSize := fileInfo.Size()

		LogProcessExecution(test.Binary, cmdLine, pid, true, exitCode, "")
		LogFileDropped(test.OutputFile, outputPath, fileSize, false)
		LogMessage("SUCCESS", test.Name, fmt.Sprintf("Download successful: %s (%d bytes, duration: %v)", outputPath, fileSize, executionDuration))

		return true, false, false, ""
	}

	// Artifact missing after exit 0: re-poll before concluding quarantine —
	// some LOLBINs exit 0 on network failures without writing the file.
	LogMessage("WARN", test.Name, fmt.Sprintf("Output file not found after execution: %s (re-polling)", outputPath))
	found := false
	for i := 0; i < 3; i++ {
		Endpoint.Wait(2)
		if fileExists(outputPath) {
			found = true
			break
		}
	}

	if found {
		fileInfo, _ := os.Stat(outputPath)
		LogProcessExecution(test.Binary, cmdLine, pid, true, exitCode, "")
		LogFileDropped(test.OutputFile, outputPath, fileInfo.Size(), false)
		return true, false, false, ""
	}

	// Exit 0 + artifact still missing after all polls + benign failure text in
	// output => benign no-write failure, NOT a quarantine.
	outputStr := outputBuffer.String()
	if exitCode == 0 && !isExplicitAVActionText(outputStr) {
		if isBenignDownloadFailure(outputStr) {
			LogProcessExecution(test.Binary, cmdLine, pid, false, exitCode, "exit 0 but benign failure text and no artifact (skipped)")
			return false, false, false, "Download failed benignly - file not created"
		}
		// Exit 0, no artifact, no benign explanation, no AV text: ambiguous —
		// stat-confirmed disappearance of a file the tool wrote is the strongest
		// available quarantine signal; count it but log the ambiguity.
		LogProcessExecution(test.Binary, cmdLine, pid, true, exitCode, "")
		LogFileDropped(test.OutputFile, outputPath, 0, true)
		LogMessage("INFO", test.Name, "File absent after exit-0 download with no benign explanation - classified quarantined (os.Stat evidence)")
		return false, false, true, "File quarantined after download (os.Stat evidence)"
	}

	LogProcessExecution(test.Binary, cmdLine, pid, false, exitCode, "File not created")
	return false, false, false, "Download failed - file not created"
}

// cleanup removes all test artifacts
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	testFiles := []string{
		"test_certutil.txt",
		"test_bitsadmin.txt",
		"test_iwr.txt",
		"test_webclient.txt",
		"test_curl.txt",
		"test_certutil_output.txt",
		"test_bitsadmin_output.txt",
		"test_iwr_output.txt",
		"test_webclient_output.txt",
		"test_curl_output.txt",
		"lolbin_test_summary.txt",
	}

	for _, file := range testFiles {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}

	// Remove downloaded payload stand-ins (ARTIFACT_DIR\downloads) and the dir
	for _, file := range testFiles {
		path := filepath.Join(ARTIFACT_SUBDIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", path))
		}
	}
	if err := os.Remove(ARTIFACT_SUBDIR); err == nil {
		LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", ARTIFACT_SUBDIR))
	}

	// Clean up certutil cache
	cleanupCmd := exec.Command("certutil.exe", "-urlcache", "*", "delete")
	cleanupCmd.Run() // Ignore errors

	LogMessage("INFO", "Cleanup", "Cleanup completed")
}

func test() {
	// Ensure log is saved on exit
	defer func() {
		if r := recover(); r != nil {
			if globalLog != nil {
				LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
				SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			}
			cleanup()
			Endpoint.Stop(ExitTestError)
		}
	}()

	// Results tracking
	var blockedTests []string
	var successfulTests []string
	var quarantinedTests []string
	var skippedTests []string

	lolbinTests := getLOLBINTests()

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	// NOTE: Endpoint.Dropper call removed — it dropped an unused binary into CWD
	// on every run and was never executed (audit 2026-11-03).

	// Create target + artifact directories
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(ExitTestError, "Failed to create target directory")
		Endpoint.Stop(ExitTestError)
	}

	if err := os.MkdirAll(ARTIFACT_SUBDIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create artifact directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create artifact directory")
		SaveLog(ExitTestError, "Failed to create artifact directory")
		Endpoint.Stop(ExitTestError)
	}
	LogMessage("INFO", "Initialization", fmt.Sprintf("Target directory: %s (artifacts: %s)", TARGET_DIR, ARTIFACT_SUBDIR))
	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Network Connectivity Check
	LogPhaseStart(2, "Network Connectivity")
	Endpoint.Say("\nPhase 2: Checking network connectivity")

	if !checkNetworkConnectivity() {
		LogPhaseEnd(1, "failed", "Network unavailable")
		SaveLog(ExitTestError, "Network unavailable - cannot perform download tests")
		Endpoint.Stop(ExitTestError) // Exit code 999 for prerequisites not met
	}

	LogPhaseEnd(1, "success", "Network connectivity verified")

	// Phase 3: LOLBIN Download Tests
	LogPhaseStart(3, "LOLBIN Download Tests")
	Endpoint.Say("\nPhase 3: Executing LOLBIN download tests (%d patterns)", len(lolbinTests))

	for i, lolbinTest := range lolbinTests {
		Endpoint.Say("\n[%d/%d] %s", i+1, len(lolbinTests), lolbinTest.Name)
		LogMessage("INFO", "LOLBIN Test", fmt.Sprintf("Starting test %d/%d: %s", i+1, len(lolbinTests), lolbinTest.Name))

		success, blocked, quarantined, errMsg := executeLOLBINTest(lolbinTest)

		if blocked {
			Endpoint.Say("    [BLOCKED] Download was blocked by EDR/AV")
			blockedTests = append(blockedTests, lolbinTest.Name)
		} else if quarantined {
			Endpoint.Say("    [QUARANTINED] Downloaded file was quarantined")
			quarantinedTests = append(quarantinedTests, lolbinTest.Name)
		} else if success {
			Endpoint.Say("    [VULNERABLE] Download succeeded without detection")
			successfulTests = append(successfulTests, lolbinTest.Name)
		} else {
			Endpoint.Say("    [SKIPPED] Test failed: %s", errMsg)
			skippedTests = append(skippedTests, fmt.Sprintf("%s (%s)", lolbinTest.Name, errMsg))
		}

		// Brief pause between tests
		Endpoint.Wait(1)
	}

	LogPhaseEnd(2, "success", fmt.Sprintf("Completed %d tests", len(lolbinTests)))

	// Phase 4: Final Assessment
	LogPhaseStart(4, "Final Assessment")
	Endpoint.Say("\nPhase 4: Final assessment and summary")

	// Create summary file
	summaryPath := filepath.Join(TARGET_DIR, "lolbin_test_summary.txt")
	summary := fmt.Sprintf(`LOLBIN Download Detection Test Summary
=======================================
Test ID: %s
Test Name: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1105: Ingress Tool Transfer
- T1059.001: Command and Scripting Interpreter - PowerShell

LOLBIN Patterns Tested: %d
Patterns Blocked: %d
Patterns Quarantined: %d
Patterns Successful (Vulnerable): %d
Patterns Skipped: %d

Blocked Patterns:
%s

Quarantined Files:
%s

Successful Downloads (VULNERABLE):
%s

Skipped Tests:
%s

Assessment:
%s
`,
		TEST_UUID,
		TEST_NAME,
		time.Now().Format("2006-01-02 15:04:05"),
		len(lolbinTests),
		len(blockedTests),
		len(quarantinedTests),
		len(successfulTests),
		len(skippedTests),
		formatTestList(blockedTests),
		formatTestList(quarantinedTests),
		formatTestList(successfulTests),
		formatTestList(skippedTests),
		generateAssessment(len(blockedTests), len(quarantinedTests), len(successfulTests)))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("lolbin_test_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(3, "success", "Assessment complete")

	// Final result output
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("LOLBIN Patterns Tested: %d", len(lolbinTests))
	Endpoint.Say("Patterns Blocked: %d", len(blockedTests))
	Endpoint.Say("Patterns Quarantined: %d", len(quarantinedTests))
	Endpoint.Say("Patterns Vulnerable: %d", len(successfulTests))
	Endpoint.Say("Patterns Skipped: %d", len(skippedTests))

	// Determine exit code based on results
	protectedCount := len(blockedTests) + len(quarantinedTests)

	if protectedCount > 0 && len(successfulTests) == 0 {
		// All tested patterns were blocked or quarantined - PROTECTED
		Endpoint.Say("\n[RESULT] PROTECTED - All LOLBIN download attempts were blocked or quarantined")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - all LOLBIN downloads blocked")

		// Determine specific protection type
		if len(quarantinedTests) > 0 && len(blockedTests) == 0 {
			SaveLog(Endpoint.FileQuarantinedOnExtraction, fmt.Sprintf("Protected: %d files quarantined", len(quarantinedTests)))
			cleanup()
			Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction) // Exit 105
		} else {
			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d blocked, %d quarantined", len(blockedTests), len(quarantinedTests)))
			cleanup()
			Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
		}

	} else if protectedCount > 0 && len(successfulTests) > 0 {
		// Mixed results - some blocked, some succeeded - still report protection (any blocking is good)
		Endpoint.Say("\n[RESULT] PARTIAL PROTECTION - Some LOLBIN downloads blocked, some succeeded")
		LogMessage("WARN", "Final Assessment", fmt.Sprintf("Partial protection: %d blocked, %d vulnerable", protectedCount, len(successfulTests)))
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Partial: %d blocked, %d vulnerable", protectedCount, len(successfulTests)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126 - report protected since at least some were blocked

	} else if len(successfulTests) > 0 {
		// All patterns succeeded - UNPROTECTED
		Endpoint.Say("\n[RESULT] UNPROTECTED - LOLBIN downloads succeeded without detection")
		LogMessage("CRITICAL", "Final Assessment", fmt.Sprintf("System UNPROTECTED - %d LOLBIN patterns succeeded", len(successfulTests)))
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d LOLBIN downloads succeeded", len(successfulTests)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101

	} else {
		// No clear result (all skipped)
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - All tests were skipped")
		LogMessage("WARN", "Final Assessment", "All LOLBIN tests skipped - inconclusive result")
		SaveLog(ExitTestError, "All tests skipped - unable to determine protection status")
		cleanup()
		Endpoint.Stop(ExitTestError) // Exit 999
	}
}

// formatTestList formats a list of test names for display
func formatTestList(tests []string) string {
	if len(tests) == 0 {
		return "  (none)"
	}
	var result string
	for _, t := range tests {
		result += fmt.Sprintf("  - %s\n", t)
	}
	return result
}

// generateAssessment creates an assessment string based on results
func generateAssessment(blocked, quarantined, successful int) string {
	total := blocked + quarantined + successful
	if total == 0 {
		return "INCONCLUSIVE - No tests completed successfully."
	}

	protectedPercent := float64(blocked+quarantined) / float64(total) * 100

	if successful == 0 {
		return fmt.Sprintf("PROTECTED (%.0f%%) - All LOLBIN download attempts were blocked or quarantined. "+
			"The endpoint demonstrates strong protection against ingress tool transfer via LOLBINs.", protectedPercent)
	} else if blocked+quarantined > 0 {
		return fmt.Sprintf("PARTIAL PROTECTION (%.0f%%) - Some LOLBIN downloads were blocked (%d) or quarantined (%d), "+
			"but %d patterns succeeded. Consider enhancing detection rules for the successful patterns.",
			protectedPercent, blocked, quarantined, successful)
	}
	return fmt.Sprintf("UNPROTECTED (0%%) - All %d LOLBIN download patterns executed successfully. "+
		"The endpoint lacks protection against ingress tool transfer via LOLBINs. "+
		"Immediate remediation recommended.", successful)
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1059.001 (PowerShell)")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "command_and_control",
		Severity:      "high",
		Techniques:    []string{"T1105", "T1059.001"},
		Tactics:       []string{"command-and-control", "execution"},
		Score:         8.0, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct do not match the v2.1 tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
		Tags: []string{"lolbin", "download", "certutil", "bitsadmin", "powershell", "curl", "native"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000, // 3 minutes for network operations
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

	timeout := 3 * time.Minute // Extended timeout for network operations

	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		cleanup()
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
