//go:build windows
// +build windows

/*
ID: d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10
NAME: Security Service Stop Simulation
TECHNIQUES: T1489, T1562.001
TACTICS: impact, defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: impact
TAGS: service-stop, defender-tampering, security-service, impair-defenses
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// Test constants
const (
	TEST_UUID = "d6a2e7f0-5b1c-2a9d-6e3f-0c1d2e3f4a10"
	TEST_NAME = "Security Service Stop Simulation"

	// Exit-code constants (framework contract; never hardcode bare literals —
	// the vendored endpoint lib maps UnexpectedTestError to 1, not 999).
	ExitUnprotected     = 101
	ExitQuarantined     = 105
	ExitPrevented       = 126
	ExitTestError       = 999
	ExitTimeoutExceeded = 102
)

// Test service constants - SAFE TEST SERVICE ONLY
const (
	TEST_SERVICE_NAME    = "F0RTIKA_TestSvc"
	TEST_SERVICE_DISPLAY = "F0RT1KA Test Service"
	TEST_SERVICE_BINARY  = "c:\\F0\\test_svc.exe"
	// A REAL service-protocol binary (gives the lifecycle a genuine RUNNING
	// state to stop); falls back to a copied cmd.exe (degraded mode) if absent.
	REAL_SERVICE_BINARY = `C:\Windows\System32\snmptrap.exe`
)

// Security services to QUERY ONLY (never stop). Includes the lab's actual EDR
// service names so tamper-protection evidence is observable; missing services
// simply report NOT_FOUND (1060) and are skipped harmlessly.
var securityServicesToQuery = []string{
	"WinDefend", // Windows Defender
	"wscsvc",    // Windows Security Center
	"VSS",       // Volume Shadow Copy Service
	"wbengine",  // Windows Backup Engine
	"CSFalconService",                    // CrowdStrike Falcon (previous lab EDR)
	"Sophos Endpoint Defense Service",    // Sophos Intercept X (current lab EDR)
	"McsAgent",                           // Sophos MCS agent
	"McsClient",                          // Sophos MCS client
}

// fileExists is a small os.Stat wrapper
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ServiceQueryResult holds service status information
type ServiceQueryResult struct {
	ServiceName string
	Status      string
	Exists      bool
	QueryError  string
}

// Global tracking
var (
	testServiceCreated bool = false
	nxcExtracted       bool = false
	testResults        []ServiceQueryResult
	serviceBinaryPath  string // resolved in extractComponents()
)

// extractComponents extracts test components to c:\F0
func extractComponents() error {
	targetDir := "c:\\F0"

	// Create tools directory for NetExec placeholder
	toolsDir := filepath.Join(targetDir, "tools")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("failed to create tools directory: %v", err)
	}
	LogMessage("INFO", "Setup", fmt.Sprintf("Created tools directory: %s", toolsDir))

	// Prefer a REAL service-protocol binary (snmptrap.exe) as binPath so the
	// lifecycle has a genuine RUNNING state to stop (Batch B realism upgrade).
	// Fall back to a cmd.exe copy in degraded mode (start will fail 1053 and
	// the stop-corroboration phase will be marked degraded, never fake-verified).
	if fileExists(REAL_SERVICE_BINARY) {
		serviceBinaryPath = REAL_SERVICE_BINARY
		Endpoint.Say("  [+] Using real service binary for lifecycle: %s", serviceBinaryPath)
	} else {
		testSvcPath := filepath.Join(targetDir, "test_svc.exe")
		cmdExe := `C:\Windows\System32\cmd.exe`
		cmdData, err := os.ReadFile(cmdExe)
		if err != nil {
			LogMessage("WARN", "Setup", "Using minimal service binary")
			stubContent := []byte("@echo off\nexit 0")
			testSvcPath = filepath.Join(targetDir, "test_svc.bat")
			if err := os.WriteFile(testSvcPath, stubContent, 0644); err != nil {
				return fmt.Errorf("failed to create test service binary: %v", err)
			}
		} else {
			if err := os.WriteFile(testSvcPath, cmdData, 0755); err != nil {
				return fmt.Errorf("failed to write test service binary: %v", err)
			}
		}
		serviceBinaryPath = testSvcPath
		LogFileDropped("test_svc.exe", testSvcPath, int64(len(cmdData)), false)
		Endpoint.Say("  [+] Created test service binary (degraded mode): %s", testSvcPath)
	}

	// Check if user has provided nxc.exe in tools directory
	nxcPath := filepath.Join(toolsDir, "nxc.exe")
	if _, err := os.Stat(nxcPath); err == nil {
		nxcExtracted = true
		LogMessage("INFO", "Setup", "NetExec (nxc.exe) found in tools directory")
		Endpoint.Say("  [+] NetExec found: %s", nxcPath)
	} else {
		// Create README for tools directory
		readmeContent := `# NetExec Tools Directory

This directory is for placing NetExec (nxc.exe) for advanced service enumeration testing.

## How to Add NetExec

1. Download NetExec from: https://github.com/Pennyw0rth/NetExec
2. Place nxc.exe in this directory (c:\F0\tools\)
3. Re-run the test

## Why NetExec?

NetExec is used for testing SMB-based service enumeration capabilities.
It allows testing detection of remote service control operations via SMB.

## Test Behavior

- If nxc.exe is present: Test will execute service enumeration via SMB (localhost)
- If nxc.exe is absent: Test will skip the NetExec phase and log accordingly
`
		readmePath := filepath.Join(toolsDir, "README.md")
		if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
			LogMessage("WARN", "Setup", "Failed to create tools README")
		}
		LogMessage("INFO", "Setup", "NetExec not found - skipping SMB service enumeration phase")
		Endpoint.Say("  [!] NetExec (nxc.exe) not found in c:\\F0\\tools\\")
		Endpoint.Say("      Place nxc.exe in c:\\F0\\tools\\ for SMB enumeration testing")
	}

	return nil
}

// querySecurityService queries a security service (QUERY ONLY - SAFE)
func querySecurityService(serviceName string) ServiceQueryResult {
	result := ServiceQueryResult{
		ServiceName: serviceName,
		Exists:      false,
	}

	Endpoint.Say("  Querying service: %s", serviceName)

	cmd := exec.Command("sc", "query", serviceName)
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	output := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	if len(output) > 0 {
		safe := strings.Map(func(r rune) rune { if r == ' ' || r == '\\' { return '_' }; return r }, serviceName)
		os.WriteFile(filepath.Join("c:\\F0", fmt.Sprintf("svc_query_%s_output.txt", safe)), []byte(output), 0644)
	}

	if err != nil {
		// Check if it's just "service not found" vs actual access denial
		if strings.Contains(output, "1060") || strings.Contains(output, "does not exist") {
			result.Status = "NOT_FOUND"
			result.QueryError = "Service does not exist"
		} else if strings.Contains(output, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
			// Exact OS denial on a privileged query while elevated (the test
			// aborts 999 when non-admin) — tamper-protection evidence (Rule 5/8)
			result.Status = "ACCESS_DENIED"
			result.QueryError = "Access denied - tamper protection"
			result.Exists = true
		} else {
			result.Status = "ERROR"
			result.QueryError = err.Error()
		}
	} else {
		result.Exists = true
		// Parse service state
		if strings.Contains(output, "RUNNING") {
			result.Status = "RUNNING"
		} else if strings.Contains(output, "STOPPED") {
			result.Status = "STOPPED"
		} else if strings.Contains(output, "PAUSED") {
			result.Status = "PAUSED"
		} else {
			result.Status = "UNKNOWN"
		}
	}

	LogMessage("INFO", "Service Query", fmt.Sprintf("Service %s: %s", serviceName, result.Status))
	LogProcessExecution("sc.exe", fmt.Sprintf("sc query %s", serviceName), pid, err == nil, 0, result.QueryError)

	return result
}

// createTestService creates our own test service
func createTestService() error {
	Endpoint.Say("  Creating test service: %s", TEST_SERVICE_NAME)

	// First check if service already exists and delete it
	cmd := exec.Command("sc", "query", TEST_SERVICE_NAME)
	if err := cmd.Run(); err == nil {
		// Service exists, delete it first
		deleteCmd := exec.Command("sc", "delete", TEST_SERVICE_NAME)
		deleteCmd.Run()
		time.Sleep(500 * time.Millisecond)
	}

	// Create the test service using the resolved service binary path
	binPath := serviceBinaryPath
	if binPath == "" {
		binPath = TEST_SERVICE_BINARY
	}
	// Call sc.exe DIRECTLY with argv-style args. Going through `cmd /C` with a
	// pre-quoted command line mangles the inner quotes (Go escapes them for
	// cmd.exe, producing sc error 1639 ERROR_INVALID_COMMAND_LINE — observed on
	// the win lab 2026-11-03). sc's `key= value` syntax maps cleanly to argv.
	cmd = exec.Command("sc", "create", TEST_SERVICE_NAME,
		"binPath=", binPath,
		"type=", "own",
		"start=", "demand",
		"displayname=", TEST_SERVICE_DISPLAY)
	cmdLine := fmt.Sprintf("sc create %s binPath= \"%s\" type= own start= demand displayname= \"%s\"",
		TEST_SERVICE_NAME, binPath, TEST_SERVICE_DISPLAY)

	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	output := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if err != nil {
		errMsg := fmt.Sprintf("Failed to create service: %v - %s", err, output)
		LogMessage("ERROR", "Service Create", errMsg)
		LogProcessExecution("sc.exe", cmdLine, pid, false, 1, errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	if strings.Contains(output, "SUCCESS") || strings.Contains(output, "[SC] CreateService SUCCESS") {
		testServiceCreated = true
		LogMessage("SUCCESS", "Service Create", fmt.Sprintf("Created test service: %s (binPath=%s)", TEST_SERVICE_NAME, binPath))
		LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "")
		Endpoint.Say("    [+] Test service created successfully")
		return nil
	}

	return fmt.Errorf("unexpected output: %s", output)
}

// startTestService attempts to start the test service and waits for RUNNING.
// Returns (started, degraded): degraded=true when the SCM handshake fails
// (e.g. 1053 with a non-service binary) — the stop phase still runs but is
// never counted as a VERIFIED stop.
func startTestService() (bool, bool) {
	Endpoint.Say("  Starting test service: %s", TEST_SERVICE_NAME)

	cmd := exec.Command("sc", "start", TEST_SERVICE_NAME)
	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	err := cmd.Run()
	output := buf.String()
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	cmdLine := fmt.Sprintf("sc start %s", TEST_SERVICE_NAME)

	if err != nil {
		// 1053: service did not respond to start in a timely fashion (binary
		// is not a real service executable) — benign degraded mode.
		if strings.Contains(output, "1053") || strings.Contains(output, "did not respond") {
			LogMessage("WARN", "Service Start", "Service handshake failed (1053) — degraded mode: stop will run but cannot be verified")
			LogProcessExecution("sc.exe", cmdLine, pid, false, 1053, "service handshake failure (degraded mode)")
			return false, true
		}
		if strings.Contains(output, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
			LogMessage("INFO", "Service Start", "Service start denied (OS denial on own service)")
			LogProcessExecution("sc.exe", cmdLine, pid, false, 126, "start denied")
			return false, false
		}
		LogMessage("WARN", "Service Start", fmt.Sprintf("Start error (benign): %v - %s", err, output))
		LogProcessExecution("sc.exe", cmdLine, pid, false, 1, err.Error())
		return false, true
	}
	LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "")

	// Poll until RUNNING (max ~10s)
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		qr := queryServiceState(TEST_SERVICE_NAME)
		if qr == "RUNNING" {
			LogMessage("SUCCESS", "Service Start", "Test service reached RUNNING state")
			Endpoint.Say("    [+] Test service is RUNNING")
			return true, false
		}
		if qr == "STOPPED" || qr == "NOT_FOUND" {
			break
		}
	}
	LogMessage("WARN", "Service Start", "Service did not reach RUNNING within poll window — degraded mode")
	return false, true
}

// queryServiceState returns the STATE line value of `sc query <name>`.
func queryServiceState(serviceName string) string {
	cmd := exec.Command("sc", "query", serviceName)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		out := buf.String()
		if strings.Contains(out, "1060") || strings.Contains(out, "does not exist") {
			return "NOT_FOUND"
		}
		if strings.Contains(out, "Access is denied") {
			return "ACCESS_DENIED"
		}
		return "ERROR"
	}
	out := buf.String()
	for _, state := range []string{"RUNNING", "STOPPED", "PAUSED", "START_PENDING", "STOP_PENDING"} {
		if strings.Contains(out, state) {
			return state
		}
	}
	return "UNKNOWN"
}

// stopTestService stops our test service and CORROBORATES via re-query
// (Bug Prevention Rule 5: a stop only counts when a follow-up query confirms
// the service is no longer RUNNING). Returns (stopped, verified, err).
func stopTestService() (bool, bool, error) {
	if !testServiceCreated {
		return false, false, fmt.Errorf("test service was not created")
	}

	Endpoint.Say("  Stopping test service: %s", TEST_SERVICE_NAME)

	cmd := exec.Command("sc", "stop", TEST_SERVICE_NAME)
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	output := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	cmdLine := fmt.Sprintf("sc stop %s", TEST_SERVICE_NAME)

	// Service not running (1062): a no-op stop is NEVER a verified stop.
	if strings.Contains(output, "1062") || strings.Contains(output, "has not been started") {
		LogMessage("INFO", "Service Stop", "Service was not running — stop is a no-op (not counted as verified)")
		LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "Service not running (no-op)")
		return false, false, nil
	}

	if err != nil {
		if strings.Contains(output, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
			LogMessage("WARN", "Service Stop", "Access denied when stopping test service")
			LogProcessExecution("sc.exe", cmdLine, pid, false, 5, "Access denied")
			return false, false, fmt.Errorf("access denied")
		}
		LogMessage("ERROR", "Service Stop", fmt.Sprintf("Error: %v - %s", err, output))
		LogProcessExecution("sc.exe", cmdLine, pid, false, 1, err.Error())
		return false, false, err
	}

	// CORROBORATION: re-query and confirm state is not RUNNING
	verified := false
	for i := 0; i < 4; i++ {
		time.Sleep(1 * time.Second)
		state := queryServiceState(TEST_SERVICE_NAME)
		if state == "STOPPED" {
			verified = true
			break
		}
		if state == "RUNNING" || state == "STOP_PENDING" {
			continue // keep polling
		}
	}

	if verified {
		LogMessage("SUCCESS", "Service Stop", "Test service stopped and corroborated STOPPED via re-query")
		LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "stop corroborated by re-query")
		Endpoint.Say("    [+] Test service stopped (corroborated via re-query)")
	} else {
		LogMessage("WARN", "Service Stop", "Stop command accepted but state could not be corroborated")
		LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "stop issued; corroboration inconclusive")
	}
	return true, verified, nil
}

// deleteTestService deletes our test service
func deleteTestService() error {
	if !testServiceCreated {
		return nil // Nothing to delete
	}

	Endpoint.Say("  Deleting test service: %s", TEST_SERVICE_NAME)

	cmd := exec.Command("sc", "delete", TEST_SERVICE_NAME)
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	output := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	cmdLine := fmt.Sprintf("sc delete %s", TEST_SERVICE_NAME)

	if err != nil {
		LogMessage("WARN", "Service Delete", fmt.Sprintf("Error deleting service: %v - %s", err, output))
		LogProcessExecution("sc.exe", cmdLine, pid, false, 1, err.Error())
		return err
	}

	if strings.Contains(output, "SUCCESS") || strings.Contains(output, "[SC] DeleteService SUCCESS") {
		LogMessage("SUCCESS", "Service Delete", "Test service deleted successfully")
		LogProcessExecution("sc.exe", cmdLine, pid, true, 0, "")
		testServiceCreated = false
		Endpoint.Say("    [+] Test service deleted")
		return nil
	}

	return nil
}

// checkTaskkillAccess checks if taskkill is accessible (QUERY ONLY)
func checkTaskkillAccess() bool {
	Endpoint.Say("  Checking taskkill accessibility...")

	// Just check if taskkill runs with /? (help)
	cmd := exec.Command("taskkill", "/?")
	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	output := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	if err == nil || strings.Contains(output, "TASKKILL") {
		LogMessage("INFO", "Taskkill Check", "Taskkill utility accessible")
		LogProcessExecution("taskkill.exe", "taskkill /?", pid, true, 0, "")
		Endpoint.Say("    [+] Taskkill is accessible")
		return true
	}

	// A failed taskkill /? is a PATH/environment outcome, NOT protection
	// evidence (Rule 8) — logged, never counted toward a block.
	LogMessage("WARN", "Taskkill Check", fmt.Sprintf("Taskkill access check failed (benign, not counted): %v", err))
	LogProcessExecution("taskkill.exe", "taskkill /?", pid, false, 1, err.Error())
	return false
}

// executeNetExec runs NetExec for SMB service enumeration (if available)
func executeNetExec() (bool, bool) { // returns (executed, blocked)
	if !nxcExtracted {
		LogMessage("INFO", "NetExec", "Skipping NetExec phase - nxc.exe not found")
		return false, false
	}

	nxcPath := "c:\\F0\\tools\\nxc.exe"
	Endpoint.Say("  Executing NetExec service enumeration...")

	// Run against localhost with dummy credentials for safe testing
	// This will fail auth but tests if EDR blocks the tool
	cmd := exec.Command(nxcPath, "smb", "127.0.0.1", "-u", "test", "-p", "test", "--services")

	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)
	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	// Save output
	outputPath := "c:\\F0\\tools\\nxc_output.txt"
	os.WriteFile(outputPath, outputBuffer.Bytes(), 0644)
	LogMessage("INFO", "NetExec", fmt.Sprintf("NetExec output saved to: %s", outputPath))

	cmdLine := "nxc smb 127.0.0.1 -u test -p test --services"

	nxcPid := 0
	if cmd.Process != nil {
		nxcPid = cmd.Process.Pid
	}

	if err != nil {
		errStr := err.Error()
		output := outputBuffer.String()
		_ = duration

		// Block ONLY on explicit denial text from the tool's own execution
		// (Rule 8). Exit 1 with a fast failure is the EXPECTED auth-failure
		// path against localhost with dummy credentials — never a block.
		if strings.Contains(errStr, "Access is denied") || strings.Contains(output, "Access is denied") {
			LogMessage("INFO", "NetExec", "NetExec execution denied (explicit denial text)")
			LogProcessExecution("nxc.exe", cmdLine, nxcPid, false, 126, "Blocked by security controls (denial text)")
			Endpoint.Say("    [!] NetExec blocked by security controls")
			return true, true
		}

		// Normal failure (auth failure expected)
		LogMessage("INFO", "NetExec", fmt.Sprintf("NetExec completed with error (expected): %v", err))
		LogProcessExecution("nxc.exe", cmdLine, nxcPid, true, 0, "Auth failure expected")
		Endpoint.Say("    [+] NetExec executed (auth failure expected)")
		return true, false
	}

	LogMessage("SUCCESS", "NetExec", "NetExec executed successfully")
	LogProcessExecution("nxc.exe", cmdLine, nxcPid, true, 0, "")
	Endpoint.Say("    [+] NetExec service enumeration completed")
	return true, false
}

// cleanup removes all test artifacts
func cleanup() {
	Endpoint.Say("\nCleanup Phase:")

	// Delete test service
	if testServiceCreated {
		deleteTestService()
	}

	// Remove test service binary (both exe and bat fallback paths)
	for _, f := range []string{"test_svc.exe", "test_svc.bat"} {
		testSvcPath := filepath.Join("c:\\F0", f)
		if err := os.Remove(testSvcPath); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed %s", f))
			Endpoint.Say("  [+] Removed %s", f)
		}
	}

	// Note: We don't remove the tools directory or nxc.exe as user may want to reuse it
	LogMessage("INFO", "Cleanup", "Cleanup completed (tools directory preserved)")
}

func test() {
	// Initialize logging with Schema v2.0
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "impact",
		Severity:      "high",
		Techniques:    []string{"T1489", "T1562.001"},
		Tactics:       []string{"impact", "defense-evasion"},
		Score:         8.2, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct do not match the v2.1 tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
		Tags: []string{"service-control", "smb", "netexec", "mitre-top10"},
	}

	orgInfo := ResolveOrganization("")
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         180000,
			CertificateMode:   "self-healing",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			cleanup()
			SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			Endpoint.Stop(ExitTestError)
		}
	}()

	// Track protection status
	anyBlocked := false
	serviceOpsSuccess := false

	// ===========================================================================
	// Phase 0: Prerequisites Check
	// ===========================================================================
	LogPhaseStart(0, "Prerequisites Check")
	Endpoint.Say("Phase 0: Prerequisites Check")

	// Check if running as admin
	cmd := exec.Command("net", "session")
	if err := cmd.Run(); err != nil {
		LogMessage("ERROR", "Prerequisites", "Administrator privileges required")
		LogPhaseEnd(0, "failed", "Not running as Administrator")
		Endpoint.Say("  [!] ERROR: Administrator privileges required for service operations")
		SaveLog(ExitTestError, "Insufficient privileges - run as Administrator")
		Endpoint.Stop(ExitTestError)
		return
	}
	LogMessage("SUCCESS", "Prerequisites", "Running with Administrator privileges")
	Endpoint.Say("  [+] Running with Administrator privileges")
	LogPhaseEnd(0, "success", "Administrator privileges confirmed")

	// ===========================================================================
	// Phase 1: Setup and Component Extraction
	// ===========================================================================
	LogPhaseStart(1, "Setup and Component Extraction")
	Endpoint.Say("\nPhase 1: Setup and Component Extraction")

	if err := extractComponents(); err != nil {
		LogMessage("ERROR", "Setup", fmt.Sprintf("Component extraction failed: %v", err))
		LogPhaseEnd(1, "failed", err.Error())
		SaveLog(ExitTestError, err.Error())
		Endpoint.Stop(ExitTestError)
		return
	}
	LogPhaseEnd(1, "success", "Components extracted successfully")

	// ===========================================================================
	// Phase 2: Security Service Query (SAFE - Query Only)
	// ===========================================================================
	LogPhaseStart(2, "Security Service Query")
	Endpoint.Say("\nPhase 2: Security Service Query (Query Only - SAFE)")
	Endpoint.Say("  NOTE: This phase ONLY queries service status - no services are stopped")

	queriesBlocked := 0
	for _, serviceName := range securityServicesToQuery {
		result := querySecurityService(serviceName)
		testResults = append(testResults, result)

		if result.Status == "ACCESS_DENIED" {
			queriesBlocked++
			Endpoint.Say("    [!] %s: BLOCKED (Access Denied)", serviceName)
		} else {
			Endpoint.Say("    [+] %s: %s", serviceName, result.Status)
		}
	}

	if queriesBlocked > 0 {
		LogMessage("WARN", "Service Query", fmt.Sprintf("%d/%d service queries blocked", queriesBlocked, len(securityServicesToQuery)))
		anyBlocked = true
	}

	LogPhaseEnd(2, "success", fmt.Sprintf("Queried %d services, %d blocked", len(securityServicesToQuery), queriesBlocked))

	// ===========================================================================
	// Phase 3: Test Service Operations (Our Own Service)
	// ===========================================================================
	LogPhaseStart(3, "Test Service Operations")
	Endpoint.Say("\nPhase 3: Test Service Operations (Creating Own Service)")
	Endpoint.Say("  NOTE: This creates/stops/deletes a test service ONLY - no real services affected")

	// Real lifecycle: create -> START -> poll RUNNING -> STOP -> re-query corroboration
	verifiedStop := false
	lifecycleDegraded := false
	if err := createTestService(); err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			LogMessage("INFO", "Service Create", "Service creation denied (OS denial while elevated) — protection evidence")
			anyBlocked = true
			Endpoint.Say("    [!] Service creation BLOCKED by security controls")
		} else {
			LogMessage("WARN", "Service Create", fmt.Sprintf("Service creation failed (benign): %v", err))
		}
	} else {
		started, degraded := startTestService()
		lifecycleDegraded = degraded

		_, verified, stopErr := stopTestService()
		verifiedStop = verified
		if stopErr != nil {
			if strings.Contains(stopErr.Error(), "access denied") {
				LogMessage("INFO", "Service Stop", "Service stop denied (OS denial on own service) — protection evidence")
				anyBlocked = true
				Endpoint.Say("    [!] Service stop BLOCKED by security controls")
			}
		}
		if !started {
			Endpoint.Say("    [i] Service never reached RUNNING (degraded=%v) — stop cannot be verified", degraded)
		}

		// Delete test service
		deleteTestService()
	}

	// serviceOpsSuccess means a VERIFIED stop (started + stopped + corroborated)
	serviceOpsSuccess = verifiedStop
	if lifecycleDegraded {
		LogMessage("WARN", "Service Lifecycle", "Lifecycle ran in degraded mode (service handshake failure) — stop not counted as verified")
	}

	if serviceOpsSuccess {
		LogPhaseEnd(3, "success", "Test service operations completed")
	} else if anyBlocked {
		LogPhaseEnd(3, "blocked", "Service operations blocked by security controls")
	} else {
		LogPhaseEnd(3, "failed", "Service operations failed")
	}

	// ===========================================================================
	// Phase 4: Taskkill Access Check (Query Only)
	// ===========================================================================
	LogPhaseStart(4, "Taskkill Access Check")
	Endpoint.Say("\nPhase 4: Taskkill Access Check (Query Only)")

	taskkillAvailable := checkTaskkillAccess()
	if taskkillAvailable {
		LogPhaseEnd(4, "success", "Taskkill utility accessible")
	} else {
		// Benign environment outcome — NOT protection evidence (Rule 8)
		LogPhaseEnd(4, "failed", "Taskkill access check failed (benign)")
	}

	// ===========================================================================
	// Phase 5: NetExec SMB Service Enumeration (Optional)
	// ===========================================================================
	LogPhaseStart(5, "NetExec SMB Service Enumeration")
	Endpoint.Say("\nPhase 5: NetExec SMB Service Enumeration (Optional)")

	nxcExecuted, nxcBlocked := executeNetExec()
	if !nxcExecuted {
		LogPhaseEnd(5, "skipped", "NetExec not available - place nxc.exe in c:\\F0\\tools\\")
		Endpoint.Say("  [*] Skipped - NetExec not available")
	} else if nxcBlocked {
		LogPhaseEnd(5, "blocked", "NetExec blocked by security controls")
		anyBlocked = true
	} else {
		LogPhaseEnd(5, "success", "NetExec service enumeration completed")
	}

	// ===========================================================================
	// Phase 6: Cleanup
	// ===========================================================================
	LogPhaseStart(6, "Cleanup")
	cleanup()
	LogPhaseEnd(6, "success", "Cleanup completed")

	// ===========================================================================
	// Determine Final Result
	// ===========================================================================
	Endpoint.Say("\n" + strings.Repeat("=", 60))
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say(strings.Repeat("=", 60))

	// Summary of service queries
	Endpoint.Say("\nSecurity Service Status (Query Results):")
	for _, result := range testResults {
		Endpoint.Say("  - %s: %s", result.ServiceName, result.Status)
	}

	Endpoint.Say("\nTest Operations:")
	Endpoint.Say("  - Service Create/Stop/Delete: %v", serviceOpsSuccess)
	Endpoint.Say("  - Taskkill Access: %v", taskkillAvailable)
	Endpoint.Say("  - NetExec Available: %v", nxcExtracted)
	if nxcExecuted {
		Endpoint.Say("  - NetExec Blocked: %v", nxcBlocked)
	}

	// Determine exit code. Protection evidence (anyBlocked / nxcBlocked) is
	// evaluated FIRST and is never masked by a successful own-service lifecycle
	// (checklist K); a benign no-result outcome maps to 999, never to 101/126.
	if anyBlocked || nxcBlocked {
		Endpoint.Say("\nRESULT: PROTECTED - Positive protection evidence observed (tamper-protected query denial or own-service operation denial)")
		SaveLog(ExitPrevented, "Protection evidence: service operation denial / tamper-protected query")
		Endpoint.Stop(ExitPrevented)
	} else if serviceOpsSuccess {
		// VERIFIED stop: started + stopped + corroborated via re-query
		Endpoint.Say("\nRESULT: UNPROTECTED - Service stop lifecycle (create/start/stop with corroboration) succeeded")
		SaveLog(ExitUnprotected, "System unprotected - verified service stop lifecycle succeeded")
		Endpoint.Stop(ExitUnprotected)
	} else {
		// No positive protection evidence AND no verified stop: inconclusive
		// test outcome — 999 (a benign failure is not an 'unprotected' verdict).
		Endpoint.Say("\nRESULT: INCONCLUSIVE - No protection evidence and no verified service stop")
		SaveLog(ExitTestError, "Inconclusive: no protection evidence, no verified stop (degraded lifecycle or benign failures)")
		Endpoint.Stop(ExitTestError)
	}
}

func main() {
	Endpoint.Say("=" + strings.Repeat("=", 59))
	Endpoint.Say("F0RT1KA Security Test: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1489 (Service Stop), T1562.001 (Impair Defenses)")
	Endpoint.Say(strings.Repeat("=", 60))
	Endpoint.Say("")
	Endpoint.Say("SAFETY NOTICE:")
	Endpoint.Say("  - This test does NOT stop real security services")
	Endpoint.Say("  - Only queries existing services (WinDefend, wscsvc, etc.)")
	Endpoint.Say("  - Creates/stops/deletes a test service (F0RTIKA_TestSvc) only")
	Endpoint.Say("  - NetExec is optional and tests against localhost only")
	Endpoint.Say("")
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("")

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// 3 minute timeout
	timeout := 3 * time.Minute

	select {
	case <-done:
		Endpoint.Say("\nTest completed")
	case <-time.After(timeout):
		Endpoint.Say("\nTest timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(ExitTimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		cleanup() // remove test service + binaries so timeout leaves no residue
		Endpoint.Stop(ExitTimeoutExceeded)
	}
}
