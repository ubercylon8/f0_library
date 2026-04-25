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
SUBCATEGORY: defense-evasion
TAGS: service-stop, defender-tampering, security-service, impair-defenses
UNIT: response
CREATED: 2025-01-11
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	_ "embed"
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
)

// Test service constants - SAFE TEST SERVICE ONLY
const (
	TEST_SERVICE_NAME    = "F0RTIKA_TestSvc"
	TEST_SERVICE_DISPLAY = "F0RT1KA Test Service"
	TEST_SERVICE_BINARY  = "c:\\F0\\test_svc.exe"
)

// Security services to QUERY ONLY (never stop)
var securityServicesToQuery = []string{
	"WinDefend", // Windows Defender
	"wscsvc",    // Windows Security Center
	"VSS",       // Volume Shadow Copy Service
	"wbengine",  // Windows Backup Engine
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

	// Create a simple dummy executable for our test service
	// This is a minimal valid PE that just exits immediately
	testSvcPath := filepath.Join(targetDir, "test_svc.exe")

	// Use cmd.exe as a harmless binary for the test service
	// We just need any valid executable for sc create
	cmdExe := `C:\Windows\System32\cmd.exe`
	cmdData, err := os.ReadFile(cmdExe)
	if err != nil {
		// Fallback: create a tiny batch file converted to exe-like stub
		LogMessage("WARN", "Setup", "Using minimal service binary")
		// Write a tiny stub - the service won't actually run, just be registered
		stubContent := []byte("@echo off\nexit 0")
		testSvcPath = filepath.Join(targetDir, "test_svc.bat")
		if err := os.WriteFile(testSvcPath, stubContent, 0644); err != nil {
			return fmt.Errorf("failed to create test service binary: %v", err)
		}
	} else {
		// Copy cmd.exe as our test service binary
		if err := os.WriteFile(testSvcPath, cmdData, 0755); err != nil {
			return fmt.Errorf("failed to write test service binary: %v", err)
		}
	}
	LogFileDropped("test_svc.exe", testSvcPath, int64(len(cmdData)), false)
	Endpoint.Say("  [+] Created test service binary: %s", testSvcPath)

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
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Run()
	output := outputBuffer.String()

	if err != nil {
		// Check if it's just "service not found" vs actual access denial
		if strings.Contains(output, "1060") || strings.Contains(output, "does not exist") {
			result.Status = "NOT_FOUND"
			result.QueryError = "Service does not exist"
		} else if strings.Contains(output, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
			result.Status = "ACCESS_DENIED"
			result.QueryError = "Access denied - EDR may be blocking"
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
	LogProcessExecution("sc.exe", fmt.Sprintf("sc query %s", serviceName), 0, err == nil, 0, result.QueryError)

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

	// Create the test service
	cmdLine := fmt.Sprintf("sc create %s binPath= \"%s\" type= own start= demand displayname= \"%s\"",
		TEST_SERVICE_NAME, TEST_SERVICE_BINARY, TEST_SERVICE_DISPLAY)

	cmd = exec.Command("cmd", "/C", cmdLine)
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Run()
	output := outputBuffer.String()

	if err != nil {
		errMsg := fmt.Sprintf("Failed to create service: %v - %s", err, output)
		LogMessage("ERROR", "Service Create", errMsg)
		LogProcessExecution("sc.exe", cmdLine, 0, false, 1, errMsg)
		return fmt.Errorf(errMsg)
	}

	if strings.Contains(output, "SUCCESS") || strings.Contains(output, "[SC] CreateService SUCCESS") {
		testServiceCreated = true
		LogMessage("SUCCESS", "Service Create", fmt.Sprintf("Created test service: %s", TEST_SERVICE_NAME))
		LogProcessExecution("sc.exe", cmdLine, 0, true, 0, "")
		Endpoint.Say("    [+] Test service created successfully")
		return nil
	}

	return fmt.Errorf("unexpected output: %s", output)
}

// stopTestService stops our test service
func stopTestService() error {
	if !testServiceCreated {
		return fmt.Errorf("test service was not created")
	}

	Endpoint.Say("  Stopping test service: %s", TEST_SERVICE_NAME)

	cmd := exec.Command("sc", "stop", TEST_SERVICE_NAME)
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Run()
	output := outputBuffer.String()

	cmdLine := fmt.Sprintf("sc stop %s", TEST_SERVICE_NAME)

	// Service might not be running (which is fine for our test)
	if strings.Contains(output, "1062") || strings.Contains(output, "has not been started") {
		LogMessage("INFO", "Service Stop", "Service was not running (expected for test service)")
		LogProcessExecution("sc.exe", cmdLine, 0, true, 0, "Service not running")
		return nil
	}

	if err != nil {
		if strings.Contains(output, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
			LogMessage("WARN", "Service Stop", "Access denied when stopping test service - possible EDR interference")
			LogProcessExecution("sc.exe", cmdLine, 0, false, 5, "Access denied")
			return fmt.Errorf("access denied")
		}
		LogMessage("ERROR", "Service Stop", fmt.Sprintf("Error: %v - %s", err, output))
		LogProcessExecution("sc.exe", cmdLine, 0, false, 1, err.Error())
		return err
	}

	LogMessage("SUCCESS", "Service Stop", "Test service stopped successfully")
	LogProcessExecution("sc.exe", cmdLine, 0, true, 0, "")
	Endpoint.Say("    [+] Test service stopped")
	return nil
}

// deleteTestService deletes our test service
func deleteTestService() error {
	if !testServiceCreated {
		return nil // Nothing to delete
	}

	Endpoint.Say("  Deleting test service: %s", TEST_SERVICE_NAME)

	cmd := exec.Command("sc", "delete", TEST_SERVICE_NAME)
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Run()
	output := outputBuffer.String()

	cmdLine := fmt.Sprintf("sc delete %s", TEST_SERVICE_NAME)

	if err != nil {
		LogMessage("WARN", "Service Delete", fmt.Sprintf("Error deleting service: %v - %s", err, output))
		LogProcessExecution("sc.exe", cmdLine, 0, false, 1, err.Error())
		return err
	}

	if strings.Contains(output, "SUCCESS") || strings.Contains(output, "[SC] DeleteService SUCCESS") {
		LogMessage("SUCCESS", "Service Delete", "Test service deleted successfully")
		LogProcessExecution("sc.exe", cmdLine, 0, true, 0, "")
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
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Run()
	output := outputBuffer.String()

	if err == nil || strings.Contains(output, "TASKKILL") {
		LogMessage("INFO", "Taskkill Check", "Taskkill utility accessible")
		LogProcessExecution("taskkill.exe", "taskkill /?", 0, true, 0, "")
		Endpoint.Say("    [+] Taskkill is accessible")
		return true
	}

	LogMessage("WARN", "Taskkill Check", fmt.Sprintf("Taskkill access check: %v", err))
	LogProcessExecution("taskkill.exe", "taskkill /?", 0, false, 1, err.Error())
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

	if err != nil {
		errStr := err.Error()
		output := outputBuffer.String()

		// Check for EDR blocking patterns
		if strings.Contains(errStr, "Access is denied") ||
			strings.Contains(output, "blocked") ||
			strings.Contains(errStr, "exit status 1") && duration < 2*time.Second {
			LogMessage("BLOCKED", "NetExec", "NetExec execution appears blocked by security controls")
			LogProcessExecution("nxc.exe", cmdLine, 0, false, 126, "Blocked by EDR")
			Endpoint.Say("    [!] NetExec blocked by security controls")
			return true, true
		}

		// Normal failure (auth failure expected)
		LogMessage("INFO", "NetExec", fmt.Sprintf("NetExec completed with error (expected): %v", err))
		LogProcessExecution("nxc.exe", cmdLine, 0, true, 0, "Auth failure expected")
		Endpoint.Say("    [+] NetExec executed (auth failure expected)")
		return true, false
	}

	LogMessage("SUCCESS", "NetExec", "NetExec executed successfully")
	LogProcessExecution("nxc.exe", cmdLine, 0, true, 0, "")
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

	// Remove test service binary
	testSvcPath := filepath.Join("c:\\F0", "test_svc.exe")
	if err := os.Remove(testSvcPath); err == nil {
		LogMessage("INFO", "Cleanup", "Removed test service binary")
		Endpoint.Say("  [+] Removed test service binary")
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
		Score:         8.0,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 2.5,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    0.5,
		},
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
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
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
		SaveLog(999, "Insufficient privileges - run as Administrator")
		Endpoint.Stop(999)
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
		SaveLog(999, err.Error())
		Endpoint.Stop(999)
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

	// Create test service
	if err := createTestService(); err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			LogMessage("BLOCKED", "Service Create", "Service creation blocked by EDR")
			anyBlocked = true
			Endpoint.Say("    [!] Service creation BLOCKED by security controls")
		} else {
			LogMessage("ERROR", "Service Create", err.Error())
		}
	} else {
		// Stop test service
		if err := stopTestService(); err != nil {
			if strings.Contains(err.Error(), "access denied") {
				LogMessage("BLOCKED", "Service Stop", "Service stop blocked by EDR")
				anyBlocked = true
				Endpoint.Say("    [!] Service stop BLOCKED by security controls")
			}
		} else {
			serviceOpsSuccess = true
		}

		// Delete test service
		deleteTestService()
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
		LogPhaseEnd(4, "blocked", "Taskkill access restricted")
		anyBlocked = true
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

	// Determine exit code
	if nxcBlocked {
		// NetExec was blocked - this is a strong protection indicator
		Endpoint.Say("\nRESULT: PROTECTED - NetExec blocked by security controls")
		SaveLog(126, "NetExec execution blocked by security controls")
		Endpoint.Stop(126)
	} else if anyBlocked && !serviceOpsSuccess {
		// Service operations blocked
		Endpoint.Say("\nRESULT: PROTECTED - Service operations blocked")
		SaveLog(126, "Service operations blocked by security controls")
		Endpoint.Stop(126)
	} else if serviceOpsSuccess {
		// Service operations succeeded
		Endpoint.Say("\nRESULT: UNPROTECTED - Service control operations succeeded")
		SaveLog(101, "System unprotected - service control operations succeeded")
		Endpoint.Stop(101)
	} else {
		// Partial protection
		Endpoint.Say("\nRESULT: PARTIAL PROTECTION - Some operations blocked")
		SaveLog(101, "Partial protection - some service operations succeeded")
		Endpoint.Stop(101)
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
			SaveLog(102, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(102)
	}
}
