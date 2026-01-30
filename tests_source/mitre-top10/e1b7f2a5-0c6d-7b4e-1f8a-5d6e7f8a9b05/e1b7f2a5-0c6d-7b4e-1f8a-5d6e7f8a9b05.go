//go:build windows
// +build windows

/*
ID: e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
NAME: System Recovery Inhibition (Safe Mode)
TECHNIQUES: T1490
TACTICS: impact
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: impact
TAGS: recovery-inhibition, shadow-copy, vssadmin, bcdedit
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
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
	TEST_UUID  = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
	TEST_NAME  = "System Recovery Inhibition (Safe Mode)"
	TARGET_DIR = "c:\\F0"
)

// RecoveryToolCheck represents the result of checking a recovery tool
type RecoveryToolCheck struct {
	ToolName    string
	ToolPath    string
	Accessible  bool
	QueryOutput string
	Blocked     bool
	ErrorMsg    string
}

// DestructiveCommand represents a command that ransomware WOULD execute
// These are logged but NEVER actually executed
type DestructiveCommand struct {
	Name        string
	Command     string
	Description string
	Impact      string
}

// getDestructiveCommands returns the list of commands that ransomware typically executes
// CRITICAL: These commands are for DOCUMENTATION ONLY - never execute them
func getDestructiveCommands() []DestructiveCommand {
	return []DestructiveCommand{
		{
			Name:        "Delete Shadow Copies",
			Command:     "vssadmin delete shadows /all /quiet",
			Description: "Deletes all Volume Shadow Copies on the system",
			Impact:      "Prevents restoration of files from previous versions",
		},
		{
			Name:        "Delete Shadow Copies (Alt)",
			Command:     "vssadmin delete shadows /for=c: /quiet",
			Description: "Deletes shadow copies for C: drive specifically",
			Impact:      "Targets primary system/user data drive",
		},
		{
			Name:        "Disable Recovery Mode",
			Command:     "bcdedit /set {default} recoveryenabled No",
			Description: "Disables Windows Recovery Environment",
			Impact:      "Prevents booting into recovery mode after attack",
		},
		{
			Name:        "Disable Boot Status Policy",
			Command:     "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
			Description: "Ignores boot failures that would trigger recovery",
			Impact:      "System won't auto-recover on boot failures",
		},
		{
			Name:        "Delete System State Backup",
			Command:     "wbadmin delete systemstatebackup -keepVersions:0",
			Description: "Deletes all system state backups",
			Impact:      "Removes system restore points and backups",
		},
		{
			Name:        "Delete Backup Catalog",
			Command:     "wbadmin delete catalog -quiet",
			Description: "Deletes the Windows backup catalog",
			Impact:      "Removes ability to restore from Windows Backup",
		},
		{
			Name:        "WMI Shadow Delete",
			Command:     `wmic shadowcopy delete /nointeractive`,
			Description: "Uses WMI to delete shadow copies",
			Impact:      "Alternative method used by some ransomware",
		},
		{
			Name:        "Resize Shadow Storage",
			Command:     "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
			Description: "Resizes shadow storage to minimum",
			Impact:      "Limits number of shadow copies that can be stored",
		},
	}
}

// checkToolAccessibility checks if a recovery tool is accessible
// This performs READ-ONLY operations only
func checkToolAccessibility(toolName, toolPath string) RecoveryToolCheck {
	result := RecoveryToolCheck{
		ToolName:   toolName,
		ToolPath:   toolPath,
		Accessible: false,
		Blocked:    false,
	}

	// Check if the tool exists
	if _, err := os.Stat(toolPath); os.IsNotExist(err) {
		result.ErrorMsg = "Tool not found at path"
		return result
	}

	// Tool exists
	result.Accessible = true
	return result
}

// executeReadOnlyQuery executes a read-only query command
// Returns: output, success, blocked, errorMsg
func executeReadOnlyQuery(toolName, toolPath string, args []string) (string, bool, bool, string) {
	Endpoint.Say("  Executing read-only query: %s %s", toolPath, strings.Join(args, " "))

	cmd := exec.Command(toolPath, args...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	cmdLine := fmt.Sprintf("%s %s", toolPath, strings.Join(args, " "))

	if err != nil {
		errorStr := err.Error()

		// Check for EDR/AV blocking indicators
		if strings.Contains(outputStr, "blocked") ||
			strings.Contains(outputStr, "denied") ||
			strings.Contains(outputStr, "prevented") ||
			strings.Contains(errorStr, "Access is denied") ||
			strings.Contains(errorStr, "operation requires elevation") {
			LogProcessExecution(toolName, cmdLine, pid, false, 126, "Blocked by security controls")
			return outputStr, false, true, fmt.Sprintf("Blocked: %s", errorStr)
		}

		// Non-blocking error
		LogProcessExecution(toolName, cmdLine, pid, false, 1, errorStr)
		return outputStr, false, false, errorStr
	}

	LogProcessExecution(toolName, cmdLine, pid, true, 0, "")
	return outputStr, true, false, ""
}

// checkVssadmin checks vssadmin.exe accessibility and executes read-only query
func checkVssadmin() RecoveryToolCheck {
	result := checkToolAccessibility("vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe")

	if !result.Accessible {
		return result
	}

	// Execute read-only query: list shadows
	output, success, blocked, errMsg := executeReadOnlyQuery(
		"vssadmin.exe",
		"C:\\Windows\\System32\\vssadmin.exe",
		[]string{"list", "shadows"},
	)

	result.QueryOutput = output
	result.Blocked = blocked

	if blocked {
		result.ErrorMsg = errMsg
		LogMessage("INFO", "vssadmin Check", "Read-only query was BLOCKED by EDR")
	} else if success {
		LogMessage("INFO", "vssadmin Check", "Read-only query executed successfully")
	} else {
		result.ErrorMsg = errMsg
		LogMessage("WARN", "vssadmin Check", fmt.Sprintf("Query failed: %s", errMsg))
	}

	return result
}

// checkBcdedit checks bcdedit.exe accessibility and executes read-only query
func checkBcdedit() RecoveryToolCheck {
	result := checkToolAccessibility("bcdedit.exe", "C:\\Windows\\System32\\bcdedit.exe")

	if !result.Accessible {
		return result
	}

	// Execute read-only query: enum boot config
	output, success, blocked, errMsg := executeReadOnlyQuery(
		"bcdedit.exe",
		"C:\\Windows\\System32\\bcdedit.exe",
		[]string{"/enum"},
	)

	result.QueryOutput = output
	result.Blocked = blocked

	if blocked {
		result.ErrorMsg = errMsg
		LogMessage("INFO", "bcdedit Check", "Read-only query was BLOCKED by EDR")
	} else if success {
		LogMessage("INFO", "bcdedit Check", "Read-only query executed successfully")
	} else {
		result.ErrorMsg = errMsg
		LogMessage("WARN", "bcdedit Check", fmt.Sprintf("Query failed: %s", errMsg))
	}

	return result
}

// checkWbadmin checks wbadmin.exe accessibility
func checkWbadmin() RecoveryToolCheck {
	result := checkToolAccessibility("wbadmin.exe", "C:\\Windows\\System32\\wbadmin.exe")

	if !result.Accessible {
		return result
	}

	// Execute read-only query: get status
	// Note: wbadmin status might require elevation, using get versions as alternative
	output, success, blocked, errMsg := executeReadOnlyQuery(
		"wbadmin.exe",
		"C:\\Windows\\System32\\wbadmin.exe",
		[]string{"get", "versions"},
	)

	result.QueryOutput = output
	result.Blocked = blocked

	if blocked {
		result.ErrorMsg = errMsg
		LogMessage("INFO", "wbadmin Check", "Read-only query was BLOCKED by EDR")
	} else if success {
		LogMessage("INFO", "wbadmin Check", "Read-only query executed successfully")
	} else {
		result.ErrorMsg = errMsg
		LogMessage("WARN", "wbadmin Check", fmt.Sprintf("Query failed: %s", errMsg))
	}

	return result
}

// isRunningAsAdmin checks if the current process has administrator privileges
func isRunningAsAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// writeTestReport writes a comprehensive test report to c:\F0
func writeTestReport(vss, bcd, wba RecoveryToolCheck, anyBlocked bool) {
	reportPath := filepath.Join(TARGET_DIR, "recovery_inhibition_report.txt")

	destructiveCommands := getDestructiveCommands()

	report := fmt.Sprintf(`System Recovery Inhibition (Safe Mode) Test Report
===================================================
Test ID: %s
Timestamp: %s
MITRE ATT&CK: T1490 (Inhibit System Recovery)

IMPORTANT: This is a SAFE MODE test - NO destructive operations performed
All checks are READ-ONLY

=== Tool Accessibility Check ===

1. vssadmin.exe (Volume Shadow Copy Administration)
   Path: C:\Windows\System32\vssadmin.exe
   Accessible: %v
   Query Blocked: %v
   Error: %s
   Query Output (truncated):
   %s

2. bcdedit.exe (Boot Configuration Data Editor)
   Path: C:\Windows\System32\bcdedit.exe
   Accessible: %v
   Query Blocked: %v
   Error: %s
   Query Output (truncated):
   %s

3. wbadmin.exe (Windows Backup Administration)
   Path: C:\Windows\System32\wbadmin.exe
   Accessible: %v
   Query Blocked: %v
   Error: %s
   Query Output (truncated):
   %s

=== Commands Ransomware WOULD Execute (NOT EXECUTED) ===
The following commands are what ransomware typically executes during T1490.
These were LOGGED but NOT EXECUTED for safety.

`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		vss.Accessible, vss.Blocked, vss.ErrorMsg, truncateOutput(vss.QueryOutput, 500),
		bcd.Accessible, bcd.Blocked, bcd.ErrorMsg, truncateOutput(bcd.QueryOutput, 500),
		wba.Accessible, wba.Blocked, wba.ErrorMsg, truncateOutput(wba.QueryOutput, 500),
	)

	for i, cmd := range destructiveCommands {
		report += fmt.Sprintf(`%d. %s
   Command: %s
   Description: %s
   Impact: %s

`, i+1, cmd.Name, cmd.Command, cmd.Description, cmd.Impact)
	}

	report += fmt.Sprintf(`
=== Assessment ===
Any Read-Only Queries Blocked: %v
Tools Accessible: vssadmin=%v, bcdedit=%v, wbadmin=%v

%s

=== Detection Opportunities for Defenders ===
1. Process creation for vssadmin.exe, bcdedit.exe, wbadmin.exe
2. Command line arguments containing "delete", "shadows", "recoveryenabled"
3. WMI queries targeting Win32_ShadowCopy
4. Registry modifications to BCD store
5. Event logs: VSS events (8193, 8194), bcdedit changes

=== End of Report ===
`,
		anyBlocked,
		vss.Accessible, bcd.Accessible, wba.Accessible,
		getAssessmentText(vss, bcd, wba, anyBlocked),
	)

	os.WriteFile(reportPath, []byte(report), 0644)
	LogFileDropped("recovery_inhibition_report.txt", reportPath, int64(len(report)), false)
	Endpoint.Say("  [+] Test report saved to: %s", reportPath)
}

// truncateOutput truncates output string to maxLen
func truncateOutput(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "\n   ... (truncated)"
	}
	return s
}

// getAssessmentText generates assessment based on results
func getAssessmentText(vss, bcd, wba RecoveryToolCheck, anyBlocked bool) string {
	if anyBlocked {
		return "PROTECTED: EDR blocked read-only queries to recovery tools.\nThis indicates active protection against T1490 reconnaissance."
	}

	allAccessible := vss.Accessible && bcd.Accessible && wba.Accessible
	if allAccessible {
		return "VULNERABLE: All recovery tools are accessible and queryable.\nRansomware could execute T1490 techniques to inhibit system recovery."
	}

	return "PARTIAL: Some recovery tools are not accessible (may indicate missing features or permissions)."
}

// logDestructiveCommands logs the commands that WOULD be executed by ransomware
// CRITICAL: These are for documentation only - never executed
func logDestructiveCommands() {
	Endpoint.Say("\n  Documenting destructive commands (NOT EXECUTING):")

	for _, cmd := range getDestructiveCommands() {
		LogMessage("INFO", "Destructive Command (NOT EXECUTED)", fmt.Sprintf(
			"Command: %s | Description: %s | Impact: %s",
			cmd.Command, cmd.Description, cmd.Impact))
		Endpoint.Say("    [DOC] %s: %s", cmd.Name, cmd.Command)
	}
}

// createMarkerFile creates a marker file to track test execution
func createMarkerFile(name, content string) {
	markerPath := filepath.Join(TARGET_DIR, name)
	if err := os.WriteFile(markerPath, []byte(content), 0644); err == nil {
		LogFileDropped(name, markerPath, int64(len(content)), false)
	}
}

func test() {
	// Results tracking
	var vssResult, bcdResult, wbaResult RecoveryToolCheck
	anyBlocked := false
	allAccessible := true

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

	// Check admin privileges
	isAdmin := isRunningAsAdmin()
	if !isAdmin {
		Endpoint.Say("  [!] WARNING: Not running as administrator")
		Endpoint.Say("      Some queries may fail due to insufficient privileges")
		LogMessage("WARN", "Initialization", "Not running as administrator - some checks may fail")
	} else {
		Endpoint.Say("  [+] Running as administrator")
		LogMessage("INFO", "Initialization", "Running with administrator privileges")
	}

	// Create start marker
	createMarkerFile("t1490_test_started.txt",
		fmt.Sprintf("T1490 Safe Mode Test Started\nTimestamp: %s\n", time.Now().Format(time.RFC3339)))

	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Check vssadmin.exe
	LogPhaseStart(2, "vssadmin Check")
	Endpoint.Say("\nPhase 2: Checking vssadmin.exe (Volume Shadow Copy)")
	Endpoint.Say("  Purpose: Test read-only query 'vssadmin list shadows'")

	vssResult = checkVssadmin()

	if vssResult.Blocked {
		Endpoint.Say("  [BLOCKED] vssadmin read-only query was blocked by EDR")
		anyBlocked = true
		LogPhaseEnd(1, "blocked", "vssadmin query blocked by security controls")
	} else if vssResult.Accessible {
		Endpoint.Say("  [ACCESSIBLE] vssadmin.exe is accessible and queryable")
		LogPhaseEnd(1, "success", "vssadmin accessible and queryable")
	} else {
		Endpoint.Say("  [ERROR] vssadmin check failed: %s", vssResult.ErrorMsg)
		allAccessible = false
		LogPhaseEnd(1, "failed", vssResult.ErrorMsg)
	}

	Endpoint.Wait(2)

	// Phase 3: Check bcdedit.exe
	LogPhaseStart(3, "bcdedit Check")
	Endpoint.Say("\nPhase 3: Checking bcdedit.exe (Boot Configuration)")
	Endpoint.Say("  Purpose: Test read-only query 'bcdedit /enum'")

	bcdResult = checkBcdedit()

	if bcdResult.Blocked {
		Endpoint.Say("  [BLOCKED] bcdedit read-only query was blocked by EDR")
		anyBlocked = true
		LogPhaseEnd(2, "blocked", "bcdedit query blocked by security controls")
	} else if bcdResult.Accessible {
		Endpoint.Say("  [ACCESSIBLE] bcdedit.exe is accessible and queryable")
		LogPhaseEnd(2, "success", "bcdedit accessible and queryable")
	} else {
		Endpoint.Say("  [ERROR] bcdedit check failed: %s", bcdResult.ErrorMsg)
		allAccessible = false
		LogPhaseEnd(2, "failed", bcdResult.ErrorMsg)
	}

	Endpoint.Wait(2)

	// Phase 4: Check wbadmin.exe
	LogPhaseStart(4, "wbadmin Check")
	Endpoint.Say("\nPhase 4: Checking wbadmin.exe (Windows Backup)")
	Endpoint.Say("  Purpose: Test read-only query 'wbadmin get versions'")

	wbaResult = checkWbadmin()

	if wbaResult.Blocked {
		Endpoint.Say("  [BLOCKED] wbadmin read-only query was blocked by EDR")
		anyBlocked = true
		LogPhaseEnd(3, "blocked", "wbadmin query blocked by security controls")
	} else if wbaResult.Accessible {
		Endpoint.Say("  [ACCESSIBLE] wbadmin.exe is accessible and queryable")
		LogPhaseEnd(3, "success", "wbadmin accessible and queryable")
	} else {
		Endpoint.Say("  [ERROR] wbadmin check failed: %s", wbaResult.ErrorMsg)
		allAccessible = false
		LogPhaseEnd(3, "failed", wbaResult.ErrorMsg)
	}

	Endpoint.Wait(2)

	// Phase 5: Document Destructive Commands (NOT EXECUTED)
	LogPhaseStart(5, "Destructive Command Documentation")
	Endpoint.Say("\nPhase 5: Documenting ransomware commands (SAFE - NOT EXECUTING)")
	Endpoint.Say("  These commands are what ransomware WOULD execute for T1490")

	logDestructiveCommands()

	LogPhaseEnd(4, "success", "Destructive commands documented for reference")

	// Phase 6: Final Assessment
	LogPhaseStart(6, "Final Assessment")
	Endpoint.Say("\nPhase 6: Final assessment and report generation")

	// Write comprehensive report
	writeTestReport(vssResult, bcdResult, wbaResult, anyBlocked)

	// Create completion marker
	createMarkerFile("t1490_test_completed.txt",
		fmt.Sprintf("T1490 Safe Mode Test Completed\nTimestamp: %s\nBlocked: %v\n",
			time.Now().Format(time.RFC3339), anyBlocked))

	LogPhaseEnd(5, "success", "Assessment complete")

	// Final result output
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("MITRE ATT&CK: T1490 (Inhibit System Recovery)")
	Endpoint.Say("Mode: SAFE (Read-Only Checks Only)")
	Endpoint.Say("")
	Endpoint.Say("Tool Accessibility:")
	Endpoint.Say("  - vssadmin.exe: Accessible=%v, Blocked=%v", vssResult.Accessible, vssResult.Blocked)
	Endpoint.Say("  - bcdedit.exe:  Accessible=%v, Blocked=%v", bcdResult.Accessible, bcdResult.Blocked)
	Endpoint.Say("  - wbadmin.exe:  Accessible=%v, Blocked=%v", wbaResult.Accessible, wbaResult.Blocked)
	Endpoint.Say("")
	Endpoint.Say("Any Queries Blocked: %v", anyBlocked)

	// Exit code determination
	if anyBlocked {
		// EDR blocked at least one read-only query - system is protected
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked read-only queries to recovery tools")
		Endpoint.Say("Exit Code: 126 (Execution Prevented)")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - EDR blocked recovery tool queries")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: Read-only queries blocked"))
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if allAccessible && isAdmin {
		// All tools accessible with admin - system is vulnerable to T1490
		Endpoint.Say("\n[RESULT] VULNERABLE - All recovery tools accessible")
		Endpoint.Say("         Ransomware could execute T1490 to inhibit system recovery")
		Endpoint.Say("Exit Code: 101 (Unprotected)")
		LogMessage("CRITICAL", "Final Assessment", "System VULNERABLE - recovery tools accessible")
		SaveLog(Endpoint.Unprotected, "Vulnerable: All recovery tools accessible for T1490")
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else if !isAdmin {
		// Not admin - can't properly assess
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Administrator privileges required")
		Endpoint.Say("         Re-run test with elevated privileges for accurate assessment")
		Endpoint.Say("Exit Code: 999 (Test Error - Prerequisites)")
		LogMessage("WARN", "Final Assessment", "Inconclusive - administrator privileges required")
		SaveLog(999, "Prerequisites not met: Administrator privileges required")
		Endpoint.Stop(999) // Exit 999
	} else {
		// Some tools not accessible but not blocked - inconclusive
		Endpoint.Say("\n[RESULT] PARTIAL - Some recovery tools not accessible")
		Endpoint.Say("Exit Code: 101 (Unprotected - accessible tools not protected)")
		LogMessage("WARN", "Final Assessment", "Partial - some tools accessible without protection")
		SaveLog(Endpoint.Unprotected, "Partial: Some recovery tools accessible without EDR protection")
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	}
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1490 (Inhibit System Recovery)")
	Endpoint.Say("")
	Endpoint.Say("!!! SAFE MODE TEST !!!")
	Endpoint.Say("This test performs READ-ONLY checks only")
	Endpoint.Say("NO destructive operations will be executed")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "impact",
		Severity:   "critical",
		Techniques: []string{"T1490"},
		Tactics:    []string{"impact"},
		Score:      8.0,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Tests actual tools used by ransomware
			TechnicalSophistication: 1.5, // Read-only checks (intentionally limited)
			SafetyMechanisms:        2.0, // Full safety - no destructive operations
			DetectionOpportunities:  1.0, // Multiple detection points documented
			LoggingObservability:    1.0, // Comprehensive logging
		},
		Tags: []string{"ransomware", "recovery-inhibition", "vssadmin", "bcdedit", "wbadmin", "safe-mode", "native"},
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

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			if globalLog != nil {
				LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
				SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			}
		}
	}()

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
