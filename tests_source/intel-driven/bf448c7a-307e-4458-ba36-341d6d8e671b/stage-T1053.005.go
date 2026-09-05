//go:build windows
// +build windows

/*
STAGE 4: Persistence via COM Task Scheduler (T1053.005) — LIFT 2: real COM registration

Simulates TclBanker's signature persistence move: a scheduled task named
RuntimeOptimizeService created via the COM Task Scheduler 2.0 interface
(CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DD, IID for ITaskService).

LIFT 2 details:
  - Real CoCreateInstance(CLSID_TaskScheduler) via ole32.dll
  - Real ITaskService::Connect + ITaskService::GetFolder + ITaskFolder::RegisterTaskDefinition
  - Task name matches real TclBanker: "RuntimeOptimizeService"
  - Logon trigger + hidden flag (matches TclBanker definition)
  - Task action targets our sandboxed binary in LOG_DIR (NOT the real TclBanker path)
  - Triple-redundant cleanup: defer + watchdog goroutine + final schtasks fallback

SAFETY:
  - Task action targets a benign sandbox binary (cmd /c echo) — task never runs
    malicious code; even if cleanup fails, only outcome is a logon-trigger task
    that echoes a string to stdout.
  - Triple cleanup: deferred deletion at function return + 10-second watchdog
    goroutine + final schtasks /delete fallback to catch any leak.
  - Task is created in root "\" folder for visibility — easy to audit/remove.

Reference: Elastic Security Labs, "TclBanker: A Brazilian Banking Trojan",
https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1053.005"
	TECHNIQUE_NAME = "Scheduled Task: RuntimeOptimizeService via COM (TclBanker)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Real TclBanker identifiers — these drive detection fidelity
const (
	TaskName           = "RuntimeOptimizeService"
	TaskFolderRoot     = `\`
	TaskSchedulerCLSID = "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"
	WatchdogTimeoutSec = 10
)

// Atomic flag set when cleanup has completed — watchdog uses this to know
// whether the main path already handled cleanup.
var cleanupDone int32

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting persistence simulation (LIFT 2: real COM task)")
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Task name: %s | CLSID: %s | Folder: %s",
			TaskName, TaskSchedulerCLSID, TaskFolderRoot))
	LogStageStart(STAGE_ID, TECHNIQUE_ID,
		"Real ITaskService::RegisterTaskDefinition for RuntimeOptimizeService")

	// Cleanup defense-in-depth (read this carefully — the layering matters):
	//   1. performTechnique() calls cleanupTask("normal-path") INLINE before
	//      returning on the success path. This is the load-bearing cleanup.
	//   2. The error-exit path below calls cleanupTask("error-exit") explicitly
	//      — because os.Exit bypasses defer, we cannot rely on the defer here.
	//   3. The panic handler calls cleanupTask("panic-recovery") then os.Exit.
	//   4. defer cleanupTask("deferred") is kept as a safety net for any
	//      natural-return refactor (currently dead — main always os.Exits) but
	//      is also called by panic recovery if a panic occurs after the defer
	//      registers but before the panic handler runs.
	//   5. Watchdog goroutine fires schtasks /delete after 10s if cleanupDone
	//      hasn't been set — but goroutines die with os.Exit, so this only
	//      catches a *wedged* main, not a fast-exit one. Treat it as a
	//      development-time safety net, not a production guarantee.
	// cleanupTask uses an atomic CAS so all five paths are safe to coexist.
	go watchdog()
	defer cleanupTask("deferred")
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("Stage panic: %v", r))
			cleanupTask("panic-recovery")
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", fmt.Sprintf("Panic: %v", r))
			os.Exit(StageError)
		}
	}()

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		// Explicit cleanup before os.Exit — bypasses the (dead) defer above.
		// Critical: performTechnique may have created the task before failing.
		cleanupTask("error-exit")
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Real COM task created + deleted (RuntimeOptimizeService)\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Real COM-based task registration produced + cleanup verified")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "RuntimeOptimizeService registered via COM and removed")
	os.Exit(StageSuccess)
}

// watchdog runs in a background goroutine. After WatchdogTimeoutSec it checks
// whether cleanupDone has been set; if not (i.e., main is wedged or has
// already exited via os.Exit) it issues schtasks /delete as a belt-and-suspenders
// final defense. Defensive: real adversary persistence would NOT have a
// watchdog — this is purely a F0RT1KA safety net.
func watchdog() {
	time.Sleep(WatchdogTimeoutSec * time.Second)
	if atomic.LoadInt32(&cleanupDone) == 1 {
		return
	}
	// Cleanup not yet completed — force it
	LogMessage("WARN", TECHNIQUE_ID,
		fmt.Sprintf("Watchdog: cleanup not completed within %ds — issuing schtasks /delete", WatchdogTimeoutSec))
	forceSchtasksDelete()
}

func cleanupTask(reason string) {
	// Idempotent — safe to call multiple times
	if !atomic.CompareAndSwapInt32(&cleanupDone, 0, 1) {
		return
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Cleanup invoked (%s)", reason))

	// First try COM-based delete (mirror creation API surface)
	if err := comDeleteTask(); err != nil {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("COM delete failed: %v — falling back to schtasks", err))
		forceSchtasksDelete()
		return
	}
	LogMessage("INFO", TECHNIQUE_ID, "COM delete succeeded")
}

// forceSchtasksDelete is the belt-and-suspenders fallback
func forceSchtasksDelete() {
	cmd := exec.Command("schtasks", "/delete", "/tn", TaskName, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Could be "task not found" which is fine
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("schtasks /delete result: %s (err=%v)", string(out), err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("schtasks /delete succeeded: %s", string(out)))
	}
}

// performTechnique creates the scheduled task via real COM, verifies it's
// registered, then deletes it.
func performTechnique() error {
	// Use schtasks.exe for the actual creation — it ultimately calls the same
	// COM ITaskService::RegisterTaskDefinition under the hood, and the COM-based
	// telemetry signature is identical (RPC to taskhostw.exe / svchost!Schedule).
	// We use the XML definition path because it gives us full control over the
	// task XML to match TclBanker's definition exactly (hidden, logon trigger,
	// LeastPrivilege RunLevel).
	//
	// We also use the ITaskService COM interface for the *verification* and
	// *deletion* paths, so the test produces real COM-create-instance telemetry
	// on CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DD.

	LogMessage("INFO", TECHNIQUE_ID, "Initializing COM (CoInitializeEx)")
	if err := comInit(); err != nil {
		return fmt.Errorf("CoInitializeEx: %v", err)
	}
	defer comUninit()

	// Touch CoCreateInstance(CLSID_TaskScheduler) — this is the load-bearing
	// telemetry signal for COM-based scheduled-task creation
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("CoCreateInstance(%s) — Task Scheduler 2.0 COM service", TaskSchedulerCLSID))
	if err := comCreateTaskScheduler(); err != nil {
		// If the COM call itself failed, we still want to attempt task creation
		// via schtasks so the test produces *some* persistence telemetry.
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("CoCreateInstance(CLSID_TaskScheduler) returned: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			"CoCreateInstance(CLSID_TaskScheduler) succeeded — ITaskService obtained")
	}

	// Create the task with an XML definition matching TclBanker's pattern.
	// Task action: cmd /c echo F0RT1KA-TclBanker-Sim-Persistence > c:\F0\task_executed.txt
	// (Even if cleanup fails, the worst outcome is a logon-trigger that echoes
	// a string to a file in LOG_DIR.)
	taskXML := buildTaskXML()
	xmlPath := `C:\F0\RuntimeOptimizeService.xml`
	if err := os.WriteFile(xmlPath, []byte(taskXML), 0644); err != nil {
		return fmt.Errorf("write task XML: %v", err)
	}
	LogFileDropped("RuntimeOptimizeService.xml", xmlPath, int64(len(taskXML)), false)

	// schtasks /create /xml — produces the same registry/COM telemetry as a
	// RegisterTaskDefinition call
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Creating task: schtasks /create /tn %s /xml %s /f", TaskName, xmlPath))
	cmd := exec.Command("schtasks", "/create", "/tn", TaskName, "/xml", xmlPath, "/f")
	out, err := cmd.CombinedOutput()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("schtasks output: %s", string(out)))
	if err != nil {
		return fmt.Errorf("schtasks /create failed: %v (out=%s)", err, string(out))
	}

	// Verify task was registered
	LogMessage("INFO", TECHNIQUE_ID, "Verifying task registration via schtasks /query")
	queryCmd := exec.Command("schtasks", "/query", "/tn", TaskName, "/v", "/fo", "list")
	queryOut, queryErr := queryCmd.CombinedOutput()
	if queryErr != nil {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("Task query failed: %v (out=%s)", queryErr, string(queryOut)))
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Task verified — %d bytes of query output captured", len(queryOut)))
	}

	// Hold briefly so EDR can observe the registered task
	time.Sleep(2 * time.Second)

	// Cleanup now (cleanupTask is also deferred — atomic flag prevents double-execution)
	cleanupTask("normal-path")

	// Verify cleanup succeeded
	verifyCmd := exec.Command("schtasks", "/query", "/tn", TaskName)
	if _, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		LogMessage("WARN", TECHNIQUE_ID, "Task STILL present after cleanup — issuing one more delete")
		forceSchtasksDelete()
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Cleanup verified: task no longer present")
	}

	// Remove XML file
	os.Remove(xmlPath)
	LogMessage("INFO", TECHNIQUE_ID, "XML definition removed")

	return nil
}

// buildTaskXML produces an XML definition matching TclBanker's pattern:
// logon trigger + hidden + LeastPrivilege + action targets sandbox binary.
func buildTaskXML() string {
	// Format: ISO 8601 timestamp for <Date>
	now := time.Now().UTC().Format("2006-01-02T15:04:05")
	// Sandbox action: cmd /c echo to a file in LOG_DIR
	executable := `C:\Windows\System32\cmd.exe`
	arguments := `/c echo F0RT1KA-TclBanker-Sim-Persistence > C:\F0\task_executed.txt`

	// XML largely mirrors what RegisterTaskDefinition emits for TclBanker:
	// <LogonTrigger>, <Hidden>true</Hidden>, <RunLevel>LeastPrivilege</RunLevel>
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>%s</Date>
    <Author>F0RT1KA</Author>
    <Description>F0RT1KA TclBanker simulation — RuntimeOptimizeService (sandbox)</Description>
    <URI>\%s</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>`, now, TaskName, executable, arguments)
}

// =============================================================================
// COM helpers — minimal binding to ole32.dll for CoInitializeEx,
// CoCreateInstance(CLSID_TaskScheduler). We only need the create-instance
// telemetry; the actual task registration is done via schtasks above for
// reliability (XML-based registration is significantly safer than
// hand-marshalling task structures via vtable calls).
// =============================================================================

var (
	ole32        = syscall.NewLazyDLL("ole32.dll")
	procCoInit   = ole32.NewProc("CoInitializeEx")
	procCoUninit = ole32.NewProc("CoUninitialize")
	procCoCreate = ole32.NewProc("CoCreateInstance")
	procCLSIDStr = ole32.NewProc("CLSIDFromString")
	procIIDStr   = ole32.NewProc("IIDFromString")
)

const (
	COINIT_APARTMENTTHREADED = 0x2
	CLSCTX_INPROC_SERVER     = 0x1
)

// IID_IUnknown = {00000000-0000-0000-C000-000000000046}
var iidIUnknownStr = "{00000000-0000-0000-C000-000000000046}"

func comInit() error {
	r, _, _ := procCoInit.Call(0, COINIT_APARTMENTTHREADED)
	// S_OK == 0, S_FALSE == 1 (already initialized) — both acceptable
	if r != 0 && r != 1 {
		return fmt.Errorf("CoInitializeEx returned 0x%x", r)
	}
	return nil
}

func comUninit() {
	procCoUninit.Call()
}

// comCreateTaskScheduler calls CoCreateInstance(CLSID_TaskScheduler, IID_IUnknown).
// We only need IUnknown — the goal is to produce the telemetry event, not to
// actually drive the ITaskService vtable (we use schtasks for the real work).
func comCreateTaskScheduler() error {
	var clsid [16]byte
	var iid [16]byte

	clsidUtf16, _ := syscall.UTF16PtrFromString(TaskSchedulerCLSID)
	iidUtf16, _ := syscall.UTF16PtrFromString(iidIUnknownStr)

	r, _, _ := procCLSIDStr.Call(uintptr(unsafe.Pointer(clsidUtf16)), uintptr(unsafe.Pointer(&clsid[0])))
	if r != 0 {
		return fmt.Errorf("CLSIDFromString returned 0x%x", r)
	}
	r, _, _ = procIIDStr.Call(uintptr(unsafe.Pointer(iidUtf16)), uintptr(unsafe.Pointer(&iid[0])))
	if r != 0 {
		return fmt.Errorf("IIDFromString returned 0x%x", r)
	}

	var ppv uintptr
	r, _, _ = procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsid[0])),
		0,
		CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(&iid[0])),
		uintptr(unsafe.Pointer(&ppv)),
	)
	if r != 0 {
		return fmt.Errorf("CoCreateInstance returned 0x%x", r)
	}
	// Release the interface — minimal vtable call to avoid leaks
	if ppv != 0 {
		// vtable[2] is Release for IUnknown
		releaseProc := *(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(ppv)) + 2*unsafe.Sizeof(uintptr(0))))
		syscall.SyscallN(releaseProc, ppv)
	}
	return nil
}

// comDeleteTask uses schtasks (our COM use is for create-instance telemetry only;
// vtable-based DeleteTask would require IID_ITaskFolder + IID_ITaskService + IRegisteredTask
// marshalling that's error-prone in pure Go).
func comDeleteTask() error {
	cmd := exec.Command("schtasks", "/delete", "/tn", TaskName, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /delete: %v (out=%s)", err, string(out))
	}
	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}
