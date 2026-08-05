//go:build windows
// +build windows

/*
STAGE 3: WinDefend Service-Stop Notification Subscription (T1562.001)

Mirrors UnDefend's WDKillerThread setup phase:
  - OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT)
  - OpenService(scm, "WinDefend", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
  - QueryServiceStatus to confirm the service is RUNNING
  - NotifyServiceStatusChangeW(hsvc, SERVICE_NOTIFY_STOPPED, &notify)

The real UnDefend then blocks on SleepEx(INFINITE, TRUE) waiting for the
callback to fire during a major platform update. This simulation registers
the subscription to exercise the detection surface, then returns without
calling SleepEx so the stage completes quickly and cleanly.

The WinDefend service is never stopped, no locks are taken on mpavbase.vdm,
and no callback is ever allowed to fire (no alertable wait is performed,
so Windows will never deliver the callback).

Safety boundary:
  - This stage only reads service state and registers a subscription.
  - The subscription is implicitly torn down when the service handle closes
    at function return.
  - No ExitProcess, no sleep loop, no kernel-object lifetime outliving the stage.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID      = "6a2351ac-654a-4112-b378-e6919beef70d"
	TECHNIQUE_ID   = "T1562.001"
	TECHNIQUE_NAME = "WinDefend Service-Stop Notification Subscription"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting WinDefend service-notification subscription simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	// NotifyServiceStatusChangeW on WinDefend requires SYSTEM context or SeServiceLogonRight.
	// Under a non-elevated user the API call will fail with access denied, which the
	// classifyError() mapping would promote to StageBlocked — a false positive that
	// inflates the exit-code roll-up. Detect and skip cleanly instead.
	if !isSystemContext() {
		LogMessage("INFO", TECHNIQUE_ID, "prerequisite-not-met: NotifyServiceStatusChangeW requires SYSTEM context")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "skipped", "requires SYSTEM context")
		os.Exit(0)
	}

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Subscription reported a condition: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Subscription condition: %v", err))

		code := classifyError(err)
		if code == StageBlocked || code == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(code)
	}

	fmt.Printf("[STAGE %s] Service-notification subscription registered and torn down cleanly\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "NotifyServiceStatusChangeW subscription on WinDefend executed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"Service-notification primitive executed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: OpenSCManager with minimum rights (SC_MANAGER_CONNECT only)
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	LogMessage("INFO", TECHNIQUE_ID, "OpenSCManager(SC_MANAGER_CONNECT) succeeded")

	// Step 2: OpenService on WinDefend with SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG
	// (same access mask UnDefend uses).
	svcName, err := syscall.UTF16PtrFromString("WinDefend")
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %v", err)
	}
	svc, err := windows.OpenService(scm, svcName,
		windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return fmt.Errorf("OpenService WinDefend: %w", err)
	}
	defer windows.CloseServiceHandle(svc)
	LogMessage("INFO", TECHNIQUE_ID,
		"OpenService(WinDefend, SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG) succeeded")

	// Step 3: QueryServiceStatus — same gating check as UnDefend's WDKillerThread.
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(svc, &status); err != nil {
		return fmt.Errorf("QueryServiceStatus: %w", err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("WinDefend service state: %d (RUNNING=%d, STOPPED=%d)",
			status.CurrentState, windows.SERVICE_RUNNING, windows.SERVICE_STOPPED))

	if status.CurrentState != windows.SERVICE_RUNNING {
		// UnDefend exits here — we also treat this as prerequisite miss
		// (neutral wording, not EDR block).
		return fmt.Errorf("WinDefend not in RUNNING state (state=%d); subscription skipped",
			status.CurrentState)
	}

	// Step 4: NotifyServiceStatusChangeW(SERVICE_NOTIFY_STOPPED).
	// Windows requires a NON-NULL function pointer for NotifyCallback —
	// passing 0 returns ERROR_INVALID_PARAMETER. We provide a stub that
	// will never actually fire because we don't issue SleepEx (alertable
	// wait). The subscription is torn down when svc closes at function
	// return. (Bug surfaced 2026-04-25 lab run: stage exited 999 because
	// of the null-pointer check in NotifyServiceStatusChangeW.)
	notify := windows.SERVICE_NOTIFY{
		Version:        windows.SERVICE_NOTIFY_STATUS_CHANGE,
		NotifyCallback: notifyCallbackStubPtr,
		Context:        uintptr(unsafe.Pointer(&notifyContextMarker)),
	}

	err = windows.NotifyServiceStatusChange(svc, windows.SERVICE_NOTIFY_STOPPED, &notify)
	if err != nil {
		return fmt.Errorf("NotifyServiceStatusChangeW: %w", err)
	}
	LogMessage("SUCCESS", TECHNIQUE_ID,
		"NotifyServiceStatusChangeW(SERVICE_NOTIFY_STOPPED) subscription registered")
	LogMessage("INFO", TECHNIQUE_ID,
		"Subscription will be torn down at function return (no SleepEx / alertable wait)")

	return nil
}

// notifyContextMarker is a stable address so the Context field of SERVICE_NOTIFY
// points at valid memory for as long as this stage's stack frame lives.
var notifyContextMarker uint32

// notifyCallbackStub is the PFN_SC_NOTIFY_CALLBACK that NotifyServiceStatusChangeW
// requires. Windows refuses a NULL pointer (ERROR_INVALID_PARAMETER), but the
// callback only fires when the calling thread enters an alertable wait state
// (SleepEx, WaitForSingleObjectEx with bAlertable=TRUE, etc.). This simulation
// never enters an alertable wait, so this stub will never actually be invoked
// — its sole purpose is to satisfy the API's non-null requirement.
//
// Signature: VOID CALLBACK PFN_SC_NOTIFY_CALLBACK(PVOID pParameter)
func notifyCallbackStub(pParameter uintptr) uintptr { return 0 }

// notifyCallbackStubPtr is the registered Win32 callback pointer. Built once
// at package init via syscall.NewCallback (which allocates a thunk that bridges
// the Go calling convention to the Windows stdcall calling convention).
var notifyCallbackStubPtr = syscall.NewCallback(notifyCallbackStub)

// classifyError maps service-API errors to stage exit codes. Neutral wording.
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()

	for _, sub := range []string{
		"access is denied",
		"access denied",
		"permission denied",
		"operation not permitted",
	} {
		if containsFold(s, sub) {
			return StageBlocked
		}
	}

	// Service missing / WinDefend not installed = prerequisite miss.
	for _, sub := range []string{
		"service does not exist",
		"does not exist",
		"cannot find",
		"not installed",
		"not running",
		"not in RUNNING",
	} {
		if containsFold(s, sub) {
			return StageError
		}
	}

	return StageError
}

func isSystemContext() bool {
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	username := strings.TrimSpace(strings.ToLower(string(output)))
	return strings.Contains(username, "nt authority\\system") || strings.Contains(username, "system")
}

func containsFold(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	ln := len(needle)
	for i := 0; i+ln <= len(haystack); i++ {
		match := true
		for j := 0; j < ln; j++ {
			a, b := haystack[i+j], needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
