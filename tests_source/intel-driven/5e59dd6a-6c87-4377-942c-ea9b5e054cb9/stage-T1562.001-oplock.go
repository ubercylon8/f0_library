//go:build windows
// +build windows

// Stage 2: Batch Oplock Primitive on a Sandbox File (T1562.001)
//
// Behavior exercised (OBSERVABLE PRIMITIVE ONLY):
//   - Create a benign sandbox file under ARTIFACT_DIR (FILE_FLAG_OVERLAPPED)
//   - Call DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK) to request a batch oplock
//   - Wait AT MOST 5 seconds for the oplock to either complete or remain pending
//   - Always release by closing the handle, regardless of oplock state
//
// This surfaces the oplock-pattern telemetry EDR can use to detect scanner-stall
// techniques (T1562.001 — Impair Defenses: Disable or Modify Tools, in the
// narrow sense of stalling AV scanner reads).
//
// Explicitly NOT done: target is a sandbox file — NOT a Defender update file,
// NOT a VSS path, NOT any file Defender would be scanning. We do not try to
// freeze Defender.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
	TECHNIQUE_ID   = "T1562.001"
	TECHNIQUE_NAME = "Batch Oplock on Sandbox File"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	fsctlRequestBatchOplock uint32 = 0x00090018
	oplockTimeoutSeconds           = 5
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procDeviceIoControl     = kernel32.NewProc("DeviceIoControl")
	procCreateEventW        = kernel32.NewProc("CreateEventW")
	procGetOverlappedResult = kernel32.NewProc("GetOverlappedResult")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	procCancelIoEx          = kernel32.NewProc("CancelIoEx")
	procCloseHandle         = kernel32.NewProc("CloseHandle")
)

type overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       syscall.Handle
}

// WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258, WAIT_FAILED = 0xFFFFFFFF
const (
	waitObject0 = 0x0
	waitTimeout = 0x102
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique errored: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique errored: %v", err))
		exitCode := classifyError(err)
		if exitCode == StageBlocked {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Oplock primitive exercised and released\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Batch-oplock primitive exercised and released within timeout")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Batch oplock requested and released on sandbox file")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	sandboxDir := filepath.Join(ARTIFACT_DIR, "BlueHammerSandbox")
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		return fmt.Errorf("create sandbox directory: %v", err)
	}
	oplockTargetPath := filepath.Join(sandboxDir, "oplock-target.txt")

	// Create/truncate the sandbox target file. Use plain os.WriteFile first so
	// the file exists on disk; we will open it with FILE_FLAG_OVERLAPPED next.
	seed := []byte("F0RT1KA BlueHammer oplock-primitive sandbox file. Safe to delete.\r\n")
	if err := os.WriteFile(oplockTargetPath, seed, 0644); err != nil {
		return fmt.Errorf("seed oplock target file: %v", err)
	}
	LogFileDropped("oplock-target.txt", oplockTargetPath, int64(len(seed)), false)
	defer os.Remove(oplockTargetPath)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Oplock target: %s", oplockTargetPath))

	targetUTF16, _ := syscall.UTF16PtrFromString(oplockTargetPath)

	// CreateFile with FILE_FLAG_OVERLAPPED — required for batch oplock semantics.
	// GENERIC_READ|GENERIC_WRITE ensures we own the handle that receives the oplock.
	handle, err := syscall.CreateFile(
		targetUTF16,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile(FILE_FLAG_OVERLAPPED) errno=%v", err)
	}
	defer syscall.CloseHandle(handle)

	// Manual-reset event for overlapped I/O
	hEvent, _, _ := procCreateEventW.Call(0, 1, 0, 0)
	if hEvent == 0 {
		return fmt.Errorf("CreateEventW returned 0")
	}
	defer procCloseHandle.Call(hEvent)

	ov := overlapped{HEvent: syscall.Handle(hEvent)}

	LogMessage("INFO", TECHNIQUE_ID, "Calling DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK)")

	var bytesReturned uint32
	ret, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		uintptr(fsctlRequestBatchOplock),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&bytesReturned)),
		uintptr(unsafe.Pointer(&ov)),
	)

	// Expected happy path: ret==0 AND GetLastError() == ERROR_IO_PENDING (997).
	// In that case the oplock is pending and we wait up to 5s with WaitForSingleObject.
	// If ret != 0 (synchronous success) the oplock completed immediately (rare); also fine.
	const errorIoPending = 997

	if ret == 0 {
		lastErr := callErr.(syscall.Errno)
		if lastErr != errorIoPending {
			// Not IO_PENDING — request was rejected synchronously. We describe
			// the operation only (bug-prevention rule #1); interpretation is
			// deferred to classifyError / orchestrator.
			return fmt.Errorf("DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK) returned errno=%d", lastErr)
		}
		LogMessage("INFO", TECHNIQUE_ID, "Oplock request is pending (ERROR_IO_PENDING) — waiting up to 5s")
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Oplock completed synchronously")
	}

	// Always-release wait: up to oplockTimeoutSeconds. If nothing fires the
	// oplock in that window, we cancel I/O and close the handle. Under no
	// circumstances does this stage block for longer than 5 seconds.
	startWait := time.Now()
	timeoutMs := uint32(oplockTimeoutSeconds * 1000)
	waitResult, _, _ := procWaitForSingleObject.Call(uintptr(hEvent), uintptr(timeoutMs))
	elapsed := time.Since(startWait)

	switch waitResult {
	case waitObject0:
		// Something broke the oplock (another handle opened the file). Gather
		// the result for telemetry, then move on — this is the expected signal
		// path when EDR/AV scans the file.
		var transferred uint32
		procGetOverlappedResult.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&ov)),
			uintptr(unsafe.Pointer(&transferred)),
			0,
		)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Oplock broke after %v (transferred=%d bytes)", elapsed, transferred))
	case waitTimeout:
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Oplock did not fire within %ds — cancelling I/O and releasing", oplockTimeoutSeconds))
		procCancelIoEx.Call(uintptr(handle), uintptr(unsafe.Pointer(&ov)))
	default:
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Unexpected wait result 0x%x after %v", waitResult, elapsed))
		procCancelIoEx.Call(uintptr(handle), uintptr(unsafe.Pointer(&ov)))
	}

	// Handle closes via defer. We have now exercised the full primitive:
	//   open with OVERLAPPED -> FSCTL_REQUEST_BATCH_OPLOCK -> 5s cap -> release.
	return nil
}

// classifyError — conservative, no generic blame keywords (bug-prevention rule #1)
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()
	// Very narrow pattern: explicit DeviceIoControl rejection with ERROR_ACCESS_DENIED
	// (errno=5). Anything else is StageError (prerequisite/runtime).
	if has(s, "errno=5") {
		return StageBlocked
	}
	return StageError
}

func has(s, sub string) bool {
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
