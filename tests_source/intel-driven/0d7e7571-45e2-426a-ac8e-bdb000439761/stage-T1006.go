//go:build windows
// +build windows

/*
STAGE 2: VSS Device Enumeration + Batch Oplock (T1006)

Simulates the RedSun PoC primitives from RetrieveCurrentVSSList() and
ShadowCopyFinderThread():
  - NtOpenDirectoryObject on \Device
  - NtQueryDirectoryObject iterating the object manager directory
  - Filter for HarddiskVolumeShadowCopy* device names (READ-ONLY, no handle
    is opened against the VSS device itself)
  - FSCTL_REQUEST_BATCH_OPLOCK on a sandbox file (NOT on a VSS shadow copy
    path). The real PoC held the oplock on the VSS path; we exercise the
    IOCTL pattern against a sandbox file so the behavioral signature is
    present without touching any real system handle.

SAFETY BOUNDARIES:
  - NtQueryDirectoryObject is read-only; enumerating \Device is not itself
    a privileged operation.
  - No handle is ever opened against a real HarddiskVolumeShadowCopy device.
  - Oplock is requested against c:\Users\fortika-test\RedSunSandbox\OplockTarget.dat
    (NOT against any system file, NOT against any VSS path).
  - Oplock is released (handle closed) within THIS function — no global
    events, no threads waiting outside the stage.
*/

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
	TEST_UUID      = "0d7e7571-45e2-426a-ac8e-bdb000439761"
	TECHNIQUE_ID   = "T1006"
	TECHNIQUE_NAME = "VSS Device Enumeration + Batch Oplock"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// UNICODE_STRING as expected by NT APIs.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type objectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *unicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// OBJECT_DIRECTORY_INFORMATION as returned by NtQueryDirectoryObject.
type objectDirectoryInformation struct {
	Name     unicodeString
	TypeName unicodeString
}

const (
	objCaseInsensitive     = 0x00000040
	directoryQuery         = 0x0001
	fsctlRequestBatchOplock = 0x00090000 | (2 << 2) | 0 | (0 << 14) // FSCTL_REQUEST_BATCH_OPLOCK control code
	statusSuccess          = 0x00000000
	statusMoreEntries      = 0x00000105
	statusNoMoreEntries    = 0x8000001A
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting VSS device enumeration + batch oplock simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "NtOpenDirectoryObject(\\Device) + FSCTL_REQUEST_BATCH_OPLOCK on sandbox file")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique did not complete: %v\n", TECHNIQUE_ID, err)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Technique outcome: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] VSS enumeration + batch oplock primitive completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "VSS enumeration + batch oplock exercised without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "NtQueryDirectoryObject + FSCTL_REQUEST_BATCH_OPLOCK completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	sandboxRoot := filepath.Join(ARTIFACT_DIR, "RedSunSandbox")
	if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
		return fmt.Errorf("could not create sandbox root: %v", err)
	}

	// Load ntdll functions we need.
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return fmt.Errorf("ntdll.dll not loadable: %v", err)
	}
	defer ntdll.Release()

	procOpenDir, err := ntdll.FindProc("NtOpenDirectoryObject")
	if err != nil {
		return fmt.Errorf("ntopendirectoryobject proc missing: %v", err)
	}
	procQueryDir, err := ntdll.FindProc("NtQueryDirectoryObject")
	if err != nil {
		return fmt.Errorf("ntquerydirectoryobject proc missing: %v", err)
	}
	procRtlInit, err := ntdll.FindProc("RtlInitUnicodeString")
	if err != nil {
		return fmt.Errorf("rtlinitunicodestring proc missing: %v", err)
	}

	// Build UNICODE_STRING for "\Device"
	devicePath, err := syscall.UTF16PtrFromString("\\Device")
	if err != nil {
		return fmt.Errorf("path conversion failed: %v", err)
	}
	var us unicodeString
	procRtlInit.Call(uintptr(unsafe.Pointer(&us)), uintptr(unsafe.Pointer(devicePath)))

	oa := objectAttributes{
		Length:     uint32(unsafe.Sizeof(objectAttributes{})),
		ObjectName: &us,
		Attributes: objCaseInsensitive,
	}

	var hDir syscall.Handle
	LogMessage("INFO", TECHNIQUE_ID, "Calling NtOpenDirectoryObject(\\Device, DIRECTORY_QUERY)")
	status, _, _ := procOpenDir.Call(
		uintptr(unsafe.Pointer(&hDir)),
		uintptr(directoryQuery),
		uintptr(unsafe.Pointer(&oa)),
	)
	if status != statusSuccess {
		// Non-zero NTSTATUS — enumeration couldn't start. Not a block, a prerequisite
		// failure. Report as error (999).
		return fmt.Errorf("ntopendirectoryobject returned non-zero status: 0x%08X (prerequisite failure)", uint32(status))
	}
	defer syscall.CloseHandle(hDir)

	LogMessage("SUCCESS", TECHNIQUE_ID, "\\Device directory handle obtained — beginning read-only enumeration")

	// Allocate buffer and query.
	bufSize := uint32(64 * 1024)
	buf := make([]byte, bufSize)
	var context uint32 = 0
	var returned uint32 = 0
	vscCount := 0
	totalEntries := 0

	for iter := 0; iter < 8; iter++ {
		restartScan := uint32(0)
		if iter == 0 {
			restartScan = 1
		}
		status, _, _ = procQueryDir.Call(
			uintptr(hDir),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			0, // ReturnSingleEntry = FALSE
			uintptr(restartScan),
			uintptr(unsafe.Pointer(&context)),
			uintptr(unsafe.Pointer(&returned)),
		)

		if status != statusSuccess && status != statusMoreEntries {
			if status == statusNoMoreEntries {
				break
			}
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("NtQueryDirectoryObject iteration %d returned 0x%08X — stopping", iter, uint32(status)))
			break
		}

		// Walk OBJECT_DIRECTORY_INFORMATION array until we hit a zeroed entry.
		offset := uintptr(0)
		entrySize := unsafe.Sizeof(objectDirectoryInformation{})
		for offset+entrySize <= uintptr(bufSize) {
			entry := (*objectDirectoryInformation)(unsafe.Pointer(&buf[offset]))
			if entry.Name.Buffer == nil || entry.Name.Length == 0 {
				break
			}
			totalEntries++

			name := utf16PtrToString(entry.Name.Buffer, entry.Name.Length/2)
			if startsWith(name, "HarddiskVolumeShadowCopy") {
				vscCount++
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Enumerated VSS device (read-only): %s", name))
			}

			offset += entrySize
		}

		if status == statusSuccess {
			break
		}
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("\\Device enumeration: %d total entries, %d HarddiskVolumeShadowCopy entries", totalEntries, vscCount))

	// Step 2: batch oplock on a sandbox file (NOT on a VSS path).
	oplockTarget := filepath.Join(sandboxRoot, "OplockTarget.dat")
	// Seed the file so the open doesn't fail with ERROR_FILE_NOT_FOUND.
	if err := os.WriteFile(oplockTarget, []byte("F0RT1KA-REDSUN-SIM-OPLOCK-TARGET"), 0644); err != nil {
		return fmt.Errorf("could not create oplock target: %v", err)
	}
	defer os.Remove(oplockTarget)

	oplockTargetW, _ := syscall.UTF16PtrFromString(oplockTarget)
	hFile, err := syscall.CreateFile(
		oplockTargetW,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return fmt.Errorf("could not open oplock target: %v", err)
	}

	// CreateEvent via kernel32 (Go's syscall package doesn't expose it cross-platform).
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		syscall.CloseHandle(hFile)
		return fmt.Errorf("kernel32.dll not loadable: %v", err)
	}
	defer kernel32.Release()
	procCreateEvent, err := kernel32.FindProc("CreateEventW")
	if err != nil {
		syscall.CloseHandle(hFile)
		return fmt.Errorf("createeventw proc missing: %v", err)
	}
	eventH, _, createEventErr := procCreateEvent.Call(0, 1, 0, 0)
	if eventH == 0 {
		syscall.CloseHandle(hFile)
		return fmt.Errorf("could not create overlapped event: %v", createEventErr)
	}
	event := syscall.Handle(eventH)
	var ov syscall.Overlapped
	ov.HEvent = event

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Requesting FSCTL_REQUEST_BATCH_OPLOCK on %s", oplockTarget))
	var bytesReturned uint32
	ioctlErr := syscall.DeviceIoControl(
		hFile,
		uint32(fsctlRequestBatchOplock),
		nil, 0, nil, 0,
		&bytesReturned,
		&ov,
	)

	if ioctlErr != nil {
		if ioctlErr == syscall.ERROR_IO_PENDING {
			LogMessage("SUCCESS", TECHNIQUE_ID, "FSCTL_REQUEST_BATCH_OPLOCK accepted (ERROR_IO_PENDING) — oplock is pending as expected")
		} else {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("FSCTL_REQUEST_BATCH_OPLOCK returned error: %v (primitive still visible in telemetry)", ioctlErr))
		}
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "FSCTL_REQUEST_BATCH_OPLOCK returned immediately (unusual on sandbox file)")
	}

	// Hold briefly so the oplock request is visible in trace, then release
	// by closing the file handle. SAFETY: the oplock lifetime is bounded to
	// this function — we do not return with any oplock still outstanding.
	time.Sleep(500 * time.Millisecond)

	syscall.CloseHandle(hFile)
	syscall.CloseHandle(event)
	LogMessage("INFO", TECHNIQUE_ID, "Oplock released (file handle closed within stage function)")

	return nil
}

// utf16PtrToString converts a UTF-16 buffer of given length (in WCHARs) into a Go string.
func utf16PtrToString(p *uint16, wcharLen uint16) string {
	if p == nil || wcharLen == 0 {
		return ""
	}
	sl := unsafe.Slice(p, int(wcharLen))
	return syscall.UTF16ToString(sl)
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not loadable", "not available", "prerequisite", "missing", "proc missing"}) {
		return StageError
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
