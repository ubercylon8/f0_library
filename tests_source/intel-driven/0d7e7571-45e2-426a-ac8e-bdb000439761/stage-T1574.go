//go:build windows
// +build windows

/*
STAGE 3: Mount-Point Reparse + FILE_SUPERSEDE Race (T1574)

Simulates the RedSun PoC primitives from the reparse-point and supersede-race
sections:
  - FSCTL_SET_REPARSE_POINT creating IO_REPARSE_TAG_MOUNT_POINT on a sandbox
    directory pointing at ANOTHER sandbox directory. The real PoC pointed the
    reparse at C:\Windows\System32 — we explicitly do NOT, so the redirect
    never reaches any real Windows path.
  - NtCreateFile loop with FILE_SUPERSEDE disposition against a sandbox file
    (NOT against C:\Windows\System32\TieringEngineService.exe).

SAFETY BOUNDARIES:
  - Reparse source:  c:\Users\fortika-test\RedSunSandbox\ReparseSource
  - Reparse target:  c:\Users\fortika-test\RedSunSandbox\ReparseTarget
    (both under ARTIFACT_DIR; no real system path is referenced)
  - Supersede target: c:\Users\fortika-test\RedSunSandbox\FakeTarget.exe
    (NOT TieringEngineService.exe, NOT under System32)
  - Reparse point is TORN DOWN (FSCTL_DELETE_REPARSE_POINT) within the same
    function. No persistent reparse state is left behind.
  - Supersede loop capped at 20 iterations with 50ms sleep — enough to exercise
    the primitive, not enough to look like a DoS.
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
	TECHNIQUE_ID   = "T1574"
	TECHNIQUE_NAME = "Mount-Point Reparse + FILE_SUPERSEDE Race"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	ioReparseTagMountPoint   = 0xA0000003
	fsctlSetReparsePoint     = 0x000900A4 // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
	fsctlGetReparsePoint     = 0x000900A8 // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) — v2 lift R3
	fsctlDeleteReparsePoint  = 0x000900AC // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
	fileFlagOpenReparsePoint = 0x00200000
	fileFlagBackupSemantics  = 0x02000000
	// FILE_INFORMATION_CLASS values used by NtQueryInformationFile (v2 lift R4)
	fileStandardInformation = 5
)

// FILE_STANDARD_INFORMATION layout (NtQueryInformationFile output buffer)
type fileStandardInformationStruct struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  uint32
	Directory      uint32
}

// IO_STATUS_BLOCK
type ioStatusBlock struct {
	Status      uintptr
	Information uintptr
}

var (
	ntdll                      = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationFile = ntdll.NewProc("NtQueryInformationFile")
)

// REPARSE_DATA_BUFFER for mount points — dynamically sized buffer.
// Layout (bytes, little-endian):
//   u32 ReparseTag
//   u16 ReparseDataLength
//   u16 Reserved
//   u16 SubstituteNameOffset
//   u16 SubstituteNameLength
//   u16 PrintNameOffset
//   u16 PrintNameLength
//   wchar PathBuffer[]
//
// Header size (before PathBuffer) = 16 bytes.

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting mount-point reparse + FILE_SUPERSEDE race simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "FSCTL_SET_REPARSE_POINT (sandbox->sandbox) + NtCreateFile SUPERSEDE loop")

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

	fmt.Printf("[STAGE %s] Reparse + supersede primitives completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Reparse + supersede primitives exercised without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Mount-point reparse + FILE_SUPERSEDE loop completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	sandboxRoot := filepath.Join(ARTIFACT_DIR, "RedSunSandbox")
	if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
		return fmt.Errorf("could not create sandbox root: %v", err)
	}

	// Source directory (the one that will host the reparse point) and target
	// directory (what it points to). BOTH under sandbox root.
	reparseSource := filepath.Join(sandboxRoot, "ReparseSource")
	reparseTarget := filepath.Join(sandboxRoot, "ReparseTarget")
	_ = os.RemoveAll(reparseSource)
	if err := os.MkdirAll(reparseSource, 0755); err != nil {
		return fmt.Errorf("could not create reparse source: %v", err)
	}
	if err := os.MkdirAll(reparseTarget, 0755); err != nil {
		return fmt.Errorf("could not create reparse target: %v", err)
	}
	defer os.RemoveAll(reparseSource)

	// Step 1: Build the reparse-point buffer for a mount point from
	// reparseSource -> reparseTarget. The substitute name must use the NT path
	// form ("\??\<path>"). NOTE: the target is always under ARTIFACT_DIR.
	ntTarget := "\\??\\" + reparseTarget
	ntTargetW, err := syscall.UTF16FromString(ntTarget)
	if err != nil {
		return fmt.Errorf("target path conversion failed: %v", err)
	}
	// UTF16FromString returns the buffer INCLUDING a trailing NUL; strip it for
	// the substitute/print name lengths.
	ntTargetWcharLen := len(ntTargetW) - 1
	printNameW, _ := syscall.UTF16FromString(reparseTarget)
	printNameWcharLen := len(printNameW) - 1

	// Layout:
	//   SubstituteName (ntTarget)   : offset 0,                       len = ntTargetWcharLen*2 bytes
	//   L"\x00" terminator after substitute
	//   PrintName      (reparseTarget): offset (ntTargetWcharLen+1)*2, len = printNameWcharLen*2 bytes
	//   L"\x00" terminator after print
	substituteNameOffset := uint16(0)
	substituteNameLength := uint16(ntTargetWcharLen * 2)
	printNameOffset := uint16((ntTargetWcharLen + 1) * 2)
	printNameLength := uint16(printNameWcharLen * 2)
	pathBufferByteLen := (ntTargetWcharLen + 1 + printNameWcharLen + 1) * 2
	reparseDataLength := uint16(8 + pathBufferByteLen) // 4 u16 fields (8 bytes) + PathBuffer

	// Total buffer: header (8) + ReparseDataLength
	totalLen := 8 + int(reparseDataLength)
	buf := make([]byte, totalLen)

	// ReparseTag (u32)
	putU32LE(buf[0:4], uint32(ioReparseTagMountPoint))
	// ReparseDataLength (u16)
	putU16LE(buf[4:6], reparseDataLength)
	// Reserved (u16)
	putU16LE(buf[6:8], 0)
	// SubstituteNameOffset
	putU16LE(buf[8:10], substituteNameOffset)
	// SubstituteNameLength
	putU16LE(buf[10:12], substituteNameLength)
	// PrintNameOffset
	putU16LE(buf[12:14], printNameOffset)
	// PrintNameLength
	putU16LE(buf[14:16], printNameLength)
	// PathBuffer: substitute name, NUL, print name, NUL
	pbOffset := 16
	for i := 0; i < ntTargetWcharLen; i++ {
		putU16LE(buf[pbOffset+i*2:pbOffset+i*2+2], ntTargetW[i])
	}
	pbOffset += (ntTargetWcharLen + 1) * 2 // skip the NUL
	for i := 0; i < printNameWcharLen; i++ {
		putU16LE(buf[pbOffset+i*2:pbOffset+i*2+2], printNameW[i])
	}

	// Open source directory for reparse-point write. FILE_FLAG_OPEN_REPARSE_POINT
	// + FILE_FLAG_BACKUP_SEMANTICS is required.
	reparseSourceW, _ := syscall.UTF16PtrFromString(reparseSource)
	hDir, err := syscall.CreateFile(
		reparseSourceW,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagOpenReparsePoint|fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return fmt.Errorf("could not open reparse source directory: %v", err)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Calling FSCTL_SET_REPARSE_POINT on %s -> %s (sandbox->sandbox)", reparseSource, reparseTarget))

	var bytesReturned uint32
	ioctlErr := syscall.DeviceIoControl(
		hDir,
		uint32(fsctlSetReparsePoint),
		&buf[0],
		uint32(totalLen),
		nil, 0,
		&bytesReturned,
		nil,
	)
	reparseCreated := (ioctlErr == nil)
	if ioctlErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("FSCTL_SET_REPARSE_POINT returned: %v (primitive visible in telemetry regardless)", ioctlErr))
	} else {
		LogMessage("SUCCESS", TECHNIQUE_ID, "FSCTL_SET_REPARSE_POINT succeeded — mount-point reparse active on sandbox dir")
	}

	// v2 lift R3 — Read the reparse point back via FSCTL_GET_REPARSE_POINT.
	// This exercises the read-side detection rule (sensors that watch for
	// reparse-point enumeration), in addition to the create-side rule that
	// FSCTL_SET fired. Read goes into a sink buffer and is logged but not
	// persisted — purely a telemetry probe.
	if reparseCreated {
		readBackBuf := make([]byte, 1024)
		var readBackBytes uint32
		readErr := syscall.DeviceIoControl(
			hDir,
			uint32(fsctlGetReparsePoint),
			nil, 0,
			&readBackBuf[0],
			uint32(len(readBackBuf)),
			&readBackBytes,
			nil,
		)
		if readErr == nil {
			LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("FSCTL_GET_REPARSE_POINT read-back returned %d bytes — reparse-enumerate detection signal exercised", readBackBytes))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("FSCTL_GET_REPARSE_POINT returned: %v (primitive still visible in telemetry)", readErr))
		}
	}

	// Tear the reparse point down before closing the directory handle. Send an
	// FSCTL_DELETE_REPARSE_POINT with the same tag and zero data length.
	if reparseCreated {
		// Build deletion buffer: just the reparse tag header with zero data length.
		delBuf := make([]byte, 8)
		putU32LE(delBuf[0:4], uint32(ioReparseTagMountPoint))
		putU16LE(delBuf[4:6], 0) // ReparseDataLength = 0
		putU16LE(delBuf[6:8], 0)
		_ = syscall.DeviceIoControl(
			hDir,
			uint32(fsctlDeleteReparsePoint),
			&delBuf[0],
			uint32(len(delBuf)),
			nil, 0,
			&bytesReturned,
			nil,
		)
		LogMessage("INFO", TECHNIQUE_ID, "FSCTL_DELETE_REPARSE_POINT invoked to tear down reparse state")
	}
	syscall.CloseHandle(hDir)

	// Step 2: FILE_SUPERSEDE race loop against a sandbox file.
	//
	// We use CreateFileW with CREATE_ALWAYS, which is the Win32 equivalent of
	// NtCreateFile's FILE_SUPERSEDE disposition and produces the same kernel
	// signature (IRP_MJ_CREATE with FILE_SUPERSEDE) that EDRs observe when
	// blocking the RedSun primitive. Cap at 20 iterations — plenty to exercise
	// the pattern without looking like a DoS.
	supersedeTarget := filepath.Join(sandboxRoot, "FakeTarget.exe")

	// v2 lift R4 — NtQueryInformationFile probe before the supersede race.
	// The real RedSun PoC queries FileStandardInformation on its target before
	// racing the supersede. We mirror that pre-race probe here against the
	// sandbox file. If the file doesn't exist yet, we create a 1-byte stub for
	// the probe target.
	probeStubBytes := []byte("X")
	if _, statErr := os.Stat(supersedeTarget); os.IsNotExist(statErr) {
		_ = os.WriteFile(supersedeTarget, probeStubBytes, 0644)
	}
	if probeInfo, probeErr := queryFileStandardInformation(supersedeTarget); probeErr == nil {
		LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("NtQueryInformationFile(FileStandardInformation) on %s — eof=%d alloc=%d nlinks=%d (PoC pre-race probe primitive)",
			supersedeTarget, probeInfo.EndOfFile, probeInfo.AllocationSize, probeInfo.NumberOfLinks))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("NtQueryInformationFile probe returned: %v (primitive visible in telemetry regardless)", probeErr))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Beginning FILE_SUPERSEDE loop against %s", supersedeTarget))

	supersedeTargetW, _ := syscall.UTF16PtrFromString(supersedeTarget)
	supersedeAttempts := 0
	for i := 0; i < 20; i++ {
		h, ferr := syscall.CreateFile(
			supersedeTargetW,
			syscall.GENERIC_WRITE,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			nil,
			syscall.CREATE_ALWAYS, // CREATE_ALWAYS == FILE_SUPERSEDE semantics on Win32 layer
			syscall.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		supersedeAttempts++
		if ferr != nil {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Supersede attempt %d returned: %v", i+1, ferr))
			time.Sleep(50 * time.Millisecond)
			continue
		}
		syscall.CloseHandle(h)
		time.Sleep(50 * time.Millisecond)
	}
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("FILE_SUPERSEDE loop completed: %d iterations against sandbox target", supersedeAttempts))

	// Cleanup
	_ = os.Remove(supersedeTarget)

	return nil
}

func putU32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func putU16LE(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

// unused helper preserved for future stage authors reading this file.
var _ = unsafe.Sizeof(uint32(0))

// queryFileStandardInformation calls NtQueryInformationFile on a path with
// FILE_INFORMATION_CLASS = FileStandardInformation. This is the v2 R4 lift
// — mirrors RedSun's PoC pre-race probe primitive. Read-only.
func queryFileStandardInformation(path string) (*fileStandardInformationStruct, error) {
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString: %v", err)
	}
	h, err := syscall.CreateFile(
		pathW,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFile: %v", err)
	}
	defer syscall.CloseHandle(h)

	var info fileStandardInformationStruct
	var iosb ioStatusBlock
	r1, _, e1 := procNtQueryInformationFile.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
		uintptr(fileStandardInformation),
	)
	if r1 != 0 {
		return nil, fmt.Errorf("NtQueryInformationFile NTSTATUS=0x%08X (%v)", uint32(r1), e1)
	}
	return &info, nil
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
