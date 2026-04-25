//go:build windows
// +build windows

/*
STAGE 2: UnDefend File-Lock Primitive (T1562.001) — Benign Target with Defender-Pattern Naming

Reproduces UnDefend's core file-lock primitive (NtCreateFile with
GENERIC_READ | SYNCHRONIZE, followed by LockFile and LockFileEx with
LOCKFILE_EXCLUSIVE_LOCK) — but against a benign sandbox file created
under ARTIFACT_DIR, NEVER against real Defender files.

v2 lifts applied:
  - U1: Sandbox files use Defender-pattern names (mpavbase.vdm,
    mpengine.dll) so path-based detection rules fire alongside
    behavior-based ones. The CONTENTS are still benign sandbox data.
  - U2: ProductAppDataPath is read at runtime from the real Defender
    registry key (HKLM\SOFTWARE\Microsoft\Windows Defender) — its
    presence in the read sequence matches UnDefend's discovery flow.
    The path is logged but the sandbox subdir is still created under
    ARTIFACT_DIR — we use the real value as TELEMETRY only.
  - U3: New FileDispositionInformation + DELETE_PENDING race primitive
    against the benign target after the lock primitives. Mirrors
    UnDefend's delete-rename race API surface.

Safety boundary:
  - Target files live under ARTIFACT_DIR\UnDefendSim\Definition Updates\
  - Filenames mimic real Defender artifacts (mpavbase.vdm, mpengine.dll)
    but live in our sandbox; they are NOT real Defender files
  - File is created by this stage (we always own it)
  - All locks released inside this function — never held after return
  - DELETE_PENDING is set on the sandbox file we own; defer-driven
    cleanup ensures the file is gone whether the kernel honored the
    pending or not
  - NO real Defender path is ever opened or locked
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "6a2351ac-654a-4112-b378-e6919beef70d"
	TECHNIQUE_ID   = "T1562.001"
	TECHNIQUE_NAME = "UnDefend File-Lock Primitive (Benign Target)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	targetSubdirRoot    = "UnDefendSim"
	targetSubdirInner   = "Definition Updates" // mirrors real Defender layout for path-rule detection (v2 U1)
	targetFile          = "mpavbase.vdm"       // v2 U1 — Defender-pattern filename
	targetFileSecondary = "mpengine.dll"       // v2 U1 — second Defender-pattern filename for U3 DELETE_PENDING race
	targetContent       = "# F0RT1KA UnDefend simulation — benign sandbox target with Defender-pattern naming\n" +
		"# This file is NOT a Defender signature. The filename intentionally\n" +
		"# matches a real Defender artifact name so that path-string detection\n" +
		"# rules fire alongside the behavioral rules. The contents are benign.\n" +
		"metadata:\n" +
		"  source: fortika-undefend-sim\n" +
		"  safe: true\n"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting UnDefend file-lock primitive simulation (benign target)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Lock primitive reported a condition: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Lock primitive condition: %v", err))

		code := classifyError(err)
		if code == StageBlocked || code == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(code)
	}

	fmt.Printf("[STAGE %s] File-lock primitive executed and released cleanly\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "LockFile + LockFileEx primitive executed against benign target")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"File-lock primitive executed on benign target without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// v2 U2 — read the real ProductAppDataPath from Defender's registry key.
	// We use the real value as TELEMETRY (logged + matches UnDefend's discovery
	// flow) but the sandbox subdir is still created under ARTIFACT_DIR.
	defenderAppDataPath := readDefenderProductAppDataPath()
	if defenderAppDataPath != "" {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\ProductAppDataPath = %q (UnDefend discovery flow telemetry)", defenderAppDataPath))
	}

	// Step 1: ensure the sandbox directory exists (ARTIFACT_DIR, NOT whitelisted).
	// Use a layout that mirrors Defender's: <sandbox>\Definition Updates\<files>.
	sandboxDir := filepath.Join(ARTIFACT_DIR, targetSubdirRoot, targetSubdirInner)
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return fmt.Errorf("mkdir sandbox %s: %w", sandboxDir, err)
	}
	targetPath := filepath.Join(sandboxDir, targetFile)
	secondaryPath := filepath.Join(sandboxDir, targetFileSecondary)

	// Step 2: create the benign target files (always owned by us)
	if err := os.WriteFile(targetPath, []byte(targetContent), 0o644); err != nil {
		return fmt.Errorf("write sandbox file %s: %w", targetPath, err)
	}
	if err := os.WriteFile(secondaryPath, []byte(targetContent), 0o644); err != nil {
		return fmt.Errorf("write sandbox secondary file %s: %w", secondaryPath, err)
	}
	LogFileDropped(targetFile, targetPath, int64(len(targetContent)), false)
	LogFileDropped(targetFileSecondary, secondaryPath, int64(len(targetContent)), false)
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Benign sandbox targets created with Defender-pattern names: %s, %s", targetPath, secondaryPath))

	// Defer cleanup of both sandbox files. DELETE_PENDING in step 5 may also
	// remove targetPath; this defer is a backstop.
	defer func() {
		_ = os.Remove(targetPath)
		_ = os.Remove(secondaryPath)
		LogMessage("INFO", TECHNIQUE_ID, "Sandbox targets removed after primitive completion")
	}()

	// Brief pause so any real-time file-write sensor has room to scan.
	time.Sleep(500 * time.Millisecond)

	// Step 3: LockFile — matches UnDefend's passive-mode path exactly.
	if err := lockFilePrimitive(targetPath); err != nil {
		return fmt.Errorf("LockFile primitive: %w", err)
	}

	// Step 4: LockFileEx with LOCKFILE_EXCLUSIVE_LOCK — matches UnDefend's
	// preemptive-backup and aggressive-mode path.
	if err := lockFileExPrimitive(targetPath); err != nil {
		return fmt.Errorf("LockFileEx primitive: %w", err)
	}

	// Step 5 (v2 U3): FileDispositionInformation + DELETE_PENDING race against
	// the secondary sandbox file. Mirrors UnDefend's delete-rename race API
	// surface. Operates on a sandbox file we own; cleanup is defer-driven.
	if err := dispositionDeletePrimitive(secondaryPath); err != nil {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("FileDispositionInformation primitive errored (non-fatal): %v", err))
	}

	return nil
}

// readDefenderProductAppDataPath reads HKLM\SOFTWARE\Microsoft\Windows Defender\ProductAppDataPath.
// Returns the empty string if the key/value isn't accessible. Read-only — does
// not mutate the registry. (v2 U2 lift)
func readDefenderProductAppDataPath() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	val, _, err := key.GetStringValue("ProductAppDataPath")
	if err != nil {
		return ""
	}
	return val
}

// dispositionDeletePrimitive opens a file with DELETE access and uses
// NtSetInformationFile(FileDispositionInformation, DeleteFile=TRUE) to mark
// it for deletion on handle close. This is the DELETE_PENDING race API
// surface that UnDefend's PoC exercises.
//
// Safety: target is always a sandbox file we created; DELETE_PENDING only
// affects files we own. The handle is closed in defer regardless of outcome.
// (v2 U3 lift)
func dispositionDeletePrimitive(path string) error {
	wpath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %v", err)
	}

	h, err := windows.CreateFile(
		wpath,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile(DELETE) %s: %v", path, err)
	}
	defer windows.CloseHandle(h)

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Handle opened with DELETE access on %s — invoking NtSetInformationFile(FileDispositionInformation, DeleteFile=TRUE)", path))

	// FILE_DISPOSITION_INFORMATION: { BOOLEAN DeleteFile; }
	type fileDispositionInformation struct {
		DeleteFile uint8
	}
	dispInfo := fileDispositionInformation{DeleteFile: 1}

	// IO_STATUS_BLOCK
	var iosb struct {
		Status      uintptr
		Information uintptr
	}

	// FILE_INFORMATION_CLASS: FileDispositionInformation = 13
	const fileDispositionInformationClass = 13

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtSetInformationFile := ntdll.NewProc("NtSetInformationFile")
	r1, _, _ := procNtSetInformationFile.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&dispInfo)),
		uintptr(unsafe.Sizeof(dispInfo)),
		uintptr(fileDispositionInformationClass),
	)
	if r1 != 0 {
		return fmt.Errorf("NtSetInformationFile NTSTATUS=0x%08X", uint32(r1))
	}

	LogMessage("SUCCESS", TECHNIQUE_ID,
		"NtSetInformationFile(FileDispositionInformation, DeleteFile=TRUE) succeeded — DELETE_PENDING set on sandbox file (telemetry signal exercised)")
	return nil
}

// lockFilePrimitive opens the target file with GENERIC_READ | SYNCHRONIZE
// using CreateFile (the Win32 wrapper over NtCreateFile), acquires an
// exclusive lock with LockFile, then releases it immediately.
func lockFilePrimitive(path string) error {
	wpath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %v", err)
	}

	// Same access mask UnDefend's UpdateBlockerThread uses: GENERIC_READ | SYNCHRONIZE.
	h, err := windows.CreateFile(
		wpath,
		windows.GENERIC_READ|windows.SYNCHRONIZE,
		windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile %s: %v", path, err)
	}
	defer windows.CloseHandle(h)
	LogMessage("INFO", TECHNIQUE_ID,
		"Handle opened (GENERIC_READ | SYNCHRONIZE) — invoking LockFile")

	sizeLow, sizeHigh, err := fileSize(path)
	if err != nil {
		return fmt.Errorf("file size lookup: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Target size: %d bytes", (uint64(sizeHigh)<<32)|uint64(sizeLow)))

	// LockFile(hFile, offsetLow=0, offsetHigh=0, sizeLow, sizeHigh)
	if err := lockFileSyscall(h, 0, 0, sizeLow, sizeHigh); err != nil {
		return fmt.Errorf("LockFile syscall: %v", err)
	}
	LogMessage("SUCCESS", TECHNIQUE_ID,
		"LockFile acquired exclusive lock on benign target")

	// Hold briefly so any behavior-based sensor has a window to observe.
	time.Sleep(200 * time.Millisecond)

	if err := unlockFileSyscall(h, 0, 0, sizeLow, sizeHigh); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("UnlockFile error: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Lock released via UnlockFile")
	}
	return nil
}

// lockFileExPrimitive opens the file and invokes LockFileEx with
// LOCKFILE_EXCLUSIVE_LOCK — exactly what UnDefend's TryLockBackup and
// WDKillerCallback do against mpavbase.vdm. Released immediately.
func lockFileExPrimitive(path string) error {
	wpath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %v", err)
	}

	h, err := windows.CreateFile(
		wpath,
		windows.GENERIC_READ|windows.SYNCHRONIZE,
		windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile: %v", err)
	}
	defer windows.CloseHandle(h)
	LogMessage("INFO", TECHNIQUE_ID,
		"Handle re-opened — invoking LockFileEx (LOCKFILE_EXCLUSIVE_LOCK)")

	sizeLow, sizeHigh, err := fileSize(path)
	if err != nil {
		return fmt.Errorf("file size lookup: %v", err)
	}

	var ov windows.Overlapped
	const LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
	if err := windows.LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, sizeLow, sizeHigh, &ov); err != nil {
		return fmt.Errorf("LockFileEx: %v", err)
	}
	LogMessage("SUCCESS", TECHNIQUE_ID,
		"LockFileEx acquired exclusive lock on benign target")

	time.Sleep(200 * time.Millisecond)

	if err := windows.UnlockFileEx(h, 0, sizeLow, sizeHigh, &ov); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("UnlockFileEx error: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Lock released via UnlockFileEx")
	}
	return nil
}

// lockFileSyscall calls LockFile directly (not exposed in x/sys/windows).
// Signature: BOOL LockFile(HANDLE, DWORD offsetLow, DWORD offsetHigh,
//
//	DWORD sizeLow, DWORD sizeHigh).
func lockFileSyscall(h windows.Handle, offsetLow, offsetHigh, sizeLow, sizeHigh uint32) error {
	r, _, e := lockFileProc.Call(
		uintptr(h),
		uintptr(offsetLow),
		uintptr(offsetHigh),
		uintptr(sizeLow),
		uintptr(sizeHigh),
	)
	if r == 0 {
		return e
	}
	return nil
}

// unlockFileSyscall calls UnlockFile.
func unlockFileSyscall(h windows.Handle, offsetLow, offsetHigh, sizeLow, sizeHigh uint32) error {
	r, _, e := unlockFileProc.Call(
		uintptr(h),
		uintptr(offsetLow),
		uintptr(offsetHigh),
		uintptr(sizeLow),
		uintptr(sizeHigh),
	)
	if r == 0 {
		return e
	}
	return nil
}

var (
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	lockFileProc   = kernel32.NewProc("LockFile")
	unlockFileProc = kernel32.NewProc("UnlockFile")
)

// fileSize returns (sizeLow, sizeHigh) in the DWORD-pair form that
// LockFile / LockFileEx expect.
func fileSize(path string) (uint32, uint32, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	sz := uint64(fi.Size())
	return uint32(sz & 0xFFFFFFFF), uint32(sz >> 32), nil
}

// classifyError maps primitive errors to stage exit codes. Neutral wording.
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()

	// Access violations strongly suggest EDR/ASR intervention on the lock API.
	for _, sub := range []string{
		"access is denied",
		"access denied",
		"permission denied",
		"operation not permitted",
		"violation of lock",
		"sharing violation",
	} {
		if containsFold(s, sub) {
			return StageBlocked
		}
	}

	// AV quarantined the sandbox target before/after write.
	for _, sub := range []string{
		"virus",
		"threat",
		"quarantine",
		"detected as",
	} {
		if containsFold(s, sub) {
			return StageQuarantined
		}
	}

	// Prerequisite misses.
	for _, sub := range []string{
		"cannot find the file",
		"cannot find the path",
		"does not exist",
		"no such",
	} {
		if containsFold(s, sub) {
			return StageError
		}
	}

	return StageError
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
