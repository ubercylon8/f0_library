//go:build windows
// +build windows

/*
STAGE 1: Defender Update-Path Discovery (T1083)

Mirrors UnDefend's wmain() reconnaissance:
  - Opens HKLM\SOFTWARE\Microsoft\Windows Defender and reads
    "ProductAppDataPath" to locate the Definition Updates root.
  - Opens HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates
    and reads "SignatureLocation" (used by UnDefend's WDKillerCallback
    to resolve the path to mpavbase.vdm).
  - Subscribes to ReadDirectoryChangesW on the real Definition Updates
    directory for ~2 seconds (FILE_NOTIFY_CHANGE_SIZE, recursive).

CRITICAL SAFETY: this stage only READS registry values and REGISTERS a
directory watch. No locks, no writes, no handles held after return.
If Defender reports a modification inside the watch window the handler
logs the filename but takes no lock action.
*/

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "6a2351ac-654a-4112-b378-e6919beef70d"
	TECHNIQUE_ID   = "T1083"
	TECHNIQUE_NAME = "Defender Update-Path Discovery"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	DefenderKeyPath   = `SOFTWARE\Microsoft\Windows Defender`
	SigUpdatesKeyPath = `SOFTWARE\Microsoft\Windows Defender\Signature Updates`

	productAppDataValue  = "ProductAppDataPath"
	signatureLocationVal = "SignatureLocation"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting UnDefend discovery-phase simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Discovery encountered a condition: %v\n", TECHNIQUE_ID, err)
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Discovery result: %v", err))
		code := classifyError(err)
		if code == StageBlocked || code == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(code)
	}

	fmt.Printf("[STAGE %s] Discovery completed — Defender update paths resolved\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Registry recon + directory watch completed successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Discovery-phase primitives executed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: read ProductAppDataPath from Defender registry
	productAppDataPath, err := readDefenderRegistryValue(DefenderKeyPath, productAppDataValue)
	if err != nil {
		// If Defender keys aren't present this is a prerequisite miss, not an EDR block.
		return fmt.Errorf("reading %s\\%s: %w", DefenderKeyPath, productAppDataValue, err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Registry ProductAppDataPath resolved: %s", productAppDataPath))

	// Step 2: read SignatureLocation — UnDefend uses this to build mpavbase.vdm path
	signatureLocation, err := readDefenderRegistryValue(SigUpdatesKeyPath, signatureLocationVal)
	if err != nil {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("SignatureLocation unavailable: %v (continuing with Definition Updates recon)", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Registry SignatureLocation resolved: %s", signatureLocation))
	}

	// Step 3: derive Definition Updates path and verify presence
	defUpdatesDir := productAppDataPath + `\Definition Updates`
	if _, err := os.Stat(defUpdatesDir); err != nil {
		// Path not accessible — EDR or permission block vs. Defender absent.
		// Use neutral wording; determineExitCode will treat this as prerequisite miss.
		return fmt.Errorf("stat Definition Updates directory: %w", err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Definition Updates directory accessible: %s", defUpdatesDir))

	// Step 4: subscribe to ReadDirectoryChangesW on the real path (read-only observable)
	if err := watchDefinitionUpdates(defUpdatesDir, 2*time.Second); err != nil {
		return fmt.Errorf("ReadDirectoryChangesW subscription: %w", err)
	}

	return nil
}

// readDefenderRegistryValue opens HKLM\<path> read-only and returns the string
// value for <name>. No writes, no modifications.
func readDefenderRegistryValue(path, name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("OpenKey HKLM\\%s: %v", path, err)
	}
	defer k.Close()

	val, _, err := k.GetStringValue(name)
	if err != nil {
		return "", fmt.Errorf("GetStringValue %s: %v", name, err)
	}
	return val, nil
}

// watchDefinitionUpdates opens the directory with FILE_LIST_DIRECTORY | SYNCHRONIZE
// and calls ReadDirectoryChangesW with FILE_NOTIFY_CHANGE_SIZE recursively, exactly
// like UnDefend's MRTWorkerThread / wmain() main loop — but for only `duration` and
// without spawning any lock thread on modifications.
func watchDefinitionUpdates(dir string, duration time.Duration) error {
	wdir, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %v", err)
	}

	handle, err := windows.CreateFile(
		wdir,
		windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile FILE_LIST_DIRECTORY: %v", err)
	}
	defer windows.CloseHandle(handle)

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Directory handle opened on %s (FILE_LIST_DIRECTORY | SYNCHRONIZE)", dir))

	// Launch a single ReadDirectoryChangesW call with a modest timeout.
	// We use OVERLAPPED with a manual-reset event so we can cancel cleanly.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent: %v", err)
	}
	defer windows.CloseHandle(event)

	buf := make([]byte, 4096)
	var ov windows.Overlapped
	ov.HEvent = event
	var retBytes uint32

	// FILE_NOTIFY_CHANGE_SIZE — same filter UnDefend uses.
	const FILE_NOTIFY_CHANGE_SIZE_LOCAL = 0x00000008

	err = windows.ReadDirectoryChanges(
		handle,
		&buf[0],
		uint32(len(buf)),
		true, // recursive — matches UnDefend
		FILE_NOTIFY_CHANGE_SIZE_LOCAL,
		&retBytes,
		&ov,
		0,
	)
	if err != nil {
		return fmt.Errorf("ReadDirectoryChangesW: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		"ReadDirectoryChangesW subscription registered (recursive, FILE_NOTIFY_CHANGE_SIZE)")

	// Wait up to `duration` for a change. If nothing fires, cancel the IO.
	timeoutMs := uint32(duration / time.Millisecond)
	waitRes, waitErr := windows.WaitForSingleObject(event, timeoutMs)
	if waitErr != nil {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("WaitForSingleObject error: %v", waitErr))
	}
	switch waitRes {
	case windows.WAIT_OBJECT_0:
		// A change notification arrived — decode the first record for logging.
		name := decodeFirstFNI(buf[:retBytes])
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Directory-change event observed: %q (SIMULATION: no lock taken)", name))
	case 0x00000102: // WAIT_TIMEOUT
		LogMessage("INFO", TECHNIQUE_ID,
			"No change within watch window (expected — Defender updates are infrequent)")
	default:
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("ReadDirectoryChangesW wait returned 0x%X", waitRes))
	}

	// Cancel any pending IO so the handle closes cleanly.
	_ = windows.CancelIo(handle)
	return nil
}

// decodeFirstFNI pulls the first FILE_NOTIFY_INFORMATION filename out of the buffer.
// Safety: purely read, never used to drive a lock operation.
func decodeFirstFNI(b []byte) string {
	if len(b) < 12 {
		return ""
	}
	// FILE_NOTIFY_INFORMATION layout:
	//   DWORD NextEntryOffset; DWORD Action; DWORD FileNameLength; WCHAR FileName[1];
	_ = *(*uint32)(unsafe.Pointer(&b[0])) // NextEntryOffset (ignored)
	// action at offset 4, length at offset 8
	fileNameLength := *(*uint32)(unsafe.Pointer(&b[8]))
	if fileNameLength == 0 || 12+int(fileNameLength) > len(b) {
		return ""
	}
	nameBytes := b[12 : 12+fileNameLength]
	n := int(fileNameLength / 2)
	u16 := make([]uint16, n)
	for i := 0; i < n; i++ {
		u16[i] = uint16(nameBytes[i*2]) | uint16(nameBytes[i*2+1])<<8
	}
	return syscall.UTF16ToString(u16)
}

// classifyError maps discovery errors to stage exit codes.
// We do NOT inject blame keywords — we describe the operation and use
// explicit path cues instead.
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()
	// Prerequisites missing: Defender key not present, directory not accessible
	for _, sub := range []string{
		"cannot find the file",
		"The system cannot find",
		"does not exist",
		"no such",
		"registry key does not",
		"ENOENT",
		"not found",
	} {
		if containsFold(s, sub) {
			return StageError
		}
	}
	// Access violation (EDR may still surface these) — exit 126 as blocked signal
	for _, sub := range []string{
		"access is denied",
		"access denied",
		"permission denied",
	} {
		if containsFold(s, sub) {
			return StageBlocked
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
