//go:build windows
// +build windows

// Stage 3: VSS Device Enumeration (read-only) + WMI Shadow Enumeration + Transacted-Open on Sandbox File (T1211)
//
// Behavior exercised (OBSERVABLE PRIMITIVES ONLY):
//   Part A — VSS device enumeration via NT Object Manager:
//     - NtOpenDirectoryObject(\Device, DIRECTORY_QUERY)
//     - NtQueryDirectoryObject loop, looking for HarddiskVolumeShadowCopy* entries
//     - The matched names are COUNTED and logged, never opened.
//   Part B (v2 lift B3) — WMI shadow-copy enumeration (read-only WQL query):
//     - "SELECT __PATH FROM Win32_ShadowCopy" via PowerShell Get-WmiObject
//     - Read-only enumeration; NEVER calls Win32_ShadowCopy.Create() or .Delete()
//     - Detection surface: wmiprvse.exe + Win32_ShadowCopy provider activity
//     - Justified PoC deviation: BlueHammer's PoC calls IWbemServices->ExecQuery
//       directly via COM. This test invokes the same WMI provider via the
//       PowerShell Get-WmiObject cmdlet for implementation simplicity. The
//       sensor-visible event (WMI provider + WQL on Win32_ShadowCopy) is
//       identical. API-Fidelity penalty: ~0.5.
//   Part C — Transacted-open probe against a benign sandbox target:
//     - CreateTransaction() -> CreateFileTransactedW() against a file inside
//       ARTIFACT_DIR\BlueHammerSandbox.
//     - File handle is closed and transaction is rolled back, regardless of
//       whether CreateFileTransactedW succeeded.
//
// Explicitly NOT done:
//   - NO handle is ever opened to any file on a VSS path.
//   - NO access of any kind to \Windows\System32\Config\SAM, SAM hive, LSA keys,
//     SYSTEM\CurrentControlSet\Control\Lsa, or SAM\Domains\Account.
//   - NO offreg use. No samlib.dll. No credential, token, or service APIs.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	TEST_UUID      = "5e59dd6a-6c87-4377-942c-ea9b5e054cb9"
	TECHNIQUE_ID   = "T1211"
	TECHNIQUE_NAME = "VSS Device Enumeration + Transacted-Open on Sandbox File"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// ==============================================================================
// Native API bindings
// ==============================================================================

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

type objectDirectoryInformation struct {
	Name     unicodeString
	TypeName unicodeString
}

const (
	directoryQuery uint32 = 0x0001
)

var (
	ntdll                      = syscall.NewLazyDLL("ntdll.dll")
	procNtOpenDirectoryObject  = ntdll.NewProc("NtOpenDirectoryObject")
	procNtQueryDirectoryObject = ntdll.NewProc("NtQueryDirectoryObject")
	procRtlInitUnicodeString   = ntdll.NewProc("RtlInitUnicodeString")
	procNtClose                = ntdll.NewProc("NtClose")

	ktmw32                  = syscall.NewLazyDLL("ktmw32.dll")
	procCreateTransaction   = ktmw32.NewProc("CreateTransaction")
	procRollbackTransaction = ktmw32.NewProc("RollbackTransaction")

	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileTransactedW = kernel32.NewProc("CreateFileTransactedW")
	procCloseHandleK          = kernel32.NewProc("CloseHandle")
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	// Part A — VSS device enumeration (read-only recon)
	vssCount, enumErr := enumerateVSSDevices()
	if enumErr != nil {
		// We treat enumeration failure as an error (prerequisite), not a block,
		// because NtOpenDirectoryObject on \Device is normally permitted for
		// standard users. Describe the operation only.
		fmt.Printf("[STAGE %s] VSS enumeration errored: %v\n", TECHNIQUE_ID, enumErr)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("VSS enumeration errored: %v", enumErr))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", enumErr.Error())
		os.Exit(StageError)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("VSS device enumeration complete — %d HarddiskVolumeShadowCopy entries observed", vssCount))

	// Part B (v2 lift B3) — WMI shadow-copy enumeration. Read-only WQL
	// query against the Win32_ShadowCopy provider. Never invokes .Create()
	// or .Delete(). Failure here is non-fatal — Part C still runs.
	wmiCount, wmiErr := enumerateShadowsViaWMI()
	if wmiErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("WMI shadow enumeration errored (non-fatal): %v", wmiErr))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("WMI Win32_ShadowCopy enumeration complete — %d shadow copies reported", wmiCount))
	}

	// Part C — transacted-open probe on a benign sandbox target. We NEVER
	// target a VSS path or any real system file. If the sandbox file exists
	// we transacted-open it and immediately close+rollback.
	if err := transactedOpenProbe(); err != nil {
		fmt.Printf("[STAGE %s] Transacted-open probe errored: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Transacted-open probe errored: %v", err))
		exitCode := classifyError(err)
		if exitCode == StageBlocked {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Recon + WMI enum + transacted-open primitives exercised\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "VSS enumeration + WMI shadow enum + transacted-open primitives exercised")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", fmt.Sprintf("VSS entries seen=%d; WMI shadows reported=%d; transacted-open on sandbox file executed", vssCount, wmiCount))
	os.Exit(StageSuccess)
}

// enumerateShadowsViaWMI runs a read-only WQL query against Win32_ShadowCopy
// via PowerShell's Get-WmiObject cmdlet. The query is purely enumerative —
// it NEVER invokes the Create() or Delete() methods of Win32_ShadowCopy.
// Detection surface: powershell.exe spawn + WmiPrvSE.exe activity + Win32_ShadowCopy
// provider query. Returns the count of shadow copies reported, or an error.
func enumerateShadowsViaWMI() (int, error) {
	// Read-only WQL via PowerShell. Output is captured and counted; we do not
	// keep handles to any shadow path.
	cmd := exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		"$shadows = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue; if ($shadows) { ($shadows | Measure-Object).Count } else { 0 }")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("powershell Get-WmiObject Win32_ShadowCopy: %v (output: %s)", err, string(out))
	}
	countStr := strings.TrimSpace(string(out))
	var count int
	if _, parseErr := fmt.Sscanf(countStr, "%d", &count); parseErr != nil {
		// Empty output means zero shadow copies — common on workstations.
		count = 0
	}
	return count, nil
}

// enumerateVSSDevices opens \Device and counts HarddiskVolumeShadowCopy* entries.
// Read-only: no child object is ever opened.
func enumerateVSSDevices() (int, error) {
	deviceStr, _ := syscall.UTF16PtrFromString(`\Device`)

	var us unicodeString
	procRtlInitUnicodeString.Call(uintptr(unsafe.Pointer(&us)), uintptr(unsafe.Pointer(deviceStr)))

	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &us

	var hDir syscall.Handle
	status, _, _ := procNtOpenDirectoryObject.Call(
		uintptr(unsafe.Pointer(&hDir)),
		uintptr(directoryQuery),
		uintptr(unsafe.Pointer(&oa)),
	)
	if status != 0 {
		return 0, fmt.Errorf("NtOpenDirectoryObject(\\Device) NTSTATUS=0x%08x", uint32(status))
	}
	defer procNtClose.Call(uintptr(hDir))

	// Query loop
	buf := make([]byte, 64*1024)
	var context uint32
	var returned uint32
	count := 0
	matched := 0

	for {
		status, _, _ := procNtQueryDirectoryObject.Call(
			uintptr(hDir),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			0, // ReturnSingleEntry = FALSE (return multiple)
			0, // RestartScan = FALSE
			uintptr(unsafe.Pointer(&context)),
			uintptr(unsafe.Pointer(&returned)),
		)
		if status != 0 {
			// NTSTATUS 0x8000001A == STATUS_NO_MORE_ENTRIES
			if uint32(status) == 0x8000001A {
				break
			}
			return matched, fmt.Errorf("NtQueryDirectoryObject NTSTATUS=0x%08x", uint32(status))
		}

		// Walk entries until we hit a zero-length entry (terminator)
		ptr := unsafe.Pointer(&buf[0])
		entrySize := unsafe.Sizeof(objectDirectoryInformation{})
		for {
			entry := (*objectDirectoryInformation)(ptr)
			if entry.Name.Length == 0 && entry.Name.Buffer == nil {
				break
			}
			count++
			// Safely materialize the name from the native UTF-16 buffer
			if entry.Name.Buffer != nil && entry.Name.Length > 0 {
				nameLen := int(entry.Name.Length) / 2
				nameSlice := (*[1 << 16]uint16)(unsafe.Pointer(entry.Name.Buffer))[:nameLen:nameLen]
				name := syscall.UTF16ToString(nameSlice)
				if hasPrefix(name, "HarddiskVolumeShadowCopy") {
					matched++
					LogMessage("DEBUG", TECHNIQUE_ID, fmt.Sprintf("Observed VSS device: %s (read-only, not opened)", name))
				}
			}
			ptr = unsafe.Pointer(uintptr(ptr) + entrySize)
			// Safety: don't walk past buffer
			if uintptr(ptr)-uintptr(unsafe.Pointer(&buf[0])) >= uintptr(len(buf)) {
				break
			}
		}
		// Break if query returned with context==0 (no restart needed) — single pass is enough.
		if returned == 0 {
			break
		}
		// One pass is sufficient for detection-coverage measurement.
		break
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("NtQueryDirectoryObject walk: %d entries inspected, %d matched HarddiskVolumeShadowCopy*", count, matched))
	return matched, nil
}

// transactedOpenProbe runs CreateTransaction + CreateFileTransactedW against
// a BENIGN SANDBOX TARGET. It never touches VSS paths or system files.
func transactedOpenProbe() error {
	sandboxDir := filepath.Join(ARTIFACT_DIR, "BlueHammerSandbox")
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		return fmt.Errorf("create sandbox directory: %v", err)
	}
	probePath := filepath.Join(sandboxDir, "transacted-probe.txt")
	seed := []byte("F0RT1KA BlueHammer transacted-open sandbox target. Safe to delete.\r\n")
	if err := os.WriteFile(probePath, seed, 0644); err != nil {
		return fmt.Errorf("seed transacted-open target: %v", err)
	}
	LogFileDropped("transacted-probe.txt", probePath, int64(len(seed)), false)
	defer os.Remove(probePath)

	LogMessage("INFO", TECHNIQUE_ID, "Calling CreateTransaction()")
	hTransactionRaw, _, callErr := procCreateTransaction.Call(
		0, 0, 0, 0, 0, 0, 0,
	)
	// CreateTransaction returns INVALID_HANDLE_VALUE (-1) on failure.
	if hTransactionRaw == 0 || int(hTransactionRaw) == -1 {
		return fmt.Errorf("CreateTransaction returned invalid handle errno=%v", callErr)
	}
	hTransaction := syscall.Handle(hTransactionRaw)
	defer procCloseHandleK.Call(uintptr(hTransaction))
	// Always roll back — the transaction is never committed, regardless of outcome.
	defer procRollbackTransaction.Call(uintptr(hTransaction))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Calling CreateFileTransactedW on sandbox target: %s", probePath))
	probeUTF16, _ := syscall.UTF16PtrFromString(probePath)
	hFileRaw, _, fileErr := procCreateFileTransactedW.Call(
		uintptr(unsafe.Pointer(probeUTF16)),
		uintptr(syscall.GENERIC_READ),
		uintptr(syscall.FILE_SHARE_READ),
		0,
		uintptr(syscall.OPEN_EXISTING),
		uintptr(syscall.FILE_ATTRIBUTE_NORMAL),
		0,
		uintptr(hTransaction),
		0,
		0,
	)
	hFile := syscall.Handle(hFileRaw)

	if int(hFileRaw) == -1 || hFile == syscall.InvalidHandle {
		// Describe the operation only
		return fmt.Errorf("CreateFileTransactedW returned invalid handle errno=%v", fileErr)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "CreateFileTransactedW returned a handle on sandbox target — closing immediately")
	procCloseHandleK.Call(uintptr(hFile))
	// Deferred RollbackTransaction + CloseHandle on transaction run next.
	return nil
}

// classifyError — conservative, no generic blame keywords (bug-prevention rule #1)
func classifyError(err error) int {
	if err == nil {
		return StageSuccess
	}
	s := err.Error()
	if has(s, "errno=5") { // ERROR_ACCESS_DENIED
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

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
