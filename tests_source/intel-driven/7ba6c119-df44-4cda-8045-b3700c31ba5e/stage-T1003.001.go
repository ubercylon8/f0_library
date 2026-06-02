// Stage 4 — T1003.001 OS Credential Dumping: LSASS Memory
// F0RT1KA Security Testing Framework
//
// The terminal objective of KslKatz is to read LSASS memory and parse credential
// material (the GhostKatz/Mimikatz half of the framework). On a clean host the
// framework would normally do this through its kernel primitive (KslD MmCopyMemory,
// bypassing PPL), but the user-mode access primitive — OpenProcess against lsass.exe
// with PROCESS_VM_READ from a non-whitelisted binary — is itself the high-confidence
// detection signal that EDR keys on (Sysmon EID 10 / DeviceEvents OpenProcess to
// lsass with read access).
//
// SAFETY (realism-first with a hard safety gate):
//   - We enumerate running processes to LOCATE lsass.exe (handle enumeration is part
//     of the genuine access primitive and the detection surface).
//   - We ATTEMPT OpenProcess(lsass, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION). The
//     access EVENT is what fires telemetry, so it genuinely happens.
//   - We issue NO ReadProcessMemory, NO MiniDumpWriteDump, NO NtReadVirtualMemory.
//     We parse NO secrets and write NO dump file. The handle is closed immediately.
// No real credentials are ever exposed. Nothing on disk is created or modified.

//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	TEST_UUID = "7ba6c119-df44-4cda-8045-b3700c31ba5e"

	TECHNIQUE_ID   = "T1003.001"
	TECHNIQUE_NAME = "OS Credential Dumping: LSASS Memory (access primitive only)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// The process whose memory KslKatz/GhostKatz ultimately targets.
const lsassImageName = "lsass.exe"

// The access mask a credential dumper requests: VM_READ to read secret material,
// QUERY_INFORMATION to resolve the target. This mask + lsass target = the signal.
const lsassAccessMask = windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage ID: %d", STAGE_ID))

	if err := performTechnique(); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Outcome: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "LSASS access primitive completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	LogMessage("INFO", TECHNIQUE_ID, "Simulating KslKatz/GhostKatz terminal objective: LSASS credential access")
	LogMessage("WARN", TECHNIQUE_ID, "Detection signal: OpenProcess(lsass.exe, PROCESS_VM_READ) from a non-whitelisted binary")

	// Step 1: Enumerate running processes to locate lsass.exe. Handle/process
	// enumeration is part of the genuine credential-access primitive.
	pid, err := findProcessByName(lsassImageName)
	if err != nil {
		// Could not snapshot the process list — genuine prerequisite problem.
		return fmt.Errorf("process enumeration returned: %v", err)
	}
	if pid == 0 {
		// lsass.exe not located. On any real Windows host lsass is always running;
		// absence means we could not observe it (e.g., heavily restricted context).
		// Treat as a benign prerequisite miss — the enumeration telemetry fired.
		LogMessage("INFO", TECHNIQUE_ID, "lsass.exe not located in process snapshot - benign prerequisite miss; enumeration telemetry generated")
		return nil
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Located %s (PID %d)", lsassImageName, pid))

	// Step 2: Attempt to open lsass.exe with read access. THE access event is the
	// detection signal — we request VM_READ but read NO memory.
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Attempting OpenProcess(PID %d, PROCESS_VM_READ|QUERY_INFORMATION) - access primitive only, no memory read", pid))

	handle, err := windows.OpenProcess(lsassAccessMask, false, pid)
	if err != nil {
		// ERROR_ACCESS_DENIED on lsass for a process that would normally obtain the
		// handle (admin/SYSTEM context) indicates a protection layer interfered —
		// PPL, an EDR mini-filter, or a credential-guard ACL denied the handle.
		// We surface the OS error verbatim; classification (block vs. benign) is
		// done in determineExitCode WITHOUT injecting blame keywords here.
		return fmt.Errorf("lsass handle open returned: %v", err)
	}

	// Handle acquired. Close it IMMEDIATELY — we issue NO ReadProcessMemory and
	// take NO dump. Acquiring a readable handle to lsass unhindered is exactly the
	// unprotected primitive this test measures.
	defer windows.CloseHandle(handle)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Acquired PROCESS_VM_READ handle to %s (PID %d) - NO memory read issued (safety boundary)", lsassImageName, pid))
	LogMessage("SUCCESS", TECHNIQUE_ID, "LSASS read-access handle obtained unhindered - credential-access primitive is unprotected")
	return nil
}

// findProcessByName walks a Toolhelp process snapshot and returns the PID of the
// first process whose image name matches (case-insensitive). Returns 0 if not found.
func findProcessByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("snapshot creation returned: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, fmt.Errorf("first process read returned: %v", err)
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if equalsIgnoreCase(exeName, name) {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			// ERROR_NO_MORE_FILES => walked the whole list, no match.
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, nil
			}
			return 0, fmt.Errorf("next process read returned: %v", err)
		}
	}
}

// determineExitCode classifies the outcome. Per Bug Prevention Rule 1, errors from
// performTechnique describe the OPERATION, never the cause. We classify on the
// OS-produced denial tokens (access-denied) the kernel itself emits, distinguishing
// a real protection block from a benign prerequisite failure.
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()

	// OS-produced denial tokens on the lsass handle => a protection layer worked
	// (PPL / EDR mini-filter / Credential Guard denied the read handle).
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Genuine prerequisite problems (could not snapshot / enumerate).
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "enumeration returned", "snapshot creation"}) {
		return StageError
	}
	// Conservative default: an unexpected interference is treated as a block.
	return StageBlocked
}

func equalsIgnoreCase(a, b string) bool {
	return len(a) == len(b) && indexIgnoreCase(a, b) == 0
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLower(s)
	substr = toLower(substr)
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
