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
//
// BLOCK ATTRIBUTION (added 2026-06-01):
//   When OpenProcess is denied, the stage performs a best-effort probe to distinguish
//   between three possible causes:
//     1. LSA Protection (PPL) — HKLM\...\Lsa RunAsPPL/RunAsPPLBoot + WinInit Event 12
//     2. Credential Guard — DeviceGuard-enabled virtualisation-based security
//     3. EDR handle-stripping — a user-mode or kernel mini-filter denied the handle
//        without the above platform controls being active
//   The attribution is logged to the result JSON (BlockedBy field) and to stdout.
//   Exit code remains 126 regardless — a real OS denial of a normally-succeeding
//   operation is positive block evidence (Bug Prevention Rule 8). The attribution is
//   HONEST: kslkatz bypasses PPL via its BYOVD kernel path, which this test does NOT
//   exercise (safety). A 126 here means "baseline PPL stopped naive user-mode reads",
//   NOT "the endpoint detects/prevents kslkatz."

//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

// lastAttribution is populated by attributeHandleDenial() inside performTechnique()
// when OpenProcess is denied. main() reads it to enrich the LogStageBlocked call
// so the attribution lands in the result JSON's BlockedBy field.
var lastAttribution string

// The access mask a credential dumper requests: VM_READ to read secret material,
// QUERY_INFORMATION to resolve the target. This mask + lsass target = the signal.
const lsassAccessMask = windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage ID: %d", STAGE_ID))

	if err := performTechnique(); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Outcome: %v", err))
		// Enrich BlockedBy with the attribution string when available; otherwise
		// fall back to the raw OS error. This ensures the result JSON's blockedBy
		// field carries the analyst-readable attribution, not just "access is denied".
		blockedReason := err.Error()
		if lastAttribution != "" {
			blockedReason = fmt.Sprintf("%s | Attribution: %s", err.Error(), lastAttribution)
		}
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, blockedReason)
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
		//
		// Before returning, probe the likely cause so analysts reading the log have
		// an honest attribution rather than a bare "access is denied".
		attribution := attributeHandleDenial()
		LogMessage("WARN", TECHNIQUE_ID, attribution)
		// Persist the attribution to a sidecar file so the orchestrator can read
		// it before it overwrites test_execution_log.json. This survives the stage
		// process boundary and makes the attribution available in both the stage's
		// blockedBy field and the orchestrator's phase/bundle details.
		_ = os.WriteFile(
			filepath.Join(LOG_DIR, "stage-T1003.001-attribution.txt"),
			[]byte(attribution),
			0644,
		)
		// Wire attribution into the BlockedBy JSON field via LogStageBlocked.
		// LogStageBlocked is called by main() after this function returns an error,
		// so we store the attribution in a package-level variable that main() picks
		// up and appends to the reason string.
		lastAttribution = attribution
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

// ==============================================================================
// BLOCK ATTRIBUTION — best-effort probe to distinguish PPL / Credential Guard /
// EDR handle-stripping. Called only when OpenProcess returns access-denied.
// All reads are non-mutating. Failures are swallowed; attribution degrades
// gracefully (we log what we can and note "unknown" for what we cannot).
// ==============================================================================

// attributeHandleDenial probes the three plausible causes of an access-denied
// on lsass and returns a single human-readable attribution string suitable for
// both the log line and the result JSON's blockedBy field.
func attributeHandleDenial() string {
	pplLevel, runAsPPL, pplBoot := probePPLRegistry()
	wevtLevel := probeWinInitEvent12()
	credGuard := probeCredentialGuard()

	// Determine effective PPL level: Event 12 is most authoritative, then registry.
	effectivePPLLevel := -1
	pplSource := ""
	if wevtLevel >= 0 {
		effectivePPLLevel = wevtLevel
		pplSource = "WinInit Event 12"
	} else if pplLevel >= 0 {
		effectivePPLLevel = pplLevel
		pplSource = fmt.Sprintf("registry RunAsPPL=%d RunAsPPLBoot=%d", runAsPPL, pplBoot)
	}

	// Build the attribution.
	var sb strings.Builder
	sb.WriteString("T1003.001 VM_READ denial attribution — ")

	if effectivePPLLevel >= 0 {
		sb.WriteString(fmt.Sprintf(
			"LSA Protection (PPL) ACTIVE: protection level %d (source: %s). "+
				"This is a PLATFORM CONFIG control, NOT a confirmed EDR detection. "+
				"NOTE: kslkatz bypasses PPL via BYOVD kernel MmCopyMemory reads — "+
				"a path this test does NOT exercise (safety boundary). "+
				"A 126 here means baseline LSASS hardening stopped naive user-mode reads, "+
				"it does NOT indicate the endpoint detects or prevents kslkatz.",
			effectivePPLLevel, pplSource,
		))
		if credGuard {
			sb.WriteString(" Credential Guard is also reported ACTIVE (may contribute to denial).")
		} else {
			sb.WriteString(" Credential Guard: not detected as active.")
		}
		return sb.String()
	}

	// PPL not detected — check Credential Guard.
	if credGuard {
		sb.WriteString(
			"LSA Protection (PPL) NOT detected in registry/event log. " +
				"Credential Guard appears ACTIVE — this may have contributed to the denial. " +
				"Consider correlating with Get-CimInstance Win32_DeviceGuard and MDE Advanced Hunting " +
				"to confirm the blocking layer.",
		)
		return sb.String()
	}

	// Neither PPL nor Credential Guard detected — likely EDR handle-stripping.
	sb.WriteString(
		"LSA Protection (PPL) NOT detected (RunAsPPL absent or 0, no WinInit Event 12). " +
			"Credential Guard NOT detected. " +
			"The denial is attributable to a non-PPL layer — likely EDR kernel handle-stripping " +
			"or a driver-level OpenProcess hook. This warrants EDR Advanced Hunting " +
			"(DeviceEvents: OpenProcessApiCall targeting lsass) to identify the blocking product.",
	)
	return sb.String()
}

// probePPLRegistry reads HKLM\SYSTEM\CurrentControlSet\Control\Lsa for RunAsPPL
// and RunAsPPLBoot. Returns (effectiveLevel, runAsPPL, runAsPPLBoot).
// effectiveLevel is -1 if PPL is not enabled or the key cannot be read.
func probePPLRegistry() (effectiveLevel int, runAsPPL int, runAsPPLBoot int) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return -1, 0, 0
	}
	defer key.Close()

	rPPL, _, _ := key.GetIntegerValue("RunAsPPL")
	rBoot, _, _ := key.GetIntegerValue("RunAsPPLBoot")
	runAsPPL = int(rPPL)
	runAsPPLBoot = int(rBoot)

	if runAsPPL > 0 {
		return runAsPPL, runAsPPL, runAsPPLBoot
	}
	if runAsPPLBoot > 0 {
		return runAsPPLBoot, runAsPPL, runAsPPLBoot
	}
	return -1, runAsPPL, runAsPPLBoot
}

// probeWinInitEvent12 queries the System event log for the most recent WinInit
// Event ID 12, which records the lsass protection level at boot:
//   "LSASS.exe was started as a protected process with level: N"
// Returns the protection level integer, or -1 if the event is not found or
// wevtutil is unavailable.
func probeWinInitEvent12() int {
	// wevtutil qe: query events; /rd:true = read most-recent first; /c:1 = one event
	cmd := exec.Command(
		"wevtutil", "qe", "System",
		"/q:*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=12)]]",
		"/c:1", "/rd:true", "/f:text",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil // suppress stderr
	if err := cmd.Run(); err != nil {
		return -1
	}
	output := out.String()
	// Parse "protected process with level: N"
	marker := "protected process with level:"
	idx := strings.Index(strings.ToLower(output), strings.ToLower(marker))
	if idx < 0 {
		return -1
	}
	rest := strings.TrimSpace(output[idx+len(marker):])
	// rest should start with the level digit(s); take up to the first non-digit
	var numStr strings.Builder
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' {
			numStr.WriteRune(ch)
		} else {
			break
		}
	}
	if numStr.Len() == 0 {
		return -1
	}
	level, err := strconv.Atoi(numStr.String())
	if err != nil {
		return -1
	}
	return level
}

// probeCredentialGuard reads the DeviceGuard-related LSA registry value
// (LsaCfgFlags) to determine if Credential Guard is enabled. Returns true if
// any non-zero value is present; does not distinguish mode (enabled vs. strict).
func probeCredentialGuard() bool {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return false
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("LsaCfgFlags")
	if err != nil {
		return false
	}
	return val != 0
}

// determineExitCode classifies the outcome. Per Bug Prevention Rules 1 and 8:
// - Errors describe the OPERATION, never inject blame keywords.
// - Block codes (126) require POSITIVE evidence of a real protection action.
// - For Stage 4, access-denied on lsass OpenProcess IS positive block evidence:
//   running as SYSTEM/admin, a denial on lsass means PPL/EDR/CredGuard acted.
// - Unknown/unrecognized errors map to StageError (999), NOT StageBlocked.
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errLower := strings.ToLower(err.Error())

	// OS-produced denial tokens on the lsass handle => positive evidence a
	// protection layer worked (PPL / EDR mini-filter / Credential Guard denied
	// the read handle). This is legitimate as SYSTEM/admin normally succeeds.
	for _, token := range []string{"access is denied", "access denied", "permission denied", "operation not permitted"} {
		if strings.Contains(errLower, token) {
			return StageBlocked
		}
	}
	// Genuine prerequisite problems (could not snapshot / enumerate).
	for _, token := range []string{"not found", "does not exist", "no such", "enumeration returned", "snapshot creation"} {
		if strings.Contains(errLower, token) {
			return StageError
		}
	}
	// Unknown/unrecognized error — per Rule 8, absence of success is NOT a block.
	return StageError
}

// equalsIgnoreCase is kept for process name comparison in findProcessByName.
func equalsIgnoreCase(a, b string) bool {
	return strings.EqualFold(a, b)
}
