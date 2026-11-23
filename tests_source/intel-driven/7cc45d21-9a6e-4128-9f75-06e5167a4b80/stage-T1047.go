// Stage 3 — T1047 WMI Lateral Movement + T1021.002 SMB/Admin Shares + T1021.001 RDP (non-gating beat)
// F0RT1KA Security Testing Framework
// The Gentlemen (GOLD SHERWOOD) — Objective 3: living-off-the-land lateral movement
//
// The Gentlemen spreads with legitimate tooling rather than custom malware:
// NetExec/nxc, WMI, PsExec and RDP (spec; Trend Micro: PsExec used for lateral
// movement; Sophos CTU: rapid RDP pivots between internal systems). This
// stage reproduces the LOLBin lateral primitives against LOOPBACK ONLY:
//
//   1. T1047 — WMI remote process creation against 127.0.0.1: the actor-era
//      wmic shape (/node: process call create) with a faithful PowerShell
//      DCOM fallback (New-CimSession -Protocol DCOM + Invoke-CimMethod
//      Win32_Process.Create) when wmic is removed (Win11 24H2+). The created
//      process is cmd.exe writing a benign marker into LOG_DIR.
//   2. NetExec identifier shape (fail-harmless): the actor's nxc smb command
//      line is fired against loopback; nxc is not present on the host so the
//      attempt fails fast. This generates the exact command-line telemetry
//      EDR sensors key on; it is explicitly NON-GATING.
//   3. T1021.002 — loopback SMB session to \\127.0.0.1\ADMIN$ (PsExec's
//      prerequisite; the actor used PsExec) + benign marker transfer into
//      ADMIN$\Temp, verified with os.Stat, then deleted; session torn down
//      (LockBit stage-3 pattern).
//   4. T1021.001 — RDP context beat (non-gating): READ-ONLY registry query
//      of fDenyTSConnections (the actor flips this value; we never write it)
//      plus a loopback TCP probe of 127.0.0.1:3389. Never mutates state.
//
// HARD SAFETY BOUNDARIES:
//   - Loopback only: every remote target is hardcoded to 127.0.0.1. No egress.
//   - NO service is created or started; no remote code beyond a cmd.exe
//     writing a marker INSIDE LOG_DIR.
//   - The transferred "binary" is a text marker with an .exe name — it can
//     never execute.
//   - RDP leg is read-only (registry query + TCP connect).
//
// CLASSIFICATION (Rule 8): blocked only on positive denial evidence in an
// elevated context (where these loopback operations normally succeed). SMB
// unavailability (errors 53/67), DCOM/RPC unavailability, and missing wmic
// are prerequisite conditions, not protection actions -> 999.
//
// ASR ATTRIBUTION: when the WMI leg does not produce its marker, the stage
// queries Microsoft-Windows-Windows Defender/Operational for event 1121 (ASR
// rule BLOCK) carrying rule d1e49aac-8f56-4280-b9ba-993a6d77406c ("Block
// process creations originating from PSExec and WMI commands") inside the
// stage time window. A matching 1121 is positive prevention evidence -> 126.
// Event 1122 (audit mode) is logged for context but is NOT prevention.
//
// EXIT CODES: 0 = WMI execution AND ADMIN$ transfer unimpeded, 126 = positive
// denial evidence on a critical leg (incl. ASR 1121 on the WMI leg),
// 999 = prerequisite/test error with no prevention evidence.

//go:build windows
// +build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
	TECHNIQUE_ID   = "T1047"
	TECHNIQUE_NAME = "LOLBin Lateral Movement: WMI/SMB/NetExec shape (T1047/T1021.002/T1021.001, loopback)"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Loopback-only targets (hardcoded — no egress beyond 127.0.0.1 is possible).
const (
	smbTarget     = `\\127.0.0.1\ADMIN$`
	markerName    = "nxcsvc.exe"
	markerRelPath = `Temp\nxcsvc.exe`
	wmiMarkerPath = `C:\F0\gentlemen_wmi_marker.txt`
)

// Defender ASR rule "Block process creations originating from PSExec and WMI
// commands". Event 1121 with this ID = block (prevention); 1122 = audit only.
const (
	asrPsexecWmiRuleID = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
	asrEventBlock      = 1121
	asrEventAudit      = 1122
	// Clock slack applied before the WMI call when querying the event log.
	asrWindowSlack = 5 * time.Second
	// Defender can write 1121 slightly after the WMI call returns; poll briefly.
	asrPollAttempts = 3
	asrPollInterval = 2 * time.Second
)

var (
	reReturnValue = regexp.MustCompile(`(?i)ReturnValue\s*=\s*(-?\d+)`)
	reProcessID   = regexp.MustCompile(`(?i)ProcessId\s*=\s*(\d+)`)
)

var elevatedContext bool

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevatedContext = isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevatedContext, isSystemContext()))

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Lateral movement primitives executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "WMI loopback execution and ADMIN$ transfer completed unimpeded")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Loopback WMI execution and ADMIN$ tool transfer unimpeded")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Lateral movement prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "WMI or ADMIN$ leg positively prevented")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Loopback lateral movement denied with positive evidence", StageBlocked)
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Lateral movement stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Leg 1: WMI remote process creation on loopback (T1047)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Leg 1: WMI process creation against 127.0.0.1 (T1047)\n", TECHNIQUE_ID)

	_ = os.Remove(wmiMarkerPath) // clean slate from prior runs

	wmiOK := wmiProcessCreate()
	if wmiOK == StageBlocked {
		return StageBlocked
	}

	// ------------------------------------------------------------------
	// Leg 2: NetExec command-shape probe (identifier fidelity, non-gating)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Leg 2: NetExec/nxc command-shape probe (non-gating)\n", TECHNIQUE_ID)
	nxcCmd := exec.Command("cmd.exe", "/Q", "/c", "nxc smb 127.0.0.1 -u fortika-probe -p --sam")
	nxcOut, nxcErr := nxcCmd.CombinedOutput()
	LogProcessExecution("nxc.exe", "nxc smb 127.0.0.1 -u fortika-probe -p --sam", 0, nxcErr == nil, 0,
		strings.TrimSpace(string(nxcOut)))
	if nxcErr != nil {
		// Expected: nxc is not installed — the attempt exists for process-
		// creation telemetry with the actor's exact argument shape.
		LogMessage("INFO", TECHNIQUE_ID, "nxc not present on host (expected) - NetExec shape telemetry emitted, non-gating")
	}

	// ------------------------------------------------------------------
	// Leg 3: SMB session to loopback ADMIN$ + tool transfer (T1021.002/T1570)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Leg 3: SMB session to %s (T1021.002, loopback only)\n", TECHNIQUE_ID, smbTarget)
	LogMessage("WARN", "T1021.002", "T1021.002: net use \\\\127.0.0.1\\ADMIN$ — loopback lateral session telemetry (PsExec prerequisite)")

	cmd := exec.Command("net.exe", "use", smbTarget)
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	outLower := strings.ToLower(outStr)
	LogProcessExecution("net.exe", fmt.Sprintf("net use %s", smbTarget), 0, runErr == nil, 0, outStr)

	if runErr == nil {
		LogMessage("INFO", TECHNIQUE_ID, "SMB session to loopback ADMIN$ established")
	} else {
		switch {
		case strings.Contains(outLower, "system error 5") || strings.Contains(outLower, "access is denied"):
			if elevatedContext {
				// Elevated loopback ADMIN$ normally succeeds — denial here is
				// positive evidence of a policy/EDR action.
				LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("SMB session denied in elevated context (positive evidence): %s", outStr))
				return StageBlocked
			}
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("SMB session denied in non-elevated context (ACL, not attributable): %s", outStr))
			return stageVerdict(wmiOK, false)
		case strings.Contains(outLower, "system error 53") ||
			strings.Contains(outLower, "system error 67") ||
			strings.Contains(outLower, "system error 1223") ||
			strings.Contains(outLower, "network path was not found") ||
			strings.Contains(outLower, "network name cannot be found"):
			// Server service off / SMB unavailable — prerequisite, not a block.
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("SMB server unavailable on loopback (prerequisite miss): %s", outStr))
			return stageVerdict(wmiOK, false)
		default:
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("net use returned unrecognized failure (inconclusive): %v | %s", runErr, outStr))
			return stageVerdict(wmiOK, false)
		}
	}

	// Session teardown is best-effort and always attempted.
	defer func() {
		delCmd := exec.Command("net.exe", "use", smbTarget, "/delete", "/y")
		delOut, _ := delCmd.CombinedOutput()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("cleanup: net use /delete returned: %s", strings.TrimSpace(string(delOut))))
	}()

	// Lateral tool transfer (T1570): benign marker into ADMIN$\Temp, verify, delete.
	markerPath := filepath.Join(smbTarget, markerRelPath)
	fmt.Printf("[STAGE %s] Transferring benign marker to %s\n", TECHNIQUE_ID, markerPath)
	LogMessage("WARN", "T1570", "T1570: lateral tool transfer of benign marker binary into ADMIN$\\Temp (loopback)")

	markerContent := buildMarkerContent()
	if err := os.WriteFile(markerPath, []byte(markerContent), 0644); err != nil {
		if elevatedContext && isOSDenial(err) {
			LogMessage("WARN", "T1570", fmt.Sprintf("Tool transfer write returned OS denial in elevated context (positive evidence): %v", err))
			return StageBlocked
		}
		LogMessage("ERROR", "T1570", fmt.Sprintf("Tool transfer write failed (not attributable to protection): %v", err))
		return stageVerdict(wmiOK, false)
	}
	LogFileDropped(markerName, markerPath, int64(len(markerContent)), false)

	time.Sleep(500 * time.Millisecond)
	transferOK := false
	if fi, statErr := os.Stat(markerPath); statErr == nil {
		transferOK = true
		LogMessage("CRITICAL", "T1570", fmt.Sprintf("Marker verified on ADMIN$ (%d bytes) - lateral transfer unimpeded", fi.Size()))
	} else {
		// Written but immediately gone — possible AV sweep. Treat as
		// inconclusive unless the write path itself showed denial evidence.
		LogMessage("WARNING", "T1570", fmt.Sprintf("Marker not present after write (stat: %v) - inconclusive", statErr))
	}

	if delErr := os.Remove(markerPath); delErr != nil {
		LogMessage("WARNING", "T1570", fmt.Sprintf("cleanup: failed to delete marker: %v", delErr))
	} else {
		LogMessage("INFO", "T1570", "cleanup: marker removed from ADMIN$")
	}

	// ------------------------------------------------------------------
	// Leg 4: RDP context beat (T1021.001, non-gating, read-only)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Leg 4: RDP context probe (T1021.001, non-gating, read-only)\n", TECHNIQUE_ID)
	rdpBeat()

	return stageVerdict(wmiOK, transferOK)
}

// wmiProcessCreate performs the T1047 leg. Returns StageSuccess when the
// loopback WMI process creation succeeded and the marker landed,
// StageBlocked on positive denial evidence (OS access denial in an elevated
// context, or a Defender ASR 1121 block for the PSExec/WMI rule inside the
// stage window), StageError only when the failure is unexplained.
func wmiProcessCreate() int {
	windowStart := time.Now().Add(-asrWindowSlack)

	result := wmiProcessCreateAttempt()
	if result != StageError {
		return result
	}

	// The WMI leg failed without positive OS denial evidence. Before calling
	// it inconclusive, check whether Defender ASR prevented the WMI-spawned
	// child (the typical ASR behaviour: Win32_Process.Create is accepted but
	// the child process is blocked, so the marker never lands).
	if blocked, detail := checkASRWmiBlock(windowStart); blocked {
		LogMessage("WARN", "T1047", fmt.Sprintf(
			"WMI child process creation BLOCKED by Defender ASR rule %s (Block process creations originating from PSExec and WMI commands) - Defender event %d: %s",
			asrPsexecWmiRuleID, asrEventBlock, detail))
		return StageBlocked
	}

	LogMessage("ERROR", "T1047", "WMI leg failed with no ASR block (event 1121) or OS denial evidence - inconclusive")
	return StageError
}

// wmiProcessCreateAttempt runs the WMI process creation and classifies the
// direct result. ASR attribution is done by the caller.
func wmiProcessCreateAttempt() int {
	wmicPath, _ := exec.LookPath("wmic.exe")

	var cmd *exec.Cmd
	var display string
	if wmicPath != "" {
		display = fmt.Sprintf(`wmic /node:127.0.0.1 process call create "cmd.exe /c echo GENTLEMEN_WMI_MARKER> %s"`, wmiMarkerPath)
		cmd = exec.Command("wmic.exe", "/node:127.0.0.1", "process", "call", "create",
			fmt.Sprintf(`cmd.exe /c echo GENTLEMEN_WMI_MARKER> %s`, wmiMarkerPath))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "wmic.exe not present (Win11 24H2 removal) - using PowerShell DCOM WMI fallback")
		psScript := fmt.Sprintf(
			`$so=New-CimSessionOption -Protocol DCOM; $s=New-CimSession -ComputerName 127.0.0.1 -SessionOption $so; $r=Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /c echo GENTLEMEN_WMI_MARKER> %s'}; if ($r) { Write-Output ('ReturnValue = {0}; ProcessId = {1};' -f $r.ReturnValue, $r.ProcessId) }`,
			strings.ReplaceAll(wmiMarkerPath, `\`, `\\`))
		display = "Invoke-CimMethod -CimSession DCOM(127.0.0.1) Win32_Process.Create (marker to LOG_DIR)"
		cmd = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	}

	LogMessage("WARN", "T1047", fmt.Sprintf("T1047: WMI remote process creation against 127.0.0.1: %s", display))
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	outLower := strings.ToLower(outStr)
	LogProcessExecution(filepath.Base(cmd.Path), display, 0, err == nil, 0, truncateOut(outStr))

	// Capture Win32_Process.Create's ReturnValue / ProcessId (wmic prints
	// them natively; the PowerShell fallback emits them in the same shape).
	returnValue, processID := "(not reported)", "(not reported)"
	if m := reReturnValue.FindStringSubmatch(outStr); m != nil {
		returnValue = m[1]
	}
	if m := reProcessID.FindStringSubmatch(outStr); m != nil {
		processID = m[1]
	}
	LogMessage("INFO", "T1047", fmt.Sprintf("Win32_Process.Create result: ReturnValue=%s ProcessId=%s", returnValue, processID))

	if err == nil || returnValue == "0" {
		// Give the spawned cmd.exe a moment to flush the marker file.
		time.Sleep(2 * time.Second)
		if _, statErr := os.Stat(wmiMarkerPath); statErr == nil {
			LogMessage("CRITICAL", "T1047", "WMI-created process verified via marker in LOG_DIR - remote execution unimpeded (loopback)")
			return StageSuccess
		}
		LogMessage("WARNING", "T1047", fmt.Sprintf(
			"WMI call returned (ReturnValue=%s ProcessId=%s) but marker file not found - checking for ASR prevention", returnValue, processID))
		return StageError
	}

	switch {
	case strings.Contains(outLower, "access is denied") || strings.Contains(outLower, "access denied"):
		if elevatedContext {
			LogMessage("WARN", "T1047", fmt.Sprintf("WMI process creation denied in elevated context (positive evidence): %s", outStr))
			return StageBlocked
		}
		LogMessage("WARNING", "T1047", fmt.Sprintf("WMI process creation denied in non-elevated context (DCOM launch rights, not attributable): %s", outStr))
		return StageError
	case strings.Contains(outLower, "invalid namespace") ||
		strings.Contains(outLower, "rpc server is unavailable") ||
		strings.Contains(outLower, "the rpc server is unavailable") ||
		strings.Contains(outLower, "not recognized"):
		// WMI/DCOM stack unavailable or wmic removed — prerequisite miss.
		LogMessage("ERROR", "T1047", fmt.Sprintf("WMI infrastructure unavailable (prerequisite miss): %s", outStr))
		return StageError
	default:
		LogMessage("ERROR", "T1047", fmt.Sprintf("WMI process creation unrecognized failure (inconclusive): %v | %s", err, outStr))
		return StageError
	}
}

// rdpBeat is the non-gating T1021.001 context probe: READ-ONLY registry query
// (fDenyTSConnections — the value The Gentlemen flips) + loopback 3389 probe.
func rdpBeat() {
	regCmd := exec.Command("reg.exe", "query", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	regOut, regErr := regCmd.CombinedOutput()
	LogProcessExecution("reg.exe", `reg query HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections (read-only)`,
		0, regErr == nil, 0, truncateOut(strings.TrimSpace(string(regOut))))

	conn, err := net.DialTimeout("tcp", "127.0.0.1:3389", 2*time.Second)
	if err != nil {
		LogMessage("INFO", "T1021.001", "loopback 3389 probe: RDP not listening (context beat, non-gating)")
		return
	}
	conn.Close()
	LogMessage("WARN", "T1021.001", "loopback 3389 probe: RDP listener present (context beat, non-gating)")
}

// stageVerdict combines the two critical legs (Rule 4: only critical metrics
// decide the stage). Both legs must have executed cleanly for success; any
// positive block short-circuits earlier (returns handled at call sites).
// A positive block on the WMI leg is never downgraded to 999 because the
// ADMIN$ leg failed for an unrelated (prerequisite) reason.
func stageVerdict(wmiResult int, transferOK bool) int {
	if wmiResult == StageBlocked || wmiResult == StageQuarantined {
		return wmiResult
	}
	if wmiResult == StageSuccess && transferOK {
		return StageSuccess
	}
	return StageError
}

// checkASRWmiBlock looks for Defender ASR evidence for the PSExec/WMI rule
// since windowStart. Returns true only for event 1121 (block). Event 1122
// (audit) is logged for context but is NOT prevention evidence. The rule ID
// is matched against the event XML (locale-independent), never the
// localized message text.
func checkASRWmiBlock(windowStart time.Time) (bool, string) {
	psScript := fmt.Sprintf(
		`$since=[DateTime]::Parse('%s',$null,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime(); `+
			`$ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=%d,%d; StartTime=$since} -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.ToXml() -match '%s' }; `+
			`foreach ($e in $ev) { $x=[xml]$e.ToXml(); $d=@{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n.'#text' }; `+
			`Write-Output ('F0ASR|{0}|{1}|{2}|{3}' -f $e.Id, $e.TimeCreated.ToUniversalTime().ToString('o'), $d['Path'], $d['Process Name']) }`,
		windowStart.UTC().Format(time.RFC3339), asrEventBlock, asrEventAudit, asrPsexecWmiRuleID)

	sawAudit := ""
	for attempt := 1; attempt <= asrPollAttempts; attempt++ {
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript).CombinedOutput()
		if err != nil {
			LogMessage("WARNING", "T1047", fmt.Sprintf("ASR event query failed (attempt %d/%d): %v | %s",
				attempt, asrPollAttempts, err, truncateOut(strings.TrimSpace(string(out)))))
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "F0ASR|") {
				continue
			}
			parts := strings.SplitN(line, "|", 5)
			if len(parts) < 5 {
				continue
			}
			detail := fmt.Sprintf("time=%s path=%s process=%s", parts[2], parts[3], parts[4])
			switch parts[1] {
			case fmt.Sprint(asrEventBlock):
				return true, detail
			case fmt.Sprint(asrEventAudit):
				sawAudit = detail
			}
		}
		if attempt < asrPollAttempts {
			time.Sleep(asrPollInterval)
		}
	}

	if sawAudit != "" {
		LogMessage("WARNING", "T1047", fmt.Sprintf(
			"ASR rule %s fired in AUDIT mode (event %d: %s) - audit is not prevention, not counted as blocked",
			asrPsexecWmiRuleID, asrEventAudit, sawAudit))
	} else {
		LogMessage("INFO", "T1047", fmt.Sprintf("No Defender ASR event %d for rule %s in stage window (since %s)",
			asrEventBlock, asrPsexecWmiRuleID, windowStart.UTC().Format(time.RFC3339)))
	}
	return false, ""
}

// buildMarkerContent produces the benign lateral-transfer payload: a plain
// text marker with an .exe name. It is NOT a PE and can never execute.
func buildMarkerContent() string {
	var sb strings.Builder
	sb.WriteString("F0RT1KA SECURITY TEST - BENIGN LATERAL MOVEMENT MARKER\n")
	sb.WriteString("========================================================\n")
	sb.WriteString("Bundle: The Gentlemen LOLBin intrusion simulation\n")
	sb.WriteString("Technique: T1570 Lateral Tool Transfer (loopback 127.0.0.1 only)\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Test UUID: %s\n", TEST_UUID))
	sb.WriteString("\nThis file is a TEXT MARKER with an .exe name. It is not a PE image,\n")
	sb.WriteString("contains no code, and cannot execute. It exists solely to emulate\n")
	sb.WriteString("The Gentlemen's LOLBin payload-copy behavior for detection-evaluation\n")
	sb.WriteString("purposes.\n")
	for sb.Len() < 4096 {
		sb.WriteString("#\n")
	}
	return sb.String()
}

func truncateOut(s string) string {
	if len(s) > 400 {
		return s[:400] + " ...[truncated]"
	}
	if s == "" {
		return "(no output)"
	}
	return s
}

// isOSDenial reports whether err carries the OS-emitted ERROR_ACCESS_DENIED
// errno. Only the numeric code counts; message text is localized and never
// trusted (stage_launch.go evidence philosophy).
func isOSDenial(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 5 // ERROR_ACCESS_DENIED
	}
	return false
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}
