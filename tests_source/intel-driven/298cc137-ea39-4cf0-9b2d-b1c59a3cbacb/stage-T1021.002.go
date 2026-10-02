// Stage 3 — T1021.002 SMB/Windows Admin Shares + T1570 Lateral Tool Transfer
// F0RT1KA Security Testing Framework
// SB-PC-2026-001 [LOCKBIT] — Objetivo 3: Movimiento lateral y propagación
//
// LockBit propagates to file/database servers over administrative shares,
// copying its payload before remote execution (AA23-165A: T1021.002 and
// T1570 documented for LockBit). This stage emulates the SMB session +
// lateral tool transfer against the LOOPBACK INTERFACE ONLY:
//
//   1. Opens an SMB session to \\127.0.0.1\ADMIN$ (net use) — generates the
//      same session/logon telemetry (4624/5140/5145) as a lateral connection
//      to a peer server, with ZERO network egress beyond 127.0.0.1.
//   2. Copies a benign marker binary (lbsvc.exe — a NON-executable text
//      marker, not a PE) into \\127.0.0.1\ADMIN$\Temp\ (T1570 lateral tool
//      transfer), verifies arrival via os.Stat, then DELETES it.
//   3. Tears the session down (net use /delete).
//
// HARD SAFETY BOUNDARIES:
//   - Loopback only: the SMB target is hardcoded to 127.0.0.1. No egress.
//   - NO service is created or started (no remote execution of any kind).
//   - The transferred "binary" is a text marker with an .exe name — it can
//     never execute.
//
// CLASSIFICATION (Rule 8): blocked only on positive denial evidence in an
// elevated context (where loopback ADMIN$ access normally succeeds). SMB
// unavailability (Server service off, error 53/67) is a prerequisite
// condition, not a protection action -> 999.
//
// EXIT CODES: 0 = session established + tool transferred unimpeded,
// 126 = positive denial evidence, 999 = prerequisite/test error.

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
)

const (
	TEST_UUID      = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TECHNIQUE_ID   = "T1021.002"
	TECHNIQUE_NAME = "Lateral Movement & Propagation (T1021.002/T1570, loopback)"
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
	markerName    = "lbsvc.exe"
	markerRelPath = `Temp\lbsvc.exe`
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
		fmt.Printf("[STAGE %s] Lateral movement primitive executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "SMB session + lateral tool transfer completed unimpeded (loopback)")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Loopback ADMIN$ session and tool transfer unimpeded")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Lateral movement prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "SMB session or tool transfer positively prevented")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Loopback ADMIN$ access/transfer denied with positive evidence")
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Lateral movement stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Step 1: SMB session to loopback ADMIN$ (T1021.002)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 1: Opening SMB session to %s (loopback only)\n", TECHNIQUE_ID, smbTarget)
	LogMessage("WARN", TECHNIQUE_ID, "T1021.002: net use \\\\127.0.0.1\\ADMIN$ — loopback lateral session telemetry")

	cmd := exec.Command("net.exe", "use", smbTarget)
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	outLower := strings.ToLower(outStr)
	LogProcessExecution("net.exe", fmt.Sprintf("net use %s", smbTarget), 0, runErr == nil, 0, outStr)

	sessionOK := false
	if runErr == nil {
		sessionOK = true
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
			return StageError
		case strings.Contains(outLower, "system error 53") ||
			strings.Contains(outLower, "system error 67") ||
			strings.Contains(outLower, "system error 1223") ||
			strings.Contains(outLower, "network path was not found") ||
			strings.Contains(outLower, "network name cannot be found"):
			// Server service off / SMB unavailable — prerequisite, not a block.
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("SMB server unavailable on loopback (prerequisite miss): %s", outStr))
			return StageError
		default:
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("net use returned unrecognized failure (inconclusive): %v | %s", runErr, outStr))
			return StageError
		}
	}

	// Session teardown is best-effort and always attempted.
	defer func() {
		delCmd := exec.Command("net.exe", "use", smbTarget, "/delete", "/y")
		delOut, _ := delCmd.CombinedOutput()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("cleanup: net use /delete returned: %s", strings.TrimSpace(string(delOut))))
	}()

	// ------------------------------------------------------------------
	// Step 2: Lateral tool transfer (T1570) — copy benign marker binary into
	// \\127.0.0.1\ADMIN$\Temp\, verify with os.Stat, delete it.
	// ------------------------------------------------------------------
	markerPath := filepath.Join(smbTarget, markerRelPath)
	fmt.Printf("[STAGE %s] Phase 2: Transferring benign marker to %s\n", TECHNIQUE_ID, markerPath)
	LogMessage("WARN", "T1570", "T1570: lateral tool transfer of benign marker binary into ADMIN$\\Temp (loopback)")

	markerContent := buildMarkerContent()
	if err := os.WriteFile(markerPath, []byte(markerContent), 0644); err != nil {
		errLower := strings.ToLower(err.Error())
		if elevatedContext && (strings.Contains(errLower, "access is denied") || strings.Contains(errLower, "access denied")) {
			LogMessage("WARN", "T1570", fmt.Sprintf("Tool transfer write returned OS denial in elevated context (positive evidence): %v", err))
			return StageBlocked
		}
		LogMessage("ERROR", "T1570", fmt.Sprintf("Tool transfer write failed (not attributable to protection): %v", err))
		return StageError
	}
	LogFileDropped(markerName, markerPath, int64(len(markerContent)), false)

	// Verify arrival (os.Stat), then delete.
	time.Sleep(500 * time.Millisecond)
	verifyOK := false
	if fi, statErr := os.Stat(markerPath); statErr == nil {
		verifyOK = true
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

	if sessionOK && verifyOK {
		return StageSuccess
	}
	return StageError
}

// buildMarkerContent produces the benign lateral-transfer payload: a plain
// text marker with an .exe name. It is NOT a PE and can never execute.
func buildMarkerContent() string {
	var sb strings.Builder
	sb.WriteString("F0RT1KA SECURITY TEST - BENIGN LATERAL MOVEMENT MARKER\n")
	sb.WriteString("========================================================\n")
	sb.WriteString("Bundle: SB-PC-2026-001 [LOCKBIT] (LockBit 3.0 double extortion simulation)\n")
	sb.WriteString("Technique: T1570 Lateral Tool Transfer (loopback 127.0.0.1 only)\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Test UUID: %s\n", TEST_UUID))
	sb.WriteString("\nThis file is a TEXT MARKER with an .exe name. It is not a PE image,\n")
	sb.WriteString("contains no code, and cannot execute. It exists solely to emulate\n")
	sb.WriteString("LockBit's payload-copy behavior for detection-evaluation purposes.\n")
	// Pad to ~4KB so the transfer looks like a small tool, not a 0-byte touch.
	for sb.Len() < 4096 {
		sb.WriteString("#\n")
	}
	return sb.String()
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}
