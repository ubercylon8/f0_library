// Stage 4 — T1484.001 Domain Policy Modification: Group Policy Modification (sandboxed)
// F0RT1KA Security Testing Framework
// The Gentlemen (GOLD SHERWOOD) — Objective 4: enterprise-wide deployment via Group Policy
//
// The Gentlemen pushes payloads domain-wide by abusing Group Policy: Trend
// Micro observed the Group Policy Management Editor launched against an
// LDAP-addressed policy object ("gpme.msc /s /gpobject:"LDAP://.../cn
// {...},cnpolicies,cnsystem,DC=...,DC=local""), and both Trend Micro and
// Sophos CTU observed final deployment through the domain's NETLOGON share
// ("\\<domain>.local\NETLOGON\<payload>.exe --password <8-byte key>",
// "cmd.exe /c \\NETLOGON\avkill.bat" for domain-wide script execution).
//
// This stage emulates the T1484.001 telemetry WITHOUT EVER TOUCHING REAL
// GROUP POLICY:
//
//   1. Sandbox GPO object — a fake {GUID} policy tree written inside
//      ARTIFACT_DIR with the exact artifacts a real GPO manipulation leaves
//      in SYSVOL: gpt.ini (General/Version header) and Machine\Registry.pol
//      (binary PReg format). File-create telemetry on Registry.pol is a
//      classic GPO-abuse detection signal; the path preserves the SYSVOL
//      directory shape while remaining inside the sandbox.
//   2. New-GPO command shape — the GroupPolicy cmdlet command line is fired
//      (fails fast: RSAT GPMC cmdlets are absent on a stock host). This is
//      the fail-harmless command-shape pattern (à la LockBit's vssadmin
//      against non-existent targets): the process-creation telemetry is the
//      point, never a mutation.
//   3. NETLOGON deployment shape — the actor's domain-wide launcher shape is
//      fired against the LOOPBACK NETLOGON share, which does not exist on a
//      non-DC host: fails fast (network path not found), non-gating.
//
// HARD SAFETY BOUNDARIES:
//   - The ONLY writes land inside ARTIFACT_DIR's gpo_sandbox subtree.
//   - No LDAP bind, no SYSVOL access, no mmc.exe launch (UI-spawning risk),
//     no real GPO is read or modified anywhere.
//   - The NETLOGON attempt targets 127.0.0.1 only.
//
// CLASSIFICATION (Rule 8): blocked only on positive OS-emitted denial of the
// sandbox writes in an elevated context. Missing RSAT cmdlets, absent
// NETLOGON share, and LDAP unavailability are prerequisite conditions.
//
// EXIT CODES: 0 = sandbox GPO staged + verified without prevention,
// 126 = positive denial evidence, 999 = prerequisite/test error.

//go:build windows
// +build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
	TECHNIQUE_ID   = "T1484.001"
	TECHNIQUE_NAME = "Group Policy Modification (T1484.001, sandboxed policy object)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Sandbox GPO layout (ALL inside ARTIFACT_DIR — real SYSVOL is never touched):
//
//   <ARTIFACT_DIR>\gpo_sandbox\SYSVOL\lab.local\Policies\{b7e6f2a1-4c3d-4e5f-9a8b-7cc45d210001}\
//       gpt.ini
//       Machine\Registry.pol
const (
	sandboxGPOGUID   = "{b7e6f2a1-4c3d-4e5f-9a8b-7cc45d210001}"
	sandboxPolicies  = `gpo_sandbox\SYSVOL\lab.local\Policies`
	gptIniContent    = "[General]\r\nVersion=2\r\ndisplayName=F0RT1KA Sandbox GPO (Gentlemen emulation)\r\n"
	registryPolValue = `SOFTWARE\F0RT1KA\Sandbox;GentlemenGPOMarker;REG_SZ;13;sandbox-policy`
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
		fmt.Printf("[STAGE %s] Sandbox GPO manipulation executed without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Sandbox GPO tree staged and verified; GPO/NETLOGON shapes emitted")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Sandboxed GPO manipulation unimpeded")
	case StageBlocked:
		fmt.Printf("[STAGE %s] GPO staging prevented (positive denial evidence)\n", TECHNIQUE_ID)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Sandbox GPO write denied with OS-emitted denial in elevated context", StageBlocked)
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Step 1: Stage the sandbox {GUID} GPO tree (the SYSVOL-write shape)
	// ------------------------------------------------------------------
	gpoRoot := filepath.Join(ARTIFACT_DIR, sandboxPolicies, sandboxGPOGUID)
	machineDir := filepath.Join(gpoRoot, "Machine")
	if err := os.MkdirAll(machineDir, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create sandbox GPO dir %s: %v", machineDir, err))
		return StageError
	}

	gptPath := filepath.Join(gpoRoot, "gpt.ini")
	if err := os.WriteFile(gptPath, []byte(gptIniContent), 0644); err != nil {
		if elevatedContext && isOSDenial(err) {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("gpt.ini write returned OS denial in elevated context (positive evidence): %v", err))
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("gpt.ini write failed (not attributable to protection): %v", err))
		return StageError
	}
	LogFileDropped("gpt.ini", gptPath, int64(len(gptIniContent)), false)
	LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("T1484.001: sandbox GPO object created at %s (SYSVOL-write shape)", gpoRoot))

	polPath := filepath.Join(machineDir, "Registry.pol")
	polBytes := buildRegistryPol(registryPolValue)
	if err := os.WriteFile(polPath, polBytes, 0644); err != nil {
		if elevatedContext && isOSDenial(err) {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Registry.pol write returned OS denial in elevated context (positive evidence): %v", err))
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Registry.pol write failed (not attributable to protection): %v", err))
		return StageError
	}
	LogFileDropped("Registry.pol", polPath, int64(len(polBytes)), false)
	LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("T1484.001: policy registry settings written (%d bytes PReg) - domain-policy modification telemetry", len(polBytes)))

	// Verify both artifacts persist (quarantine sweep check).
	time.Sleep(3 * time.Second)
	for _, p := range []string{gptPath, polPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("sandbox GPO artifact vanished after write: %s", p))
			return StageQuarantined
		}
	}

	// ------------------------------------------------------------------
	// Step 2: New-GPO command shape (fail-harmless; RSAT cmdlets absent)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Firing GPO management command shapes (fail-harmless)\n", TECHNIQUE_ID)
	newGPOCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`New-GPO -Name 'F0RT1KA-Sandbox-GPO' -Domain lab.local`)
	out, err := newGPOCmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	LogProcessExecution("powershell.exe", "New-GPO -Name 'F0RT1KA-Sandbox-GPO' -Domain lab.local", 0, err == nil, 0, truncateOut(outStr))
	if err != nil {
		// Expected on a stock host: 'New-GPO' is not recognized (no RSAT).
		LogMessage("INFO", TECHNIQUE_ID, "New-GPO cmdlet absent on host (expected) - command-shape telemetry emitted")
	} else {
		LogMessage("WARNING", TECHNIQUE_ID, "New-GPO cmdlet ran (RSAT present) - verify output above: only sandbox action taken")
	}

	// ------------------------------------------------------------------
	// Step 3: NETLOGON deployment shape (loopback, non-gating)
	// ------------------------------------------------------------------
	netlogonCmd := exec.Command("cmd.exe", "/Q", "/c",
		`\\127.0.0.1\NETLOGON\gentlemen_deploy_marker.exe --password F0SANDBOX`)
	out2, err2 := netlogonCmd.CombinedOutput()
	outStr2 := strings.TrimSpace(string(out2))
	LogProcessExecution("cmd.exe", `\\127.0.0.1\NETLOGON\gentlemen_deploy_marker.exe --password *** (loopback shape)`, 0, err2 == nil, 0, truncateOut(outStr2))
	if err2 != nil {
		LogMessage("INFO", TECHNIQUE_ID, "loopback NETLOGON share absent (expected on non-DC) - domain-deployment shape telemetry emitted, non-gating")
	}

	// Cleanup note: the sandbox GPO tree stays in ARTIFACT_DIR deliberately —
	// it is inert text and inside the test's sandbox; leaving it provides
	// forensic evidence for the run. (ARTIFACT_DIR is the designated decoy
	// area; PA/deploy workflows handle its lifecycle.)
	LogMessage("INFO", TECHNIQUE_ID, "sandbox GPO tree retained in ARTIFACT_DIR as run evidence (inert, sandboxed)")
	return StageSuccess
}

// buildRegistryPol produces a minimal binary PReg-format Registry.pol body:
// 5-byte header "PReg\x00" followed by UTF-16LE "[key;value;type;size;data]".
func buildRegistryPol(entry string) []byte {
	var b []byte
	b = append(b, 'P', 'R', 'e', 'g', 0x00)
	b = append(b, '[')
	b = append(b, utf16LE(entry)...)
	b = append(b, ']')
	return b
}

// utf16LE encodes s as little-endian UTF-16 code units (ASCII-safe subset).
func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0x7F {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// isOSDenial reports whether err carries the OS-emitted ERROR_ACCESS_DENIED
// errno (numeric evidence only; message text is never trusted).
func isOSDenial(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 5 // ERROR_ACCESS_DENIED
	}
	return false
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

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}
