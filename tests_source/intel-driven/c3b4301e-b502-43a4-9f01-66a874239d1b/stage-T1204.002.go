//go:build windows
// +build windows

/*
STAGE 1: User Execution via Malicious File (T1204.002)
Simulates the Star Blizzard event-invite delivery: the victim receives a
password-protected archive containing an LNK disguised as a PDF. Opening the
LNK launches a hidden conhost.exe which spawns cmd.exe running a BAT script
that displays a decoy PDF while staging the follow-on chain (RedFlick,
January variant).

Sandbox mapping: decoy invite artifacts are created in ARTIFACT_DIR, the
conhost -> cmd -> BAT chain executes for real, and the decoy PDF "opens"
(content staged to LOG_DIR — no GUI dependency in non-interactive sessions).
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1204.002"
	TECHNIQUE_NAME = "User Execution: Malicious File (Event-Invite LNK)"
	STAGE_ID       = 1

	INVITE_SUBDIR = "StarBlizzardInvite"
	DECOY_PDF     = "IISS_Event_Invitation.pdf"
	DECOY_ARCHIVE = "Event_Materials_password_protected.rar"
	DECOY_LNK     = "Event_Invitation.pdf.lnk"
	INVITE_BAT    = "invite_viewer.bat"
	MARKER_FILE   = "lnk_execution_marker.txt"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func inviteDir() string { return filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR) }

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Event-invite archive contents executed via LNK -> conhost -> cmd -> BAT")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Event-invite LNK execution chain completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "LNK -> conhost -> cmd -> BAT chain executed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "conhost/cmd/BAT chain executed and decoy PDF displayed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	dir := inviteDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("invite directory creation failed: %v", err)
	}

	// 1. Stage the archive contents exactly as the victim would see them:
	//    decoy PDF, password-protected archive placeholder, LNK, and the
	//    BAT the LNK ultimately runs.
	decoyPDF := []byte("%PDF-1.4\n" +
		"F0RT1KA DECOY - IISS Transatlantic Security Event Invitation\n" +
		"Panel: Emerging Threats in Eastern Europe - Registration Confirmed\n" +
		"(sandbox simulation artifact - benign content)\n%%EOF\n")
	if err := os.WriteFile(filepath.Join(dir, DECOY_PDF), decoyPDF, 0644); err != nil {
		return fmt.Errorf("decoy PDF write failed: %v", err)
	}
	LogFileDropped(DECOY_PDF, filepath.Join(dir, DECOY_PDF), int64(len(decoyPDF)), false)

	archive := []byte("F0RT1KA decoy password-protected archive (password delivered as image per RedFlick report)\n")
	if err := os.WriteFile(filepath.Join(dir, DECOY_ARCHIVE), archive, 0644); err != nil {
		return fmt.Errorf("decoy archive write failed: %v", err)
	}
	LogFileDropped(DECOY_ARCHIVE, filepath.Join(dir, DECOY_ARCHIVE), int64(len(archive)), false)

	// BAT script: opens the decoy PDF for the victim, then leaves the marker
	// the stage verifies (stands in for invoking the next-stage download).
	bat := "@echo off\r\n" +
		fmt.Sprintf("start \"\" \"%s\"\r\n", filepath.Join(dir, DECOY_PDF)) +
		fmt.Sprintf("echo opened > \"%s\"\r\n", filepath.Join(LOG_DIR, MARKER_FILE))
	if err := os.WriteFile(filepath.Join(dir, INVITE_BAT), []byte(bat), 0755); err != nil {
		return fmt.Errorf("invite BAT write failed: %v", err)
	}
	LogFileDropped(INVITE_BAT, filepath.Join(dir, INVITE_BAT), int64(len(bat)), false)

	// 2. Create the LNK whose target is the hidden-conhost chain (masquerade:
	//    named/shaped like the invite PDF). Built via the WScript.Shell COM
	//    interface, the same way real LNKs are weaponized.
	lnkPath := filepath.Join(dir, DECOY_LNK)
	lnkScript := fmt.Sprintf(
		`$s = New-Object -ComObject WScript.Shell; `+
			`$l = $s.CreateShortcut('%s'); `+
			`$l.TargetPath = 'C:\Windows\System32\conhost.exe'; `+
			`$l.Arguments = '--headless cmd.exe /c "%s"'; `+
			`$l.WindowStyle = 7; `+
			`$l.IconLocation = 'C:\Windows\System32\shell32.dll,70'; `+
			`$l.Save(); Write-Host 'LNK created'`,
		lnkPath, filepath.Join(dir, INVITE_BAT))
	out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", lnkScript).CombinedOutput()
	if err != nil {
		return fmt.Errorf("LNK creation via WScript.Shell failed: %v (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(lnkPath); os.IsNotExist(err) {
		return fmt.Errorf("LNK file not present after creation: %s", lnkPath)
	}
	LogFileDropped(DECOY_LNK, lnkPath, 0, false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("LNK created targeting hidden conhost chain: %s", lnkPath))

	// 3. Execute the LNK's target chain for real: conhost.exe (hidden window)
	//    spawning cmd.exe running the BAT.
	markerPath := filepath.Join(LOG_DIR, MARKER_FILE)
	_ = os.Remove(markerPath)

	conhost := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "conhost.exe"),
		"--headless", "cmd.exe", "/c", filepath.Join(dir, INVITE_BAT))
	conhost.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	conhostOut, conhostErr := conhost.CombinedOutput()
	LogProcessExecution("conhost.exe", fmt.Sprintf("conhost.exe --headless cmd.exe /c %s", filepath.Join(dir, INVITE_BAT)), pidOf(conhost), conhostErr == nil, exitCodeOf(conhostErr), "")

	// The conhost chain may be unavailable in non-interactive sessions; the
	// BAT execution via cmd.exe is the load-bearing primitive — fall back and
	// verify the observable either way.
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		LogMessage("WARN", TECHNIQUE_ID,
			fmt.Sprintf("conhost chain produced no marker (%v, output: %s) — falling back to direct cmd.exe execution", conhostErr, strings.TrimSpace(string(conhostOut))))
		cmdExe := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", filepath.Join(dir, INVITE_BAT))
		cmdExe.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmdOut, cmdErr := cmdExe.CombinedOutput()
		LogProcessExecution("cmd.exe", fmt.Sprintf("cmd.exe /c %s", filepath.Join(dir, INVITE_BAT)), pidOf(cmdExe), cmdErr == nil, exitCodeOf(cmdErr), "")
		if cmdErr != nil {
			return fmt.Errorf("cmd.exe chain failed: %v (output: %s)", cmdErr, strings.TrimSpace(string(cmdOut)))
		}
	}

	// 4. Verify the chain executed (marker written by the BAT)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		return fmt.Errorf("execution marker not found after BAT chain: %s", markerPath)
	}

	LogMessage("INFO", TECHNIQUE_ID, "Decoy PDF displayed and execution marker written — victim interaction chain complete")
	return nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 999
}

// pidOf safely extracts a PID (0 when the process never started)
func pidOf(cmd *exec.Cmd) int {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Pid
	}
	return 0
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "not present", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	// Unrecognized failures are test errors, never protection verdicts (Rule 8)
	return StageError
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}
