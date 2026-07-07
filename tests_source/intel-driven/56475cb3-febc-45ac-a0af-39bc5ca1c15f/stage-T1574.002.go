//go:build windows
// +build windows

/*
STAGE 1: DLL Side-Loading (T1574.002)

Mirrors the 3CX trojan's core evasion primitive: the validly code-signed
3CXDesktopApp.exe loaded a malicious d3dcompiler_47.dll from its own
(user-writable) application directory, and a weaponized ffmpeg.dll carried the
appended-shellcode second stage. The detonation signal is a signed parent
process loading a NON-system DLL from a user-writable path.

Safety: a benign Microsoft-signed system binary (notepad.exe) is copied to a
sandboxed ARTIFACT_DIR path to stand in for 3CXDesktopApp.exe, and benign
marker DLLs (valid MZ header, F0RT1KA sentinel content) are dropped beside it.
The stand-in is launched from that directory so the OS resolves the companion
DLLs from the app dir (the side-load behavior), then terminated. No real 3CX
binary, no real DLL, no shellcode. All writes stay inside ARTIFACT_DIR.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TECHNIQUE_ID   = "T1574.002"
	TECHNIQUE_NAME = "DLL Side-Loading"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting DLL side-loading simulation (3CXDesktopApp role)")
	LogMessage("INFO", TECHNIQUE_ID, "Signed parent loads companion DLL from a user-writable app-dir path")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Signed stand-in for 3CXDesktopApp.exe side-loads d3dcompiler_47.dll / ffmpeg.dll")

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

	fmt.Printf("[STAGE %s] DLL side-loading simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "DLL side-loading simulation completed successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Signed stand-in launched with companion DLLs resolvable from app dir; no prevention observed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// 3CX chain recreated safely:
	//   1. Copy a legitimate Microsoft-signed binary and rename it to 3CXDesktopApp.exe
	//      (the trusted signed parent). We use notepad.exe as a benign stand-in.
	//   2. Drop benign marker DLLs d3dcompiler_47.dll and ffmpeg.dll beside it
	//      (the side-loaded companions). Benign MZ + sentinel content only.
	//   3. Launch the stand-in FROM that directory so the OS DLL search order
	//      resolves the companions from the app dir (the side-load), then terminate.
	//   All artifacts live under the sandboxed ARTIFACT_DIR.

	appDir := filepath.Join(ARTIFACT_DIR, "3CXDesktopApp", "app")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return fmt.Errorf("could not create app directory under ARTIFACT_DIR: %v", err)
	}

	// Step 1: trusted signed parent stand-in
	sourceBinary := "C:\\Windows\\System32\\notepad.exe"
	signedParent := filepath.Join(appDir, "3CXDesktopApp.exe")

	LogMessage("INFO", TECHNIQUE_ID, "Staging signed parent stand-in (3CXDesktopApp.exe) from a legitimate system binary")
	sourceData, err := os.ReadFile(sourceBinary)
	if err != nil {
		return fmt.Errorf("could not read system binary for stand-in: %v", err)
	}
	if err := os.WriteFile(signedParent, sourceData, 0755); err != nil {
		return fmt.Errorf("could not stage signed parent stand-in: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Staged signed parent: %s (%d bytes)", signedParent, len(sourceData)))

	// Step 2: benign side-loaded companion DLLs (valid MZ header + sentinel)
	companions := map[string][]byte{
		"d3dcompiler_47.dll": []byte("MZ\x90\x00\x03\x00\x00\x00F0RT1KA-SIMULATED-SIDELOAD-3cx-d3dcompiler_47\x00"),
		"ffmpeg.dll":         []byte("MZ\x90\x00\x03\x00\x00\x00F0RT1KA-SIMULATED-SIDELOAD-3cx-ffmpeg-appended-stage\x00"),
	}
	for name, content := range companions {
		p := filepath.Join(appDir, name)
		if err := os.WriteFile(p, content, 0755); err != nil {
			return fmt.Errorf("could not stage companion DLL %s: %v", name, err)
		}
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Placed side-loaded companion DLL: %s (%d bytes)", name, len(content)))
	}

	// Step 3: detection window for the staged artifacts (Rule 3: os.Stat quarantine check)
	LogMessage("INFO", TECHNIQUE_ID, "Detection window: waiting for reaction to the side-load layout...")
	time.Sleep(3 * time.Second)

	for _, name := range []string{"3CXDesktopApp.exe", "d3dcompiler_47.dll", "ffmpeg.dll"} {
		p := filepath.Join(appDir, name)
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			// Positive evidence: an artifact we just wrote was removed by a protection layer.
			return fmt.Errorf("side-load artifact %s was quarantined after staging", name)
		}
	}

	// Step 4: launch the signed parent stand-in from the app dir (triggers DLL search-order resolution)
	LogMessage("INFO", TECHNIQUE_ID, "Launching signed parent from app dir to trigger companion-DLL side-load...")
	cmd := exec.Command(signedParent)
	cmd.Dir = appDir
	if err := cmd.Start(); err != nil {
		// Launch failure here is ambiguous/benign, not a confirmed block.
		return fmt.Errorf("could not launch signed parent stand-in: %v", err)
	}
	pid := cmd.Process.Pid
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Signed parent launched with PID: %d (companions resolvable from %s)", pid, appDir))

	// Give a protection layer time to react to the signed-parent-loads-untrusted-DLL pattern
	time.Sleep(4 * time.Second)

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	// Positive block evidence: the signed parent stand-in was quarantined after launch.
	if _, statErr := os.Stat(signedParent); os.IsNotExist(statErr) {
		return fmt.Errorf("signed parent stand-in was quarantined after launch")
	}

	LogMessage("INFO", TECHNIQUE_ID, "Side-load pattern exercised: signed parent + non-system companion DLLs in a user-writable path")

	// Cleanup staged decoy artifacts (leave no lingering fake binaries)
	if err := os.RemoveAll(filepath.Join(ARTIFACT_DIR, "3CXDesktopApp")); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Cleanup of staged app dir incomplete: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Cleaned up staged side-load artifacts from ARTIFACT_DIR")
	}

	return nil
}

// ==============================================================================
// EXIT CODE DETERMINATION (Bug Prevention Rule 8: never default to a block code)
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	// Confirmed quarantine (positive evidence: an artifact we created disappeared).
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	// OS-emitted denial on an operation that normally succeeds in this context.
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Everything else (prerequisite / ambiguous / benign failure) maps to 999 — never a block.
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
