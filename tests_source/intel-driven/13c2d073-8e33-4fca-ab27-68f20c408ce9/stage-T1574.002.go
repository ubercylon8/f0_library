//go:build windows
// +build windows

/*
STAGE 2: DLL Side-Loading (T1574.002)
Simulates APT33 Tickler DLL sideloading technique where a renamed
legitimate Microsoft binary loads malicious versions of msvcp140.dll
and vcruntime140.dll from the same directory. Tests EDR detection of
DLL sideloading patterns involving renamed Microsoft signed binaries.
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
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1574.002"
	TECHNIQUE_NAME = "DLL Side-Loading"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting DLL Side-Loading simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating Tickler sideloading via renamed Microsoft binary")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "DLL sideloading via Microsoft.SharePoint.NativeMessaging.exe")

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

	fmt.Printf("[STAGE %s] DLL sideloading simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "DLL sideloading simulation completed successfully")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "DLL sideloading via renamed binary executed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 Tickler uses DLL sideloading:
	// 1. A legitimate Microsoft binary is renamed (e.g., SharePoint component)
	// 2. Malicious msvcp140.dll and vcruntime140.dll are placed alongside it
	// 3. When the binary runs, it loads the DLLs from the same directory
	//
	// We simulate this by:
	// a) Copying a legitimate system binary (notepad.exe) as the renamed binary
	// b) Creating marker DLL files in the same directory
	// c) Running the renamed binary (which triggers EDR DLL sideloading detection)

	sideloadDir := filepath.Join(ARTIFACT_DIR, "tickler_extract")
	if err := os.MkdirAll(sideloadDir, 0755); err != nil {
		return fmt.Errorf("failed to create sideloading directory: %v", err)
	}

	// Step 1: Copy a legitimate Microsoft signed binary and rename it
	// This simulates APT33 using Microsoft.SharePoint.NativeMessaging.exe
	sourceBinary := "C:\\Windows\\System32\\notepad.exe"
	renamedBinary := filepath.Join(sideloadDir, "Microsoft.SharePoint.NativeMessaging.exe")

	LogMessage("INFO", TECHNIQUE_ID, "Copying legitimate Microsoft binary for sideloading simulation")
	sourceData, err := os.ReadFile(sourceBinary)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %v", err)
	}

	if err := os.WriteFile(renamedBinary, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write renamed binary: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created renamed binary: %s (%d bytes)", renamedBinary, len(sourceData)))

	// Step 2: Create sideloaded DLL files (simulated - benign marker content with MZ header)
	dllFiles := map[string][]byte{
		"msvcp140.dll":     []byte("MZ\x90\x00\x03\x00\x00\x00F0RT1KA-SIMULATED-SIDELOAD-msvcp140\x00"),
		"vcruntime140.dll": []byte("MZ\x90\x00\x03\x00\x00\x00F0RT1KA-SIMULATED-SIDELOAD-vcruntime140\x00"),
	}

	for dllName, dllContent := range dllFiles {
		dllPath := filepath.Join(sideloadDir, dllName)
		if err := os.WriteFile(dllPath, dllContent, 0755); err != nil {
			return fmt.Errorf("failed to write DLL %s: %v", dllName, err)
		}
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Placed sideloaded DLL: %s (%d bytes)", dllName, len(dllContent)))
	}

	// Step 3: Wait for EDR reaction to sideloading setup
	LogMessage("INFO", TECHNIQUE_ID, "Waiting for EDR reaction to sideloading artifacts...")
	time.Sleep(3 * time.Second)

	// Check if any files were quarantined
	for _, name := range []string{"Microsoft.SharePoint.NativeMessaging.exe", "msvcp140.dll", "vcruntime140.dll"} {
		fpath := filepath.Join(sideloadDir, name)
		if _, err := os.Stat(fpath); os.IsNotExist(err) {
			return fmt.Errorf("sideloading artifact %s was quarantined", name)
		}
	}

	// Step 4: Execute the renamed binary (triggers sideloading detection)
	// We run it with /? flag so notepad shows help and exits quickly
	LogMessage("INFO", TECHNIQUE_ID, "Executing renamed binary to trigger sideloading detection...")
	cmd := exec.Command(renamedBinary)
	cmd.Dir = sideloadDir

	// Start the process - we just need it to launch (notepad will open)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to launch renamed binary: %v", err)
	}

	pid := cmd.Process.Pid
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Renamed binary launched with PID: %d", pid))

	// Give EDR time to detect the sideloading pattern
	time.Sleep(5 * time.Second)

	// Kill the process (notepad would stay open otherwise)
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	// Check if the binary was terminated by EDR (would have been killed already)
	// Check if the binary still exists (EDR may have quarantined it)
	if _, err := os.Stat(renamedBinary); os.IsNotExist(err) {
		return fmt.Errorf("renamed binary was quarantined after execution")
	}

	LogMessage("INFO", TECHNIQUE_ID, "DLL sideloading simulation completed - renamed binary executed with DLLs in same directory")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Sideloading directory: %s", sideloadDir))

	return nil
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

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
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	// Default to error (999), NOT blocked (126) — prevents false "EDR blocked" results
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
