//go:build windows
// +build windows

/*
STAGE 5: Masquerading (T1036)
Simulates APT33 Tickler masquerading technique where the backdoor binary
is renamed to Microsoft.SharePoint.NativeMessaging.exe to blend with
legitimate Microsoft SharePoint components. Tests EDR detection of
binary masquerading and renamed executable execution.
*/

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1036"
	TECHNIQUE_NAME = "Masquerading"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Masquerading simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Testing binary masquerading as Microsoft SharePoint component")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Masquerade binary as Microsoft.SharePoint.NativeMessaging.exe")

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

	fmt.Printf("[STAGE %s] Masquerading simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Binary masquerading completed without detection")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Masqueraded binary executed as SharePoint.exe without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 Tickler masquerades as legitimate Microsoft software:
	// 1. The backdoor is named Microsoft.SharePoint.NativeMessaging.exe
	// 2. It runs from a non-standard path (not Program Files)
	// 3. It creates a second copy as SharePoint.exe for the Run key
	//
	// Test: Copy a legitimate binary, rename to SharePoint.exe,
	// place in non-standard path, and execute to test EDR detection

	extractDir := filepath.Join(ARTIFACT_DIR, "tickler_extract")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create masquerading directory: %v", err)
	}

	// Create the renamed copy as "SharePoint.exe" (used by Run key)
	sourceBinary := filepath.Join(extractDir, "Microsoft.SharePoint.NativeMessaging.exe")
	sharepointExe := filepath.Join(extractDir, "SharePoint.exe")

	// Read the source binary (from Stage 2 or create from system binary)
	var binaryData []byte
	if data, err := os.ReadFile(sourceBinary); err == nil {
		binaryData = data
	} else {
		// Fallback: copy from system
		systemBinary := "C:\\Windows\\System32\\whoami.exe"
		data, err := os.ReadFile(systemBinary)
		if err != nil {
			return fmt.Errorf("failed to read source binary: %v", err)
		}
		binaryData = data
		// Also create the NativeMessaging version
		os.WriteFile(sourceBinary, binaryData, 0755)
	}

	// Create SharePoint.exe (the masqueraded name used in Run key)
	if err := os.WriteFile(sharepointExe, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to create masqueraded binary: %v", err)
	}

	// Calculate hash for logging
	hash := sha256.Sum256(binaryData)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created SharePoint.exe (%d bytes, SHA256: %x...)", len(binaryData), hash[:8]))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Non-standard path: %s", sharepointExe))

	// Wait for EDR reaction
	time.Sleep(3 * time.Second)

	// Check if masqueraded binary was quarantined
	if _, err := os.Stat(sharepointExe); os.IsNotExist(err) {
		return fmt.Errorf("SharePoint.exe was quarantined")
	}

	// Execute the masqueraded binary from non-standard path
	LogMessage("INFO", TECHNIQUE_ID, "Executing masqueraded binary 'SharePoint.exe' from non-standard path...")

	cmd := exec.Command(sharepointExe)
	cmd.Dir = extractDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if execution was blocked vs just a runtime error
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SharePoint.exe output: %s", outputStr))
		}

		// If the binary still exists, it ran but may have had a non-zero exit
		// This is expected for whoami.exe or similar
		if _, statErr := os.Stat(sharepointExe); statErr == nil {
			// Binary still exists - execution was attempted
			if exitErr, ok := err.(*exec.ExitError); ok {
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SharePoint.exe exited with code: %d (non-zero is OK for masquerading test)", exitErr.ExitCode()))
			}
			// Not blocked, just a non-zero exit from the masqueraded program
		} else {
			// Binary was removed during execution - quarantined
			return fmt.Errorf("SharePoint.exe was quarantined during execution")
		}
	} else {
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SharePoint.exe output: %s", outputStr))
		}
	}

	// Verify masqueraded binary still exists post-execution
	if _, err := os.Stat(sharepointExe); os.IsNotExist(err) {
		return fmt.Errorf("SharePoint.exe was removed after execution")
	}

	LogMessage("INFO", TECHNIQUE_ID, "Masquerading complete: Binary executed as SharePoint.exe from non-standard path")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Masquerading artifacts: %s, %s", sourceBinary, sharepointExe))

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
