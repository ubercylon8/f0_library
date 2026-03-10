//go:build windows
// +build windows

/*
STAGE 4: Scheduled Task (T1053.005)
Simulates APT33 Tickler redundant persistence via Windows Scheduled Task.
Creates a scheduled task that runs the sideloaded binary at logon,
providing dual persistence alongside the registry Run key.
*/

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
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1053.005"
	TECHNIQUE_NAME = "Scheduled Task"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	TASK_NAME = "MicrosoftSharePointSync"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Scheduled Task persistence simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Creating redundant persistence via scheduled task")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Create scheduled task for Tickler persistence")

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

	fmt.Printf("[STAGE %s] Scheduled task persistence created successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Scheduled task persistence established")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", fmt.Sprintf("Scheduled task '%s' created for persistence", TASK_NAME))
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 creates a scheduled task as redundant persistence
	// alongside the registry Run key. The task runs the sideloaded binary at logon.

	backdoorPath := filepath.Join(ARTIFACT_DIR, "tickler_extract", "Microsoft.SharePoint.NativeMessaging.exe")

	// Verify the backdoor binary exists
	if _, err := os.Stat(backdoorPath); os.IsNotExist(err) {
		// Create placeholder if prior stage didn't create it
		os.MkdirAll(filepath.Dir(backdoorPath), 0755)
		placeholder := []byte("REM F0RT1KA simulated Tickler backdoor\r\n")
		os.WriteFile(backdoorPath, placeholder, 0755)
		LogMessage("INFO", TECHNIQUE_ID, "Created placeholder backdoor binary for scheduled task reference")
	}

	// Save task state for cleanup
	stateFile := filepath.Join("c:\\F0", "scheduled_task_state.txt")
	taskExisted := scheduledTaskExists(TASK_NAME)
	stateContent := fmt.Sprintf("TASK_NAME=%s\nEXISTED_BEFORE=%v\n", TASK_NAME, taskExisted)
	os.WriteFile(stateFile, []byte(stateContent), 0644)

	if taskExisted {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Task '%s' already exists - will be overwritten", TASK_NAME))
	}

	// Create the scheduled task using schtasks.exe
	// Models APT33's use of logon triggers for persistence
	//
	// Rule 2: Handle SYSTEM vs user context
	// SYSTEM context: Use /RU SYSTEM (avoids SID resolution error with /RL HIGHEST)
	// User context: Use /RL HIGHEST for elevated persistence
	isSystem := isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: SYSTEM=%v", isSystem))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating scheduled task: %s", TASK_NAME))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Task action: %s", backdoorPath))

	args := []string{
		"/Create",
		"/TN", TASK_NAME,
		"/TR", fmt.Sprintf("\"%s\"", backdoorPath),
		"/SC", "ONLOGON",
		"/F", // Force overwrite if exists
	}

	if isSystem {
		// SYSTEM has no interactive user SID — /RL HIGHEST causes
		// "No mapping between account names and security IDs" error
		args = append(args, "/RU", "SYSTEM")
		LogMessage("INFO", TECHNIQUE_ID, "Using /RU SYSTEM for SYSTEM context")
	} else {
		args = append(args, "/RL", "HIGHEST")
		LogMessage("INFO", TECHNIQUE_ID, "Using /RL HIGHEST for user context")
	}

	cmd := exec.Command("schtasks.exe", args...)

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		// Rule 5: Handle empty/unclear sc.exe output
		if outputStr == "" {
			return fmt.Errorf("schtasks returned empty output with error: %v", err)
		}
		// Log raw output for diagnostics
		fmt.Printf("[STAGE %s] schtasks output: %s\n", TECHNIQUE_ID, outputStr)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("schtasks output: %s", outputStr))
		return fmt.Errorf("schtasks failed: %v (output: %s)", err, outputStr)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("schtasks output: %s", outputStr))

	// Verify the task was created
	time.Sleep(2 * time.Second)

	if !scheduledTaskExists(TASK_NAME) {
		return fmt.Errorf("scheduled task '%s' not found after creation", TASK_NAME)
	}

	// Query task details for logging
	queryCmd := exec.Command("schtasks.exe", "/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST")
	queryOutput, queryErr := queryCmd.CombinedOutput()
	if queryErr == nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Task details:\n%s", strings.TrimSpace(string(queryOutput))))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Scheduled task '%s' created with ONLOGON trigger", TASK_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Dual persistence established: Registry Run key + Scheduled Task")

	return nil
}

func scheduledTaskExists(taskName string) bool {
	cmd := exec.Command("schtasks.exe", "/Query", "/TN", taskName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(output))) > 0
}

// ==============================================================================
// CONTEXT DETECTION (Rule 2)
// ==============================================================================

func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
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
	// Only pattern-matched keywords above should trigger blocked/quarantined exit codes
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
