//go:build windows
// +build windows

/*
STAGE 3: Registry Run Keys (T1547.001)
Simulates APT33 Tickler persistence via registry Run key.
Tickler adds a value named "SharePoint.exe" pointing to the sideloaded
binary in a non-standard path. Handles SYSTEM vs user context
(Rule 2: isSystemContext check).
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1547.001"
	TECHNIQUE_NAME = "Registry Run Keys"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	RUN_KEY_VALUE_NAME = "SharePoint"
	RUN_KEY_PATH_HKCU  = `Software\Microsoft\Windows\CurrentVersion\Run`
	RUN_KEY_PATH_HKLM  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Registry Run Key persistence simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating APT33 Tickler persistence as 'SharePoint.exe'")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Add registry Run key persistence")

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

	fmt.Printf("[STAGE %s] Registry Run key persistence set successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Registry Run key persistence established")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Registry Run key 'SharePoint' added for persistence")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 Tickler creates a Run key entry named "SharePoint.exe"
	// pointing to the sideloaded binary in a non-standard path
	//
	// Rule 2: Detect SYSTEM vs user context
	// - SYSTEM context: Use HKLM (machine-wide persistence)
	// - User context: Use HKCU (user-level persistence)

	// Determine the path to the "backdoor" binary
	backdoorPath := filepath.Join(ARTIFACT_DIR, "tickler_extract", "Microsoft.SharePoint.NativeMessaging.exe")

	// If the actual extraction dir doesn't have it, use a simulated path
	if _, err := os.Stat(backdoorPath); os.IsNotExist(err) {
		// Create a benign placeholder to reference
		os.MkdirAll(filepath.Dir(backdoorPath), 0755)
		placeholder := []byte("REM F0RT1KA simulated Tickler backdoor\r\n")
		os.WriteFile(backdoorPath, placeholder, 0755)
		LogMessage("INFO", TECHNIQUE_ID, "Created placeholder backdoor binary for persistence reference")
	}

	runKeyValue := fmt.Sprintf("\"%s\"", backdoorPath)

	// Rule 2: Check execution context
	isSystem := isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: SYSTEM=%v", isSystem))

	var regKey registry.Key
	var keyPath string
	var hiveStr string
	var err error

	if isSystem {
		// SYSTEM context - use HKLM for machine-wide persistence
		hiveStr = "HKLM"
		keyPath = RUN_KEY_PATH_HKLM
		regKey, err = registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	} else {
		// User context - use HKCU
		hiveStr = "HKCU"
		keyPath = RUN_KEY_PATH_HKCU
		regKey, err = registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	}

	if err != nil {
		return fmt.Errorf("registry open failed on %s\\%s: %v", hiveStr, keyPath, err)
	}
	defer regKey.Close()

	// Save original value for cleanup (if it exists)
	originalValue, _, origErr := regKey.GetStringValue(RUN_KEY_VALUE_NAME)
	if origErr == nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Existing '%s' value found: %s (will be restored on cleanup)", RUN_KEY_VALUE_NAME, originalValue))
		// Save original to state file for cleanup
		stateFile := filepath.Join("c:\\F0", "registry_run_key_state.txt")
		stateContent := fmt.Sprintf("HIVE=%s\nKEY=%s\nVALUE_NAME=%s\nORIGINAL_VALUE=%s\nHAD_VALUE=true\n",
			hiveStr, keyPath, RUN_KEY_VALUE_NAME, originalValue)
		os.WriteFile(stateFile, []byte(stateContent), 0644)
	} else {
		// No original value - note for cleanup to remove
		stateFile := filepath.Join("c:\\F0", "registry_run_key_state.txt")
		stateContent := fmt.Sprintf("HIVE=%s\nKEY=%s\nVALUE_NAME=%s\nHAD_VALUE=false\n",
			hiveStr, keyPath, RUN_KEY_VALUE_NAME)
		os.WriteFile(stateFile, []byte(stateContent), 0644)
	}

	// Set the registry Run key value
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Setting %s\\%s\\%s = %s", hiveStr, keyPath, RUN_KEY_VALUE_NAME, runKeyValue))

	if err := regKey.SetStringValue(RUN_KEY_VALUE_NAME, runKeyValue); err != nil {
		return fmt.Errorf("registry write failed for %s: %v", RUN_KEY_VALUE_NAME, err)
	}

	// Verify the value was written
	time.Sleep(1 * time.Second)
	verifyValue, _, verifyErr := regKey.GetStringValue(RUN_KEY_VALUE_NAME)
	if verifyErr != nil {
		return fmt.Errorf("registry verification failed: %v", verifyErr)
	}

	if verifyValue != runKeyValue {
		return fmt.Errorf("registry value mismatch: expected %s, got %s", runKeyValue, verifyValue)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Registry Run key verified: %s\\%s\\%s", hiveStr, keyPath, RUN_KEY_VALUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Tickler persistence established - 'SharePoint' Run key points to sideloaded binary")

	return nil
}

// isSystemContext detects if running as SYSTEM (Rule 2)
func isSystemContext() bool {
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	username := strings.TrimSpace(strings.ToLower(string(output)))
	return strings.Contains(username, "nt authority\\system") || strings.Contains(username, "system")
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
	return StageBlocked
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
