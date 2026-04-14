//go:build windows
// +build windows

/*
STAGE 3: Boot or Logon Autostart Execution — Startup Folder (T1547.001)

Simulates PROMPTFLUX's user-Startup persistence: drops an obfuscated benign
VBS to %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\ScreenRecUpdater.vbs.
The VBS is NOT executed here — the detection signal is the drop itself. The
orchestrator cleans up this file on every exit path.

Rule 2: SYSTEM vs user context handling. If running as SYSTEM, APPDATA may be
absent or point to .DEFAULT; fall back to the All-Users Startup folder under
%ProgramData%.

Detection opportunities:
  - Any write to a Startup folder by a non-installer, non-Explorer process
  - VBS file extension in a Startup folder (rare in modern Windows baselines)
  - File created with name "ScreenRecUpdater.vbs" (string IOC)
  - Binary from c:\F0 performing the write
*/

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "0a749b39-409e-46f5-9338-ee886b439cfa"
	TECHNIQUE_ID   = "T1547.001"
	TECHNIQUE_NAME = "Startup Folder Persistence"
	STAGE_ID       = 3

	STARTUP_VBS_FILENAME = "ScreenRecUpdater.vbs"
)

// A third benign obfuscated VBS body, distinct from the stage-1 and stage-2
// payloads. The detection signal is presence in Startup — execution at
// test-time is not desired (that fires at next logon, not now).
//
//go:embed embedded_startup_payload.vbs
var startupVbsBody []byte

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting PROMPTFLUX stage-3 (user Startup folder persistence)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Drop ScreenRecUpdater.vbs into user Startup folder")

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

	fmt.Printf("[STAGE %s] Startup VBS staged; not invoked at test-time\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Stage-3 persistence established")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ScreenRecUpdater.vbs present in Startup folder")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	if len(startupVbsBody) < 40 {
		return fmt.Errorf("embedded startup VBS missing or too short (%d bytes)", len(startupVbsBody))
	}

	startupDir, hiveStr, err := resolveStartupDir()
	if err != nil {
		return fmt.Errorf("startup dir resolution: %v", err)
	}

	if err := os.MkdirAll(startupDir, 0755); err != nil {
		return fmt.Errorf("startup dir create: %v", err)
	}

	targetPath := filepath.Join(startupDir, STARTUP_VBS_FILENAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Writing startup VBS: %s (hive=%s)", targetPath, hiveStr))

	if err := os.WriteFile(targetPath, startupVbsBody, 0644); err != nil {
		return fmt.Errorf("startup vbs write: %v", err)
	}

	LogFileDropped(STARTUP_VBS_FILENAME, targetPath, int64(len(startupVbsBody)), false)

	// Rule 3: os.Stat quarantine check (not Endpoint.Quarantined).
	time.Sleep(1500 * time.Millisecond)
	if _, statErr := os.Stat(targetPath); os.IsNotExist(statErr) {
		return fmt.Errorf("startup vbs quarantined after write")
	}

	LogMessage("INFO", TECHNIQUE_ID, "PROMPTFLUX-style startup persistence established (VBS not executed at test-time)")
	return nil
}

// resolveStartupDir picks the correct Startup folder for the current context.
// User context → %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup.
// SYSTEM context → %ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp (All-Users).
func resolveStartupDir() (dir, hive string, err error) {
	isSystem := isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: SYSTEM=%v", isSystem))

	if !isSystem {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", "", fmt.Errorf("APPDATA environment variable not set")
		}
		return filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`), "APPDATA", nil
	}

	// SYSTEM context: write to the All-Users Startup folder.
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`), "ProgramData", nil
}

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
// EXIT CODE — blame-free (Rule 1)
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
