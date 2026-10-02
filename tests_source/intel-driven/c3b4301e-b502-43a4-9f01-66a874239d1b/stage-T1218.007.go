//go:build windows
// +build windows

/*
STAGE 4: Msiexec Silent Execution (T1218.007)
Simulates the RedFlick MSI delivery step: the package fetched by the
ssh.exe/curl.exe cradle is installed silently by msiexec.exe — and the
package is REAL (realism lift 3): lab_assets/redflick_persistence.msi is a
genuine Windows Installer package authored via the Windows Installer COM
API (see lab_assets/build_msi.ps1) and Authenticode-signed. Its type-34
CustomActions create the three persistence scheduled tasks with the exact
names from the disclosure — the documented adversary mechanism, so task
creation happens through msiexec exactly as in the real chain (Stage 5 then
verifies and records cleanup state).

A repeat install of an already-registered product is a silent no-op (exit
0); the cleanup utility uninstalls the product after each run.

Rule 8 classification: exit 0 = silent install completed; exit 5
(ERROR_ACCESS_DENIED) or 1260 (AppLocker/policy rejection) are OS-emitted
denials abnormal for this context and count as protection evidence;
package-level errors are unexpected here and surface as test errors.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1218.007"
	TECHNIQUE_NAME = "Msiexec Silent Package Execution"
	STAGE_ID       = 4

	MSI_NAME = "setup.msi"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "msiexec.exe /q /i silent install of fetched package")

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

	fmt.Printf("[STAGE %s] msiexec silent invocation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "msiexec.exe silent-install invocation exercised")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "msiexec /q /i telemetry generated (decoy package deviation documented)")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	msiPath := filepath.Join(LOG_DIR, MSI_NAME)
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		return fmt.Errorf("prerequisite missing: package not found at %s (Stage 2 must run first)", msiPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Exact silent-install flag surface from the disclosure
	cmd := exec.CommandContext(ctx, "msiexec.exe", "/i", msiPath, "/q", "/norestart")
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))
	exit := exitCodeOf(err)
	LogProcessExecution("msiexec.exe", fmt.Sprintf("msiexec.exe /i %s /q /norestart", msiPath), pidOf(cmd), err == nil, exit, outputStr)

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("msiexec exceeded 90s")
	}
	if err != nil && exit == 999 {
		// msiexec.exe never launched — infrastructure failure, not a verdict
		return fmt.Errorf("msiexec.exe launch attempt ended without an exit code: %v (output: %s)", err, outputStr)
	}

	switch exit {
	case 5:
		// OS-emitted denial abnormal for this context — positive protection evidence.
		// The message carries the OS constant name so determineExitCode can
		// classify it from the actual reported code, not an injected guess.
		return fmt.Errorf("msiexec.exe reported exit code 5 (ERROR_ACCESS_DENIED) for package %s", msiPath)
	case 1260:
		return fmt.Errorf("msiexec.exe reported exit code 1260 (ERROR_INSTALL_PACKAGE_REJECTED by policy) for package %s", msiPath)
	case 0:
		_ = os.WriteFile(filepath.Join(LOG_DIR, "stage4_verdict.json"),
			[]byte(fmt.Sprintf(`{"stage":4,"msiexec_exit":%d,"genuine_msi_installed":true}`+"\n", exit)), 0644)
		LogMessage("SUCCESS", TECHNIQUE_ID, "genuine MSI installed silently (exit 0) — CustomActions created the persistence task trio")
	default:
		return fmt.Errorf("msiexec exited %d on the genuine package (package-level failure; see msiexec documentation for the code)", exit)
	}

	LogMessage("INFO", TECHNIQUE_ID, "silent MSI install complete — Stage 5 verifies the persistence tasks")
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
	// "error_access_denied" / "rejected by policy" appear only when msiexec
	// itself reported the OS denial code — affirmative evidence, not a guess
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted", "error_access_denied", "rejected by policy"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "not present", "does not exist", "no such", "not running", "not available", "prerequisite missing"}) {
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
