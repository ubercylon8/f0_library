//go:build windows
// +build windows

// Stage 1: ASPXSpy Webshell Deployment (T1505.003)
// Simulates Agrius deployment of ASPXSpy webshell to staging directory
// SAFE: Writes benign .aspx file to c:\F0 (NOT to actual IIS directories)

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TECHNIQUE_ID   = "T1505.003"
	TECHNIQUE_NAME = "Server Software Component: Web Shell"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Simulated ASPXSpy webshell content (benign - no actual server-side execution capability)
const webshellContent = `<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<!-- SIMULATION: ASPXSpy Webshell (Agrius/Pink Sandstorm) -->
<!-- This is a BENIGN simulation file for F0RT1KA security testing -->
<!-- It does NOT contain actual webshell functionality -->
<script runat="server">
// F0RT1KA SIMULATION - NOT A REAL WEBSHELL
// This file simulates the deployment artifact for EDR detection testing
// Agrius deploys ASPXSpy variants to establish initial foothold
// Real IOCs: aspxspy.aspx, error5.aspx, contact.aspx
protected void Page_Load(object sender, EventArgs e)
{
    // Simulation marker - EDR should detect this file pattern
    Response.Write("F0RT1KA-SIMULATION-WEBSHELL-MARKER");
}
</script>
<html>
<head><title>Error</title></head>
<body>
<!-- Agrius typically deploys webshells to IIS wwwroot directories -->
<!-- Common paths: C:\inetpub\wwwroot\, C:\Program Files\Microsoft\Exchange Server\ -->
<p>An error occurred.</p>
</body>
</html>`

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	fmt.Printf("[STAGE %s] Starting %s\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Simulating ASPXSpy webshell deployment (Agrius campaign)")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	fmt.Printf("[STAGE %s] %s executed successfully\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ASPXSpy webshell simulation deployed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"

	// Deploy simulated ASPXSpy webshell variants (Agrius uses multiple names)
	webshellFiles := []string{
		"aspxspy.aspx", // Primary ASPXSpy variant
		"error5.aspx",  // Renamed variant for stealth
		"contact.aspx", // Another common Agrius naming pattern
	}

	for _, filename := range webshellFiles {
		webshellPath := filepath.Join(targetDir, filename)

		fmt.Printf("[STAGE %s] Deploying simulated webshell: %s\n", TECHNIQUE_ID, filename)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Deploying simulated webshell: %s", filename))

		if err := os.WriteFile(webshellPath, []byte(webshellContent), 0644); err != nil {
			return fmt.Errorf("webshell deployment blocked: %v", err)
		}

		// Check for quarantine
		time.Sleep(1 * time.Second)
		if _, err := os.Stat(webshellPath); os.IsNotExist(err) {
			return fmt.Errorf("webshell quarantined by EDR: %s", filename)
		}

		LogFileDropped(filename, webshellPath, int64(len(webshellContent)), false)
		fmt.Printf("[STAGE %s] Webshell deployed: %s (%d bytes)\n", TECHNIQUE_ID, filename, len(webshellContent))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Deployed %d simulated ASPXSpy webshell variants", len(webshellFiles)))
	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"quarantined", "blocked", "access denied", "permission denied"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"not found", "does not exist"}) {
		return StageError
	}
	return StageBlocked
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsIgnoreCase(s, substr) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	sLower := toLowerStr(s)
	subLower := toLowerStr(substr)
	for i := 0; i <= len(sLower)-len(subLower); i++ {
		if sLower[i:i+len(subLower)] == subLower {
			return true
		}
	}
	return false
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
