//go:build windows
// +build windows

/*
ID: ecd2514c-512a-4251-a6f4-eb3aa834d401
NAME: CyberEye RAT - Windows Defender Disabling via PowerShell
TECHNIQUES: T1562.001
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: edr-evasion
TAGS: cybereye, powershell, defender-disabling, rat
UNIT: response
CREATED: 2025-07-02
AUTHOR: sectest-builder
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

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "ecd2514c-512a-4251-a6f4-eb3aa834d401"
	TEST_NAME = "CyberEye RAT - Windows Defender Disabling via PowerShell"
)

//go:embed CyberEye-TTPs.ps1
var maliciousScript []byte

//go:embed Cleanup-CyberEye-TTPs.ps1
var cleanupScript []byte

func execute() error {
	// Define paths
	targetDir := LOG_DIR
	scriptPath := filepath.Join(targetDir, "CyberEye-TTPs.ps1")

	// Extract PowerShell script to target directory
	Endpoint.Say("Extracting PowerShell script to %s", scriptPath)

	if err := os.WriteFile(scriptPath, maliciousScript, 0755); err != nil {
		return err
	}

	// Log file drop
	LogFileDropped("CyberEye-TTPs.ps1", scriptPath, int64(len(maliciousScript)), false)

	// Check if script was quarantined after extraction
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		Endpoint.Say("PowerShell script was quarantined after extraction")
		LogFileDropped("CyberEye-TTPs.ps1", scriptPath, int64(len(maliciousScript)), true)
		return err
	}

	Endpoint.Say("PowerShell script successfully extracted")
	time.Sleep(2 * time.Second)

	// Attempt to execute the PowerShell script
	Endpoint.Say("Attempting to execute Windows Defender disabling script")

	// Use PowerShell with execution policy bypass
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)

	// Set working directory
	cmd.Dir = targetDir

	// Execute the command
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Log process execution
	cmdSuccess := err == nil
	cmdExitCode := 0
	cmdErrMsg := ""
	if err != nil {
		cmdErrMsg = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			cmdExitCode = exitErr.ExitCode()
		}
	}
	LogProcessExecution("powershell.exe", fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -File %s", scriptPath), cmd.Process.Pid, cmdSuccess, cmdExitCode, cmdErrMsg)

	// Always log the output for debugging
	Endpoint.Say("Script output: %s", outputStr)

	// Check if registry modifications were blocked (system is protected)
	protectedIndicators := []string{
		"Requested registry access is not allowed",
		"Access is denied",
		"Access denied",
		"Failed to set TamperProtection",
		"Failed to query Defender settings",
		"Cannot write to the registry key",
		"Registry access denied",
		"Insufficient privileges",
		"requires administrative privileges",
	}

	systemProtected := false
	for _, indicator := range protectedIndicators {
		if strings.Contains(outputStr, indicator) {
			systemProtected = true
			Endpoint.Say("System protection detected: %s", indicator)
			break
		}
	}

	// Check for successful registry modifications (system is unprotected)
	successIndicators := []string{
		"Registry manipulations completed successfully",
		"Set TamperProtection to 0",
		"Set DisableAntiSpyware to 1",
		"Set DisableBehaviorMonitoring to 1",
		"Set DisableOnAccessProtection to 1",
		"Set DisableScanOnRealtimeEnable to 1",
	}

	modificationSuccessCount := 0
	for _, indicator := range successIndicators {
		if strings.Contains(outputStr, indicator) {
			modificationSuccessCount++
		}
	}

	// If PowerShell execution failed with an error, check if it's due to protection
	if err != nil {
		Endpoint.Say("PowerShell execution returned error: %v", err)
		if systemProtected {
			// Error due to protection - this is good, system blocked the attack
			return fmt.Errorf("registry modifications blocked by security controls")
		}
		// Other error - treat as unexpected
		return err
	}

	// If multiple registry modifications succeeded, system is unprotected
	if modificationSuccessCount >= 3 && !systemProtected {
		Endpoint.Say("WARNING: Multiple registry modifications succeeded - system appears unprotected")
		// Wait for potential delayed detection
		time.Sleep(5 * time.Second)

		// Check if Windows Defender is still running
		Endpoint.Say("Checking if Windows Defender service is affected")
		serviceCmd := exec.Command("sc", "query", "WinDefend")
		serviceOutput, serviceErr := serviceCmd.CombinedOutput()

		if serviceErr != nil {
			Endpoint.Say("Failed to query Windows Defender service: %v", serviceErr)
		} else {
			Endpoint.Say("Windows Defender service status: %s", string(serviceOutput))
		}

		return nil // Success in disabling - system unprotected
	}

	// If we detected protection indicators, return error to indicate blocking
	if systemProtected {
		return fmt.Errorf("registry modifications blocked by security controls")
	}

	// Ambiguous case - treat as potential protection
	return fmt.Errorf("unable to determine if registry modifications succeeded")
}

func cleanup() {
	// Clean up dropped files
	targetDir := LOG_DIR
	scriptPath := filepath.Join(targetDir, "CyberEye-TTPs.ps1")
	cleanupPath := filepath.Join(targetDir, "Cleanup-CyberEye-TTPs.ps1")

	if _, err := os.Stat(scriptPath); err == nil {
		os.Remove(scriptPath)
		Endpoint.Say("Cleaned up PowerShell script")
	}

	if _, err := os.Stat(cleanupPath); err == nil {
		os.Remove(cleanupPath)
		Endpoint.Say("Cleaned up cleanup script")
	}
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "intel-driven",
		Severity:   "high",
		Techniques: []string{"T1562.001"},
		Tactics:    []string{"defense-evasion"},
		Score:      7.5,
		Tags:       []string{"cybereye", "powershell", "defender-disabling", "rat"},
	}

	orgInfo := ResolveOrganization("")
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Create target directory
	targetDir := LOG_DIR
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		Endpoint.Say("Failed to create target directory: %v", err)
		LogMessage("ERROR", "Setup", fmt.Sprintf("Failed to create target directory: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to create target directory: %v", err))
		os.Exit(999)
	}

	// Change to target directory
	originalDir, _ := os.Getwd()
	os.Chdir(targetDir)
	defer func() {
		os.Chdir(originalDir)
		cleanup()
	}()

	// Phase 1: Script extraction and quarantine check
	LogPhaseStart(0, "Script Extraction")

	Endpoint.Say("Testing Windows Defender disabling via PowerShell script")

	scriptPath := filepath.Join(targetDir, "CyberEye-TTPs.ps1")
	if err := os.WriteFile(scriptPath, maliciousScript, 0755); err != nil {
		Endpoint.Say("Failed to write PowerShell script: %v", err)
		LogPhaseEnd(0, "failed", fmt.Sprintf("Failed to write script: %v", err))
		LogMessage("ERROR", "Script Extraction", fmt.Sprintf("Failed to write script: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to write script: %v", err))
		os.Exit(999)
	}

	LogFileDropped("CyberEye-TTPs.ps1", scriptPath, int64(len(maliciousScript)), false)

	// Check quarantine using os.Stat (Bug Prevention Rule #3)
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		Endpoint.Say("PowerShell script was quarantined during extraction!")
		LogFileDropped("CyberEye-TTPs.ps1", scriptPath, int64(len(maliciousScript)), true)
		LogPhaseEnd(0, "blocked", "Script quarantined on extraction")
		LogMessage("INFO", "Script Extraction", "PowerShell script quarantined by AV/EDR on extraction")
		SaveLog(105, "PowerShell script quarantined on extraction")
		os.Exit(105)
	}

	// Also extract cleanup script (non-malicious, for restoration)
	cleanupPath := filepath.Join(targetDir, "Cleanup-CyberEye-TTPs.ps1")
	if err := os.WriteFile(cleanupPath, cleanupScript, 0755); err != nil {
		Endpoint.Say("Warning: Failed to extract cleanup script: %v", err)
		// Non-fatal - test can continue
	} else {
		Endpoint.Say("Cleanup script available at: %s", cleanupPath)
		LogFileDropped("Cleanup-CyberEye-TTPs.ps1", cleanupPath, int64(len(cleanupScript)), false)
	}

	// Remove the script we just wrote - execute() will write it again as part of its flow
	os.Remove(scriptPath)

	LogPhaseEnd(0, "success", "Script extraction successful, not quarantined")

	// Phase 2: Execute attack simulation
	LogPhaseStart(1, "Defender Disabling Execution")

	if err := execute(); err != nil {
		Endpoint.Say("Test execution prevented by security controls: %v", err)
		LogPhaseEnd(1, "blocked", fmt.Sprintf("Execution prevented: %v", err))
		LogMessage("INFO", "Defender Disabling Execution", fmt.Sprintf("Security controls prevented execution: %v", err))
		SaveLog(126, fmt.Sprintf("Execution prevented by security controls: %v", err))
		os.Exit(126)
	}

	LogPhaseEnd(1, "success", "Defender disabling technique executed without prevention")

	Endpoint.Say("Windows Defender disabling technique executed without prevention")
	LogMessage("WARN", "Defender Disabling Execution", "Attack succeeded - endpoint is unprotected")
	SaveLog(101, "Windows Defender disabling technique executed without prevention - endpoint unprotected")
	os.Exit(101)
}
