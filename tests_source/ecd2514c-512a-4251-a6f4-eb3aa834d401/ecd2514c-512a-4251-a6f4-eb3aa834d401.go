//go:build windows
// +build windows

/*
ID: ecd2514c-512a-4251-a6f4-eb3aa834d401
NAME: CyberEye RAT - Windows Defender Disabling via PowerShell
TECHNIQUE: T1562.001
UNIT: response
CREATED: 2025-07-02
*/

package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed CyberEye-TTPs.ps1
var maliciousScript []byte

func execute() error {
	// Define paths
	targetDir := "c:\\F0"
	scriptPath := filepath.Join(targetDir, "CyberEye-TTPs.ps1")

	// Extract PowerShell script to target directory
	Endpoint.Say("Extracting PowerShell script to %s", scriptPath)
	
	if err := os.WriteFile(scriptPath, maliciousScript, 0755); err != nil {
		return err
	}

	// Check if script was quarantined after extraction
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		Endpoint.Say("PowerShell script was quarantined after extraction")
		return err
	}

	Endpoint.Say("PowerShell script successfully extracted")
	Endpoint.Wait(2)

	// Attempt to execute the PowerShell script
	Endpoint.Say("Attempting to execute Windows Defender disabling script")
	
	// Use PowerShell with execution policy bypass
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	
	// Set working directory
	cmd.Dir = targetDir
	
	// Execute the command
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		Endpoint.Say("PowerShell execution failed: %v", err)
		Endpoint.Say("Output: %s", string(output))
		return err
	}

	Endpoint.Say("PowerShell script executed successfully")
	Endpoint.Say("Script output: %s", string(output))

	// Wait for potential detection
	Endpoint.Wait(5)

	// Check if Windows Defender is still running (basic check)
	Endpoint.Say("Checking if Windows Defender service is affected")
	serviceCmd := exec.Command("sc", "query", "WinDefend")
	serviceOutput, serviceErr := serviceCmd.CombinedOutput()
	
	if serviceErr != nil {
		Endpoint.Say("Failed to query Windows Defender service: %v", serviceErr)
	} else {
		Endpoint.Say("Windows Defender service status: %s", string(serviceOutput))
	}

	return nil
}

func cleanup() {
	// Clean up dropped files
	targetDir := "c:\\F0"
	scriptPath := filepath.Join(targetDir, "CyberEye-TTPs.ps1")
	
	if _, err := os.Stat(scriptPath); err == nil {
		os.Remove(scriptPath)
		Endpoint.Say("Cleaned up PowerShell script")
	}
}

func test() {
	// Initialize dropper
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("Failed to initialize dropper: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Create target directory
	targetDir := "c:\\F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		Endpoint.Say("Failed to create target directory: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Change to target directory
	originalDir, _ := os.Getwd()
	os.Chdir(targetDir)
	defer func() {
		os.Chdir(originalDir)
		cleanup()
	}()

	// Check if PowerShell script is quarantined during extraction
	Endpoint.Say("Testing Windows Defender disabling via PowerShell script")
	
	if Endpoint.Quarantined("CyberEye-TTPs.ps1", maliciousScript) {
		Endpoint.Say("PowerShell script was quarantined during extraction!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	// Execute the test
	if err := execute(); err != nil {
		Endpoint.Say("Test execution prevented by security controls: %v", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("Windows Defender disabling technique executed without prevention")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}