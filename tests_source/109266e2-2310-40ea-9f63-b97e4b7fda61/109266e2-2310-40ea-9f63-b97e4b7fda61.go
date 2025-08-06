//go:build windows
// +build windows

/*
ID: 109266e2-2310-40ea-9f63-b97e4b7fda61
NAME: SafePay Enhanced Ransomware Simulation & Mass Data Operations
TECHNIQUE: T1486, T1560.001, T1071.001, T1490, T1083, T1005
UNIT: response
CREATED: 2025-07-30 00:00:00.000000
ENHANCED: 2025-08-06 00:00:00.000000
*/
package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed safepay_ransomware_sim.ps1
var ransomwareScript []byte

//go:embed WinRAR.exe 
var winrarBinary []byte

func executeRansomwareSimulation() error {
	// Drop all files to c:\F0
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)
	
	// Drop WinRAR binary
	winrarPath := filepath.Join(targetDir, "WinRAR.exe")
	err := os.WriteFile(winrarPath, winrarBinary, 0755)
	if err != nil {
		return err
	}
	
	// Drop PowerShell script
	scriptPath := filepath.Join(targetDir, "safepay_ransomware_sim.ps1")
	err = os.WriteFile(scriptPath, ransomwareScript, 0644)
	if err != nil {
		return err
	}
	
	// Execute the PowerShell script with bypass
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	_, err = cmd.Output()
	return err
}

func test() {
	// Initialize the dropper
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("Dropper initialization failed: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	Endpoint.Say("Starting SafePay Enhanced Ransomware Simulation with Mass Data Operations")
	Endpoint.Say("This test simulates realistic ransomware behavior targeting user directories")
	Endpoint.Say("Expected behaviors: Mass file creation, compression, deletion, encryption")
	Endpoint.Say("Dropping WinRAR binary and enhanced PowerShell script")
	Endpoint.Say("Pausing for 5 seconds to gauge initial defensive reaction")
	Endpoint.Wait(5)

	// Check if components get quarantined
	if Endpoint.Quarantined("safepay_ransomware_sim.ps1", ransomwareScript) {
		Endpoint.Say("SafePay enhanced ransomware script was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("WinRAR.exe", winrarBinary) {
		Endpoint.Say("WinRAR binary was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	Endpoint.Say("Components were not caught, executing enhanced ransomware simulation")
	Endpoint.Say("Target: C:\\Users\\fortika-test (realistic user directory targeting)")
	Endpoint.Say("Expected operations: 500-1500 files, multi-phase compression, mass deletion")

	// Try to execute the enhanced ransomware simulation
	err := executeRansomwareSimulation()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when executing enhanced ransomware simulation", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("Enhanced ransomware simulation execution was not prevented")
	Endpoint.Say("Mass file operations, compression, and deletion completed successfully")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}
