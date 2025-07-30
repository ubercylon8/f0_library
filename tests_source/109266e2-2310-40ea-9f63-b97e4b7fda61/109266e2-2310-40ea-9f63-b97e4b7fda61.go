//go:build windows
// +build windows

/*
ID: 109266e2-2310-40ea-9f63-b97e4b7fda61
NAME: SafePay Ransomware Simulation & Data Staging
TECHNIQUE: T1486, T1560.001, T1071.001, T1490
UNIT: response
CREATED: 2025-07-30 00:00:00.000000
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

//go:embed winrar_placeholder.exe
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

	Endpoint.Say("Starting SafePay Ransomware Simulation & Data Staging test")
	Endpoint.Say("Dropping WinRAR binary and PowerShell script for ransomware simulation")
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	Endpoint.Wait(3)

	// Check if components get quarantined
	if Endpoint.Quarantined("safepay_ransomware_sim.ps1", ransomwareScript) {
		Endpoint.Say("SafePay ransomware script was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("WinRAR.exe", winrarBinary) {
		Endpoint.Say("WinRAR binary was caught!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	Endpoint.Say("Components were not caught, attempting ransomware simulation execution")

	// Try to execute the ransomware simulation
	err := executeRansomwareSimulation()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when executing ransomware simulation", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("Ransomware simulation execution was not prevented")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Start(test)
}