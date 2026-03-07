//go:build windows
// +build windows

// Stage 2: IPsec Helper Service Persistence (T1543.003)
// Simulates Agrius persistence via Windows service creation with non-standard binary path
// Attempts to create a Windows service - if blocked by EDR, that's detection success

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "7d39b861-644d-4f8b-bb19-4faae527a130"
	TECHNIQUE_ID   = "T1543.003"
	TECHNIQUE_NAME = "Create or Modify System Process: Windows Service"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	serviceName    = "F0RT1KA_IPsecHelper"
	serviceDisplay = "IPsec Helper Service (F0RT1KA Test)"
	serviceBinPath = "c:\\F0\\ipsec_helper_svc.exe"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	fmt.Printf("[STAGE %s] Starting %s\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, "Simulating IPsec Helper service persistence (Agrius campaign)")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
		LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		os.Exit(determineExitCode(err))
	}

	fmt.Printf("[STAGE %s] %s executed successfully\n", TECHNIQUE_ID, TECHNIQUE_NAME)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "IPsec Helper service persistence established")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Create a fake service binary (benign placeholder)
	fmt.Printf("[STAGE %s] Creating fake service binary at %s\n", TECHNIQUE_ID, serviceBinPath)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating fake service binary: %s", serviceBinPath))

	fakeBinaryContent := []byte("REM F0RT1KA SIMULATION - NOT A REAL SERVICE BINARY\r\nREM Agrius IPsec Helper persistence simulation\r\n")
	if err := os.WriteFile(serviceBinPath, fakeBinaryContent, 0755); err != nil {
		return fmt.Errorf("failed to create fake service binary: %v", err)
	}

	// Check if fake binary got quarantined
	time.Sleep(1 * time.Second)
	if _, err := os.Stat(serviceBinPath); os.IsNotExist(err) {
		return fmt.Errorf("service binary quarantined by EDR")
	}

	// Attempt to create a Windows service using sc.exe
	// This is a key detection opportunity - EDR should alert on service creation
	fmt.Printf("[STAGE %s] Attempting to create Windows service: %s\n", TECHNIQUE_ID, serviceName)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating service: %s (binPath=%s)", serviceName, serviceBinPath))

	cmd := exec.Command("sc.exe", "create", serviceName,
		"binPath=", serviceBinPath,
		"DisplayName=", serviceDisplay,
		"start=", "auto",
		"type=", "own")

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		fmt.Printf("[STAGE %s] Service creation result: %s (err: %v)\n", TECHNIQUE_ID, outputStr, err)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("sc.exe output: %s", outputStr))

		// Check if blocked by EDR or insufficient privileges
		if strings.Contains(strings.ToLower(outputStr), "access") ||
			strings.Contains(strings.ToLower(outputStr), "denied") ||
			strings.Contains(strings.ToLower(outputStr), "blocked") {
			return fmt.Errorf("service creation blocked: %s", outputStr)
		}

		// Not admin
		if strings.Contains(strings.ToLower(outputStr), "openscmanager") {
			return fmt.Errorf("service creation requires admin privileges: %s", outputStr)
		}

		return fmt.Errorf("service creation failed: %s", outputStr)
	}

	fmt.Printf("[STAGE %s] Service created successfully: %s\n", TECHNIQUE_ID, outputStr)
	LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Service created without detection: %s", serviceName))

	// Attempt to query the service to confirm it exists
	queryCmd := exec.Command("sc.exe", "qc", serviceName)
	queryOutput, _ := queryCmd.CombinedOutput()
	fmt.Printf("[STAGE %s] Service query: %s\n", TECHNIQUE_ID, strings.TrimSpace(string(queryOutput)))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Service query result: %s", strings.TrimSpace(string(queryOutput))))

	// Cleanup: delete the service (safety mechanism)
	fmt.Printf("[STAGE %s] Cleaning up: deleting test service\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Cleaning up test service")

	stopCmd := exec.Command("sc.exe", "stop", serviceName)
	stopCmd.CombinedOutput() // Ignore error - service may not be running

	deleteCmd := exec.Command("sc.exe", "delete", serviceName)
	deleteOutput, deleteErr := deleteCmd.CombinedOutput()
	if deleteErr != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Service cleanup warning: %s", strings.TrimSpace(string(deleteOutput))))
	} else {
		fmt.Printf("[STAGE %s] Service deleted: %s\n", TECHNIQUE_ID, strings.TrimSpace(string(deleteOutput)))
		LogMessage("INFO", TECHNIQUE_ID, "Test service cleaned up successfully")
	}

	// Cleanup fake binary
	os.Remove(serviceBinPath)

	return nil
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "blocked") || strings.Contains(errStr, "access") ||
		strings.Contains(errStr, "denied") || strings.Contains(errStr, "prevented") ||
		strings.Contains(errStr, "quarantined") {
		return StageBlocked
	}
	if strings.Contains(errStr, "requires admin") || strings.Contains(errStr, "privilege") ||
		strings.Contains(errStr, "openscmanager") {
		return StageError
	}
	return StageBlocked
}
