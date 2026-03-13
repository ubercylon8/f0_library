//go:build windows
// +build windows

/*
ID: bcba14e7-6f87-4cbd-9c32-718fdeb39b65
NAME: EDRSilencer Detection
TECHNIQUES: T1562.001
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: edr-evasion
TAGS: edrsilencer, wfp-filter, telemetry-blocking
UNIT: response
CREATED: 2024-10-07
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "bcba14e7-6f87-4cbd-9c32-718fdeb39b65"
	TEST_NAME = "EDRSilencer Detection"
)

//go:embed EDRSilencer.exe
var malicious []byte

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")

	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "defense_evasion",
		Severity:   "high",
		Techniques: []string{"T1562.001"},
		Tactics:    []string{"defense-evasion"},
		Score:      7.8,
		Tags:       []string{"edrsilencer", "wfp-filter", "telemetry-blocking"},
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
			os.Exit(999)
		}
	}()

	// --- Attack simulation logic (preserved) ---

	// Ensure LOG_DIR exists
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		LogMessage("ERROR", "Setup", fmt.Sprintf("Failed to create LOG_DIR: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to create LOG_DIR: %v", err))
		os.Exit(999)
	}

	// Extract the EDRSilencer binary to LOG_DIR
	binaryPath := filepath.Join(LOG_DIR, "EDRSilencer.exe")
	Endpoint.Say("Extracting EDRSilencer tool for quarantine test")

	if err := os.WriteFile(binaryPath, malicious, 0755); err != nil {
		LogMessage("ERROR", "Extraction", fmt.Sprintf("Failed to write EDRSilencer.exe: %v", err))
		SaveLog(999, fmt.Sprintf("Failed to write EDRSilencer.exe: %v", err))
		os.Exit(999)
	}
	LogFileDropped("EDRSilencer.exe", binaryPath, int64(len(malicious)), false)

	// Pause to allow AV/EDR to react
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	time.Sleep(3 * time.Second)

	// Check if file was quarantined using os.Stat (Bug Prevention Rule #3)
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		Endpoint.Say("EDRSilencer binary was caught!")
		LogMessage("INFO", "Quarantine", "EDRSilencer.exe was quarantined after extraction")
		LogFileDropped("EDRSilencer.exe", binaryPath, int64(len(malicious)), true)
		SaveLog(105, "EDRSilencer.exe quarantined on extraction")
		os.Exit(105)
	}

	Endpoint.Say("EDRSilencer binary was not caught, attempting execution")
	LogMessage("INFO", "Execution", "Attempting EDRSilencer execution")

	// Try to execute EDRSilencer
	err := execute(binaryPath)
	if err != nil {
		Endpoint.Say("Got error \"%v\" when executing EDRSilencer", err)
		LogMessage("INFO", "Execution", fmt.Sprintf("EDRSilencer execution failed: %v", err))
		SaveLog(126, fmt.Sprintf("EDRSilencer execution prevented: %v", err))
		os.Exit(126)
	}

	Endpoint.Say("EDRSilencer execution was not prevented")
	LogMessage("WARNING", "Result", "EDRSilencer executed successfully - endpoint unprotected")

	// Cleanup extracted binary
	os.Remove(binaryPath)

	SaveLog(101, "EDRSilencer executed successfully - endpoint unprotected")
	os.Exit(101)
}

func execute(binaryPath string) error {
	// Command to run EDRSilencer to detect EDR processes
	cmd := exec.Command(binaryPath, "blockedr")

	// Capture stdout/stderr to file using io.MultiWriter
	outputPath := filepath.Join(LOG_DIR, "EDRSilencer_output.txt")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	cmd.Stdout = io.MultiWriter(os.Stdout, outputFile)
	cmd.Stderr = io.MultiWriter(os.Stderr, outputFile)

	if err := cmd.Run(); err != nil {
		LogProcessExecution("EDRSilencer.exe", binaryPath+" blockedr", 0, false, 1, err.Error())
		return err
	}
	LogProcessExecution("EDRSilencer.exe", binaryPath+" blockedr", 0, true, 0, "")

	// Clean up by removing all filters
	cleanupCmd := exec.Command(binaryPath, "unblockall")
	cleanupCmd.Stdout = io.MultiWriter(os.Stdout, outputFile)
	cleanupCmd.Stderr = io.MultiWriter(os.Stderr, outputFile)

	if err := cleanupCmd.Run(); err != nil {
		Endpoint.Say("Warning: Failed to clean up WFP filters: %v", err)
		LogProcessExecution("EDRSilencer.exe", binaryPath+" unblockall", 0, false, 1, err.Error())
		// Continue execution even if cleanup fails
	} else {
		LogProcessExecution("EDRSilencer.exe", binaryPath+" unblockall", 0, true, 0, "")
	}

	return nil
}
