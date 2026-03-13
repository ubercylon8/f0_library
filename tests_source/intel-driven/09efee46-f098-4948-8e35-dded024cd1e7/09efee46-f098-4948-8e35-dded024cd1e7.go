//go:build windows
// +build windows

/*
ID: 09efee46-f098-4948-8e35-dded024cd1e7
NAME: Sliver C2 Client Detection
TECHNIQUES: T1219
TACTICS: command-and-control
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: c2
TAGS: sliver, c2-implant, remote-access
UNIT: response
CREATED: 2025-04-22
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "09efee46-f098-4948-8e35-dded024cd1e7"
	TEST_NAME = "Sliver C2 Client Detection"
)

//go:embed sliver_client.exe
var malicious []byte

func execute() error {
	// Execute the sliver client with --help flag
	// In a real scenario, this would attempt to connect to a C2 server
	binaryPath := filepath.Join(LOG_DIR, "sliver_client.exe")

	cmd := exec.Command(binaryPath, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		LogProcessExecution("sliver_client.exe", binaryPath+" --help", 0, false, 1, err.Error())
		return err
	}

	LogProcessExecution("sliver_client.exe", binaryPath+" --help", 0, true, 0, "")
	LogMessage("INFO", "Execution", fmt.Sprintf("Sliver client output: %s", string(output)))
	return nil
}

func test() {
	// Phase 0: Initialization - Extract binary to LOG_DIR
	LogPhaseStart(0, "Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting Sliver C2 client binary...")

	// Ensure LOG_DIR exists
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		LogMessage("ERROR", "Binary Extraction", fmt.Sprintf("Failed to create LOG_DIR: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create LOG_DIR")
		Endpoint.Say("FATAL: Failed to create LOG_DIR: %v", err)
		SaveLog(999, fmt.Sprintf("Failed to create LOG_DIR: %v", err))
		os.Exit(999)
	}

	// Write embedded binary to LOG_DIR
	binaryPath := filepath.Join(LOG_DIR, "sliver_client.exe")
	if err := os.WriteFile(binaryPath, malicious, 0755); err != nil {
		LogMessage("ERROR", "Binary Extraction", fmt.Sprintf("Failed to write binary: %v", err))
		LogPhaseEnd(0, "failed", "Failed to write binary")
		Endpoint.Say("FATAL: Failed to write sliver_client.exe: %v", err)
		SaveLog(999, fmt.Sprintf("Failed to write binary: %v", err))
		os.Exit(999)
	}

	LogFileDropped("sliver_client.exe", binaryPath, int64(len(malicious)), false)
	Endpoint.Say("    [+] Extracted: sliver_client.exe (%d bytes)", len(malicious))
	LogPhaseEnd(0, "success", "Binary extracted successfully")
	Endpoint.Say("")

	// Phase 1: Quarantine Detection
	LogPhaseStart(1, "Quarantine Detection")
	Endpoint.Say("[*] Phase 1: Checking for quarantine reaction...")
	Endpoint.Say("    Extracting Sliver C2 client for quarantine test")
	Endpoint.Say("    Pausing for 3 seconds to gauge defensive reaction")
	time.Sleep(3 * time.Second)

	// Check if file was quarantined using os.Stat (per Bug Prevention Rule #3)
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		LogFileDropped("sliver_client.exe", binaryPath, int64(len(malicious)), true)
		LogPhaseEnd(1, "blocked", "Binary was quarantined by AV/EDR")
		Endpoint.Say("    Sliver client binary was caught!")
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED - File Quarantined on Extraction")
		Endpoint.Say("Exit Code: 105")
		Endpoint.Say("=================================================================")
		SaveLog(105, "Sliver C2 client binary was quarantined on extraction")
		os.Exit(105)
	}

	LogPhaseEnd(1, "success", "Binary survived quarantine check")
	Endpoint.Say("    Binary not quarantined, proceeding to execution")
	Endpoint.Say("")

	// Phase 2: Execution Attempt
	LogPhaseStart(2, "Execution Attempt")
	Endpoint.Say("[*] Phase 2: Attempting Sliver client execution...")
	Endpoint.Say("    Sliver client binary was not caught, attempting execution")

	err := execute()
	if err != nil {
		LogPhaseEnd(2, "blocked", fmt.Sprintf("Execution was prevented: %v", err))
		Endpoint.Say("    Got error \"%v\" when executing Sliver client", err)
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED - Execution Prevented")
		Endpoint.Say("Exit Code: 126")
		Endpoint.Say("=================================================================")
		SaveLog(126, fmt.Sprintf("Sliver C2 client execution was prevented: %v", err))
		os.Exit(126)
	}

	// Execution succeeded - endpoint is unprotected
	LogPhaseEnd(2, "success", "Sliver client executed successfully - endpoint unprotected")
	Endpoint.Say("    Sliver client execution was not prevented")
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: UNPROTECTED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("The Sliver C2 client binary was not quarantined and executed successfully.")
	Endpoint.Say("AV/EDR did not detect or block the C2 implant.")
	Endpoint.Say("")
	Endpoint.Say("Exit Code: 101")
	Endpoint.Say("=================================================================")

	SaveLog(101, "Sliver C2 client was not detected - binary extracted and executed successfully")
	os.Exit(101)
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Schema v2.0 metadata from header comment
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "command-and-control",
		Severity:   "high",
		Techniques: []string{"T1219"},
		Tactics:    []string{"command-and-control"},
		Score:      7.0,
		Tags:       []string{"sliver", "c2-implant", "remote-access"},
	}

	// Resolve organization
	orgInfo := ResolveOrganization("")

	// Execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
	}

	// Initialize Schema v2.0 logger
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(999, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Run the test
	test()
}
