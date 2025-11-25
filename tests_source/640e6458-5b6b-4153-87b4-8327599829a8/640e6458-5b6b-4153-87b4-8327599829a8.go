//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	_ "embed"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "640e6458-5b6b-4153-87b4-8327599829a8"
	TEST_NAME = "EDR Network Isolation via Windows Filtering Platform"
	VERSION   = "1.0.0"
)

// Embed signed stage binaries (MUST be signed before embedding!)
//
// Build process:
// 1. Build each stage: GOOS=windows GOARCH=amd64 go build -o <uuid>-<technique>.exe stage.go test_logger.go org_resolver.go
// 2. Sign each stage: ../../utils/codesign sign <uuid>-<technique>.exe
// 3. Then these //go:embed directives will embed the SIGNED binaries
//
// Note: build_all.sh handles this entire process automatically

//go:embed 640e6458-5b6b-4153-87b4-8327599829a8-T1016.exe
var stage1Binary []byte

//go:embed 640e6458-5b6b-4153-87b4-8327599829a8-T1562.004.exe
var stage2Binary []byte

//go:embed 640e6458-5b6b-4153-87b4-8327599829a8-T1489.exe
var stage3Binary []byte

// KillchainStage represents one technique in the attack chain
// Renamed from "Stage" to avoid conflict with test_logger.go logging Stage
type KillchainStage struct {
	ID          int
	Name        string
	Technique   string
	BinaryName  string
	BinaryData  []byte
	Description string
}

func main() {
	// Initialize logger with Schema v2.0 metadata and execution context
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "defense_evasion",
		Severity: "high",
		Techniques: []string{
			"T1016",     // System Network Configuration Discovery
			"T1562.004", // Impair Defenses: Disable Windows Firewall
			"T1489",     // Service Stop
		},
		Tactics: []string{"defense-evasion", "discovery", "impact"},
		Score:   9.2,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.2,
			DetectionOpportunities:  0.7,
			LoggingObservability:    1.5,
		},
		Tags: []string{"windows-filtering-platform", "network-isolation", "edr-evasion", "multi-stage", "silentbutdeadly"},
	}

	// Resolve organization info
	orgInfo := ResolveOrganization("")

	// Define execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000,
			MultiStageEnabled: true,
		},
	}

	// Initialize logger with v2.0 signature
	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}()

	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Multi-Stage Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Version: %s", VERSION)
	Endpoint.Say("Organization: %s", orgInfo.ShortName)
	Endpoint.Say("Execution ID: %s", executionContext.ExecutionID)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Run the test
	test()
}

func test() {
	// Define attack killchain
	killchain := []KillchainStage{
		{
			ID:          1,
			Name:        "EDR Process Discovery",
			Technique:   "T1016",
			BinaryName:  fmt.Sprintf("%s-T1016.exe", TEST_UUID),
			BinaryData:  stage1Binary,
			Description: "Enumerate running processes to identify EDR/AV products",
		},
		{
			ID:          2,
			Name:        "WFP Filter Application",
			Technique:   "T1562.004",
			BinaryName:  fmt.Sprintf("%s-T1562.004.exe", TEST_UUID),
			BinaryData:  stage2Binary,
			Description: "Apply Windows Filtering Platform filters to block EDR cloud connectivity",
		},
		{
			ID:          3,
			Name:        "EDR Service Disruption",
			Technique:   "T1489",
			BinaryName:  fmt.Sprintf("%s-T1489.exe", TEST_UUID),
			BinaryData:  stage3Binary,
			Description: "Attempt to stop and disable EDR services",
		},
	}

	// Phase 0: Extract all stage binaries
	LogPhaseStart(0, "Stage Binary Extraction")
	Endpoint.Say("[*] Phase 0: Extracting %d stage binaries...", len(killchain))

	for i, stage := range killchain {
		Endpoint.Say("    [%d/%d] Extracting %s (%s)", i+1, len(killchain), stage.BinaryName, stage.Technique)

		if err := extractStage(stage); err != nil {
			LogPhaseEnd(0, "error", fmt.Sprintf("Failed to extract %s: %v", stage.BinaryName, err))
			Endpoint.Say("")
			Endpoint.Say("❌ FATAL: Failed to extract stage binary: %s", stage.BinaryName)
			Endpoint.Say("    Error: %v", err)
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage extraction failed: %v", err))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}
	}

	LogPhaseEnd(0, "success", fmt.Sprintf("Successfully extracted %d stage binaries", len(killchain)))
	Endpoint.Say("    ✓ All stage binaries extracted successfully")
	Endpoint.Say("")

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing %d-stage attack killchain...", len(killchain))
	Endpoint.Say("")

	for _, stage := range killchain {
		// Log stage start
		LogStageStart(stage.ID, stage.Technique, stage.Name)

		Endpoint.Say("=================================================================")
		Endpoint.Say("Stage %d/%d: %s", stage.ID, len(killchain), stage.Name)
		Endpoint.Say("Technique: %s", stage.Technique)
		Endpoint.Say("Description: %s", stage.Description)
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		// Execute stage binary
		exitCode := executeStage(stage)

		// Evaluate stage result
		if exitCode == 126 || exitCode == 105 {
			// Stage was blocked by EDR - system is protected
			LogStageEnd(stage.ID, stage.Technique, "blocked", fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("=================================================================")
			Endpoint.Say("FINAL EVALUATION: Stage %d Blocked", stage.ID)
			Endpoint.Say("=================================================================")
			Endpoint.Say("")
			Endpoint.Say("✅ RESULT: PROTECTED")
			Endpoint.Say("")
			Endpoint.Say("EDR successfully blocked the attack at stage %d:", stage.ID)
			Endpoint.Say("  • Technique: %s", stage.Technique)
			Endpoint.Say("  • Stage: %s", stage.Name)
			Endpoint.Say("  • Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("Attack Chain Interrupted:")
			Endpoint.Say("  • Completed Stages: %d/%d", stage.ID-1, len(killchain))
			Endpoint.Say("  • Blocked Stage: %d (%s)", stage.ID, stage.Technique)
			Endpoint.Say("  • Remaining Stages: %d (not executed)", len(killchain)-stage.ID)
			Endpoint.Say("")
			Endpoint.Say("Security Status: ENDPOINT IS SECURE")
			Endpoint.Say("=================================================================")
			Endpoint.Say("")

			SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("EDR blocked at stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique))
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		} else if exitCode == 999 {
			// Stage failed with unexpected error
			LogStageEnd(stage.ID, stage.Technique, "error", fmt.Sprintf("Stage %d failed with exit code %d", stage.ID, exitCode))

			Endpoint.Say("")
			Endpoint.Say("❌ Stage %d failed with error (exit code: %d)", stage.ID, exitCode)
			Endpoint.Say("   This may indicate test prerequisites not met")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		} else if exitCode == 101 {
			// Stage succeeded (unprotected)
			LogStageEnd(stage.ID, stage.Technique, "success", fmt.Sprintf("Stage %d completed successfully", stage.ID))
			Endpoint.Say("")
			Endpoint.Say("✓ Stage %d completed successfully", stage.ID)
			Endpoint.Say("")
		} else {
			// Unexpected exit code
			LogStageEnd(stage.ID, stage.Technique, "unknown", fmt.Sprintf("Stage %d returned unexpected exit code %d", stage.ID, exitCode))
			Endpoint.Say("")
			Endpoint.Say("⚠ Stage %d returned unexpected exit code: %d", stage.ID, exitCode)
			Endpoint.Say("")
		}
	}

	// All stages completed successfully - system is vulnerable
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("❌ RESULT: UNPROTECTED")
	Endpoint.Say("")
	Endpoint.Say("Complete attack chain executed successfully:")
	Endpoint.Say("  • All %d stages completed without blocking", len(killchain))
	Endpoint.Say("  • EDR processes identified")
	Endpoint.Say("  • WFP filters applied")
	Endpoint.Say("  • Services disrupted")
	Endpoint.Say("")
	Endpoint.Say("Security Status: ENDPOINT IS VULNERABLE")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete attack chain successful", len(killchain)))
	Endpoint.Stop(Endpoint.Unprotected)
}

func extractStage(stage KillchainStage) error {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	err := os.WriteFile(stagePath, stage.BinaryData, 0755)
	if err != nil {
		return fmt.Errorf("failed to write stage binary: %v", err)
	}

	// Check if file was quarantined
	if Endpoint.Quarantined(stagePath, stage.BinaryData) {
		LogMessage("WARNING", fmt.Sprintf("Stage %d", stage.ID),
			fmt.Sprintf("Stage binary quarantined: %s", stage.BinaryName))
		return fmt.Errorf("stage binary was quarantined by AV")
	}

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID),
		fmt.Sprintf("Extracted stage binary: %s", stage.BinaryName))

	return nil
}

func executeStage(stage KillchainStage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	cmd := exec.Command(stagePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// Command failed to execute
			LogMessage("ERROR", fmt.Sprintf("Stage %d", stage.ID),
				fmt.Sprintf("Failed to execute stage: %v", err))
			return 999 // UnexpectedTestError
		}
	}

	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID),
		fmt.Sprintf("Stage completed with exit code: %d", exitCode))

	return exitCode
}
