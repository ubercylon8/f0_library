// Multi-Stage Test Orchestrator Template
// F0RT1KA Security Testing Framework
//
// This template provides a lightweight orchestrator for multi-stage attack chain tests.
// Each ATT&CK technique is implemented as a separate signed binary that is embedded
// in this main orchestrator.
//
// USAGE INSTRUCTIONS:
// 1. Copy this template to tests_source/<your-uuid>/<your-uuid>.go
// 2. Copy test_logger.go and org_resolver.go to your test directory
// 3. Replace TEMPLATE-UUID with your actual test UUID (lowercase)
// 4. Update TEST_NAME with your test name
// 5. Update the metadata header block below with your test details
// 6. Update test metadata (techniques, tactics, scoring) in main()
// 7. Define your killchain stages in the killchain array
// 8. Create stage binaries (copy stage-template.go for each technique)
// 9. Build stage binaries and sign them BEFORE embedding
// 10. Update //go:embed directives to embed your signed stage binaries
// 11. Implement any test-specific initialization or cleanup logic
//
// CRITICAL: Stage binaries MUST be signed BEFORE embedding!
// See build_all.sh for the complete build process.

//go:build windows

/*
ID: TEMPLATE-UUID
NAME: Multi-Stage Attack Chain Template
TECHNIQUES: T1134.001, T1055.001, T1003.001
TACTICS: privilege-escalation, defense-evasion, credential-access
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: high
THREAT_ACTOR: N/A
SUBCATEGORY: apt
TAGS: multi-stage, privilege-escalation, credential-theft
UNIT: response
CREATED: 2026-01-17
AUTHOR: sectest-builder
*/

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION - CUSTOMIZE THIS SECTION FOR YOUR TEST
// ==============================================================================

const (
	TEST_UUID = "TEMPLATE-UUID"                     // Replace with your test UUID
	TEST_NAME = "Multi-Stage Attack Chain Template" // Replace with your test name
)

// Embed gzip-compressed signed stage binaries
// Compressed at build time to reduce orchestrator size (~35% smaller)
// Decompressed in memory during extraction — files on disk are normal signed PEs
//
// Build process:
// 1. Build: GOOS=windows GOARCH=amd64 go build -o TEMPLATE-UUID-T1234.001.exe stage-T1234.001.go test_logger.go org_resolver.go
// 2. Sign:  ../../utils/codesign sign TEMPLATE-UUID-T1234.001.exe
// 3. Compress: gzip -9 -k TEMPLATE-UUID-T1234.001.exe
// 4. Then this //go:embed directive will embed the SIGNED+COMPRESSED binary
//
// IMPORTANT: NEVER use UPX or runtime packers (trigger EDR heuristic detections)

//go:embed TEMPLATE-UUID-T1134.001.exe.gz
var stage1Compressed []byte

//go:embed TEMPLATE-UUID-T1055.001.exe.gz
var stage2Compressed []byte

//go:embed TEMPLATE-UUID-T1003.001.exe.gz
var stage3Compressed []byte

// Add more stage binaries as needed for your test
// Example:
// //go:embed TEMPLATE-UUID-T1071.001.exe.gz
// var stage4Compressed []byte

// ==============================================================================
// STAGE DEFINITION
// ==============================================================================

// Stage represents one technique in the attack killchain
type Stage struct {
	ID          int    // Sequential stage number (1, 2, 3, ...)
	Name        string // Human-readable stage name
	Technique   string // MITRE ATT&CK technique ID (e.g., "T1134.001")
	BinaryName  string // Stage binary filename (e.g., "abc123-T1134.001.exe")
	BinaryData  []byte // Embedded signed binary data
	Description string // Brief description of what this stage does
}

// ==============================================================================
// MAIN FUNCTION
// ==============================================================================

func main() {
	// Initialize logger with Schema v2.0 metadata and execution context
	//
	// Define test metadata (MITRE ATT&CK mapping, scoring, categorization)
	metadata := TestMetadata{
		Version:       "1.0.0",
		Category:      "privilege_escalation",                                                   // Update for your test
		Severity:      "high",                                                                   // critical, high, medium, low, informational
		Techniques:    []string{"T1134.001", "T1055.001", "T1003.001"},                          // Update with your techniques
		Tactics:       []string{"privilege-escalation", "defense-evasion", "credential-access"}, // Update with your tactics
		Score:         8.5,
		RubricVersion: "v2.1", // Tiered realism-first rubric (active). Adds 2d Execution-Context Fidelity + 3d Operational Hygiene; reframes 2c as Telemetry Signal Quality (test-property, not tenant-defense). See .claude/agents/sectest-documentation.md and docs/PROPOSED_RUBRIC_V2.1_SIGNAL_QUALITY.md
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5,
			TechnicalSophistication: 3.0,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.5,
			LoggingObservability:    1.0,
		},
		Tags: []string{"multi-stage", "killchain"}, // Add relevant tags
	}

	// Resolve organization info (UUID or short name)
	// This can come from command-line arg, environment variable, or use default
	// For this template, using default organization from registry
	orgInfo := ResolveOrganization("") // Empty string uses default from registry

	// Define execution context
	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(), // Generate unique execution ID
		Organization:   orgInfo.UUID,        // UUID for Elasticsearch analytics
		Environment:    "lab",               // production, staging, lab, development, testing
		DeploymentType: "manual",            // manual, automated, cicd, scheduled
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000, // 5 minutes
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
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	// Run the test
	test()
}

// ==============================================================================
// TEST IMPLEMENTATION
// ==============================================================================

func test() {
	// Define attack killchain
	// Customize this array with your specific attack stages
	killchain := []Stage{
		{
			ID:          1,
			Name:        "Access Token Manipulation",
			Technique:   "T1134.001",
			BinaryName:  fmt.Sprintf("%s-T1134.001.exe", TEST_UUID),
			BinaryData:  stage1Compressed,
			Description: "Manipulate access tokens for privilege escalation",
		},
		{
			ID:          2,
			Name:        "Process Injection: DLL Injection",
			Technique:   "T1055.001",
			BinaryName:  fmt.Sprintf("%s-T1055.001.exe", TEST_UUID),
			BinaryData:  stage2Compressed,
			Description: "Inject malicious DLL into target process",
		},
		{
			ID:          3,
			Name:        "LSASS Memory Dump",
			Technique:   "T1003.001",
			BinaryName:  fmt.Sprintf("%s-T1003.001.exe", TEST_UUID),
			BinaryData:  stage3Compressed,
			Description: "Dump LSASS process memory to extract credentials",
		},
		// Add more stages as needed
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

	// Track per-stage results for bundle fan-out (per-stage ES documents)
	// NOTE: Update severity and tactics to match your test's metadata
	stageSeverity := "high"                                                                  // Must match metadata.Severity above
	stageTactics := []string{"privilege-escalation", "defense-evasion", "credential-access"} // Must match metadata.Tactics above
	stageResults := make([]StageBundleDef, len(killchain))
	for i, stage := range killchain {
		stageResults[i] = StageBundleDef{
			Technique: stage.Technique,
			Name:      stage.Name,
			Severity:  stageSeverity,
			Tactics:   stageTactics,
			ExitCode:  0,
			Status:    "skipped", // default; overwritten when stage executes
		}
	}

	// Execute killchain in sequential order
	Endpoint.Say("[*] Executing %d-stage attack killchain...", len(killchain))
	Endpoint.Say("")

	for idx, stage := range killchain {
		// Log phase start
		LogPhaseStart(stage.ID, fmt.Sprintf("%s (%s)", stage.Name, stage.Technique))

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
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "blocked"
			stageResults[idx].Details = fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode)
			LogPhaseEnd(stage.ID, "blocked", fmt.Sprintf("EDR blocked %s (exit code: %d)", stage.Technique, exitCode))

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
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.ExecutionPrevented)

		} else if exitCode != 0 {
			// Stage encountered an error (not blocked, but failed)
			stageResults[idx].ExitCode = exitCode
			stageResults[idx].Status = "error"
			stageResults[idx].Details = fmt.Sprintf("Stage error: exit code %d", exitCode)
			LogPhaseEnd(stage.ID, "error", fmt.Sprintf("Stage %s failed with exit code %d", stage.Technique, exitCode))

			Endpoint.Say("")
			Endpoint.Say("❌ ERROR: Stage %d encountered an error", stage.ID)
			Endpoint.Say("    Technique: %s", stage.Technique)
			Endpoint.Say("    Exit Code: %d", exitCode)
			Endpoint.Say("")
			Endpoint.Say("This may indicate:")
			Endpoint.Say("  • Prerequisites not met (e.g., target process not running)")
			Endpoint.Say("  • Insufficient privileges")
			Endpoint.Say("  • Test implementation issue")
			Endpoint.Say("")

			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Stage %d (%s) failed with exit code %d", stage.ID, stage.Technique, exitCode))
			WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
			Endpoint.Stop(Endpoint.UnexpectedTestError)
		}

		// Stage succeeded - continue to next stage
		stageResults[idx].ExitCode = exitCode
		stageResults[idx].Status = "success"
		stageResults[idx].Details = fmt.Sprintf("%s completed successfully", stage.Technique)
		LogPhaseEnd(stage.ID, "success", fmt.Sprintf("Stage %s completed successfully", stage.Technique))
		Endpoint.Say("    ✓ Stage %d completed successfully", stage.ID)
		Endpoint.Say("")
	}

	// All stages completed successfully - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("FINAL EVALUATION: All Stages Completed")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("❌ RESULT: VULNERABLE")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete attack chain executed without prevention")
	Endpoint.Say("")
	Endpoint.Say("Attack Chain Summary:")
	Endpoint.Say("  • Total Stages: %d", len(killchain))
	Endpoint.Say("  • Successful Stages: %d", len(killchain))
	Endpoint.Say("  • Blocked Stages: 0")
	Endpoint.Say("")
	Endpoint.Say("Executed Techniques:")
	for _, stage := range killchain {
		Endpoint.Say("  • Stage %d: %s (%s)", stage.ID, stage.Name, stage.Technique)
	}
	Endpoint.Say("")
	Endpoint.Say("Security Impact: HIGH")
	Endpoint.Say("  • Privilege escalation successful")
	Endpoint.Say("  • Credential access achieved")
	Endpoint.Say("  • EDR failed to detect or prevent attack")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(Endpoint.Unprotected, fmt.Sprintf("All %d stages completed - complete attack chain successful", len(killchain)))
	WriteStageBundleResults(TEST_UUID, TEST_NAME, "intel-driven", "killchain", stageResults)
	Endpoint.Stop(Endpoint.Unprotected)
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

// extractStage extracts a gzip-compressed stage binary to C:\F0
func extractStage(stage Stage) error {
	targetDir := "c:\\F0"

	// Ensure target directory exists
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", targetDir, err)
	}

	// Decompress gzip-compressed binary data
	binaryData, err := decompressGzip(stage.BinaryData)
	if err != nil {
		return fmt.Errorf("failed to decompress %s: %v", stage.BinaryName, err)
	}

	// Write decompressed stage binary to disk (normal signed PE)
	stagePath := filepath.Join(targetDir, stage.BinaryName)
	if err := os.WriteFile(stagePath, binaryData, 0755); err != nil {
		return fmt.Errorf("failed to write %s: %v", stage.BinaryName, err)
	}

	// Log file drop
	LogFileDropped(stage.BinaryName, stagePath, int64(len(binaryData)), false)

	return nil
}

// decompressGzip decompresses gzip-compressed data in memory
func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %v", err)
	}
	return decompressed, nil
}

// executeStage executes a stage binary and returns its exit code
func executeStage(stage Stage) int {
	stagePath := filepath.Join("c:\\F0", stage.BinaryName)

	// Create command
	cmd := exec.Command(stagePath)

	// Log process execution attempt
	LogMessage("INFO", fmt.Sprintf("Stage %d", stage.ID), fmt.Sprintf("Executing %s", stage.BinaryName))

	// Run command
	err := cmd.Run()

	// Determine exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			LogProcessExecution(stage.BinaryName, stagePath, 0, false, exitCode, exitErr.Error())
			return exitCode
		}
		// Unknown error
		LogProcessExecution(stage.BinaryName, stagePath, 0, false, 999, err.Error())
		return 999
	}

	// Success
	LogProcessExecution(stage.BinaryName, stagePath, 0, true, 0, "")
	return 0
}
