// Stage Binary Template
// F0RT1KA Security Testing Framework
//
// This template provides a standard structure for individual stage binaries
// in a multi-stage attack chain test. Each stage implements ONE ATT&CK technique.
//
// USAGE INSTRUCTIONS:
// 1. Copy this template for each technique in your killchain
// 2. Rename to stage-T<technique-id>.go (e.g., stage-T1134.001.go)
// 3. Update the constants section with your technique details
// 4. Implement the performTechnique() function with your attack logic
// 5. Build and sign BEFORE embedding in main orchestrator
//
// CRITICAL: This stage binary will be built separately, signed, then embedded
// in the main orchestrator. It must use standardized exit codes.
//
// STANDARDIZED EXIT CODES:
//   0   - Stage succeeded (technique executed successfully)
//   126 - Stage blocked by EDR (technique was prevented)
//   105 - Binary quarantined before execution
//   999 - Stage error (prerequisites not met, insufficient privileges, etc.)

//go:build windows

package main

import (
	"fmt"
	"os"
)

// ==============================================================================
// CONFIGURATION - CUSTOMIZE THIS SECTION FOR YOUR TECHNIQUE
// ==============================================================================

const (
	// Test identification
	TEST_UUID = "TEMPLATE-UUID"  // Must match main orchestrator UUID

	// Technique identification (replace with your actual technique)
	TECHNIQUE_ID   = "T1234.001"  // MITRE ATT&CK technique ID
	TECHNIQUE_NAME = "Technique Name"  // Human-readable name
	STAGE_ID       = 1  // Stage number in killchain (1, 2, 3, ...)
)

// Standardized exit codes
const (
	StageSuccess     = 0    // Technique executed successfully
	StageBlocked     = 126  // Technique blocked by EDR
	StageQuarantined = 105  // Binary quarantined
	StageError       = 999  // Error (prerequisites not met)
)

// ==============================================================================
// MAIN FUNCTION
// ==============================================================================

func main() {
	// Attach to shared log file (created by main orchestrator)
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage ID: %d", STAGE_ID))

	// Execute technique
	if err := performTechnique(); err != nil {
		// Technique was blocked or failed
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Blocked/Failed: %v", err))
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())

		// Determine appropriate exit code
		exitCode := determineExitCode(err)
		os.Exit(exitCode)
	}

	// Technique succeeded
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Technique completed without prevention")
	os.Exit(StageSuccess)
}

// ==============================================================================
// TECHNIQUE IMPLEMENTATION - CUSTOMIZE THIS SECTION
// ==============================================================================

// performTechnique implements the actual ATT&CK technique
// Return nil if technique succeeds, error if blocked or failed
func performTechnique() error {
	// REPLACE THIS WITH YOUR ACTUAL TECHNIQUE IMPLEMENTATION
	//
	// Examples based on technique type:

	// Example 1: Process Injection (T1055.001)
	// handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, targetPID)
	// if err != nil {
	//     return fmt.Errorf("process access denied: %v", err)  // Blocked
	// }
	// defer windows.CloseHandle(handle)
	//
	// _, err = windows.WriteProcessMemory(handle, targetAddr, payload, ...)
	// if err != nil {
	//     return fmt.Errorf("memory write denied: %v", err)  // Blocked
	// }

	// Example 2: Token Manipulation (T1134.001)
	// token, err := getProcessToken()
	// if err != nil {
	//     return fmt.Errorf("token access denied: %v", err)  // Blocked
	// }
	//
	// err = adjustTokenPrivileges(token, SE_DEBUG_NAME)
	// if err != nil {
	//     return fmt.Errorf("privilege elevation denied: %v", err)  // Blocked
	// }

	// Example 3: LSASS Dump (T1003.001)
	// lsassPID, err := findLSASSProcess()
	// if err != nil {
	//     return fmt.Errorf("LSASS process not found: %v", err)  // Error
	// }
	//
	// err = createDumpFile(lsassPID, "C:\\F0\\lsass.dmp")
	// if err != nil {
	//     return fmt.Errorf("dump creation denied: %v", err)  // Blocked
	// }

	// Example 4: Registry Modification (T1112)
	// key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.SET_VALUE)
	// if err != nil {
	//     return fmt.Errorf("registry access denied: %v", err)  // Blocked
	// }
	// defer key.Close()
	//
	// err = key.SetStringValue(valueName, maliciousValue)
	// if err != nil {
	//     return fmt.Errorf("registry write denied: %v", err)  // Blocked
	// }

	// TEMPLATE PLACEHOLDER - Remove this when implementing real technique
	LogMessage("WARN", TECHNIQUE_ID, "Using template placeholder - implement actual technique")

	// Simulate technique execution
	// In real implementation, this would be replaced with actual attack code
	return nil  // Success (technique executed)

	// To simulate blocking, return error:
	// return fmt.Errorf("simulated EDR block")
}

// ==============================================================================
// HELPER FUNCTIONS
// ==============================================================================

// determineExitCode converts error to appropriate exit code
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}

	errStr := err.Error()

	// Check for common EDR block patterns
	if containsAny(errStr, []string{
		"access denied",
		"access is denied",
		"permission denied",
		"operation not permitted",
		"blocked",
		"prevented",
		"quarantined",
	}) {
		return StageBlocked
	}

	// Check for quarantine patterns
	if containsAny(errStr, []string{
		"quarantine",
		"file not found", // May indicate quarantine
		"virus",
		"threat",
	}) {
		return StageQuarantined
	}

	// Check for prerequisite errors
	if containsAny(errStr, []string{
		"not found",
		"does not exist",
		"no such",
		"not running",
		"not available",
		"insufficient privilege",
		"not elevated",
	}) {
		return StageError
	}

	// Default to blocked (conservative approach)
	return StageBlocked
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if contains(s, substr) {
			return true
		}
	}
	return false
}

// contains checks if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

// indexIgnoreCase finds index of substring (case-insensitive)
func indexIgnoreCase(s, substr string) int {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// toLower converts string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

// ==============================================================================
// TECHNIQUE-SPECIFIC HELPER FUNCTIONS
// ==============================================================================

// Add any helper functions specific to your technique below
// Examples:
//
// func findTargetProcess(name string) (uint32, error) { ... }
// func injectPayload(pid uint32, payload []byte) error { ... }
// func elevatePrivileges() error { ... }
// func dumpMemory(pid uint32, output string) error { ... }
// func modifyRegistry(key, value string) error { ... }
