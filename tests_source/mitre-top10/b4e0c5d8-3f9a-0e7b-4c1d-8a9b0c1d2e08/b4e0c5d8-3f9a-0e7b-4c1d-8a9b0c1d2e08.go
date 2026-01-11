//go:build windows
// +build windows

/*
ID: b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08
NAME: Ransomware Encryption (Safe Mode)
TECHNIQUES: T1486, T1491.001
UNIT: response
CREATED: 2025-01-11
*/
package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
	TEST_NAME = "Ransomware Encryption (Safe Mode)"

	// Target directory for test files (NOT whitelisted - EDR can detect)
	TEST_DIRECTORY = "c:\\Users\\fortika-test\\test_documents"

	// Ransom note location
	RANSOM_NOTE_PATH = "c:\\Users\\fortika-test\\README_F0RTIKA.txt"

	// Extension for "encrypted" files
	ENCRYPTED_EXTENSION = ".f0rtika"
)

// TestFileInfo stores information about test files for cleanup
type TestFileInfo struct {
	OriginalName string
	RenamedName  string
	Content      []byte
	Size         int64
}

// Global state for cleanup
var createdTestFiles []TestFileInfo
var generatedAESKey []byte

// generateAESKey generates a 256-bit AES key and logs it (never actually used for encryption)
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %v", err)
	}
	return key, nil
}

// createTestFiles creates simulated document files for the ransomware simulation
func createTestFiles() error {
	testFiles := []struct {
		name    string
		content string
	}{
		{"financial_report_2025.docx", "PK\x03\x04 (WORD DOCUMENT SIMULATION)\nQuarterly Financial Report\nThis is a simulated Word document for F0RT1KA security testing.\nConfidential data placeholder."},
		{"employee_database.xlsx", "PK\x03\x04 (EXCEL DOCUMENT SIMULATION)\nEmployee ID,Name,Department,Salary\n1001,John Smith,Engineering,85000\n1002,Jane Doe,Marketing,72000"},
		{"executive_briefing.pdf", "%PDF-1.4 (PDF SIMULATION)\nExecutive Briefing - Q1 2025\nStrategic initiatives and budget allocations.\nFor internal use only."},
		{"client_contracts.docx", "PK\x03\x04 (WORD DOCUMENT SIMULATION)\nClient Service Agreement\nTerms and conditions for enterprise software deployment.\nLegal document placeholder."},
		{"product_roadmap.xlsx", "PK\x03\x04 (EXCEL DOCUMENT SIMULATION)\nFeature,Priority,Target Date,Status\nCloud Integration,High,2025-Q2,In Progress\nAI Assistant,Medium,2025-Q3,Planning"},
		{"board_presentation.pdf", "%PDF-1.4 (PDF SIMULATION)\nBoard of Directors Presentation\nAnnual review and strategic direction.\nHighly confidential document."},
		{"customer_data.csv", "CustomerID,Name,Email,PurchaseHistory\n10001,Acme Corp,contact@acme.com,$250000\n10002,TechStart Inc,info@techstart.io,$125000"},
		{"project_plans.docx", "PK\x03\x04 (WORD DOCUMENT SIMULATION)\nProject Alpha - Implementation Plan\nMilestones and deliverables for Q1-Q2 2025.\nProject management document."},
		{"backup_config.xml", "<?xml version=\"1.0\"?>\n<backup><schedule>daily</schedule><retention>30days</retention><encrypted>true</encrypted></backup>"},
		{"system_credentials.txt", "# SIMULATED CREDENTIALS FILE\n# This is NOT real - created for security testing\nserver: production-db-01\nuser: admin\npass: [REDACTED]"},
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(TEST_DIRECTORY, tf.name)
		content := []byte(tf.content)

		if err := os.WriteFile(filePath, content, 0644); err != nil {
			return fmt.Errorf("failed to create test file %s: %v", tf.name, err)
		}

		createdTestFiles = append(createdTestFiles, TestFileInfo{
			OriginalName: filePath,
			Content:      content,
			Size:         int64(len(content)),
		})

		LogFileDropped(tf.name, filePath, int64(len(content)), false)
		Endpoint.Say("  [+] Created: %s (%d bytes)", tf.name, len(content))
	}

	return nil
}

// simulateEncryption renames files with .f0rtika extension (SAFE - no actual encryption)
func simulateEncryption() (int, int, error) {
	encrypted := 0
	blocked := 0

	for i, tf := range createdTestFiles {
		// Check if original file still exists (might have been quarantined)
		if _, err := os.Stat(tf.OriginalName); os.IsNotExist(err) {
			Endpoint.Say("  [!] File not found (quarantined?): %s", filepath.Base(tf.OriginalName))
			blocked++
			continue
		}

		// Create renamed path
		renamedPath := tf.OriginalName + ENCRYPTED_EXTENSION

		// Attempt to rename (simulates encryption)
		if err := os.Rename(tf.OriginalName, renamedPath); err != nil {
			Endpoint.Say("  [!] Rename blocked for: %s - %v", filepath.Base(tf.OriginalName), err)
			LogMessage("WARN", "Encryption Simulation", fmt.Sprintf("Rename blocked: %s - %v", filepath.Base(tf.OriginalName), err))
			blocked++

			// Check if this is an EDR block
			if strings.Contains(err.Error(), "Access") || strings.Contains(err.Error(), "denied") {
				return encrypted, blocked, fmt.Errorf("EDR blocked file rename operation")
			}
			continue
		}

		// Update tracking for cleanup
		createdTestFiles[i].RenamedName = renamedPath

		encrypted++
		Endpoint.Say("  [+] Simulated encryption: %s -> %s%s",
			filepath.Base(tf.OriginalName),
			filepath.Base(tf.OriginalName),
			ENCRYPTED_EXTENSION)

		LogMessage("INFO", "Encryption Simulation",
			fmt.Sprintf("File renamed: %s -> %s", filepath.Base(tf.OriginalName), filepath.Base(renamedPath)))
	}

	return encrypted, blocked, nil
}

// createRansomNote creates the ransom note file
func createRansomNote() error {
	ransomNote := fmt.Sprintf(`
================================================================================
                        F0RT1KA SECURITY TEST - RANSOMWARE SIMULATION
================================================================================

*** THIS IS A SECURITY TEST - NOT A REAL RANSOMWARE ATTACK ***

Your files have been SIMULATED as encrypted by the F0RT1KA security testing
framework. This is a controlled test to evaluate your endpoint detection and
response (EDR) capabilities.

IMPORTANT:
- Your files are NOT actually encrypted
- Files were only RENAMED with .f0rtika extension
- All files remain fully readable and functional
- This test will automatically restore all files

SIMULATED ATTACK DETAILS:
- Test ID: %s
- Test Name: %s
- Timestamp: %s
- Technique: T1486 (Data Encrypted for Impact)
- Simulated Key: AES-256 (key logged but never used)

DETECTION OPPORTUNITY:
If you are seeing this note, your EDR solution did NOT prevent the following:
1. Mass file rename operations (.f0rtika extension)
2. Ransom note file creation
3. Bulk file system operations targeting documents

MITRE ATT&CK Coverage:
- T1486: Data Encrypted for Impact
- T1491.001: Internal Defacement

================================================================================
This test is part of the F0RT1KA security testing framework.
For more information, contact your security team.
================================================================================
`, TEST_UUID, TEST_NAME, time.Now().Format("2006-01-02 15:04:05 MST"))

	if err := os.WriteFile(RANSOM_NOTE_PATH, []byte(ransomNote), 0644); err != nil {
		return fmt.Errorf("failed to create ransom note: %v", err)
	}

	LogFileDropped("README_F0RTIKA.txt", RANSOM_NOTE_PATH, int64(len(ransomNote)), false)
	return nil
}

// cleanup restores all test files to their original state and removes test artifacts
func cleanup() {
	Endpoint.Say("")
	Endpoint.Say("Phase 5: Cleanup and Restoration")
	LogPhaseStart(5, "Cleanup and Restoration")

	restored := 0
	removed := 0
	errors := 0

	// Restore renamed files
	for _, tf := range createdTestFiles {
		if tf.RenamedName != "" {
			// File was renamed, restore original name
			if err := os.Rename(tf.RenamedName, tf.OriginalName); err != nil {
				// If rename back fails, try to remove the renamed file
				os.Remove(tf.RenamedName)
				errors++
				LogMessage("WARN", "Cleanup", fmt.Sprintf("Failed to restore %s: %v", filepath.Base(tf.RenamedName), err))
			} else {
				// Now remove the restored file
				if err := os.Remove(tf.OriginalName); err != nil {
					errors++
				} else {
					removed++
				}
				restored++
			}
		} else {
			// File wasn't renamed, just remove original
			if err := os.Remove(tf.OriginalName); err != nil {
				// File might not exist (quarantined)
				if !os.IsNotExist(err) {
					errors++
				}
			} else {
				removed++
			}
		}
	}

	// Remove ransom note
	if err := os.Remove(RANSOM_NOTE_PATH); err != nil {
		if !os.IsNotExist(err) {
			errors++
			LogMessage("WARN", "Cleanup", fmt.Sprintf("Failed to remove ransom note: %v", err))
		}
	} else {
		removed++
	}

	// Remove test directory
	if err := os.RemoveAll(TEST_DIRECTORY); err != nil {
		LogMessage("WARN", "Cleanup", fmt.Sprintf("Failed to remove test directory: %v", err))
	}

	// Remove parent directory if empty
	parentDir := filepath.Dir(TEST_DIRECTORY)
	os.Remove(parentDir) // Ignore error - might not be empty or might not exist

	Endpoint.Say("  [+] Restored %d files", restored)
	Endpoint.Say("  [+] Removed %d artifacts", removed)
	if errors > 0 {
		Endpoint.Say("  [!] Errors during cleanup: %d", errors)
	}

	LogMessage("INFO", "Cleanup", fmt.Sprintf("Restored: %d, Removed: %d, Errors: %d", restored, removed, errors))
	LogPhaseEnd(5, "success", fmt.Sprintf("Cleanup completed - %d restored, %d removed", restored, removed))
}

func test() {
	// Ensure cleanup runs even on panic/early exit
	defer cleanup()

	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
		}
	}()

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initialization")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("  [!] Dropper initialization failed: %v", err)
		LogPhaseEnd(1, "failed", "Dropper initialization failed")
		SaveLog(Endpoint.UnexpectedTestError, "Dropper initialization failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Create target directory
	if err := os.MkdirAll(TEST_DIRECTORY, 0755); err != nil {
		Endpoint.Say("  [!] Failed to create test directory: %v", err)
		LogPhaseEnd(1, "failed", "Failed to create test directory")
		SaveLog(999, fmt.Sprintf("Failed to create test directory: %v", err))
		Endpoint.Stop(999)
	}

	// Ensure c:\F0 exists for logging
	os.MkdirAll("c:\\F0", 0755)

	Endpoint.Say("  [+] Test directory created: %s", TEST_DIRECTORY)
	Endpoint.Say("  [+] Dropper initialized successfully")
	LogPhaseEnd(1, "success", "Initialization completed")

	// Phase 2: Test File Creation
	LogPhaseStart(2, "Test File Creation")
	Endpoint.Say("")
	Endpoint.Say("Phase 2: Creating test document files")

	if err := createTestFiles(); err != nil {
		Endpoint.Say("  [!] Failed to create test files: %v", err)
		LogPhaseEnd(2, "failed", "Failed to create test files")
		SaveLog(999, fmt.Sprintf("Failed to create test files: %v", err))
		Endpoint.Stop(999)
	}

	Endpoint.Say("  [+] Created %d test files", len(createdTestFiles))
	LogPhaseEnd(2, "success", fmt.Sprintf("Created %d test files", len(createdTestFiles)))

	// Brief pause to allow EDR to detect file operations
	Endpoint.Say("")
	Endpoint.Say("Waiting for potential EDR detection (3 seconds)...")
	Endpoint.Wait(3)

	// Phase 3: AES Key Generation (logged but never used)
	LogPhaseStart(3, "AES Key Generation")
	Endpoint.Say("")
	Endpoint.Say("Phase 3: Generating AES-256 encryption key (simulation only)")

	var err error
	generatedAESKey, err = generateAESKey()
	if err != nil {
		Endpoint.Say("  [!] Key generation failed: %v", err)
		LogPhaseEnd(3, "failed", "Key generation failed")
		SaveLog(Endpoint.UnexpectedTestError, "Key generation failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	keyHex := hex.EncodeToString(generatedAESKey)
	Endpoint.Say("  [+] Generated AES-256 key: %s...%s", keyHex[:8], keyHex[len(keyHex)-8:])
	Endpoint.Say("  [i] NOTE: This key is logged but NEVER used for actual encryption")

	LogMessage("INFO", "AES Key Generation", fmt.Sprintf("Generated key (first 8 chars): %s...", keyHex[:16]))
	LogMessage("INFO", "AES Key Generation", "Key is logged for demonstration only - no actual encryption performed")

	// Verify key can create a cipher (proves it's valid)
	if _, err := aes.NewCipher(generatedAESKey); err != nil {
		Endpoint.Say("  [!] Key validation failed: %v", err)
		LogPhaseEnd(3, "failed", "Key validation failed")
	} else {
		Endpoint.Say("  [+] Key validated successfully (AES cipher created)")
		LogPhaseEnd(3, "success", "AES-256 key generated and validated")
	}

	// Phase 4: Ransomware Simulation (file rename + ransom note)
	LogPhaseStart(4, "Ransomware Simulation")
	Endpoint.Say("")
	Endpoint.Say("Phase 4: Simulating ransomware encryption (safe mode)")
	Endpoint.Say("  [i] Files will be RENAMED with %s extension", ENCRYPTED_EXTENSION)
	Endpoint.Say("  [i] NO actual encryption - files remain readable")

	// Simulate encryption (rename files)
	encrypted, blocked, err := simulateEncryption()

	if err != nil {
		Endpoint.Say("  [!] EDR blocked file operations: %v", err)
		LogMessage("INFO", "Ransomware Simulation", fmt.Sprintf("Blocked by EDR: %v", err))
		LogPhaseEnd(4, "blocked", "EDR blocked file rename operations")
		SaveLog(Endpoint.ExecutionPrevented, "EDR blocked ransomware file operations")
		// Cleanup will run via defer
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	Endpoint.Say("  [+] Simulated encryption: %d files", encrypted)
	if blocked > 0 {
		Endpoint.Say("  [!] Blocked/missing: %d files", blocked)
	}

	// Check if all files were blocked
	if encrypted == 0 && blocked > 0 {
		Endpoint.Say("  [!] All file operations were blocked - EDR protection detected")
		LogPhaseEnd(4, "blocked", "All file operations blocked by EDR")
		SaveLog(Endpoint.ExecutionPrevented, "EDR blocked all ransomware file operations")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	// Create ransom note
	Endpoint.Say("")
	Endpoint.Say("Creating ransom note: %s", RANSOM_NOTE_PATH)
	if err := createRansomNote(); err != nil {
		Endpoint.Say("  [!] Ransom note creation blocked: %v", err)
		LogMessage("WARN", "Ransomware Simulation", fmt.Sprintf("Ransom note creation blocked: %v", err))

		// If ransom note creation is blocked but files were renamed, partial success
		if encrypted > 0 {
			LogPhaseEnd(4, "partial", "Files renamed but ransom note blocked")
		} else {
			LogPhaseEnd(4, "blocked", "EDR blocked ransom note creation")
			SaveLog(Endpoint.ExecutionPrevented, "EDR blocked ransom note creation")
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		}
	} else {
		Endpoint.Say("  [+] Ransom note created successfully")
	}

	LogMessage("INFO", "Ransomware Simulation",
		fmt.Sprintf("Simulation complete - %d files renamed, %d blocked", encrypted, blocked))
	LogPhaseEnd(4, "success", fmt.Sprintf("Ransomware simulation: %d encrypted, %d blocked", encrypted, blocked))

	// Brief pause to allow EDR to detect
	Endpoint.Say("")
	Endpoint.Say("Waiting for post-execution EDR detection (5 seconds)...")
	Endpoint.Wait(5)

	// Check if ransom note was quarantined
	if _, err := os.Stat(RANSOM_NOTE_PATH); os.IsNotExist(err) {
		Endpoint.Say("  [!] Ransom note was quarantined - EDR detected the attack")
		LogMessage("INFO", "Post-Execution Check", "Ransom note quarantined by EDR")
		SaveLog(Endpoint.FileQuarantinedOnExecution, "Ransom note quarantined post-execution")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExecution)
	}

	// Attack simulation completed successfully
	Endpoint.Say("")
	Endpoint.Say("================================================================================")
	Endpoint.Say("RANSOMWARE SIMULATION COMPLETED - SYSTEM UNPROTECTED")
	Endpoint.Say("================================================================================")
	Endpoint.Say("  - %d files were renamed with %s extension", encrypted, ENCRYPTED_EXTENSION)
	Endpoint.Say("  - Ransom note created at: %s", RANSOM_NOTE_PATH)
	Endpoint.Say("  - AES-256 key generated (but not used for encryption)")
	Endpoint.Say("")
	Endpoint.Say("IMPORTANT: EDR did NOT prevent this ransomware simulation!")
	Endpoint.Say("")

	LogMessage("CRITICAL", "Final Assessment", "System is UNPROTECTED - ransomware simulation succeeded")

	// Cleanup will run via defer, save log before cleanup
	SaveLog(Endpoint.Unprotected, fmt.Sprintf("Ransomware simulation succeeded - %d files renamed, ransom note created", encrypted))

	// Note: Cleanup runs automatically via defer
	Endpoint.Stop(Endpoint.Unprotected)
}

func main() {
	Endpoint.Say("================================================================================")
	Endpoint.Say("F0RT1KA Security Test - Ransomware Encryption (Safe Mode)")
	Endpoint.Say("================================================================================")
	Endpoint.Say("Test ID: %s", TEST_UUID)
	Endpoint.Say("Start Time: %s", time.Now().Format("2006-01-02T15:04:05 MST"))
	Endpoint.Say("")
	Endpoint.Say("SAFETY NOTICE:")
	Endpoint.Say("  - This test does NOT perform actual file encryption")
	Endpoint.Say("  - Files are only RENAMED (remain fully readable)")
	Endpoint.Say("  - All test files are automatically cleaned up")
	Endpoint.Say("  - Only self-created test files are affected")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0 metadata
	metadata := TestMetadata{
		Version:  "1.0.0",
		Category: "impact",
		Severity: "critical",
		Techniques: []string{"T1486", "T1491.001"},
		Tactics:    []string{"impact"},
		Score:      8.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Simulates realistic ransomware behavior patterns
			TechnicalSophistication: 2.5, // AES key generation, file operations, ransom note
			SafetyMechanisms:        2.0, // Full safety - no actual encryption, auto-cleanup
			DetectionOpportunities:  1.0, // Multiple detection points
			LoggingObservability:    0.5, // Comprehensive logging
		},
		Tags: []string{"ransomware", "safe-simulation", "file-operations", "impact"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         120000,
			CertificateMode:   "self-healing",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// Timeout for ransomware simulation
	timeout := 2 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test execution completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		cleanup() // Ensure cleanup runs on timeout
		if globalLog != nil {
			LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
