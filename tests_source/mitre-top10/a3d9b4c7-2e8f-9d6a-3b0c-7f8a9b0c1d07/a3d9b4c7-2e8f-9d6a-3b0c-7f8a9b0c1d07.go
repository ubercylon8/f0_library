//go:build windows
// +build windows

/*
ID: a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07
NAME: Pre-Encryption File Enumeration
TECHNIQUES: T1083, T1119, T1082
SEVERITY: medium
UNIT: response
CREATED: 2026-01-11
*/
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID        = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
	TEST_NAME        = "Pre-Encryption File Enumeration"
	TARGET_DIR       = "c:\\F0"
	TEST_DOCS_DIR    = "c:\\Users\\fortika-test\\test_documents"
)

// Seatbelt binary is loaded at runtime from c:\F0\tools\Seatbelt.exe
// User must place the binary there before running the test
// See tools/README.md for instructions on obtaining Seatbelt
var seatbeltBinary []byte // Will be populated if Seatbelt is found at runtime

// Target file extensions for pre-encryption reconnaissance
var targetExtensions = []string{
	".docx", ".xlsx", ".pdf", ".db", ".sql", ".bak",
	".doc", ".xls", ".ppt", ".pptx", ".csv", ".txt",
	".mdb", ".accdb", ".sqlite", ".json", ".xml",
}

// Test document content for creating realistic test files
var testDocuments = map[string]string{
	"financial_report_2024.docx":    "F0RT1KA Test Document - Financial Report",
	"customer_database.db":          "F0RT1KA Test Document - Customer Database Placeholder",
	"quarterly_earnings.xlsx":       "F0RT1KA Test Document - Quarterly Earnings",
	"backup_config.bak":             "F0RT1KA Test Document - Backup Configuration",
	"invoice_template.pdf":          "F0RT1KA Test Document - Invoice Template",
	"employee_records.sql":          "-- F0RT1KA Test SQL Dump\nCREATE TABLE employees (id INT, name VARCHAR(255));",
	"project_plan.docx":             "F0RT1KA Test Document - Project Plan",
	"credentials_backup.txt":        "F0RT1KA Test Document - Credentials Backup Placeholder",
	"database_schema.sql":           "-- F0RT1KA Test SQL Schema\nCREATE DATABASE test_db;",
	"annual_budget.xlsx":            "F0RT1KA Test Document - Annual Budget",
}

// createTestDocuments creates test documents in the test_documents directory
func createTestDocuments() (int, error) {
	Endpoint.Say("  Creating test documents in %s", TEST_DOCS_DIR)

	// Create the test documents directory
	if err := os.MkdirAll(TEST_DOCS_DIR, 0755); err != nil {
		return 0, fmt.Errorf("failed to create test documents directory: %v", err)
	}

	createdCount := 0
	for filename, content := range testDocuments {
		filePath := filepath.Join(TEST_DOCS_DIR, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			LogMessage("WARN", "Test Documents", fmt.Sprintf("Failed to create %s: %v", filename, err))
			continue
		}
		LogFileDropped(filename, filePath, int64(len(content)), false)
		createdCount++
	}

	LogMessage("INFO", "Test Documents", fmt.Sprintf("Created %d test documents in %s", createdCount, TEST_DOCS_DIR))
	return createdCount, nil
}

// performDirEnumeration performs dir /s /b style enumeration
// Returns: success, blocked, filesFound, errorMsg
func performDirEnumeration(targetDir string) (bool, bool, int, string) {
	Endpoint.Say("  Executing recursive file enumeration (dir /s /b pattern)...")

	// Build command to enumerate files with target extensions
	// This simulates ransomware's pre-encryption reconnaissance
	cmdLine := fmt.Sprintf("cmd /c dir /s /b \"%s\"", targetDir)
	cmd := exec.Command("cmd", "/c", "dir", "/s", "/b", targetDir)

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	output := outputBuffer.String()

	// Save raw output to file
	outputPath := filepath.Join(TARGET_DIR, "dir_enumeration_output.txt")
	os.WriteFile(outputPath, []byte(output), 0644)
	LogFileDropped("dir_enumeration_output.txt", outputPath, int64(len(output)), false)

	if err != nil {
		errorStr := err.Error()

		// Check for blocking indicators
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "access is denied") {

			LogProcessExecution("cmd.exe", cmdLine, pid, false, 126, "Blocked by security controls")
			LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumeration blocked after %v", duration))
			return false, true, 0, "Directory enumeration blocked by EDR"
		}

		LogProcessExecution("cmd.exe", cmdLine, pid, false, cmd.ProcessState.ExitCode(), errorStr)
		// dir command may return error if no files found - not necessarily a failure
		LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumeration completed with exit code %d in %v", cmd.ProcessState.ExitCode(), duration))
	} else {
		LogProcessExecution("cmd.exe", cmdLine, pid, true, 0, "")
	}

	// Count files found
	lines := strings.Split(strings.TrimSpace(output), "\n")
	filesFound := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "File Not Found") {
			filesFound++
		}
	}

	LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumerated %d files in %v", filesFound, duration))
	return true, false, filesFound, fmt.Sprintf("Enumerated %d files", filesFound)
}

// performExtensionFiltering filters enumerated files by target extensions
// Returns: success, blocked, targetFilesCount, errorMsg
func performExtensionFiltering(targetDir string) (bool, bool, int, string) {
	Endpoint.Say("  Filtering files by target extensions...")

	var targetFiles []string

	// Use dir command with extension filtering to simulate ransomware behavior
	for _, ext := range targetExtensions {
		pattern := fmt.Sprintf("%s\\*%s", targetDir, ext)
		cmd := exec.Command("cmd", "/c", "dir", "/s", "/b", pattern)

		output, err := cmd.CombinedOutput()

		if err != nil {
			errorStr := err.Error()
			outputStr := string(output)

			// Check for blocking
			if strings.Contains(strings.ToLower(outputStr), "blocked") ||
				strings.Contains(strings.ToLower(outputStr), "denied") ||
				strings.Contains(strings.ToLower(errorStr), "access is denied") {

				LogMessage("INFO", "Extension Filtering", fmt.Sprintf("Extension filtering blocked for %s", ext))
				return false, true, 0, "Extension filtering blocked by EDR"
			}
			// File not found is expected for some extensions
			continue
		}

		// Parse files found for this extension
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" && !strings.Contains(outputStr, "File Not Found") {
			for _, line := range strings.Split(outputStr, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					targetFiles = append(targetFiles, line)
				}
			}
		}
	}

	// Log target files
	LogMessage("INFO", "Extension Filtering", fmt.Sprintf("Found %d files matching target extensions", len(targetFiles)))

	return true, false, len(targetFiles), fmt.Sprintf("Found %d target files", len(targetFiles))
}

// generateTargetList creates a target list file (simulates pre-encryption recon output)
// Returns: success, blocked, path, errorMsg
func generateTargetList(targetDir string) (bool, bool, string, string) {
	Endpoint.Say("  Generating target list file (pre-encryption reconnaissance)...")

	var targetFiles []string

	// Recursively enumerate files
	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}
		if info.IsDir() {
			return nil
		}

		// Check if file matches target extensions
		ext := strings.ToLower(filepath.Ext(path))
		for _, targetExt := range targetExtensions {
			if ext == targetExt {
				targetFiles = append(targetFiles, path)
				break
			}
		}
		return nil
	})

	if err != nil {
		errorStr := err.Error()
		if strings.Contains(strings.ToLower(errorStr), "access is denied") ||
			strings.Contains(strings.ToLower(errorStr), "blocked") {
			LogMessage("INFO", "Target List Generation", "File walk blocked by security controls")
			return false, true, "", "Target list generation blocked by EDR"
		}
	}

	// Generate target list content
	var content strings.Builder
	content.WriteString("# Pre-Encryption Target List\n")
	content.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("# Test ID: %s\n", TEST_UUID))
	content.WriteString(fmt.Sprintf("# Source Directory: %s\n", targetDir))
	content.WriteString(fmt.Sprintf("# Total Targets: %d\n\n", len(targetFiles)))

	for _, file := range targetFiles {
		// Get file info for size
		if info, err := os.Stat(file); err == nil {
			content.WriteString(fmt.Sprintf("%s|%d\n", file, info.Size()))
		} else {
			content.WriteString(fmt.Sprintf("%s|0\n", file))
		}
	}

	// Write target list to file
	targetListPath := filepath.Join(TARGET_DIR, "target_list.txt")
	if err := os.WriteFile(targetListPath, []byte(content.String()), 0644); err != nil {
		LogMessage("ERROR", "Target List Generation", fmt.Sprintf("Failed to write target list: %v", err))
		return false, false, "", fmt.Sprintf("Failed to write target list: %v", err)
	}

	LogFileDropped("target_list.txt", targetListPath, int64(content.Len()), false)
	LogMessage("INFO", "Target List Generation", fmt.Sprintf("Generated target list with %d files", len(targetFiles)))

	return true, false, targetListPath, fmt.Sprintf("Generated target list with %d files", len(targetFiles))
}

// checkSeatbeltAvailable checks if Seatbelt binary is available
// It looks for Seatbelt.exe in c:\F0\tools\ directory
func checkSeatbeltAvailable() bool {
	// Check if Seatbelt binary was loaded at runtime
	if len(seatbeltBinary) > 0 {
		return true
	}

	// Check for Seatbelt in the tools directory
	seatbeltPath := filepath.Join(TARGET_DIR, "tools", "Seatbelt.exe")
	if _, err := os.Stat(seatbeltPath); err == nil {
		// Load the binary for later use
		data, err := os.ReadFile(seatbeltPath)
		if err == nil && len(data) > 0 {
			seatbeltBinary = data
			return true
		}
	}

	return false
}

// loadSeatbelt attempts to load Seatbelt from tools directory
func loadSeatbelt() (bool, string) {
	seatbeltToolPath := filepath.Join(TARGET_DIR, "tools", "Seatbelt.exe")

	if _, err := os.Stat(seatbeltToolPath); err != nil {
		return false, fmt.Sprintf("Seatbelt.exe not found in %s", filepath.Join(TARGET_DIR, "tools"))
	}

	data, err := os.ReadFile(seatbeltToolPath)
	if err != nil {
		return false, fmt.Sprintf("Failed to read Seatbelt.exe: %v", err)
	}

	if len(data) == 0 {
		return false, "Seatbelt.exe is empty"
	}

	seatbeltBinary = data
	return true, seatbeltToolPath
}

// extractSeatbelt copies Seatbelt from tools directory to c:\F0 for execution
func extractSeatbelt() (string, error) {
	// First try to load from tools directory
	if len(seatbeltBinary) == 0 {
		available, msg := loadSeatbelt()
		if !available {
			return "", fmt.Errorf("Seatbelt not available: %s - see tools/README.md for instructions", msg)
		}
	}

	// Copy to target directory for execution
	seatbeltPath := filepath.Join(TARGET_DIR, "Seatbelt.exe")
	err := os.WriteFile(seatbeltPath, seatbeltBinary, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write Seatbelt: %v", err)
	}

	LogFileDropped("Seatbelt.exe", seatbeltPath, int64(len(seatbeltBinary)), false)
	return seatbeltPath, nil
}

// testSeatbeltGroupAll executes Seatbelt with -group=all for comprehensive enumeration
// Returns: success, blocked, errorMsg
func testSeatbeltGroupAll(seatbeltPath string) (bool, bool, string) {
	Endpoint.Say("  Executing Seatbelt -group=all (comprehensive enumeration)...")

	// Check if file was quarantined before execution
	if _, err := os.Stat(seatbeltPath); os.IsNotExist(err) {
		LogMessage("INFO", "Seatbelt", "Seatbelt.exe was quarantined before execution")
		return false, true, "Seatbelt.exe quarantined on extraction"
	}

	// Wait for potential quarantine
	Endpoint.Wait(3)

	// Check again after delay
	if _, err := os.Stat(seatbeltPath); os.IsNotExist(err) {
		LogMessage("INFO", "Seatbelt", "Seatbelt.exe was quarantined after brief delay")
		LogFileDropped("Seatbelt.exe", seatbeltPath, int64(len(seatbeltBinary)), true)
		return false, true, "Seatbelt.exe quarantined after extraction"
	}

	// Execute Seatbelt with -group=all
	cmd := exec.Command(seatbeltPath, "-group=all")

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	output := outputBuffer.String()

	// Save output to file
	outputPath := filepath.Join(TARGET_DIR, "seatbelt_groupall_output.txt")
	os.WriteFile(outputPath, []byte(output), 0644)
	LogFileDropped("seatbelt_groupall_output.txt", outputPath, int64(len(output)), false)

	if err != nil {
		errorStr := err.Error()

		// Check for execution prevention
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "not recognized") ||
			strings.Contains(strings.ToLower(errorStr), "operation is not allowed") ||
			strings.Contains(strings.ToLower(errorStr), "blocked by") {

			LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, false, 126, "Execution blocked")
			LogMessage("INFO", "Seatbelt", "Seatbelt execution blocked by EDR")
			return false, true, "Seatbelt execution blocked by EDR"
		}

		// Check for exit code indicating EDR block
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Some EDRs return specific exit codes
		if exitCode == -1073741502 || // STATUS_DLL_NOT_FOUND
			exitCode == -1073740760 { // STATUS_NONCONTINUABLE_EXCEPTION

			LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, false, 126, "Execution prevented")
			LogMessage("INFO", "Seatbelt", fmt.Sprintf("Seatbelt execution prevented (exit code: %d)", exitCode))
			return false, true, "Seatbelt execution prevented by EDR"
		}

		// Normal execution failure (tool ran but some checks failed)
		LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, false, exitCode, errorStr)
		LogMessage("INFO", "Seatbelt", fmt.Sprintf("Seatbelt execution completed with error: %s (duration: %v)", errorStr, duration))

		// If the tool executed (not blocked), it's still a detection opportunity
		return true, false, fmt.Sprintf("Seatbelt executed but some checks failed: %s", errorStr)
	}

	LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, true, 0, "")
	LogMessage("INFO", "Seatbelt", fmt.Sprintf("Seatbelt -group=all completed successfully in %v", duration))
	return true, false, "Seatbelt -group=all executed successfully"
}

// testSeatbeltCredentialChecks executes Seatbelt with credential-specific checks
// Returns: success, blocked, errorMsg
func testSeatbeltCredentialChecks(seatbeltPath string) (bool, bool, string) {
	Endpoint.Say("  Executing Seatbelt credential checks (WindowsCredentialFiles, WindowsVault, InterestingFiles)...")

	// Check if file exists (may have been removed by AV)
	if _, err := os.Stat(seatbeltPath); os.IsNotExist(err) {
		LogMessage("INFO", "Seatbelt", "Seatbelt.exe not found for credential checks")
		return false, true, "Seatbelt.exe not available for credential checks"
	}

	// Execute Seatbelt with specific credential checks
	cmd := exec.Command(seatbeltPath, "WindowsCredentialFiles", "WindowsVault", "InterestingFiles")

	// Capture output
	var outputBuffer bytes.Buffer
	stdoutMulti := io.MultiWriter(os.Stdout, &outputBuffer)
	stderrMulti := io.MultiWriter(os.Stderr, &outputBuffer)

	cmd.Stdout = stdoutMulti
	cmd.Stderr = stderrMulti

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	output := outputBuffer.String()

	// Save output to file
	outputPath := filepath.Join(TARGET_DIR, "seatbelt_credentials_output.txt")
	os.WriteFile(outputPath, []byte(output), 0644)
	LogFileDropped("seatbelt_credentials_output.txt", outputPath, int64(len(output)), false)

	if err != nil {
		errorStr := err.Error()

		// Check for execution prevention
		if strings.Contains(strings.ToLower(output), "blocked") ||
			strings.Contains(strings.ToLower(output), "denied") ||
			strings.Contains(strings.ToLower(errorStr), "blocked by") {

			LogProcessExecution("Seatbelt.exe", "Seatbelt WindowsCredentialFiles WindowsVault InterestingFiles", pid, false, 126, "Execution blocked")
			LogMessage("INFO", "Seatbelt", "Seatbelt credential checks blocked by EDR")
			return false, true, "Seatbelt credential checks blocked by EDR"
		}

		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		LogProcessExecution("Seatbelt.exe", "Seatbelt WindowsCredentialFiles WindowsVault InterestingFiles", pid, false, exitCode, errorStr)
		LogMessage("INFO", "Seatbelt", fmt.Sprintf("Seatbelt credential checks completed with error: %s (duration: %v)", errorStr, duration))

		return true, false, fmt.Sprintf("Seatbelt credential checks executed: %s", errorStr)
	}

	LogProcessExecution("Seatbelt.exe", "Seatbelt WindowsCredentialFiles WindowsVault InterestingFiles", pid, true, 0, "")
	LogMessage("INFO", "Seatbelt", fmt.Sprintf("Seatbelt credential checks completed successfully in %v", duration))
	return true, false, "Seatbelt credential checks executed successfully"
}

// cleanup removes test artifacts
func cleanup() {
	Endpoint.Say("\nCleaning up test artifacts...")

	// Remove test documents directory
	if err := os.RemoveAll(TEST_DOCS_DIR); err == nil {
		LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed test documents directory: %s", TEST_DOCS_DIR))
	}

	// Remove artifact files
	filesToRemove := []string{
		"dir_enumeration_output.txt",
		"target_list.txt",
		"seatbelt_groupall_output.txt",
		"seatbelt_credentials_output.txt",
		"enumeration_summary.txt",
		"Seatbelt.exe",
	}

	for _, file := range filesToRemove {
		path := filepath.Join(TARGET_DIR, file)
		if err := os.Remove(path); err == nil {
			LogMessage("INFO", "Cleanup", fmt.Sprintf("Removed: %s", file))
		}
	}
}

func test() {
	// Ensure log is saved on exit
	defer func() {
		if r := recover(); r != nil {
			if globalLog != nil {
				LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
				SaveLog(Endpoint.UnexpectedTestError, fmt.Sprintf("Panic: %v", r))
			}
		}
	}()

	// Results tracking
	var blockedPatterns []string
	var successfulPatterns []string
	seatbeltQuarantined := false

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		LogPhaseError(0, fmt.Sprintf("Dropper initialization failed: %v", err))
		LogPhaseEnd(0, "failed", "Dropper initialization failed")
		SaveLog(Endpoint.UnexpectedTestError, "Dropper initialization failed")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Create target directory
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(Endpoint.UnexpectedTestError, "Failed to create target directory")
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	LogPhaseEnd(0, "success", "Environment initialized")

	// Phase 2: Create Test Documents
	LogPhaseStart(2, "Test Document Creation")
	Endpoint.Say("\nPhase 2: Creating test documents in %s", TEST_DOCS_DIR)

	docCount, err := createTestDocuments()
	if err != nil {
		Endpoint.Say("  [ERROR] Failed to create test documents: %v", err)
		LogPhaseError(1, fmt.Sprintf("Failed to create test documents: %v", err))
		LogPhaseEnd(1, "failed", "Test document creation failed")
		// Continue anyway - we can still test enumeration on c:\ if needed
	} else {
		Endpoint.Say("  [+] Created %d test documents", docCount)
		LogPhaseEnd(1, "success", fmt.Sprintf("Created %d test documents", docCount))
	}

	Endpoint.Wait(2)

	// Phase 3: Recursive File Enumeration
	LogPhaseStart(3, "Recursive File Enumeration")
	Endpoint.Say("\nPhase 3: Performing recursive file enumeration (dir /s /b style)")

	success, blocked, filesFound, msg := performDirEnumeration(TEST_DOCS_DIR)
	if blocked {
		Endpoint.Say("  [BLOCKED] File enumeration was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "Recursive File Enumeration (dir /s /b)")
		LogPhaseEnd(2, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] File enumeration succeeded (%d files found)", filesFound)
		successfulPatterns = append(successfulPatterns, "Recursive File Enumeration (dir /s /b)")
		LogPhaseEnd(2, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] File enumeration failed: %s", msg)
		LogPhaseEnd(2, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 4: Extension-Based Filtering
	LogPhaseStart(4, "Extension-Based File Filtering")
	Endpoint.Say("\nPhase 4: Filtering files by target extensions (.docx, .xlsx, .pdf, .db, .sql, .bak)")

	success, blocked, targetCount, msg := performExtensionFiltering(TEST_DOCS_DIR)
	if blocked {
		Endpoint.Say("  [BLOCKED] Extension filtering was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "Extension-Based File Filtering")
		LogPhaseEnd(3, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] Extension filtering succeeded (%d target files)", targetCount)
		successfulPatterns = append(successfulPatterns, "Extension-Based File Filtering")
		LogPhaseEnd(3, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] Extension filtering failed: %s", msg)
		LogPhaseEnd(3, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 5: Target List Generation
	LogPhaseStart(5, "Target List Generation")
	Endpoint.Say("\nPhase 5: Generating target list file (pre-encryption recon)")

	success, blocked, targetListPath, msg := generateTargetList(TEST_DOCS_DIR)
	if blocked {
		Endpoint.Say("  [BLOCKED] Target list generation was blocked by EDR")
		blockedPatterns = append(blockedPatterns, "Target List Generation")
		LogPhaseEnd(4, "blocked", msg)
	} else if success {
		Endpoint.Say("  [VULNERABLE] Target list generated: %s", targetListPath)
		successfulPatterns = append(successfulPatterns, "Target List Generation")
		LogPhaseEnd(4, "success", msg)
	} else {
		Endpoint.Say("  [ERROR] Target list generation failed: %s", msg)
		LogPhaseEnd(4, "failed", msg)
	}

	Endpoint.Wait(2)

	// Phase 6: Seatbelt Group All (if available)
	LogPhaseStart(6, "Seatbelt Comprehensive Enumeration")
	Endpoint.Say("\nPhase 6: Seatbelt -group=all (PLACEHOLDER - requires Seatbelt.exe)")

	if checkSeatbeltAvailable() {
		Endpoint.Say("  Seatbelt binary found - extracting...")

		seatbeltPath, err := extractSeatbelt()
		if err != nil {
			Endpoint.Say("  [ERROR] Failed to extract Seatbelt: %v", err)
			LogMessage("ERROR", "Seatbelt", fmt.Sprintf("Extraction failed: %v", err))
			LogPhaseEnd(5, "failed", err.Error())
		} else {
			Endpoint.Say("  [+] Seatbelt extracted to: %s", seatbeltPath)

			// Wait for potential quarantine
			Endpoint.Wait(3)

			// Check if quarantined
			if Endpoint.Quarantined("Seatbelt.exe", seatbeltBinary) {
				Endpoint.Say("  [QUARANTINED] Seatbelt.exe was quarantined on extraction")
				LogFileDropped("Seatbelt.exe", seatbeltPath, int64(len(seatbeltBinary)), true)
				seatbeltQuarantined = true
				blockedPatterns = append(blockedPatterns, "Seatbelt (Quarantined on Extraction)")
				LogPhaseEnd(5, "blocked", "Seatbelt quarantined on extraction")
			} else {
				// Try to execute Seatbelt -group=all
				successSeatbelt, blockedSeatbelt, msgSeatbelt := testSeatbeltGroupAll(seatbeltPath)
				if blockedSeatbelt {
					Endpoint.Say("  [BLOCKED] Seatbelt -group=all was blocked by EDR")
					blockedPatterns = append(blockedPatterns, "Seatbelt -group=all")
					LogPhaseEnd(5, "blocked", msgSeatbelt)
				} else if successSeatbelt {
					Endpoint.Say("  [VULNERABLE] Seatbelt -group=all executed without detection")
					successfulPatterns = append(successfulPatterns, "Seatbelt -group=all (60+ checks)")
					LogPhaseEnd(5, "success", msgSeatbelt)
				} else {
					Endpoint.Say("  [ERROR] Seatbelt test failed: %s", msgSeatbelt)
					LogPhaseEnd(5, "failed", msgSeatbelt)
				}
			}
		}
	} else {
		Endpoint.Say("  [INFO] Seatbelt not available - see tools/README.md for instructions")
		LogMessage("INFO", "Seatbelt", "Binary not available - skipping -group=all test")
		LogPhaseEnd(5, "skipped", "Seatbelt binary not available")
	}

	Endpoint.Wait(2)

	// Phase 7: Seatbelt Credential Checks (if available)
	LogPhaseStart(7, "Seatbelt Credential Enumeration")
	Endpoint.Say("\nPhase 7: Seatbelt credential checks (PLACEHOLDER - requires Seatbelt.exe)")

	if checkSeatbeltAvailable() && !seatbeltQuarantined {
		seatbeltPath := filepath.Join(TARGET_DIR, "Seatbelt.exe")

		// Check if Seatbelt still exists
		if _, err := os.Stat(seatbeltPath); err == nil {
			successCred, blockedCred, msgCred := testSeatbeltCredentialChecks(seatbeltPath)
			if blockedCred {
				Endpoint.Say("  [BLOCKED] Seatbelt credential checks were blocked by EDR")
				blockedPatterns = append(blockedPatterns, "Seatbelt Credential Checks")
				LogPhaseEnd(6, "blocked", msgCred)
			} else if successCred {
				Endpoint.Say("  [VULNERABLE] Seatbelt credential checks executed without detection")
				successfulPatterns = append(successfulPatterns, "Seatbelt Credential Checks")
				LogPhaseEnd(6, "success", msgCred)
			} else {
				Endpoint.Say("  [ERROR] Seatbelt credential checks failed: %s", msgCred)
				LogPhaseEnd(6, "failed", msgCred)
			}
		} else {
			Endpoint.Say("  [INFO] Seatbelt was removed after previous execution")
			LogMessage("INFO", "Seatbelt", "Seatbelt removed after -group=all execution")
			LogPhaseEnd(6, "skipped", "Seatbelt was removed")
		}
	} else {
		if seatbeltQuarantined {
			Endpoint.Say("  [INFO] Skipped - Seatbelt was quarantined")
			LogPhaseEnd(6, "skipped", "Seatbelt was quarantined")
		} else {
			Endpoint.Say("  [INFO] Seatbelt not available - skipping credential checks")
			LogPhaseEnd(6, "skipped", "Seatbelt binary not available")
		}
	}

	// Phase 8: Final Assessment
	LogPhaseStart(8, "Final Assessment")
	Endpoint.Say("\nPhase 8: Final assessment and summary")

	// Create summary
	summaryPath := filepath.Join(TARGET_DIR, "enumeration_summary.txt")
	summary := fmt.Sprintf(`Pre-Encryption File Enumeration Test Summary
=============================================
Test ID: %s
Timestamp: %s

MITRE ATT&CK Techniques:
- T1083: File and Directory Discovery
- T1119: Automated Collection
- T1082: System Information Discovery (via Seatbelt)

Test Components:
1. Test Document Creation (c:\Users\fortika-test\test_documents\)
2. Recursive File Enumeration (dir /s /b)
3. Extension-Based Filtering (.docx, .xlsx, .pdf, .db, .sql, .bak)
4. Target List Generation (pre-encryption recon output)
5. Seatbelt -group=all (comprehensive enumeration)
6. Seatbelt Credential Checks (WindowsCredentialFiles, WindowsVault, InterestingFiles)

Results:
- Patterns Blocked: %d
- Patterns Successful: %d
- Seatbelt Available: %v
- Seatbelt Quarantined: %v

Blocked Patterns:
%s

Successful Patterns (VULNERABLE):
%s

Detection Opportunities:
1. dir.exe with recursive enumeration flags
2. Bulk file access patterns
3. Extension filtering behavior
4. Target list file creation
5. Seatbelt.exe binary detection
6. Seatbelt execution with enumeration arguments
7. High-volume file system queries

Assessment:
%s
`,
		TEST_UUID,
		time.Now().Format("2006-01-02 15:04:05"),
		len(blockedPatterns),
		len(successfulPatterns),
		checkSeatbeltAvailable(),
		seatbeltQuarantined,
		formatPatternList(blockedPatterns),
		formatPatternList(successfulPatterns),
		generateAssessment(len(blockedPatterns), len(successfulPatterns), seatbeltQuarantined))

	os.WriteFile(summaryPath, []byte(summary), 0644)
	LogFileDropped("enumeration_summary.txt", summaryPath, int64(len(summary)), false)

	LogPhaseEnd(7, "success", fmt.Sprintf("Assessment complete: %d blocked, %d successful", len(blockedPatterns), len(successfulPatterns)))

	// Final result
	Endpoint.Say("\n========================================")
	Endpoint.Say("TEST RESULTS SUMMARY")
	Endpoint.Say("========================================")
	Endpoint.Say("Patterns Blocked: %d", len(blockedPatterns))
	Endpoint.Say("Patterns Successful: %d", len(successfulPatterns))
	Endpoint.Say("Seatbelt Available: %v", checkSeatbeltAvailable())
	Endpoint.Say("Seatbelt Quarantined: %v", seatbeltQuarantined)

	// Determine exit code
	if seatbeltQuarantined {
		// Seatbelt was quarantined on extraction - exit 105
		Endpoint.Say("\n[RESULT] PROTECTED - Seatbelt quarantined on extraction")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - Seatbelt quarantined")
		SaveLog(Endpoint.FileQuarantinedOnExtraction, "Seatbelt.exe quarantined on extraction")
		cleanup()
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction) // Exit 105
	} else if len(blockedPatterns) > 0 {
		// At least one pattern was blocked - system has protection
		Endpoint.Say("\n[RESULT] PROTECTED - EDR blocked file enumeration patterns")
		LogMessage("INFO", "Final Assessment", "System PROTECTED - enumeration controls active")
		SaveLog(Endpoint.ExecutionPrevented, fmt.Sprintf("Protected: %d patterns blocked", len(blockedPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.ExecutionPrevented) // Exit 126
	} else if len(successfulPatterns) > 0 {
		// All patterns executed successfully - system is unprotected
		Endpoint.Say("\n[RESULT] UNPROTECTED - File enumeration patterns executed without detection")
		LogMessage("CRITICAL", "Final Assessment", "System UNPROTECTED - enumeration undetected")
		SaveLog(Endpoint.Unprotected, fmt.Sprintf("Unprotected: %d patterns executed", len(successfulPatterns)))
		cleanup()
		Endpoint.Stop(Endpoint.Unprotected) // Exit 101
	} else {
		// No clear result (unlikely, but handle gracefully)
		Endpoint.Say("\n[RESULT] INCONCLUSIVE - Test did not produce clear results")
		LogMessage("WARN", "Final Assessment", "Test inconclusive")
		SaveLog(Endpoint.UnexpectedTestError, "Test inconclusive")
		cleanup()
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}
}

// formatPatternList formats a list of patterns for display
func formatPatternList(patterns []string) string {
	if len(patterns) == 0 {
		return "  (none)"
	}
	var result string
	for _, p := range patterns {
		result += fmt.Sprintf("  - %s\n", p)
	}
	return result
}

// generateAssessment creates an assessment string based on results
func generateAssessment(blocked, successful int, quarantined bool) string {
	if quarantined {
		return "PROTECTED - Seatbelt binary was quarantined on extraction, indicating strong AV/EDR protection against enumeration tools."
	} else if blocked > 0 && successful == 0 {
		return "PROTECTED - All file enumeration patterns were blocked by security controls."
	} else if blocked > 0 && successful > 0 {
		return "PARTIAL PROTECTION - Some enumeration patterns were blocked, but others succeeded."
	} else if successful > 0 {
		return "UNPROTECTED - Pre-encryption reconnaissance patterns executed successfully without detection."
	}
	return "INCONCLUSIVE - Unable to determine protection status."
}

func main() {
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Test: %s", TEST_NAME)
	Endpoint.Say("UUID: %s", TEST_UUID)
	Endpoint.Say("MITRE ATT&CK: T1083 (File Discovery), T1119 (Automated Collection), T1082 (System Info)")
	Endpoint.Say("")

	// Initialize Schema v2.0 compliant logger
	metadata := TestMetadata{
		Version:    "1.0.0",
		Category:   "discovery",
		Severity:   "high",
		Techniques: []string{"T1083", "T1119", "T1082"},
		Tactics:    []string{"discovery", "collection"},
		Score:      8.5,
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.5, // Real tool (Seatbelt with 60+ checks), realistic enumeration
			TechnicalSophistication: 2.5, // Multiple techniques, comprehensive enumeration
			SafetyMechanisms:        2.0, // Creates own test files, read-only enumeration, full cleanup
			DetectionOpportunities:  1.0, // 7+ detection points
			LoggingObservability:    0.5, // Comprehensive logging with output capture
		},
		Tags: []string{"file-discovery", "enumeration", "pre-encryption", "seatbelt", "native"},
	}

	// Resolve organization from registry
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000,
			CertificateMode:   "not-required",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	// Run test with timeout
	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	timeout := 5 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		if globalLog != nil {
			LogMessage("ERROR", "Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
			SaveLog(Endpoint.TimeoutExceeded, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		}
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
