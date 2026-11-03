//go:build windows
// +build windows

/*
ID: a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07
NAME: Pre-Encryption File Enumeration
TECHNIQUES: T1083, T1119, T1082
TACTICS: discovery, collection
SEVERITY: high
TARGET: windows-endpoint
COMPLEXITY: low
THREAT_ACTOR: N/A
SUBCATEGORY: discovery
TAGS: file-discovery, enumeration, pre-encryption, seatbelt, native
SOURCE_URL: https://top-attack-techniques.mitre-engenuity.org/
UNIT: response
CREATED: 2026-01-11
AUTHOR: sectest-builder
*/
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID     = "a3d9b4c7-2e8f-9d6a-3b0c-7f8a9b0c1d07"
	TEST_NAME     = "Pre-Encryption File Enumeration"
	TARGET_DIR    = "c:\\F0"
	TEST_DOCS_DIR = "c:\\Users\\fortika-test\\test_documents"

	// ExitTestError is the framework test-error exit code. The vendored prelude
	// endpoint lib maps UnexpectedTestError to exit 1 — do not use it (CLAUDE.md).
	ExitTestError = 999
)

// isAdminContext gates denial classification (Bug Prevention Rule 8).
var isAdminContext = false

// probeAdminContext checks whether the current context is elevated.
func probeAdminContext() bool {
	return exec.Command("net", "session").Run() == nil
}

// isPositiveProtectionEvidence returns true ONLY for exact OS/policy denial
// markers (generic words anywhere in output are NOT evidence).
func isPositiveProtectionEvidence(s string) bool {
	return strings.Contains(s, "Access is denied") ||
		strings.Contains(s, "This program is blocked by group policy") ||
		strings.Contains(s, "Operation did not complete successfully because the file contains a virus")
}

// fileExists is a small os.Stat wrapper
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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
	"financial_report_2024.docx": "F0RT1KA Test Document - Financial Report",
	"customer_database.db":       "F0RT1KA Test Document - Customer Database Placeholder",
	"quarterly_earnings.xlsx":    "F0RT1KA Test Document - Quarterly Earnings",
	"backup_config.bak":          "F0RT1KA Test Document - Backup Configuration",
	"invoice_template.pdf":       "F0RT1KA Test Document - Invoice Template",
	"employee_records.sql":       "-- F0RT1KA Test SQL Dump\nCREATE TABLE employees (id INT, name VARCHAR(255));",
	"project_plan.docx":          "F0RT1KA Test Document - Project Plan",
	"credentials_backup.txt":     "F0RT1KA Test Document - Credentials Backup Placeholder",
	"database_schema.sql":        "-- F0RT1KA Test SQL Schema\nCREATE DATABASE test_db;",
	"annual_budget.xlsx":         "F0RT1KA Test Document - Annual Budget",
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

	// Count files found
	lines := strings.Split(strings.TrimSpace(output), "\n")
	filesFound := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "File Not Found") {
			filesFound++
		}
	}

	if err != nil {
		errorStr := err.Error()

		// Block ONLY on exact OS denial in the error channel, admin-gated
		// (Rule 8). A failed dir with zero results is a benign failure, not
		// success and not a block.
		if isAdminContext && (isPositiveProtectionEvidence(errorStr) || isPositiveProtectionEvidence(output)) {
			LogProcessExecution("cmd.exe", cmdLine, pid, false, 126, "Blocked by security controls (OS denial)")
			LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumeration blocked after %v", duration))
			return false, true, 0, "Directory enumeration blocked by EDR"
		}

		LogProcessExecution("cmd.exe", cmdLine, pid, false, cmd.ProcessState.ExitCode(), errorStr)
		if filesFound == 0 {
			// dir failed AND produced nothing: benign failure — NOT success
			LogMessage("WARN", "Dir Enumeration", fmt.Sprintf("Enumeration failed with no results (exit %d, %v)", cmd.ProcessState.ExitCode(), duration))
			return false, false, 0, fmt.Sprintf("Enumeration failed: %s", errorStr)
		}
		// Partial results: count as success with a note
		LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumeration completed with exit code %d, %d files in %v", cmd.ProcessState.ExitCode(), filesFound, duration))
	} else {
		LogProcessExecution("cmd.exe", cmdLine, pid, true, 0, "")
	}

	LogMessage("INFO", "Dir Enumeration", fmt.Sprintf("Enumerated %d files in %v", filesFound, duration))
	return true, false, filesFound, fmt.Sprintf("Enumerated %d files", filesFound)
}

// enumerateRealUserProfiles performs READ-ONLY enumeration of real user profile
// directories (Documents/Desktop) — the tradecraft signal real pre-encryption
// recon produces (Batch B realism upgrade). Benign-count only: this phase can
// never drive the exit code.
func enumerateRealUserProfiles() {
	Endpoint.Say("  Enumerating real user profile directories (read-only)...")

	targets, _ := filepath.Glob("C:\\Users\\*\\Documents")
	desktops, _ := filepath.Glob("C:\\Users\\*\\Desktop")
	targets = append(targets, desktops...)

	total := 0
	for _, dir := range targets {
		cmd := exec.Command("cmd", "/c", "dir", "/s", "/b", dir)
		var buf bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
		err := cmd.Run()
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		out := buf.String()
		count := 0
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" && !strings.Contains(line, "File Not Found") {
				count++
			}
		}
		total += count
		exitCode := 0
		if err != nil && cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		// Cap persisted output at 200 lines
		capped := out
		outLines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(outLines) > 200 {
			capped = strings.Join(outLines[:200], "\n") + "\n... (truncated)"
		}
		safe := strings.Map(func(r rune) rune { if r == '\\' { return '_' }; return r }, filepath.Base(filepath.Dir(dir))+"_"+filepath.Base(dir))
		outPath := filepath.Join(TARGET_DIR, "profile_enum_"+safe+".txt")
		os.WriteFile(outPath, []byte(capped), 0644)
		LogFileDropped(filepath.Base(outPath), outPath, int64(len(capped)), false)
		LogProcessExecution("cmd.exe", fmt.Sprintf("cmd /c dir /s /b \"%s\"", dir), pid, err == nil, exitCode,
			fmt.Sprintf("user-profile enumeration (benign count: %d files)", count))
	}
	LogMessage("INFO", "User Profile Enumeration", fmt.Sprintf("Enumerated %d files across %d user profile directories (read-only, benign)", total, len(targets)))
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
		cmdLine := fmt.Sprintf("cmd /c dir /s /b \"%s\"", pattern)

		var buf bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)

		err := cmd.Run()
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		outputStr := buf.String()

		exitCode := 0
		if err != nil && cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Persist + log every extension-filter child (was uncaptured)
		outPath := filepath.Join(TARGET_DIR, fmt.Sprintf("dir_ext%s_output.txt", ext))
		os.WriteFile(outPath, []byte(outputStr), 0644)

		if err != nil {
			errorStr := err.Error()

			// Block ONLY on exact OS denial, admin-gated (Rule 8).
			// "File Not Found" style errors are expected for some extensions.
			if isAdminContext && (isPositiveProtectionEvidence(errorStr) || isPositiveProtectionEvidence(outputStr)) {
				LogProcessExecution("cmd.exe", cmdLine, pid, false, 126, "Blocked by security controls (OS denial)")
				LogMessage("INFO", "Extension Filtering", fmt.Sprintf("Extension filtering blocked for %s", ext))
				return false, true, 0, "Extension filtering blocked by EDR"
			}
			LogProcessExecution("cmd.exe", cmdLine, pid, false, exitCode, fmt.Sprintf("no results for %s (expected for some extensions)", ext))
			continue
		}

		LogProcessExecution("cmd.exe", cmdLine, pid, true, 0, fmt.Sprintf("filtered %s", ext))

		// Parse files found for this extension
		trimmed := strings.TrimSpace(outputStr)
		if trimmed != "" && !strings.Contains(trimmed, "File Not Found") {
			for _, line := range strings.Split(trimmed, "\n") {
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
		if isAdminContext && (isPositiveProtectionEvidence(errorStr)) {
			LogMessage("INFO", "Target List Generation", "File walk blocked by security controls (OS denial)")
			return false, true, "", "Target list generation blocked by EDR"
		}
		// Walk errors are otherwise skipped per-file; a top-level walk error
		// with no results is a benign failure (not success, not block).
		if len(targetFiles) == 0 {
			return false, false, "", fmt.Sprintf("Walk failed benignly: %s", errorStr)
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
	// Embedded build (built with the `seatbelt` tag, see build_all.sh)
	if isEmbeddedSeatbeltValid() {
		return true
	}

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

// isEmbeddedSeatbeltValid reports whether a real PE was embedded at build time
func isEmbeddedSeatbeltValid() bool {
	return len(seatbeltEmbedded) > 2 && seatbeltEmbedded[0] == 'M' && seatbeltEmbedded[1] == 'Z'
}

// extractSeatbelt makes Seatbelt executable-ready under c:\F0, preferring the
// build-time embedded copy (single-binary deployment, CLAUDE.md rule 3) and
// falling back to the runtime-provided copy in c:\F0\tools\.
func extractSeatbelt() (string, error) {
	// 1) Embedded copy (built with the `seatbelt` tag; provenance in build_all.sh)
	if isEmbeddedSeatbeltValid() {
		seatbeltPath := filepath.Join(TARGET_DIR, "Seatbelt.exe")
		if err := os.WriteFile(seatbeltPath, seatbeltEmbedded, 0755); err != nil {
			return "", fmt.Errorf("failed to write embedded Seatbelt: %v", err)
		}
		seatbeltBinary = seatbeltEmbedded
		sum := sha256.Sum256(seatbeltEmbedded)
		LogMessage("INFO", "Seatbelt", fmt.Sprintf("Extracted EMBEDDED Seatbelt.exe: size=%d sha256=%s (GhostPack@392171df, built from pinned source)",
			len(seatbeltEmbedded), hex.EncodeToString(sum[:])))
		LogFileDropped("Seatbelt.exe", seatbeltPath, int64(len(seatbeltEmbedded)), false)
		return seatbeltPath, nil
	}

	// 2) Runtime-provided copy
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
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Block ONLY on explicit security-product action text (Rule 8);
		// "not recognized"/DLL/exit codes are benign environment failures.
		if isPositiveProtectionEvidence(output) || isPositiveProtectionEvidence(errorStr) {
			LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, false, 126, "Execution blocked (positive evidence)")
			LogMessage("INFO", "Seatbelt", "Seatbelt execution blocked by EDR")
			return false, true, "Seatbelt execution blocked by EDR"
		}

		// Tool ran but failed operationally (missing runtime, crashed, etc.):
		// benign failure — NOT success, NOT a block (Rules 4 & 8).
		LogProcessExecution("Seatbelt.exe", "Seatbelt -group=all", pid, false, exitCode,
			"tool executed but failed operationally (benign — not counted)")
		LogMessage("WARN", "Seatbelt", fmt.Sprintf("Seatbelt -group=all failed operationally: %s (duration: %v)", errorStr, duration))
		return false, false, fmt.Sprintf("Seatbelt ran but failed: %s", errorStr)
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
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		if isPositiveProtectionEvidence(output) || isPositiveProtectionEvidence(errorStr) {
			LogProcessExecution("Seatbelt.exe", "Seatbelt WindowsCredentialFiles WindowsVault InterestingFiles", pid, false, 126, "Execution blocked (positive evidence)")
			LogMessage("INFO", "Seatbelt", "Seatbelt credential checks blocked by EDR")
			return false, true, "Seatbelt credential checks blocked by EDR"
		}

		// Benign operational failure — NOT success (Rules 4 & 8).
		LogProcessExecution("Seatbelt.exe", "Seatbelt WindowsCredentialFiles WindowsVault InterestingFiles", pid, false, exitCode,
			"tool executed but failed operationally (benign — not counted)")
		LogMessage("WARN", "Seatbelt", fmt.Sprintf("Seatbelt credential checks failed operationally: %s (duration: %v)", errorStr, duration))
		return false, false, fmt.Sprintf("Seatbelt credential checks ran but failed: %s", errorStr)
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
				SaveLog(ExitTestError, fmt.Sprintf("Panic: %v", r))
			}
			cleanup()
			Endpoint.Stop(ExitTestError)
		}
	}()

	// Results tracking
	var blockedPatterns []string
	var successfulPatterns []string
	seatbeltQuarantined := false

	// Phase 1: Initialization
	LogPhaseStart(1, "Initialization")
	Endpoint.Say("Phase 1: Initializing test environment")

	// NOTE: Endpoint.Dropper call removed — it dropped an unused binary into CWD
	// on every run and was never executed (audit 2026-11-03).

	// Create target directory
	if err := os.MkdirAll(TARGET_DIR, 0755); err != nil {
		LogPhaseError(0, fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(ExitTestError, "Failed to create target directory")
		Endpoint.Stop(ExitTestError)
	}

	// Probe privilege context once — gates denial classification (Rule 8)
	isAdminContext = probeAdminContext()
	if isAdminContext {
		LogMessage("INFO", "Initialization", "Running elevated (administrator)")
	} else {
		LogMessage("WARN", "Initialization", "Running NON-elevated — access-denied outcomes will be treated as benign environment results")
	}

	// Log SHA256 of the runtime-provided tool (integrity trail, log-only)
	if toolPath := filepath.Join(TARGET_DIR, "tools", "Seatbelt.exe"); fileExists(toolPath) {
		if data, err := os.ReadFile(toolPath); err == nil {
			sum := sha256.Sum256(data)
			LogMessage("INFO", "Initialization", fmt.Sprintf("Seatbelt.exe present: size=%d sha256=%s (log-only integrity record)", len(data), hex.EncodeToString(sum[:])))
		}
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

	// Phase 5b: Real User Profile Enumeration (read-only, benign-count only)
	LogPhaseStart(6, "Real User Profile Enumeration")
	Endpoint.Say("\nPhase 5b: Enumerating real user profile directories (read-only)")

	enumerateRealUserProfiles()

	LogPhaseEnd(5, "info", "User profile enumeration completed (read-only, benign)")

	Endpoint.Wait(2)

	// Phase 6: Seatbelt Group All (if available)
	LogPhaseStart(7, "Seatbelt Comprehensive Enumeration")
	Endpoint.Say("\nPhase 6: Seatbelt -group=all (runtime-optional)")

	if checkSeatbeltAvailable() {
		Endpoint.Say("  Seatbelt binary found - extracting...")

		seatbeltPath, err := extractSeatbelt()
		if err != nil {
			Endpoint.Say("  [ERROR] Failed to extract Seatbelt: %v", err)
			LogMessage("ERROR", "Seatbelt", fmt.Sprintf("Extraction failed: %v", err))
			LogPhaseEnd(6, "failed", err.Error())
		} else {
			Endpoint.Say("  [+] Seatbelt extracted to: %s", seatbeltPath)

			// Wait for potential quarantine, then verify via os.Stat on the
			// exact extracted path (pure-stat; library helper re-writes to CWD)
			Endpoint.Wait(3)

			if !fileExists(seatbeltPath) {
				Endpoint.Say("  [QUARANTINED] Seatbelt.exe was quarantined on extraction")
				LogFileDropped("Seatbelt.exe", seatbeltPath, int64(len(seatbeltBinary)), true)
				seatbeltQuarantined = true
				blockedPatterns = append(blockedPatterns, "Seatbelt (Quarantined on Extraction)")
				LogPhaseEnd(6, "blocked", "Seatbelt quarantined on extraction")
			} else {
				// Try to execute Seatbelt -group=all
				successSeatbelt, blockedSeatbelt, msgSeatbelt := testSeatbeltGroupAll(seatbeltPath)
				if blockedSeatbelt {
					Endpoint.Say("  [BLOCKED] Seatbelt -group=all was blocked by EDR")
					blockedPatterns = append(blockedPatterns, "Seatbelt -group=all")
					LogPhaseEnd(6, "blocked", msgSeatbelt)
				} else if successSeatbelt {
					Endpoint.Say("  [VULNERABLE] Seatbelt -group=all executed without detection")
					successfulPatterns = append(successfulPatterns, "Seatbelt -group=all (60+ checks)")
					LogPhaseEnd(6, "success", msgSeatbelt)
				} else {
					Endpoint.Say("  [ERROR] Seatbelt test failed: %s", msgSeatbelt)
					LogPhaseEnd(6, "failed", msgSeatbelt)
				}
			}
		}
	} else {
		Endpoint.Say("  [INFO] Seatbelt not available - see tools/README.md for instructions")
		LogMessage("INFO", "Seatbelt", "Binary not available - skipping -group=all test")
		LogPhaseEnd(6, "skipped", "Seatbelt binary not available")
	}

	Endpoint.Wait(2)

	// Phase 7: Seatbelt Credential Checks (if available)
	LogPhaseStart(8, "Seatbelt Credential Enumeration")
	Endpoint.Say("\nPhase 7: Seatbelt credential checks (runtime-optional)")

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
			LogPhaseEnd(7, "skipped", "Seatbelt was removed")
		}
	} else {
		if seatbeltQuarantined {
			Endpoint.Say("  [INFO] Skipped - Seatbelt was quarantined")
			LogPhaseEnd(7, "skipped", "Seatbelt was quarantined")
		} else {
			Endpoint.Say("  [INFO] Seatbelt not available - skipping credential checks")
			LogPhaseEnd(7, "skipped", "Seatbelt binary not available")
		}
	}

	// Phase 8: Final Assessment
	LogPhaseStart(9, "Final Assessment")
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
		SaveLog(ExitTestError, "Test inconclusive")
		cleanup()
		Endpoint.Stop(ExitTestError)
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
		Version:       "1.0.0",
		Category:      "discovery",
		Severity:      "high",
		Techniques:    []string{"T1083", "T1119", "T1082"},
		Tactics:       []string{"discovery", "collection"},
		Score:         8.2, // v2.1 — lab-verified 2026-11-03 on the win lab (Sophos Intercept X). See info.md v2.1 scorecard.
		RubricVersion: "v2.1",
		// ScoreBreakdown intentionally nil under v2.1 — the v1 dimensions in
		// the struct do not match the v2.1 tiered structure. The v2.1 breakdown
		// lives in the info.md scorecard table.
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
		cleanup()
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}
