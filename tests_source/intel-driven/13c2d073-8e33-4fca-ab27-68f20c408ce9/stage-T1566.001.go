//go:build windows
// +build windows

/*
STAGE 1: Spearphishing Attachment (T1566.001)
Simulates APT33 Tickler delivery via ZIP archive masquerading as PDF.
Creates a ZIP archive containing simulated Tickler payload alongside
legitimate Windows DLLs (msvcp140.dll, vcruntime140.dll) to model
the actual APT33 delivery mechanism.
*/

package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1566.001"
	TECHNIQUE_NAME = "Spearphishing Attachment"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Spearphishing Attachment simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating APT33 Tickler delivery: ZIP masquerading as PDF")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Deliver Tickler payload via spearphishing ZIP")

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))

		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Spearphishing payload delivered successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Spearphishing payload delivered and extracted")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ZIP archive with Tickler payload created and extracted")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 delivers a ZIP archive disguised as a PDF containing:
	// 1. The Tickler backdoor (simulated)
	// 2. Legitimate msvcp140.dll
	// 3. Legitimate vcruntime140.dll
	// 4. A renamed Microsoft binary (Microsoft.SharePoint.NativeMessaging.exe)

	artifactDir := ARTIFACT_DIR
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	// Create the ZIP archive (masquerading as PDF - double extension)
	zipPath := filepath.Join(artifactDir, "Q3_Financial_Report_2025.pdf.zip")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating spearphishing ZIP at: %s", zipPath))

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create ZIP archive: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)

	// Add simulated Tickler payload (benign content)
	ticklerContent := []byte("REM Simulated APT33 Tickler backdoor payload\r\nREM This file simulates the Tickler malware for security testing\r\nREM Real Tickler is a C/C++ backdoor with DLL sideloading capability\r\necho F0RT1KA Security Test - Tickler Simulation\r\n")
	if err := addFileToZip(zipWriter, "Microsoft.SharePoint.NativeMessaging.exe", ticklerContent); err != nil {
		return fmt.Errorf("failed to add Tickler payload to ZIP: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Added simulated Tickler payload to ZIP")

	// Add simulated msvcp140.dll (benign marker content)
	dllContent := []byte("MZ\x00\x00F0RT1KA-SIMULATED-DLL-msvcp140\x00")
	if err := addFileToZip(zipWriter, "msvcp140.dll", dllContent); err != nil {
		return fmt.Errorf("failed to add msvcp140.dll to ZIP: %v", err)
	}

	// Add simulated vcruntime140.dll
	vcrContent := []byte("MZ\x00\x00F0RT1KA-SIMULATED-DLL-vcruntime140\x00")
	if err := addFileToZip(zipWriter, "vcruntime140.dll", vcrContent); err != nil {
		return fmt.Errorf("failed to add vcruntime140.dll to ZIP: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Added simulated sideloaded DLLs to ZIP")

	// Add decoy PDF document
	decoyContent := []byte("%PDF-1.4\r\n1 0 obj\r\n<< /Type /Catalog >>\r\nendobj\r\ntrailer << /Root 1 0 R >>\r\n%%EOF\r\n")
	if err := addFileToZip(zipWriter, "Q3_Financial_Report_2025.pdf", decoyContent); err != nil {
		return fmt.Errorf("failed to add decoy PDF to ZIP: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Added decoy PDF document to ZIP")

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize ZIP archive: %v", err)
	}

	// Check if ZIP was quarantined
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		return fmt.Errorf("ZIP archive was quarantined after creation")
	}

	// Simulate extraction of ZIP contents to artifact directory
	extractDir := filepath.Join(artifactDir, "tickler_extract")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create extraction directory: %v", err)
	}

	// Write extracted files
	files := map[string][]byte{
		"Microsoft.SharePoint.NativeMessaging.exe": ticklerContent,
		"msvcp140.dll":     dllContent,
		"vcruntime140.dll": vcrContent,
	}

	for name, content := range files {
		fpath := filepath.Join(extractDir, name)
		if err := os.WriteFile(fpath, content, 0755); err != nil {
			return fmt.Errorf("failed to extract %s: %v", name, err)
		}
	}

	// Check if extracted files were quarantined
	time.Sleep(3 * time.Second)
	for name := range files {
		fpath := filepath.Join(extractDir, name)
		if _, err := os.Stat(fpath); os.IsNotExist(err) {
			return fmt.Errorf("extracted file %s was quarantined", name)
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ZIP payload extracted to: %s", extractDir))
	LogMessage("INFO", TECHNIQUE_ID, "All payload components present after extraction")

	return nil
}

func addFileToZip(w *zip.Writer, name string, content []byte) error {
	header := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(content)
	return err
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	return StageBlocked
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsCI(s, substr) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

func indexIgnoreCase(s, substr string) int {
	s = toLowerStr(s)
	substr = toLowerStr(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toLowerStr(s string) string {
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
