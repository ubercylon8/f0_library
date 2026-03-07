//go:build windows
// +build windows

/*
STAGE 5: Financial Data Exfiltration (T1041, T1567.002, T1560.001)
Simulates credential staging, archive compression (AMOS "out.zip" pattern),
AWS S3 exfiltration with hardcoded credentials (NotLockBit pattern),
Google Drive exfiltration (TodoSwift), and HTTP POST exfiltration
with metadata identifiers (hwid, wid, user).
Primary technique mapped: T1041 (Exfiltration Over C2 Channel)
*/

package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
	TECHNIQUE_ID   = "T1041"
	TECHNIQUE_NAME = "Exfiltration Over C2 Channel"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// ExfiltrationMethod represents a simulated exfil channel
type ExfiltrationMethod struct {
	Method      string `json:"method"`
	Destination string `json:"destination"`
	DataSize    int64  `json:"data_size_bytes"`
	Status      string `json:"status"`
	Campaign    string `json:"campaign"`
	Description string `json:"description"`
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Simulate financial data exfiltration via multiple channels")

	fmt.Printf("[STAGE %s] Starting Financial Data Exfiltration\n", TECHNIQUE_ID)

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
			fmt.Printf("[STAGE %s] Technique blocked: %v\n", TECHNIQUE_ID, err)
			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Technique blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	fmt.Printf("[STAGE %s] Data exfiltration simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Financial data exfiltration completed without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Data exfiltration simulation completed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	artifactDir := "c:\\Users\\fortika-test"
	stagingDir := filepath.Join(targetDir, "credential_staging")
	exfilDir := filepath.Join(targetDir, "exfil_staging")

	if err := os.MkdirAll(exfilDir, 0755); err != nil {
		return fmt.Errorf("failed to create exfil directory: %v", err)
	}

	var exfilMethods []ExfiltrationMethod

	// --- Phase 1: Stage collected data ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 1: Staging collected data for exfiltration")
	fmt.Printf("[STAGE %s] Phase 1: Staging collected data\n", TECHNIQUE_ID)

	// Aggregate data from previous stages (credential_staging from Stage 3)
	var totalStagedSize int64

	// Check if credential staging directory exists (from Stage 3)
	if _, err := os.Stat(stagingDir); os.IsNotExist(err) {
		// Create with synthetic data if Stage 3 artifacts were cleaned
		LogMessage("INFO", TECHNIQUE_ID, "Creating synthetic staged data (Stage 3 artifacts may have been cleaned)")
		if err := os.MkdirAll(stagingDir, 0755); err != nil {
			return fmt.Errorf("failed to create staging: %v", err)
		}

		syntheticData := map[string]string{
			"browser_creds.json":   `{"simulation":true,"source":"Chrome Login Data","entries":5}`,
			"keychain_dump.txt":    "Simulated Keychain dump - 12 entries extracted",
			"metamask_vault.json":  `{"simulation":true,"wallet":"MetaMask","vault":"SIMULATED_DATA"}`,
			"system_info.json":     `{"hostname":"target-mac","os":"macOS 14.2","arch":"arm64"}`,
		}
		for fname, content := range syntheticData {
			fpath := filepath.Join(stagingDir, fname)
			os.WriteFile(fpath, []byte(content), 0644)
		}
	}

	// Walk staging directory and count data
	filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		totalStagedSize += info.Size()
		return nil
	})

	// Also stage data from artifact directory
	artifactFiles := []string{
		filepath.Join(artifactDir, "InternalPDFViewer.sh"),
		filepath.Join(artifactDir, ".zshenv"),
		filepath.Join(artifactDir, "CryptoExchangePro_Info.plist"),
	}
	for _, af := range artifactFiles {
		if info, err := os.Stat(af); err == nil {
			totalStagedSize += info.Size()
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Total staged data: %d bytes", totalStagedSize))

	// --- Phase 2: Compress to archive (AMOS "out.zip" pattern) ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 2: Compressing data to archive (AMOS out.zip pattern, T1560.001)")
	fmt.Printf("[STAGE %s] Phase 2: Archive compression (T1560.001)\n", TECHNIQUE_ID)

	// AMOS Stealer uses "out.zip" as the standard archive name
	archivePath := filepath.Join(exfilDir, "out.zip")
	archiveSize, err := createExfilArchive(stagingDir, archivePath)
	if err != nil {
		return fmt.Errorf("archive creation blocked: %v", err)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Archive created: %s (%d bytes)", archivePath, archiveSize))

	// Verify archive survived AV scanning
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("exfiltration archive quarantined: removed by security controls")
	}

	// --- Phase 3: Simulate AWS S3 exfiltration (NotLockBit pattern) ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 3: Simulating AWS S3 exfiltration (macOS.NotLockBit pattern, T1567.002)")
	fmt.Printf("[STAGE %s] Phase 3: AWS S3 exfiltration simulation\n", TECHNIQUE_ID)

	s3ExfilConfig := `{
  "simulation": true,
  "campaign": "macOS.NotLockBit",
  "technique": "T1567.002 - Exfiltration to Cloud Storage",
  "note": "macOS.NotLockBit exfiltrates to AWS S3 with hardcoded credentials before encryption",
  "aws_config": {
    "region": "us-east-1",
    "bucket": "simulated-exfil-bucket-f0rtika",
    "access_key": "SIMULATED_AKIAIOSFODNN7EXAMPLE",
    "secret_key": "SIMULATED_wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY",
    "endpoint": "https://s3.amazonaws.com"
  },
  "upload_details": {
    "object_key": "exfil/target-mac/out.zip",
    "content_type": "application/zip",
    "encryption": "AES-256",
    "metadata": {
      "hwid": "SIMULATED-HARDWARE-UUID",
      "campaign": "bluenoroff-2024",
      "timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
    }
  }
}`

	s3ConfigPath := filepath.Join(exfilDir, "s3_exfil_config.json")
	if err := os.WriteFile(s3ConfigPath, []byte(s3ExfilConfig), 0644); err != nil {
		return fmt.Errorf("failed to write S3 exfil config: %v", err)
	}

	// Simulate the S3 upload by copying archive to "uploaded" location
	s3UploadPath := filepath.Join(exfilDir, "s3_uploaded_out.zip")
	if err := copyFile(archivePath, s3UploadPath); err != nil {
		return fmt.Errorf("S3 upload simulation failed: %v", err)
	}

	exfilMethods = append(exfilMethods, ExfiltrationMethod{
		Method:      "AWS S3",
		Destination: "s3://simulated-exfil-bucket-f0rtika/exfil/target-mac/out.zip",
		DataSize:    archiveSize,
		Status:      "simulated",
		Campaign:    "macOS.NotLockBit",
		Description: "AWS S3 upload with hardcoded credentials (pre-encryption exfil)",
	})

	LogMessage("INFO", TECHNIQUE_ID, "S3 exfiltration simulation completed")

	// --- Phase 4: Simulate Google Drive exfiltration (TodoSwift) ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 4: Simulating Google Drive exfiltration (TodoSwift pattern)")
	fmt.Printf("[STAGE %s] Phase 4: Google Drive exfiltration\n", TECHNIQUE_ID)

	gdriveExfilConfig := `{
  "simulation": true,
  "campaign": "TodoSwift",
  "technique": "T1567.002 - Exfiltration to Cloud Storage",
  "note": "TodoSwift uses Google Drive for both payload delivery and exfiltration",
  "gdrive_config": {
    "oauth_token": "SIMULATED_OAUTH_TOKEN_F0RTIKA",
    "upload_url": "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
    "folder_id": "SIMULATED_FOLDER_ID",
    "file_name": "system_report.zip"
  },
  "metadata": {
    "victim_id": "SIMULATED-HWID",
    "upload_timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `"
  }
}`

	gdriveConfigPath := filepath.Join(exfilDir, "gdrive_exfil_config.json")
	if err := os.WriteFile(gdriveConfigPath, []byte(gdriveExfilConfig), 0644); err != nil {
		return fmt.Errorf("failed to write Google Drive config: %v", err)
	}

	exfilMethods = append(exfilMethods, ExfiltrationMethod{
		Method:      "Google Drive",
		Destination: "drive.google.com/SIMULATED_FOLDER_ID",
		DataSize:    archiveSize,
		Status:      "simulated",
		Campaign:    "TodoSwift",
		Description: "Google Drive API upload with OAuth token",
	})

	// --- Phase 5: Simulate HTTP POST exfiltration ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 5: Simulating HTTP POST exfiltration with metadata identifiers")
	fmt.Printf("[STAGE %s] Phase 5: HTTP POST exfiltration with identifiers\n", TECHNIQUE_ID)

	hostname, _ := os.Hostname()
	httpPostPayload := map[string]interface{}{
		"simulation": true,
		"technique":  "T1041 - Exfiltration Over C2 Channel",
		"campaign":   "BlueNoroff/Lazarus",
		"c2_url":     "https://app.linkpc.net/api/upload",
		"identifiers": map[string]string{
			"hwid": "SIMULATED-HARDWARE-UUID-" + time.Now().Format("20060102"),
			"wid":  "SIMULATED-WALLET-ID-BN2024",
			"user": hostname,
		},
		"payload": map[string]interface{}{
			"type":     "application/zip",
			"filename": "out.zip",
			"size":     archiveSize,
			"encoding": "base64",
		},
		"headers": map[string]string{
			"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15",
			"Content-Type": "multipart/form-data",
			"X-Campaign":   "hidden-risk-2024",
		},
	}

	httpPayloadJSON, err := json.MarshalIndent(httpPostPayload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP payload: %v", err)
	}

	httpPayloadPath := filepath.Join(exfilDir, "http_post_exfil.json")
	if err := os.WriteFile(httpPayloadPath, httpPayloadJSON, 0644); err != nil {
		return fmt.Errorf("failed to write HTTP exfil payload: %v", err)
	}

	exfilMethods = append(exfilMethods, ExfiltrationMethod{
		Method:      "HTTP POST",
		Destination: "https://app.linkpc.net/api/upload",
		DataSize:    archiveSize,
		Status:      "simulated",
		Campaign:    "Hidden Risk",
		Description: "HTTP POST with hwid/wid/user metadata identifiers",
	})

	// --- Save exfiltration summary ---
	exfilSummary, err := json.MarshalIndent(map[string]interface{}{
		"simulation":    true,
		"test_uuid":     TEST_UUID,
		"stage":         STAGE_ID,
		"technique":     TECHNIQUE_ID,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"total_data":    totalStagedSize,
		"archive_size":  archiveSize,
		"channels_used": len(exfilMethods),
		"channels":      exfilMethods,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal exfil summary: %v", err)
	}

	summaryPath := filepath.Join(exfilDir, "exfiltration_summary.json")
	if err := os.WriteFile(summaryPath, exfilSummary, 0644); err != nil {
		return fmt.Errorf("failed to write exfil summary: %v", err)
	}

	// Final verification
	time.Sleep(2 * time.Second)
	criticalFiles := []string{archivePath, s3UploadPath, summaryPath}
	for _, f := range criticalFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return fmt.Errorf("exfiltration artifact quarantined: %s removed by security controls", filepath.Base(f))
		}
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("Data exfiltrated via %d channels, total %d bytes archived", len(exfilMethods), archiveSize))
	LogMessage("INFO", TECHNIQUE_ID, "Exfiltration Summary:")
	for i, m := range exfilMethods {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("  Channel %d: %s -> %s (%s)", i+1, m.Method, m.Destination, m.Campaign))
	}

	return nil
}

// createExfilArchive compresses the staging directory into a zip archive
func createExfilArchive(sourceDir, archivePath string) (int64, error) {
	zipFile, err := os.Create(archivePath)
	if err != nil {
		return 0, fmt.Errorf("failed to create archive: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		fileContent, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fileContent.Close()

		_, err = io.Copy(zipEntry, fileContent)
		return err
	})

	if err != nil {
		return 0, fmt.Errorf("compression failed: %v", err)
	}

	// Flush and get size
	zipWriter.Close()
	zipFile.Close()

	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return 0, err
	}

	return archiveInfo.Size(), nil
}

// copyFile copies a file for upload simulation
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

func isBlockedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	blockIndicators := []string{
		"access denied", "access is denied", "permission denied",
		"blocked", "prevented", "quarantined", "removed by security",
	}
	for _, indicator := range blockIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}
