// Stage 4 — T1567.002 Exfiltration to Cloud Storage
// F0RT1KA Security Testing Framework
// SB-PC-2026-001 [LOCKBIT] — Objetivo 4: Exfiltración de datos previa al cifrado
//
// LockBit's double-extortion model exfiltrates sensitive data BEFORE the
// encryption stage, using custom tooling (StealBit) and cloud storage/file-
// sharing services (AA23-165A: T1567.002 documented for LockBit; rclone is a
// hallmark affiliate tool). This stage emulates the full exfil primitive with
// ZERO external egress:
//
//   1. Generates ~2 MB of SYNTHETIC customer PII CSVs in ARTIFACT_DIR
//      (clearly fake names/accounts/emails — every row is marked synthetic;
//      per SB Aclaraciones, exfiltration uses synthetic data only).
//   2. Archives them via PowerShell Compress-Archive into LOG_DIR staging.
//   3. Starts a local HTTP listener on 127.0.0.1 (ephemeral port) and POSTs
//      the archive to it with a cloud-storage client signature (rclone
//      User-Agent + cloud-upload-style headers), mimicking StealBit/rclone
//      exfil behavior.
//   4. Classifies by whether the bytes arrived at the listener.
//
// HARD SAFETY BOUNDARIES:
//   - The listener is bound to 127.0.0.1 and the POST URL is built from the
//     listener's own address — no external egress is possible.
//   - All data is synthetic. Staging CSVs and the archive are removed in
//     cleanup.
//
// EXIT CODES: 0 = archive bytes arrived at the listener (exfil channel
// unimpeded), 126 = positive denial evidence on the transfer, 999 = error.

//go:build windows
// +build windows

package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "298cc137-ea39-4cf0-9b2d-b1c59a3cbacb"
	TECHNIQUE_ID   = "T1567.002"
	TECHNIQUE_NAME = "Pre-Encryption Exfiltration to Cloud Storage (T1567.002)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	csvFileCount  = 4
	csvTargetSize = 512 * 1024 // 512 KB per CSV -> ~2 MB total
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Exfiltration channel unimpeded - archive bytes received\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Archive POST completed - all bytes arrived at cloud-storage emulation listener")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Synthetic data exfiltrated unimpeded (loopback)")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Exfiltration prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Exfiltration transfer positively prevented")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Exfiltration transfer denied with positive evidence")
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Exfiltration stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Step 1: Generate synthetic customer PII CSVs in ARTIFACT_DIR
	// ------------------------------------------------------------------
	stagingDir := filepath.Join(ARTIFACT_DIR, "lockbit_staging")
	fmt.Printf("[STAGE %s] Phase 1: Generating ~2MB synthetic PII in %s\n", TECHNIQUE_ID, stagingDir)
	LogMessage("INFO", TECHNIQUE_ID, "Generating synthetic customer PII CSVs (SB Aclaraciones: synthetic data only)")

	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create staging directory: %v", err))
		return StageError
	}
	defer func() {
		if err := os.RemoveAll(stagingDir); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: failed to remove staging dir: %v", err))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "cleanup: staging directory removed")
		}
	}()

	totalBytes := 0
	for i := 1; i <= csvFileCount; i++ {
		csvPath := filepath.Join(stagingDir, fmt.Sprintf("customers_%03d.csv", i))
		n, err := generateSyntheticCSV(csvPath, csvTargetSize, i*100000)
		if err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to generate %s: %v", csvPath, err))
			return StageError
		}
		totalBytes += n
		LogFileDropped(filepath.Base(csvPath), csvPath, int64(n), false)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Generated %d synthetic CSVs (%d bytes total)", csvFileCount, totalBytes))

	// ------------------------------------------------------------------
	// Step 2: Archive via PowerShell Compress-Archive into LOG_DIR
	// ------------------------------------------------------------------
	zipPath := filepath.Join(LOG_DIR, "lockbit_exfil.zip")
	_ = os.Remove(zipPath) // stale archive from a prior run
	fmt.Printf("[STAGE %s] Phase 2: Archiving staged data to %s\n", TECHNIQUE_ID, zipPath)
	LogMessage("INFO", TECHNIQUE_ID, "Compress-Archive staging (LockBit pre-exfil archive behavior)")

	psCmd := fmt.Sprintf("Compress-Archive -Path '%s' -DestinationPath '%s' -Force",
		filepath.Join(stagingDir, "*.csv"), zipPath)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
	out, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	LogProcessExecution("powershell.exe", psCmd, 0, runErr == nil, 0, outStr)
	if runErr != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Compress-Archive returned: %v | %s", runErr, outStr))
		return StageError
	}
	defer func() {
		if err := os.Remove(zipPath); err == nil {
			LogMessage("INFO", TECHNIQUE_ID, "cleanup: exfil archive removed")
		}
	}()

	zipInfo, err := os.Stat(zipPath)
	if err != nil || zipInfo.Size() == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, "Archive missing or empty after Compress-Archive")
		return StageError
	}
	zipSize := zipInfo.Size()
	LogFileDropped("lockbit_exfil.zip", zipPath, zipSize, false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Archive ready: %d bytes", zipSize))

	// ------------------------------------------------------------------
	// Step 3: Local cloud-storage emulation listener on 127.0.0.1 + POST
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 3: Starting loopback listener and POSTing archive (rclone client signature)\n", TECHNIQUE_ID)
	LogMessage("WARN", TECHNIQUE_ID, "Exfiltration attempt: HTTP POST with rclone User-Agent (StealBit/cloud pattern) — 127.0.0.1 only")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to bind loopback listener: %v", err))
		return StageError
	}
	defer listener.Close()

	var received int64
	receivedDone := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received += n
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Listener: %s %s — %d bytes (UA: %s)", r.Method, r.URL.Path, n, r.UserAgent()))
		w.WriteHeader(http.StatusOK)
		close(receivedDone)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	uploadURL := fmt.Sprintf("http://%s/v1/files/upload/lockbit_exfil.zip", listener.Addr().String())

	zipFile, err := os.Open(zipPath)
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to open archive for upload: %v", err))
		return StageError
	}
	defer zipFile.Close()

	req, err := http.NewRequest(http.MethodPost, uploadURL, zipFile)
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to build upload request: %v", err))
		return StageError
	}
	req.ContentLength = zipSize
	// Cloud-storage client signature: rclone is the hallmark LockBit affiliate
	// exfil tool (StealBit is custom; rclone covers the cloud-storage pattern).
	req.Header.Set("User-Agent", "rclone/v1.61.1")
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("X-Remote-Name", "lockbit_exfil.zip")
	req.Header.Set("X-Remote-Path", "/stolen_data/customers/")
	req.Header.Set("Authorization", "Bearer SYNTHETIC-F0RT1KA-TEST-TOKEN")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, postErr := client.Do(req)
	if postErr != nil {
		errLower := strings.ToLower(postErr.Error())
		if strings.Contains(errLower, "forcibly closed") ||
			strings.Contains(errLower, "connection reset") ||
			strings.Contains(errLower, "access denied") {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Exfiltration transfer returned denial evidence: %v (received=%d/%d)", postErr, received, zipSize))
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Exfiltration POST failed (inconclusive): %v (received=%d/%d)", postErr, received, zipSize))
		return StageError
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Wait briefly for the handler to finish counting.
	select {
	case <-receivedDone:
	case <-time.After(5 * time.Second):
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Transfer complete: sent=%d received=%d status=%d", zipSize, received, resp.StatusCode))

	if received == zipSize {
		LogMessage("CRITICAL", TECHNIQUE_ID, "All archive bytes arrived at the exfil endpoint - channel unimpeded")
		return StageSuccess
	}
	if received == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, "No bytes arrived at listener despite completed POST - inconclusive")
		return StageError
	}
	LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Partial transfer (%d/%d bytes) - inconclusive", received, zipSize))
	return StageError
}

// generateSyntheticCSV writes ~targetSize bytes of clearly-synthetic customer
// PII rows. Every record is marked SYNTHETIC and uses reserved example domains.
func generateSyntheticCSV(path string, targetSize int, seedOffset int) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %v", path, err)
	}
	defer f.Close()

	rng := rand.New(rand.NewSource(int64(seedOffset)))
	n := 0
	header := "# SYNTHETIC DATA — F0RT1KA SB-PC-2026-001 LockBit simulation. NOT real customer data.\n" +
		"record_id,full_name,national_id,account_number,iban,email,phone,balance_dop,branch\n"
	if _, err := f.WriteString(header); err != nil {
		return 0, err
	}
	n += len(header)

	rowID := seedOffset
	for n < targetSize {
		rowID++
		row := fmt.Sprintf("%d,SYNTHETIC Person %08d,SYN-%08d,ACCT-SYN-%010d,DO22SYNT%016d,synthetic.user%08d@example.test,+1-809-555-%04d,%d.%02d,SYN-BRANCH-%03d\n",
			rowID, rowID, rng.Intn(99999999), rng.Int63n(9999999999), rng.Int63n(9999999999999999),
			rowID, rng.Intn(9999), rng.Int63n(9000000), rng.Intn(99), rng.Intn(20))
		if _, err := f.WriteString(row); err != nil {
			return n, err
		}
		n += len(row)
	}
	return n, nil
}
