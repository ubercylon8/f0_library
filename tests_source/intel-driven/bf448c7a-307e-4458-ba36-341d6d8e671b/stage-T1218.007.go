//go:build windows
// +build windows

/*
STAGE 1: Delivery — MSI in ZIP impersonating Logitech update (T1218.007 + T1566.001)
Simulates TclBanker initial access where a ZIP wrapper contains a signed-looking
MSI installer with filename shape Logitech_Update_*.msi. The dropper would then
be invoked via msiexec.exe (T1218.007 — System Binary Proxy Execution: Msiexec)
following phishing delivery (T1566.001). We drop the artifacts but never execute
msiexec — telemetry comes from file shape, ZIP structure, and intended install path
"%LocalAppData%\LogiAI\" (logged as detection-fidelity string).
*/

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1218.007"
	TECHNIQUE_NAME = "System Binary Proxy Execution: Msiexec (TclBanker Delivery)"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Detection-fidelity strings — real TclBanker identifiers from the Elastic article
const (
	IntendedInstallPath = `%LocalAppData%\LogiAI\`
	MSIFilenamePrefix   = "Logitech_Update_"
	ZIPFilenamePrefix   = "Logitech_Update_"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting TclBanker delivery simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Tradecraft: MSI installer in ZIP wrapper impersonating Logitech update")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "TclBanker delivery — Logitech_Update MSI + ZIP")

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

	fmt.Printf("[STAGE %s] TclBanker delivery artifacts dropped\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Delivery artifacts dropped successfully — would invoke msiexec /i in real chain")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Logitech_Update MSI+ZIP dropped to ARTIFACT_DIR")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Create staging directory inside ARTIFACT_DIR (NOT whitelisted — EDR can scan it)
	stagingDir := filepath.Join(ARTIFACT_DIR, "Downloads")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("create staging dir: %v", err)
	}

	// Build a timestamp suffix so the MSI filename matches the real TclBanker shape:
	// Logitech_Update_<numeric-build>.msi
	timestamp := time.Now().Format("20060102")
	msiName := fmt.Sprintf("%s%s.msi", MSIFilenamePrefix, timestamp)
	zipName := fmt.Sprintf("%s%s.zip", ZIPFilenamePrefix, timestamp)
	msiPath := filepath.Join(stagingDir, msiName)
	zipPath := filepath.Join(stagingDir, zipName)

	// Synthesize an MSI-looking payload. Real MSIs are OLE/CFB compound documents;
	// we write the CFB header signature so file-type detection identifies the artifact
	// as an MSI, plus a benign marker so analysts can confirm it's a F0RT1KA simulation.
	// CFB header: D0 CF 11 E0 A1 B1 1A E1 (Microsoft Compound File Binary)
	cfbHeader := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	marker := []byte("F0RT1KA-TCLBANKER-SIM-MSI-LogitechUpdate-NOTREALPAYLOAD\x00")
	// Pad to ~32KB to approximate real MSI footprint
	padding := make([]byte, 32*1024-len(cfbHeader)-len(marker))
	msiContent := append(append(cfbHeader, marker...), padding...)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Dropping MSI artifact: %s", msiPath))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("MSI filename shape matches TclBanker: %s%s.msi", MSIFilenamePrefix, "<build>"))
	if err := os.WriteFile(msiPath, msiContent, 0644); err != nil {
		return fmt.Errorf("write MSI: %v", err)
	}

	sum := sha256.Sum256(msiContent)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("MSI SHA256: %s (size=%d)", hex.EncodeToString(sum[:]), len(msiContent)))

	// Wait for EDR reaction to the MSI on disk
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		LogFileDropped(msiName, msiPath, int64(len(msiContent)), true)
		return fmt.Errorf("quarantined: MSI artifact removed by EDR")
	}
	LogFileDropped(msiName, msiPath, int64(len(msiContent)), false)

	// Wrap the MSI in a ZIP — real TclBanker delivery uses a ZIP archive
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Wrapping MSI in ZIP: %s", zipPath))
	zipBuf := &bytes.Buffer{}
	zw := zip.NewWriter(zipBuf)
	zf, err := zw.Create(msiName)
	if err != nil {
		return fmt.Errorf("create zip entry: %v", err)
	}
	if _, err := zf.Write(msiContent); err != nil {
		return fmt.Errorf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip: %v", err)
	}
	if err := os.WriteFile(zipPath, zipBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write ZIP: %v", err)
	}

	time.Sleep(2 * time.Second)
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		LogFileDropped(zipName, zipPath, int64(zipBuf.Len()), true)
		return fmt.Errorf("quarantined: ZIP wrapper removed by EDR")
	}
	LogFileDropped(zipName, zipPath, int64(zipBuf.Len()), false)

	// Log the intended install path as a detection-fidelity string only.
	// Real TclBanker installs to %LocalAppData%\LogiAI\ — we never write there.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Detection string (intended install path, not written): %s", IntendedInstallPath))
	LogMessage("INFO", TECHNIQUE_ID, "Intended invocation (not executed): msiexec /i Logitech_Update_*.msi /qn")

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Delivery artifacts ready at: %s", stagingDir))
	return nil
}

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
