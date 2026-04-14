//go:build windows
// +build windows

/*
STAGE 1: LLM API Fetch (T1071.001 - Application Layer Protocol: Web Protocols)

Simulates HONESTCUE's use of a cloud LLM API (Gemini) to fetch stage-2 C#
source code at runtime. Spins up a loopback HTTPS server with a self-signed
certificate pinned in the client's TLSClientConfig, issues a POST that mimics
HONESTCUE's prompt pattern, and writes the returned C# source to disk for
stage-2 handoff.

Detection opportunities:
  - Outbound HTTPS to cloud LLM APIs from non-browser processes
  - Process command line / parent-child tree showing odd client signing the
    HTTPS POST (direct-from-PE rather than curl/browser)
  - Client process running a TLS handshake against a self-signed cert
*/

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "LLM API Fetch (Mock Gemini)"
	STAGE_ID       = 1

	// Output file where stage 2 will read the LLM-sourced C# source
	CSHARP_HANDOFF = `c:\F0\honestcue_stage2_source.cs`

	MOCK_LLM_HOST = "127.0.0.1"
	MOCK_LLM_PORT = "48443" // loopback-only; not a real Gemini port
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// The "LLM response" C# source for stage 2.
// This is a minimal benign payload that:
//   - reads HKLM\SOFTWARE\Microsoft\Windows Defender\Features (arbitrary read)
//   - writes a marker file to ARTIFACT_DIR (c:\Users\fortika-test\honestcue_marker.txt)
// Stage 2 compiles & reflectively loads this source in-memory.
const syntheticLLMResponse = `using System;
using System.IO;
using Microsoft.Win32;

public class HonestcueStage2
{
    public static string Run()
    {
        string defenderSub = "unavailable";
        try
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Features"))
            {
                if (k != null)
                {
                    string[] names = k.GetValueNames();
                    defenderSub = "read_ok:" + names.Length + "_values";
                }
            }
        }
        catch (Exception ex) { defenderSub = "read_err:" + ex.Message; }

        string artifactDir = @"c:\Users\fortika-test";
        try { Directory.CreateDirectory(artifactDir); } catch { }
        string marker = Path.Combine(artifactDir, "honestcue_marker.txt");
        File.WriteAllText(marker, "honestcue-stage2-reflective-load " +
            DateTime.UtcNow.ToString("o") + " defender=" + defenderSub);
        return "marker:" + marker;
    }
}
`

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting LLM API fetch simulation (mock Gemini)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "HTTPS POST to loopback mock LLM server to fetch stage-2 C# source")

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

	fmt.Printf("[STAGE %s] LLM API fetch complete; stage-2 source handed off at %s\n", TECHNIQUE_ID, CSHARP_HANDOFF)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Mock Gemini fetch succeeded; stage-2 source written")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "HTTPS POST to loopback mock LLM returned C# source; written to handoff file")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: generate a self-signed certificate at runtime
	cert, certPEM, err := generateSelfSignedCert("mock-gemini.loopback")
	if err != nil {
		return fmt.Errorf("cert generation failed: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Self-signed cert generated (%d PEM bytes)", len(certPEM)))

	// Step 2: start loopback TLS server
	listener, err := tls.Listen("tcp", net.JoinHostPort(MOCK_LLM_HOST, MOCK_LLM_PORT), &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		// Port bind failure is environmental; map to StageError (999), never StageBlocked
		return fmt.Errorf("listener bind on %s:%s unavailable: %v", MOCK_LLM_HOST, MOCK_LLM_PORT, err)
	}
	defer listener.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Mock LLM server listening on https://%s:%s", MOCK_LLM_HOST, MOCK_LLM_PORT))

	mux := http.NewServeMux()
	// Endpoint path mirrors Gemini API shape: /v1beta/models/gemini-pro:generateContent
	mux.HandleFunc("/v1beta/models/gemini-pro:generateContent", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Mock Gemini received prompt (%d bytes)", len(body)))

		// Shape response to look like Gemini's generateContent JSON schema
		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]string{
							{"text": syntheticLLMResponse},
						},
					},
					"finishReason": "STOP",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{Handler: mux}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()

	// Give the server a moment to settle
	time.Sleep(300 * time.Millisecond)

	// Step 3: build HTTPS client with pinned self-signed cert
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("cert pool append: PEM rejected")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				ServerName: "mock-gemini.loopback",
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// Step 4: POST a HONESTCUE-style prompt
	prompt := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": "Produce a C# class named HonestcueStage2 with a public static string Run() " +
						"method that enumerates HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features " +
						"and writes a marker file. Return only source code."},
				},
			},
		},
	}
	promptBody, _ := json.Marshal(prompt)

	// Note the ServerName - we're using the pinned CN; Host header is informational.
	// This mirrors the HONESTCUE network-layer behavior of a direct HTTPS POST from
	// a non-browser process to an LLM API endpoint.
	req, err := http.NewRequest("POST",
		fmt.Sprintf("https://%s:%s/v1beta/models/gemini-pro:generateContent", MOCK_LLM_HOST, MOCK_LLM_PORT),
		bytes.NewReader(promptBody))
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HonestcueClient/1.0 (simulated)")
	req.Header.Set("x-goog-api-key", "SIMULATED-API-KEY-0000")

	LogMessage("INFO", TECHNIQUE_ID, "Issuing HONESTCUE-style HTTPS POST to mock Gemini endpoint")
	resp, err := client.Do(req)
	if err != nil {
		// TLS/handshake failure here could indicate EDR TLS interception — map
		// to StageBlocked only if error strings explicitly indicate a block.
		return fmt.Errorf("https post to mock llm failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mock llm returned non-200 status: %d", resp.StatusCode)
	}

	// Step 5: parse Gemini-shaped response and extract the C# source
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("json decode of llm response: %v", err)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return fmt.Errorf("llm response missing candidates[0].content.parts[0]")
	}
	csharpSource := parsed.Candidates[0].Content.Parts[0].Text

	// Step 6: write to disk handoff file for stage 2
	if err := os.MkdirAll(filepath.Dir(CSHARP_HANDOFF), 0755); err != nil {
		return fmt.Errorf("handoff dir creation: %v", err)
	}
	if err := os.WriteFile(CSHARP_HANDOFF, []byte(csharpSource), 0644); err != nil {
		return fmt.Errorf("handoff write: %v", err)
	}
	LogFileDropped("honestcue_stage2_source.cs", CSHARP_HANDOFF, int64(len(csharpSource)), false)

	// Step 7: confirm handoff file survived EDR quarantine (Rule 3)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(CSHARP_HANDOFF); os.IsNotExist(err) {
		return fmt.Errorf("handoff file quarantined after write")
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage-2 C# source handed off (%d bytes)", len(csharpSource)))
	LogMessage("INFO", TECHNIQUE_ID,
		"Detection points: loopback HTTPS POST with Gemini-shaped JSON, non-browser client UA, x-goog-api-key header")

	// Give server goroutine a chance to log, then clean up
	shutdownCtx := make(chan struct{})
	go func() {
		_ = server.Close()
		close(shutdownCtx)
	}()
	select {
	case <-shutdownCtx:
	case <-time.After(2 * time.Second):
	}

	return nil
}

// generateSelfSignedCert produces an ephemeral ECDSA self-signed certificate
// valid for the given CN on 127.0.0.1. Returned PEM is the CA pin used by the
// client TLSClientConfig.
func generateSelfSignedCert(commonName string) (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{commonName, "localhost"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, certPEM, nil
}

// ==============================================================================
// EXIT CODE DETERMINATION
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	// Only blame-free keyword checks — per Bug Prevention Rule 1
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable"}) {
		return StageError
	}
	// Default to error (999), NOT blocked (126)
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
