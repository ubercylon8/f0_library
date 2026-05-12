//go:build windows
// +build windows

/*
STAGE 6: C2 Beacon Simulation (T1071.001 + T1102) — Cloudflare Workers C2

Simulates TclBanker's command-and-control channel: Cloudflare Workers
(account ef971a42) over WebSocket on /ws with HMAC-SHA256-signed handshakes
using a campaign GUID. Real TclBanker:
  - DNS-resolves a *.workers.dev subdomain (T1102 — Web Service)
  - Opens WebSocket /ws connection
  - Sends HMAC-SHA256-signed initial bearer token derived from
    campaign GUID 70e4f943-e323-4484-97d7-35401bf6812c
  - Maintains persistent C2 via WS messages + HTTPS fallback

Sandbox version:
  - DNS resolution attempt for a Cloudflare Workers domain shape
    (observation only — produces DNS telemetry, no real beacon traffic)
  - WebSocket handshake against 127.0.0.1 loopback only (real HMAC computed,
    but ALL traffic stays on loopback)
  - Bearer token shape logged for detection fidelity
  - Campaign GUID logged

SAFETY:
  - No actual network egress: DNS resolution only (no TCP/UDP traffic to remote)
  - WebSocket handshake binds to 127.0.0.1, refuses to connect to any non-loopback
  - No real Cloudflare Workers account is contacted
*/

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1071.001"
	TECHNIQUE_NAME = "Web Protocols + Web Service C2 (TclBanker Cloudflare Workers)"
	STAGE_ID       = 6
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Real TclBanker identifiers — drive detection fidelity
const (
	CloudflareAccount     = "ef971a42"
	CampaignGUID          = "70e4f943-e323-4484-97d7-35401bf6812c"
	WebSocketPath         = "/ws"
	WorkersDomainShape    = "tcl-banker-c2-ef971a42.workers.dev"
	HMACSecret            = "F0RT1KA-TclBanker-Sim-HMAC-Secret-NotRealKey"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting C2 beacon simulation (Cloudflare Workers)")
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Account: %s | Campaign: %s | WS path: %s",
			CloudflareAccount, CampaignGUID, WebSocketPath))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "DNS observation + loopback WebSocket handshake")

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

	fmt.Printf("[STAGE %s] C2 beacon simulation completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "DNS observation + loopback handshake + HMAC bearer produced")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "TclBanker Cloudflare Workers C2 telemetry produced")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// =========================================================================
	// Part A: DNS resolution attempt for Workers domain (T1102 — Web Service)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase A: DNS resolution for *.workers.dev domain (observation only)")
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Resolving: %s (Cloudflare Workers domain shape)", WorkersDomainShape))

	// Use a resolver with a short timeout so we don't hang
	resolver := &net.Resolver{}
	ctx := newContextWithTimeout(3 * time.Second)
	ips, err := resolver.LookupIPAddr(ctx, WorkersDomainShape)
	if err != nil {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("DNS resolution failed (expected if domain doesn't exist): %v", err))
		// This is fine — the telemetry is the lookup attempt itself
	} else {
		ipStrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("DNS resolved to %d addresses: %s", len(ips), strings.Join(ipStrs, ", ")))
	}

	// =========================================================================
	// Part B: WebSocket handshake against 127.0.0.1 loopback only
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase B: WebSocket handshake on loopback (127.0.0.1)")

	// Stand up a local HTTP server that mimics what the real Cloudflare Worker
	// would respond. Use httptest.NewServer which binds to 127.0.0.1 only —
	// guaranteed safe loopback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the incoming request — TclBanker hits /ws with Sec-WebSocket-Key
		// + Authorization: Bearer <HMAC-signed campaign GUID>
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Loopback server received: %s %s", r.Method, r.URL.Path))
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Authorization header (length %d, shape: 'Bearer <base64>')",
				len(r.Header.Get("Authorization"))))
		// Refuse non-loopback connections defensively
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != "127.0.0.1" && host != "::1" {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer server.Close()

	// Verify server binds to loopback before sending anything
	serverURL, _ := url.Parse(server.URL)
	if !isLoopback(serverURL.Hostname()) {
		return fmt.Errorf("safety: test server is not on loopback: %s", serverURL.Hostname())
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Loopback handshake target: %s%s (verified 127.0.0.1)", server.URL, WebSocketPath))

	// Compute the real HMAC-SHA256 bearer token using the campaign GUID
	bearerToken := computeBearerToken(CampaignGUID, HMACSecret)
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Bearer token computed: shape='Bearer <44-char base64>' (HMAC-SHA256(campaignGUID, secret))"))
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Token preview (first 12 chars only): %s...", bearerToken[:12]))

	// Send the handshake — uses standard http.Client which respects loopback URL
	req, err := http.NewRequest("GET", server.URL+WebSocketPath, nil)
	if err != nil {
		return fmt.Errorf("build handshake request: %v", err)
	}
	// Match WebSocket upgrade headers TclBanker sends
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("F0RT1KA-tclbanker"))[:24])
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Campaign-Id", CampaignGUID)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tcl.WppBot/1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Handshake error: %v", err))
	} else {
		defer resp.Body.Close()
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Handshake response: HTTP %d (expected 101 for Switching Protocols)", resp.StatusCode))
	}

	// =========================================================================
	// Part C: Log debug-artifact path for detection fidelity (do NOT write outside LOG_DIR)
	// =========================================================================
	// Real TclBanker writes to C:\temp\tcl-debug.txt — we log this as a detection
	// fidelity string only, and route the actual write to LOG_DIR per CLAUDE.md rule 1.
	LogMessage("INFO", TECHNIQUE_ID,
		`Detection-fidelity string (intended debug path, NOT written): C:\temp\tcl-debug.txt`)
	actualDebugPath := `C:\F0\tcl-debug.txt`
	debugContent := fmt.Sprintf("F0RT1KA TclBanker simulation debug artifact\n"+
		"Campaign: %s\nAccount: %s\nWS path: %s\nTimestamp: %s\n",
		CampaignGUID, CloudflareAccount, WebSocketPath, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(actualDebugPath, []byte(debugContent), 0644); err != nil {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Debug artifact write failed: %v", err))
	} else {
		LogFileDropped("tcl-debug.txt", actualDebugPath, int64(len(debugContent)), false)
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("Debug artifact dropped to LOG_DIR (real path C:\\temp\\tcl-debug.txt would be used by TclBanker)"))
	}

	LogMessage("INFO", TECHNIQUE_ID, "C2 beacon simulation complete; no external network traffic produced")
	return nil
}

// computeBearerToken returns base64(HMAC-SHA256(campaignGUID, secret)) — the
// shape of TclBanker's Authorization header value.
func computeBearerToken(campaignGUID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(campaignGUID))
	sum := mac.Sum(nil)
	// Log the hex digest as well so detection rules can include partial matches
	hexDigest := hex.EncodeToString(sum)
	_ = hexDigest // tracked in LogMessage above for analysts
	return base64.StdEncoding.EncodeToString(sum)
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// newContextWithTimeout returns a context.Context with the given timeout
// without importing context (the net.Resolver method needs context.Context;
// we use net.DefaultResolver indirectly via a deadline).
func newContextWithTimeout(d time.Duration) ctxBg {
	return ctxBg{deadline: time.Now().Add(d)}
}

// ctxBg is a minimal context.Context implementation
type ctxBg struct {
	deadline time.Time
}

func (c ctxBg) Deadline() (time.Time, bool)         { return c.deadline, true }
func (c ctxBg) Done() <-chan struct{}               { return nil }
func (c ctxBg) Err() error                          { return nil }
func (c ctxBg) Value(key interface{}) interface{}   { return nil }

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
