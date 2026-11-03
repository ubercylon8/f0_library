// Stage 2 — T1036 Masquerading (legitimate DFIR tool guise) + T1219 Remote Access Software
// F0RT1KA Security Testing Framework
// The Gentlemen (GOLD SHERWOOD) — Objective 2: deploy remote-access C2 under a legitimate-tool guise
//
// The Gentlemen's signature tradecraft is turning legitimate software into
// attack infrastructure: it repurposes Velociraptor — a legitimate, signed
// DFIR tool — as its remote-access/C2 channel, and stages attacker tooling in
// trusted system directories (Sophos CTU: tools staged in C:\PerfLogs, "not
// commonly scrutinized by security controls"; Trend Micro: legitimate tools
// like PowerRun/Nmap/AnyDesk abused throughout; Huntress: binaries named
// after Windows services to disguise them).
//
// This stage emulates the Velociraptor-client deployment WITHOUT shipping any
// real Velociraptor code:
//
//   1. T1036 — stage a masqueraded "client" binary named Velociraptor.exe in
//      a PerfLogs-style staging directory. The decoy is a TEXT MARKER with an
//      .exe name — it is not a PE and can never execute (LockBit marker
//      pattern). The staging directory lives INSIDE ARTIFACT_DIR (sandbox
//      boundary per spec); the directory NAME preserves the actor's trusted-
//      path identifier.
//   2. T1036 — write Velociraptor's real deployment artifacts beside it:
//      client.config.yaml (frontend URL, client nonce, CA block) and the
//      client.writeback file. These exact filenames/fields are what Velociraptor
//      deployments leave on disk and what EDR file rules key on.
//   3. T1219 — beacon to the "frontend": an in-process loopback HTTP listener
//      on 127.0.0.1:8000 (Velociraptor's default frontend port; fallback 8800
//      if occupied). The beacon reproduces the client's request shape:
//      POST /control?v=1&client_id=C.<hex>&nonce=<hex> with a Velociraptor
//      User-Agent. ZERO egress beyond loopback.
//   4. Quarantine evidence: the decoy must still be present (os.Stat after
//      3s, Bug Prevention Rule 3). A successfully-written decoy that then
//      vanishes is positive removal evidence (AV sweep of a masqueraded
//      binary) -> 105.
//
// CLASSIFICATION (Rule 8): blocked/quarantined only on positive evidence —
// OS-emitted denial on a write that normally succeeds in this context, or the
// verified disappearance of a written file. Listener port exhaustion is a
// prerequisite condition (999), not a protection action.
//
// EXIT CODES: 0 = masqueraded deployment staged + beacon delivered without
// prevention, 105 = decoy removed after write, 126 = positive denial evidence,
// 999 = prerequisite/test error.

//go:build windows
// +build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	TEST_UUID      = "7cc45d21-9a6e-4128-9f75-06e5167a4b80"
	TECHNIQUE_ID   = "T1036"
	TECHNIQUE_NAME = "Masqueraded Remote-Access Deployment: Velociraptor as C2 (T1036/T1219, loopback)"
	STAGE_ID       = 2
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Staging layout — trusted-path identifier preserved, sandbox-contained:
//   <ARTIFACT_DIR>\PerfLogs\Velociraptor.exe      (text marker, NOT a PE)
//   <ARTIFACT_DIR>\PerfLogs\client.config.yaml    (real Velociraptor artifact name)
//   <ARTIFACT_DIR>\PerfLogs\client.writeback      (real Velociraptor artifact name)
const (
	stagingDirName = "PerfLogs"
	decoyName      = "Velociraptor.exe"
	configName     = "client.config.yaml"
	writebackName  = "client.writeback"
	beaconUA       = "Velociraptor 0.74.1 (windows amd64)"
	frontendPort   = 8000
	frontendPortAlt = 8800
)

var elevatedContext bool

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	elevatedContext = isAdmin() || isSystemContext()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Execution context: elevated=%v system=%v", elevatedContext, isSystemContext()))

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Masqueraded C2 deployment staged and beaconing without prevention\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Velociraptor-guise deployment staged; loopback frontend beacon delivered")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Masqueraded remote-access deployment unimpeded (loopback)")
	case StageQuarantined:
		fmt.Printf("[STAGE %s] Masqueraded decoy removed after write (quarantine evidence)\n", TECHNIQUE_ID)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Masqueraded Velociraptor.exe removed after successful write (os.Stat evidence)", StageQuarantined)
	case StageBlocked:
		fmt.Printf("[STAGE %s] Deployment prevented (positive denial evidence)\n", TECHNIQUE_ID)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Masqueraded deployment write denied with OS-emitted denial in elevated context", StageBlocked)
	default:
		fmt.Printf("[STAGE %s] Stage error - prerequisites not met or inconclusive\n", TECHNIQUE_ID)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Step 1: Stage the masqueraded client (T1036)
	// ------------------------------------------------------------------
	stagingDir := filepath.Join(ARTIFACT_DIR, stagingDirName)
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create staging dir %s: %v", stagingDir, err))
		return StageError
	}

	clientID := "C." + randomHex(16)
	nonce := randomHex(32)

	decoyPath := filepath.Join(stagingDir, decoyName)
	decoyContent := buildDecoyContent(clientID)
	if err := os.WriteFile(decoyPath, []byte(decoyContent), 0644); err != nil {
		if elevatedContext && isOSDenial(err) {
			LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("decoy write returned OS denial in elevated context (positive evidence): %v", err))
			return StageBlocked
		}
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("decoy write failed (not attributable to protection): %v", err))
		return StageError
	}
	LogFileDropped(decoyName, decoyPath, int64(len(decoyContent)), false)
	LogMessage("WARN", "T1036", fmt.Sprintf("T1036: masqueraded client staged as %s (legitimate DFIR-tool guise, PerfLogs-style staging)", decoyPath))

	// ------------------------------------------------------------------
	// Step 2: Velociraptor deployment artifacts (T1036 identifier fidelity)
	// ------------------------------------------------------------------
	configPath := filepath.Join(stagingDir, configName)
	configYAML := buildClientConfig(clientID, nonce)
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("client.config.yaml write failed (continuing): %v", err))
	} else {
		LogFileDropped(configName, configPath, int64(len(configYAML)), false)
		LogMessage("WARN", "T1036", "T1036: Velociraptor client.config.yaml written (frontend pinned to loopback)")
	}

	writebackPath := filepath.Join(stagingDir, writebackName)
	writebackJSON := buildWriteback(clientID)
	if err := os.WriteFile(writebackPath, []byte(writebackJSON), 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("client.writeback write failed (continuing): %v", err))
	} else {
		LogFileDropped(writebackName, writebackPath, int64(len(writebackJSON)), false)
	}

	// ------------------------------------------------------------------
	// Step 3: Quarantine check on the masqueraded decoy (Rule 3)
	// ------------------------------------------------------------------
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(decoyPath); os.IsNotExist(err) {
		LogMessage("CRITICAL", TECHNIQUE_ID, "decoy vanished after successful write - removal evidence in test-owned ARTIFACT_DIR")
		return StageQuarantined
	}
	LogMessage("INFO", TECHNIQUE_ID, "masqueraded decoy persists after 3s (no quarantine sweep)")

	// ------------------------------------------------------------------
	// Step 4: Loopback frontend + beacon (T1219)
	// ------------------------------------------------------------------
	fmt.Printf("[STAGE %s] Phase 2: Beaconing to Velociraptor frontend on loopback (T1219)\n", TECHNIQUE_ID)

	port := frontendPort
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("loopback listen on %d failed (%v) - falling back to %d", port, err, frontendPortAlt))
		port = frontendPortAlt
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("no loopback listener could be established: %v", err))
			return StageError
		}
	}

	beaconURL := fmt.Sprintf("http://127.0.0.1:%d/control?v=1&client_id=%s&nonce=%s", port, clientID, nonce)
	received := make(chan string, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- fmt.Sprintf("POST %s from UA=%q body=%dB", r.URL.RequestURI(), r.UserAgent(), len(body))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer func() {
		server.Close()
		listener.Close()
	}()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("loopback Velociraptor frontend listening on 127.0.0.1:%d (simulating actor C2)", port))

	delivered := 0
	envelope := buildEnvelopes(clientID, nonce)
	for i := 0; i < len(envelope); i++ {
		LogMessage("WARN", "T1219", fmt.Sprintf("T1219: Velociraptor client beacon %d/%d -> %s", i+1, len(envelope), beaconURL))
		req, _ := http.NewRequest("POST", beaconURL, bytes.NewReader([]byte(envelope[i])))
		req.Header.Set("User-Agent", beaconUA)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("beacon %d transport failed: %v", i+1, err))
			continue
		}
		resp.Body.Close()
		delivered++
		LogProcessExecution("velociraptor-client(beacon)", fmt.Sprintf("POST http://127.0.0.1:%d/control client_id=%s", port, clientID), 0, true, 0,
			fmt.Sprintf("HTTP %d from loopback frontend", resp.StatusCode))
		time.Sleep(500 * time.Millisecond)
	}

	// Drain the listener's captured requests into the log.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case seen := <-received:
			LogMessage("INFO", "T1219", fmt.Sprintf("frontend observed: %s", seen))
		case <-time.After(200 * time.Millisecond):
			// no more requests arriving
		}
	}

	if delivered == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, "no beacon reached the loopback frontend - transport failure")
		return StageError
	}
	LogMessage("CRITICAL", "T1219", fmt.Sprintf("%d/%d Velociraptor-shaped beacons delivered to loopback frontend - remote-access channel established (simulated)", delivered, len(envelope)))
	return StageSuccess
}

// buildDecoyContent produces the masqueraded "client binary": a plain text
// marker with a legitimate-tool name. It is NOT a PE and can never execute.
func buildDecoyContent(clientID string) string {
	var sb strings.Builder
	sb.WriteString("F0RT1KA SECURITY TEST - MASQUERADED DECOY (THE GENTLEMEN T1036/T1219)\n")
	sb.WriteString("======================================================================\n")
	sb.WriteString("This file is a TEXT MARKER named Velociraptor.exe. It is not a PE\n")
	sb.WriteString("image, contains no code, and cannot execute. It emulates The\n")
	sb.WriteString("Gentlemen's abuse of legitimate DFIR tooling (Velociraptor as C2)\n")
	sb.WriteString("for detection-evaluation purposes.\n")
	sb.WriteString(fmt.Sprintf("Client ID: %s\n", clientID))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Test UUID: %s\n", TEST_UUID))
	for sb.Len() < 2048 {
		sb.WriteString("#\n")
	}
	return sb.String()
}

// buildClientConfig reproduces the field surface of a real Velociraptor
// client.config.yaml with the frontend pinned to loopback.
func buildClientConfig(clientID, nonce string) string {
	return fmt.Sprintf(`Client:
  nonce: "%s"
  writeback: "%s"
  max_poll: 60
  puppetca: false
  server_urls:
    - http://127.0.0.1:%d/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    F0RT1KA-LOOPBACK-FRONTEND-SANDBOX-PLACEHOLDER
    -----END CERTIFICATE-----
  pinned_server_name: VelociraptorServer
`, nonce, writebackName, frontendPort)
}

// buildWriteback reproduces the shape of Velociraptor's client.writeback file.
func buildWriteback(clientID string) string {
	return fmt.Sprintf(`{
  "client_id": "%s",
  "last_server_pem": "F0RT1KA-LOOPBACK-FRONTEND-SANDBOX-PLACEHOLDER",
  "last_hunt_timestamp": 1748000000000,
  "last_event_table_version": 3,
  "last_server_version": "0.74.1"
}
`, clientID)
}

// buildEnvelopes returns the client->frontend message payloads (enrollment,
// poll, status) in Velociraptor's Message Packed envelope JSON shape.
func buildEnvelopes(clientID, nonce string) []string {
	return []string{
		fmt.Sprintf(`{"client_id":"%s","nonce":"%s","type":" Enrollment","args":{},"session_id":"F"}`, clientID, nonce),
		fmt.Sprintf(`{"client_id":"%s","nonce":"%s","type":"FOREMANCheck","args":{},"session_id":"F"}`, clientID, nonce),
		fmt.Sprintf(`{"client_id":"%s","nonce":"%s","type":"Stat","args":{},"session_id":"F"}`, clientID, nonce),
	}
}

// isOSDenial reports whether err carries an OS-emitted access-denial code.
// Only the numeric errno counts (ERROR_ACCESS_DENIED = 5): message text is
// localized and never trusted (stage_launch.go evidence philosophy).
func isOSDenial(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 5 // ERROR_ACCESS_DENIED
	}
	return false
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// Deterministic fallback (never expected on Windows).
		for i := range b {
			b[i] = byte(i * 7)
		}
	}
	return hex.EncodeToString(b)
}

// isSystemContext reports whether the process runs as SYSTEM (Rule 2).
func isSystemContext() bool {
	username := os.Getenv("USERNAME")
	return strings.HasSuffix(username, "$") || strings.EqualFold(username, "SYSTEM")
}
