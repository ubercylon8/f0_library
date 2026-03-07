//go:build windows

/*
STAGE 4: Credentials from Password Stores - Credentials from Web Browsers (T1555.003)
Simulates APT42 browser credential theft:
  (a) Edge remote debugging port activation
  (b) Chrome Login Data SQLite database access attempt
  (c) Runs.dll data chunking behavior simulation
Tests EDR detection of browser credential access patterns.
*/

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "92b0b4f6-a09b-4c7b-b593-31ce461f804c"
	TECHNIQUE_ID   = "T1555.003"
	TECHNIQUE_NAME = "Browser Credential Theft Simulation"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting browser credential theft simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Edge remote debugging + Chrome credential access + Runs.dll chunking")

	if err := performTechnique(); err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "access denied") ||
			strings.Contains(errStr, "access is denied") ||
			strings.Contains(errStr, "blocked") ||
			strings.Contains(errStr, "prevented") ||
			strings.Contains(errStr, "protected") ||
			strings.Contains(errStr, "permission denied") {
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

	LogMessage("SUCCESS", TECHNIQUE_ID, "Browser credential theft simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Browser credential access techniques executed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "c:\\F0"
	results := make(map[string]string)

	// =========================================================================
	// Part A: Edge Remote Debugging Port Activation
	// =========================================================================
	fmt.Printf("[STAGE %s] Part A: Attempting Edge remote debugging port activation...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting Edge remote debugging port activation on port 9222")

	edgeResult := attemptEdgeRemoteDebugging()
	results["edge_remote_debug"] = edgeResult
	fmt.Printf("[STAGE %s] Edge remote debugging result: %s\n", TECHNIQUE_ID, edgeResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Edge remote debugging: %s", edgeResult))

	// =========================================================================
	// Part B: Chrome Login Data SQLite Access
	// =========================================================================
	fmt.Printf("[STAGE %s] Part B: Attempting Chrome Login Data access...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting to read Chrome Login Data SQLite database")

	chromeResult := attemptChromeCredentialAccess()
	results["chrome_login_data"] = chromeResult
	fmt.Printf("[STAGE %s] Chrome credential access result: %s\n", TECHNIQUE_ID, chromeResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Chrome credential access: %s", chromeResult))

	// =========================================================================
	// Part C: Runs.dll Data Chunking Simulation
	// =========================================================================
	fmt.Printf("[STAGE %s] Part C: Simulating Runs.dll data chunking behavior...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Simulating Runs.dll credential data chunking for exfiltration")

	chunkResult := simulateRunsDllChunking(targetDir)
	results["runs_dll_chunking"] = chunkResult
	fmt.Printf("[STAGE %s] Runs.dll chunking result: %s\n", TECHNIQUE_ID, chunkResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Runs.dll chunking: %s", chunkResult))

	// =========================================================================
	// Part D: Edge User Data Access
	// =========================================================================
	fmt.Printf("[STAGE %s] Part D: Attempting Edge user data access...\n", TECHNIQUE_ID)
	LogMessage("INFO", TECHNIQUE_ID, "Attempting to read Edge Login Data")

	edgeDataResult := attemptEdgeCredentialAccess()
	results["edge_login_data"] = edgeDataResult
	fmt.Printf("[STAGE %s] Edge credential access result: %s\n", TECHNIQUE_ID, edgeDataResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Edge credential access: %s", edgeDataResult))

	// =========================================================================
	// Evaluate Results
	// =========================================================================
	blockedCount := 0
	totalCount := 0
	for technique, result := range results {
		totalCount++
		if strings.Contains(result, "blocked") || strings.Contains(result, "denied") || strings.Contains(result, "protected") {
			blockedCount++
			fmt.Printf("[STAGE %s]   %s: BLOCKED\n", TECHNIQUE_ID, technique)
		} else {
			fmt.Printf("[STAGE %s]   %s: %s\n", TECHNIQUE_ID, technique, result)
		}
	}

	// Save results
	var sb strings.Builder
	sb.WriteString("APT42 Browser Credential Theft Simulation Results\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Blocked: %d/%d techniques\n\n", blockedCount, totalCount))
	for k, v := range results {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	os.WriteFile(filepath.Join(targetDir, "browser_cred_results.txt"), []byte(sb.String()), 0644)

	// If all sub-techniques were blocked, report as blocked
	if blockedCount == totalCount {
		return fmt.Errorf("all browser credential access attempts were blocked by security controls")
	}

	return nil
}

// attemptEdgeRemoteDebugging tries to activate Edge's remote debugging port
func attemptEdgeRemoteDebugging() string {
	// Check if Edge is running
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq msedge.exe", "/NH")
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "msedge.exe") {
		// Edge not running - try to launch with remote debugging
		edgePath := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
		if _, err := os.Stat(edgePath); os.IsNotExist(err) {
			edgePath = `C:\Program Files\Microsoft\Edge\Application\msedge.exe`
		}

		if _, err := os.Stat(edgePath); os.IsNotExist(err) {
			return "edge_not_installed"
		}

		// Attempt to launch Edge with remote debugging port
		// This is a key detection opportunity - EDR should flag this
		cmd := exec.Command(edgePath,
			"--remote-debugging-port=9222",
			"--headless",
			"--disable-gpu",
			"about:blank",
		)
		err := cmd.Start()
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "access") ||
				strings.Contains(strings.ToLower(err.Error()), "blocked") {
				return "blocked - edge remote debugging prevented"
			}
			return fmt.Sprintf("error: %v", err)
		}

		// Give Edge a moment to start
		time.Sleep(3 * time.Second)

		// Check if debugging port is open
		conn, err := net.DialTimeout("tcp", "127.0.0.1:9222", 3*time.Second)
		if err != nil {
			// Kill the Edge process we started
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			return "port_not_listening - may be blocked"
		}
		conn.Close()

		// Kill the Edge process
		if cmd.Process != nil {
			cmd.Process.Kill()
		}

		return "success - remote debugging port 9222 activated"
	}

	// Edge is already running - try to check if debugging port is open
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9222", 2*time.Second)
	if err != nil {
		return "edge_running_but_debug_port_closed"
	}
	conn.Close()
	return "success - existing debug port detected"
}

// attemptChromeCredentialAccess tries to read Chrome's Login Data SQLite database
func attemptChromeCredentialAccess() string {
	// Locate Chrome's Login Data file
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return "error: LOCALAPPDATA not set"
	}

	chromeLoginData := filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data")

	// Check if Chrome profile exists
	if _, err := os.Stat(chromeLoginData); os.IsNotExist(err) {
		return "chrome_not_installed_or_no_profile"
	}

	// Attempt to read Chrome Login Data (key detection point)
	// Chrome normally locks this file; EDR should detect access attempts
	fmt.Printf("[STAGE %s]   Attempting to copy Chrome Login Data...\n", TECHNIQUE_ID)

	// Try to copy the file (common credential theft technique)
	destPath := filepath.Join("c:\\F0", "chrome_login_data_copy.db")
	src, err := os.Open(chromeLoginData)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "access") ||
			strings.Contains(strings.ToLower(err.Error()), "denied") ||
			strings.Contains(strings.ToLower(err.Error()), "sharing") ||
			strings.Contains(strings.ToLower(err.Error()), "locked") {
			return "blocked - credential database access denied"
		}
		return fmt.Sprintf("error: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Sprintf("error creating copy: %v", err)
	}
	defer dst.Close()

	written, err := io.Copy(dst, src)
	if err != nil {
		return fmt.Sprintf("partial_copy: %v", err)
	}
	dst.Close()

	// Attempt CryptUnprotectData DPAPI call on the copied database
	// Real credential stealers call DPAPI to decrypt Chrome's encrypted_value column
	// This call will fail (wrong key context) but triggers EDR behavioral detection
	dpapiResult := attemptDPAPIDecrypt(destPath)
	fmt.Printf("[STAGE %s]   DPAPI decrypt attempt: %s\n", TECHNIQUE_ID, dpapiResult)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("DPAPI decrypt attempt: %s", dpapiResult))

	// Clean up the copy immediately
	os.Remove(destPath)

	return fmt.Sprintf("success - copied %d bytes, dpapi=%s (copy deleted)", written, dpapiResult)
}

// attemptEdgeCredentialAccess tries to read Edge's Login Data
func attemptEdgeCredentialAccess() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return "error: LOCALAPPDATA not set"
	}

	edgeLoginData := filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data")

	if _, err := os.Stat(edgeLoginData); os.IsNotExist(err) {
		return "edge_no_profile_data"
	}

	// Attempt to read Edge Login Data
	fmt.Printf("[STAGE %s]   Attempting to copy Edge Login Data...\n", TECHNIQUE_ID)

	destPath := filepath.Join("c:\\F0", "edge_login_data_copy.db")
	src, err := os.Open(edgeLoginData)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "access") ||
			strings.Contains(strings.ToLower(err.Error()), "denied") ||
			strings.Contains(strings.ToLower(err.Error()), "sharing") ||
			strings.Contains(strings.ToLower(err.Error()), "locked") {
			return "blocked - Edge credential database access denied"
		}
		return fmt.Sprintf("error: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Sprintf("error creating copy: %v", err)
	}
	defer dst.Close()

	written, err := io.Copy(dst, src)
	if err != nil {
		return fmt.Sprintf("partial_copy: %v", err)
	}

	dst.Close()
	os.Remove(destPath)

	return fmt.Sprintf("success - copied %d bytes (immediately deleted)", written)
}

// simulateRunsDllChunking simulates the APT42 Runs.dll data chunking behavior
// where stolen credentials are split into 4KB chunks for staged exfiltration
func simulateRunsDllChunking(targetDir string) string {
	// Create simulated credential data (benign)
	simulatedData := generateSimulatedCredentialData()

	// Chunk the data into 4KB pieces (Runs.dll behavior)
	chunkSize := 4096
	chunks := make([][]byte, 0)
	for i := 0; i < len(simulatedData); i += chunkSize {
		end := i + chunkSize
		if end > len(simulatedData) {
			end = len(simulatedData)
		}
		chunks = append(chunks, simulatedData[i:end])
	}

	fmt.Printf("[STAGE %s]   Data size: %d bytes, chunks: %d (4KB each)\n", TECHNIQUE_ID, len(simulatedData), len(chunks))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Runs.dll chunking: %d bytes -> %d chunks", len(simulatedData), len(chunks)))

	// Write chunks to staging directory (simulates Runs.dll behavior)
	stagingDir := filepath.Join(targetDir, "runs_staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Sprintf("error: staging dir creation failed: %v", err)
	}

	for i, chunk := range chunks {
		chunkFile := filepath.Join(stagingDir, fmt.Sprintf("chunk_%03d.dat", i))
		if err := os.WriteFile(chunkFile, chunk, 0644); err != nil {
			return fmt.Sprintf("error: chunk write failed: %v", err)
		}
	}

	// Clean up staging data
	os.RemoveAll(stagingDir)

	return fmt.Sprintf("success - %d chunks created and cleaned up", len(chunks))
}

// DATA_BLOB is the Windows DPAPI data structure for CryptUnprotectData
type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// attemptDPAPIDecrypt calls CryptUnprotectData on simulated encrypted data.
// Chrome stores credential encryption keys protected by DPAPI. Real stealers
// read the encrypted_value from Login Data SQLite, then call CryptUnprotectData.
// This call triggers EDR DPAPI monitoring without decrypting anything real.
func attemptDPAPIDecrypt(dbPath string) string {
	crypt32 := syscall.NewLazyDLL("crypt32.dll")
	procDecrypt := crypt32.NewProc("CryptUnprotectData")

	// Use a fake 48-byte "encrypted" blob (Chrome encrypted_value prefix v10/v20)
	// This is NOT real encrypted data — just triggers the DPAPI API call
	fakeEncrypted := []byte{
		0x76, 0x31, 0x30, // "v10" Chrome encryption version prefix
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	}

	inBlob := DATA_BLOB{
		cbData: uint32(len(fakeEncrypted)),
		pbData: &fakeEncrypted[0],
	}
	var outBlob DATA_BLOB

	// Call CryptUnprotectData — expected to fail (fake data, wrong DPAPI context)
	// The API call itself is what triggers EDR detection
	ret, _, err := procDecrypt.Call(
		uintptr(unsafe.Pointer(&inBlob)),  // pDataIn
		0,                                  // ppszDataDescr
		0,                                  // pOptionalEntropy
		0,                                  // pvReserved
		0,                                  // pPromptStruct
		0,                                  // dwFlags
		uintptr(unsafe.Pointer(&outBlob)), // pDataOut
	)

	if ret == 0 {
		return fmt.Sprintf("expected_failure (err: %v)", err)
	}

	// If it somehow succeeded, free the output buffer
	if outBlob.pbData != nil {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		localFree := kernel32.NewProc("LocalFree")
		localFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	}
	return "unexpected_success"
}

// generateSimulatedCredentialData creates benign simulated credential data
func generateSimulatedCredentialData() []byte {
	var sb strings.Builder
	// Create ~16KB of simulated data (4 chunks of Runs.dll)
	for i := 0; i < 50; i++ {
		sb.WriteString(fmt.Sprintf("SIMULATED_ENTRY_%03d|url=https://example.com/portal_%d|", i, i))
		sb.WriteString(fmt.Sprintf("username=test_user_%d@example.com|", i))
		sb.WriteString("password=<SIMULATED_NO_REAL_CREDS>|")
		sb.WriteString(fmt.Sprintf("created=%s|", time.Now().Format(time.RFC3339)))
		sb.WriteString("source=F0RT1KA_SIMULATION\n")
	}
	return []byte(sb.String())
}
