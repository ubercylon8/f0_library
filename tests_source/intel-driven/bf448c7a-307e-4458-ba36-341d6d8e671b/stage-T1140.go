//go:build windows
// +build windows

/*
STAGE 3: Deobfuscate + Environment Gate (T1140 + T1027 + T1497.001/.003)

Simulates TclBanker's .NET Reactor-protected payload decryption and the
Brazilian-locale victim gating it performs before activating. Real TclBanker:
  - Ships AES-encrypted .NET assemblies (Tcl.Agent, Tcl.WppBot)
  - Decrypts at runtime using a hardcoded key derived from .NET Reactor metadata
  - Checks GetUserDefaultUILanguage / time zone against Brazil before activating
  - Uses RDTSC / QueryPerformanceCounter for VM-detection timing checks

This stage performs:
  - AES-256-CBC decryption of a real ciphertext blob (deobfuscation)
  - Read of GetUserDefaultUILanguage and time zone (passive observation only)
  - RDTSC and QueryPerformanceCounter readings (timing-based VM detection)
  - Logs the gating decision but NEVER aborts — we always proceed to the next
    stage so the test runs end-to-end on any locale.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	TEST_UUID      = "bf448c7a-307e-4458-ba36-341d6d8e671b"
	TECHNIQUE_ID   = "T1140"
	TECHNIQUE_NAME = "Deobfuscate/Decode + Environment Gate (TclBanker)"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Brazilian locale identifiers TclBanker checks
const (
	pt_BR_LCID     = 0x0416 // Portuguese (Brazil)
	BrazilTZName   = "E. South America Standard Time"
	IntendedTarget = "Brazilian banking customers"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, "Starting deobfuscation + environment-gate simulation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "AES decryption of Tcl.Agent payload + locale gate")

	// Idempotent cleanup of this stage's artifacts in ARTIFACT_DIR\LogiAI.
	// os.Exit bypasses defer, so cleanup() is called explicitly on every
	// exit path below. os.Remove on a missing file is a no-op, so this is
	// safe even when performTechnique fails before writing anything.
	cleanup := func() {
		blobDir := filepath.Join(ARTIFACT_DIR, "LogiAI")
		_ = os.Remove(filepath.Join(blobDir, "Tcl.Agent.enc"))
		_ = os.Remove(filepath.Join(blobDir, "Tcl.Agent.dec.bin"))
		// Best-effort dir removal — succeeds only if empty (other stages may
		// own the directory). Failure is fine.
		_ = os.Remove(blobDir)
		LogMessage("INFO", TECHNIQUE_ID, "Cleanup: Tcl.Agent.* artifacts removed from ARTIFACT_DIR/LogiAI")
	}

	if err := performTechnique(); err != nil {
		fmt.Printf("[STAGE %s] Technique failed: %v\n", TECHNIQUE_ID, err)
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Technique failed: %v", err))
		exitCode := determineExitCode(err)
		if exitCode == StageBlocked || exitCode == StageQuarantined {
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
		} else {
			LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		}
		cleanup()
		os.Exit(exitCode)
	}

	fmt.Printf("[STAGE %s] Deobfuscation + environment-gate complete\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "AES decrypt + locale + timing gate executed (passive)")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Tcl.Agent decryption + Brazilian locale gate observed")
	cleanup()
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// =========================================================================
	// Part A: AES-256-CBC decryption of a "Tcl.Agent" payload blob
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase A: AES-256-CBC decryption of simulated Tcl.Agent payload")

	// Use a hardcoded key — this mirrors how .NET Reactor-protected assemblies
	// have their AES key embedded as constants in the deobfuscation stub.
	keyHex := "54636c2e4167656e742d54636c42616e6b65722d4632325230" // "Tcl.Agent-TclBanker-F22R0" + pad
	// Truncate/pad to 32 bytes for AES-256
	keyBytes, _ := hex.DecodeString(keyHex)
	for len(keyBytes) < 32 {
		keyBytes = append(keyBytes, 0x00)
	}
	keyBytes = keyBytes[:32]

	// Simulated plaintext that would be the decrypted .NET assembly header
	plaintext := []byte("MZ\x90\x00\x03\x00\x00\x00F0RT1KA-TclAgent-SIMULATED-NETPAYLOAD-NotRealAssembly\x00")
	// Pad to AES block size
	for len(plaintext)%aes.BlockSize != 0 {
		plaintext = append(plaintext, 0x00)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("AES cipher init: %v", err)
	}

	// Random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("IV gen: %v", err)
	}

	ciphertext := make([]byte, len(plaintext))
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext, plaintext)

	// Drop the ciphertext blob to ARTIFACT_DIR as a detection artifact
	blobDir := filepath.Join(ARTIFACT_DIR, "LogiAI")
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return fmt.Errorf("create blob dir: %v", err)
	}
	blobPath := filepath.Join(blobDir, "Tcl.Agent.enc")
	if err := os.WriteFile(blobPath, append(iv, ciphertext...), 0644); err != nil {
		return fmt.Errorf("write encrypted blob: %v", err)
	}
	LogFileDropped("Tcl.Agent.enc", blobPath, int64(len(iv)+len(ciphertext)), false)

	// Now decrypt to demonstrate runtime deobfuscation
	decryptedPath := filepath.Join(blobDir, "Tcl.Agent.dec.bin")
	decrypted := make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decrypted, ciphertext)

	if err := os.WriteFile(decryptedPath, decrypted, 0644); err != nil {
		return fmt.Errorf("write decrypted blob: %v", err)
	}
	LogFileDropped("Tcl.Agent.dec.bin", decryptedPath, int64(len(decrypted)), false)

	sum := sha256.Sum256(decrypted)
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("AES-256-CBC decrypted Tcl.Agent: %d bytes, SHA256=%s",
			len(decrypted), hex.EncodeToString(sum[:])))
	LogMessage("INFO", TECHNIQUE_ID, "Plaintext header confirms simulated .NET PE (MZ\\x90 prefix)")

	// =========================================================================
	// Part B: Brazilian locale and time-zone environment check (T1497.001)
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase B: locale + time-zone gate (passive — never aborts)")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getUserUILang := kernel32.NewProc("GetUserDefaultUILanguage")
	getSystemUILang := kernel32.NewProc("GetSystemDefaultUILanguage")

	userLCID, _, _ := getUserUILang.Call()
	systemLCID, _, _ := getSystemUILang.Call()

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("GetUserDefaultUILanguage=0x%04x (decimal %d)", userLCID, userLCID))
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("GetSystemDefaultUILanguage=0x%04x (decimal %d)", systemLCID, systemLCID))
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Target gate (TclBanker): pt-BR (0x%04x)", pt_BR_LCID))

	matchesBR := userLCID == pt_BR_LCID || systemLCID == pt_BR_LCID
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Brazilian locale match: %v", matchesBR))

	// Time zone check
	tzName, tzOffset := time.Now().Zone()
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("Local time zone: %s offset=%d (Brazil expected: %s, offset=-10800)",
			tzName, tzOffset, BrazilTZName))

	// Decision: real TclBanker would abort here if not Brazil — we ALWAYS proceed
	// so the test completes end-to-end on any victim system.
	if !matchesBR {
		LogMessage("INFO", TECHNIQUE_ID,
			"Locale gate would have aborted activation in real TclBanker; F0RT1KA simulation proceeds intentionally")
	} else {
		LogMessage("INFO", TECHNIQUE_ID,
			"Locale matches TclBanker target — would activate banking-fraud module in real chain")
	}

	// =========================================================================
	// Part C: Timing-based VM detection (T1497.003) — RDTSC + QPC
	// =========================================================================
	LogMessage("INFO", TECHNIQUE_ID, "Phase C: timing-based VM/sandbox detection observation")

	// QueryPerformanceCounter via syscall
	qpc := kernel32.NewProc("QueryPerformanceCounter")
	qpf := kernel32.NewProc("QueryPerformanceFrequency")

	var freq, t0, t1 int64
	qpf.Call(uintptr(unsafe.Pointer(&freq)))
	qpc.Call(uintptr(unsafe.Pointer(&t0)))
	// Perform a small amount of work
	x := 1
	for i := 0; i < 100000; i++ {
		x = (x * 31) ^ i
	}
	_ = x
	qpc.Call(uintptr(unsafe.Pointer(&t1)))
	deltaQPC := t1 - t0
	deltaUs := (deltaQPC * 1_000_000) / freq

	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("QPC delta over 100k ops: %d ticks (~%d us, freq=%d)", deltaQPC, deltaUs, freq))
	LogMessage("INFO", TECHNIQUE_ID,
		"TclBanker uses this delta + RDTSC to fingerprint sandboxes (passive observation only)")

	// Note: pure-Go can't emit RDTSC inline without CGO. The QPC reading above
	// is the equivalent high-resolution counter and gives equivalent telemetry
	// to what TclBanker's anti-VM stub produces.

	LogMessage("INFO", TECHNIQUE_ID, "Environment gate observations recorded; advancing to persistence")
	return nil
}

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
