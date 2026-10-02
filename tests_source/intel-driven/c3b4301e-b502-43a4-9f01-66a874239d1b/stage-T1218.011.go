//go:build windows
// +build windows

/*
STAGE 6: Control_RunDLL CPL Execution + Registry Key Staging (T1218.011)
Simulates the CosmicPulse installation primitives from the disclosure:

  1. The "System Health Monitor" task runs control.exe against a CPL
     (Control Panel applet); Task 1 executes attacker DLLs remotely through
     Shell32.dll's Control_RunDLL entry point over a WebDAV UNC path.

  2. The CosmicPulse downloader writes an AES key encrypted payload to the
     registry key HKCU\Software\Classes\.mollis — the bootstrapper later
     recovers the key (AES-ECB, embedded key) to decode the payload.

Sandbox mapping: rundll32.exe and control.exe are launched with the exact
command surfaces against a decoy .cpl in ARTIFACT_DIR (documented deviation:
the decoy is not a valid CPL — the process-creation telemetry is the
observable). The .mollis key staging is performed for real: a payload is
AES-ECB encrypted, written to the exact registry path, read back, decrypted
and verified. No WebDAV service is started (documented lift proposal).
*/

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	TEST_UUID      = "c3b4301e-b502-43a4-9f01-66a874239d1b"
	TECHNIQUE_ID   = "T1218.011"
	TECHNIQUE_NAME = "Control_RunDLL CPL Execution + .mollis AES Staging"
	STAGE_ID       = 6

	INVITE_SUBDIR   = "StarBlizzardInvite"
	DECOY_CPL       = "network_probe.cpl"
	MOLLIS_REG_PATH = `Software\Classes\.mollis`
	MOLLIS_VALUE    = "" // default value of the key, as used by the downloader
	MOLLIS_STATE    = "mollis_state.txt"
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
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Control_RunDLL/control.exe CPL launch + AES-ECB payload staged in HKCU .mollis")

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

	fmt.Printf("[STAGE %s] CPL execution + registry staging completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "CPL launch surfaces exercised and .mollis round-trip verified")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "rundll32/control.exe telemetry + AES-ECB .mollis staging verified")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	dir := filepath.Join(ARTIFACT_DIR, INVITE_SUBDIR)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("artifact directory creation failed: %v", err)
	}

	// ------------------------------------------------------------------
	// Primitive 1: decoy CPL + the two documented launch surfaces
	// ------------------------------------------------------------------
	cplPath := filepath.Join(dir, DECOY_CPL)
	cplContent := []byte("F0RT1KA decoy CPL (documented deviation: not a valid applet — command-line telemetry is the observable)\n")
	if err := os.WriteFile(cplPath, cplContent, 0644); err != nil {
		return fmt.Errorf("decoy CPL write failed: %v", err)
	}
	LogFileDropped(DECOY_CPL, cplPath, int64(len(cplContent)), false)

	if err := launchWithTimeout(25*time.Second, "rundll32.exe",
		[]string{"shell32.dll,Control_RunDLL", cplPath}); err != nil {
		return fmt.Errorf("rundll32 launch attempt ended: %v", err)
	}
	if err := launchWithTimeout(25*time.Second, "control.exe",
		[]string{cplPath}); err != nil {
		return fmt.Errorf("control.exe launch attempt ended: %v", err)
	}

	// ------------------------------------------------------------------
	// Primitive 2: AES-ECB key/payload staging in HKCU\.mollis
	// ------------------------------------------------------------------
	// Pre-existing-key safety: if the key already exists (host state we did
	// not create), stage into a namespaced value instead of the default
	// value, so cleanup only ever removes what this test wrote.
	keyExisted := mollisKeyExists()
	valueName := MOLLIS_VALUE
	cleanupAction := "delete-key"
	if keyExisted {
		if existing, found := readMollisDefault(); found && strings.TrimSpace(existing) != "" {
			valueName = fmt.Sprintf("F0RT1KA-%s", TEST_UUID)
			cleanupAction = "delete-value"
			LogMessage("WARN", TECHNIQUE_ID, "pre-existing .mollis data found — staging into namespaced value to avoid host changes")
		}
	}

	payload := fmt.Sprintf("CosmicPulse config|test=%s|beacon=/agent/poll|mode=loopback", TEST_UUID)

	// 32-byte AES-256 key (the real chain uses an embedded key; we generate
	// one per run — the write/read/decrypt round-trip is the observable)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("key material generation failed: %v", err)
	}
	encrypted, err := aesEncryptECB(aesKey, []byte(payload))
	if err != nil {
		return fmt.Errorf("payload encryption failed: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, MOLLIS_REG_PATH, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return classifyRegistryFailure(err)
	}
	defer k.Close()
	if err := k.SetStringValue(valueName, encoded); err != nil {
		return classifyRegistryFailure(err)
	}
	LogMessage("INFO", TECHNIQUE_ID,
		fmt.Sprintf("AES-ECB payload (%d bytes -> %d b64 chars) written to HKCU\\%s value '%s'", len(encrypted), len(encoded), MOLLIS_REG_PATH, valueName))

	// Record cleanup state: how the cleanup utility must restore the key
	state := fmt.Sprintf("KEY_EXISTED_BEFORE=%v\nVALUE_NAME=%s\nCLEANUP_ACTION=%s\n", keyExisted, valueName, cleanupAction)
	if err := os.WriteFile(filepath.Join(LOG_DIR, MOLLIS_STATE), []byte(state), 0644); err != nil {
		return fmt.Errorf("registry state write failed: %v", err)
	}

	// Bootstrapper behavior: read back, decrypt, verify
	readBack, _, err := k.GetStringValue(valueName)
	if err != nil {
		return classifyRegistryFailure(err)
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(readBack)
	if err != nil {
		return fmt.Errorf("registry payload decode failed: %v", err)
	}
	decrypted, err := aesDecryptECB(aesKey, cipherBytes)
	if err != nil {
		return fmt.Errorf("registry payload decryption failed: %v", err)
	}
	if string(decrypted) != payload {
		return fmt.Errorf("registry round-trip mismatch: payload differs after decrypt")
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("bootstrapper round-trip verified: %s", string(decrypted)))

	return nil
}

// launchWithTimeout runs one of the documented CPL launch surfaces under a
// short timeout. A non-valid CPL commonly blocks on a suppressed error dialog
// in non-interactive sessions — that outcome still generated the
// process-creation telemetry under test and is recorded, not failed.
func launchWithTimeout(timeout time.Duration, binary string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))

	if ctx.Err() == context.DeadlineExceeded {
		LogProcessExecution(binary, fmt.Sprintf("%s %s", binary, strings.Join(args, " ")), pidOf(cmd), false, 102,
			"no exit within timeout (suppressed applet error dialog) — telemetry generated")
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("%s generated telemetry then stalled on suppressed dialog (documented decoy deviation)", binary))
		return nil
	}
	LogProcessExecution(binary, fmt.Sprintf("%s %s", binary, strings.Join(args, " ")), pidOf(cmd), err == nil, exitCodeOf(err), outputStr)

	if err != nil && exitCodeOf(err) == 999 {
		return fmt.Errorf("%s launch attempt produced no exit code: %v (output: %s)", binary, err, outputStr)
	}
	if err != nil {
		LogMessage("INFO", TECHNIQUE_ID,
			fmt.Sprintf("%s exited %d on decoy applet (expected deviation — invocation telemetry generated)", binary, exitCodeOf(err)))
	}
	return nil
}

func mollisKeyExists() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, MOLLIS_REG_PATH, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// readMollisDefault reads the key's default value if present
func readMollisDefault() (string, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, MOLLIS_REG_PATH, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(MOLLIS_VALUE)
	if err != nil {
		return "", false
	}
	return v, true
}

// classifyRegistryFailure separates an OS-emitted registry denial (positive
// protection evidence) from other failures, per Bug Prevention Rule 8.
func classifyRegistryFailure(err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "access is denied") {
		return fmt.Errorf("registry write to HKCU\\%s reported OS-emitted denial: %v", MOLLIS_REG_PATH, err)
	}
	return fmt.Errorf("registry operation on HKCU\\%s ended: %v", MOLLIS_REG_PATH, err)
}

// aesEncryptECB encrypts with AES-ECB and PKCS#7 padding (block-by-block,
// matching the CosmicPulse bootstrapper's embedded-key scheme).
func aesEncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	for off := 0; off < len(padded); off += block.BlockSize() {
		block.Encrypt(ciphertext[off:off+block.BlockSize()], padded[off:off+block.BlockSize()])
	}
	return ciphertext, nil
}

func aesDecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length %d not a block multiple", len(ciphertext))
	}
	plaintext := make([]byte, len(ciphertext))
	for off := 0; off < len(ciphertext); off += block.BlockSize() {
		block.Decrypt(plaintext[off:off+block.BlockSize()], ciphertext[off:off+block.BlockSize()])
	}
	return pkcs7Unpad(plaintext, block.BlockSize())
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(data))
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding byte %d", padLen)
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("inconsistent padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 999
}

func pidOf(cmd *exec.Cmd) int {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Pid
	}
	return 0
}

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"os-emitted denial", "access denied", "access is denied", "permission denied", "operation not permitted"}) {
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
