//go:build linux
// +build linux

/*
STAGE 1: npm Install-Hook Execution & Staged Deobfuscation (T1195.002, T1059.007)
Simulates the "mini Shai-Hulud" entry vector: a malicious npm package whose
package.json preinstall hook runs `node index.js` during `npm install`, which
then performs multi-layer deobfuscation (char-code map -> AES-128-GCM blobs) of
an embedded payload.

SAFETY: The "payload" decrypted here is a BENIGN, locally generated marker string.
No real obfuscated malware is embedded, decrypted, or executed. All artifacts are
written under the artifact dir as decoys. Node/npm are NOT invoked.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "ae9002e4-3d82-4fcd-8b45-f7e0628f7375"
	TECHNIQUE_ID   = "T1195.002"
	TECHNIQUE_NAME = "npm Install-Hook Execution & Staged Deobfuscation"
	STAGE_ID       = 1
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// ARTIFACT_DIR for Linux is defined in test_logger_linux.go (/home/fortika-test).

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "npm preinstall hook + staged deobfuscation of a benign payload")

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
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Install-hook execution and staged deobfuscation simulated")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Stage artifacts under the (non-whitelisted) artifact dir so EDR can observe
	// file operations, plus a working copy in /tmp/F0 for forensic review.
	pkgDir := filepath.Join(ARTIFACT_DIR, "node_modules", "@redhat-cloud-services", "chrome")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		return fmt.Errorf("failed to create simulated package directory: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Created simulated compromised package tree under artifact dir")

	// Phase 1: Write a package.json carrying the malicious preinstall hook signature.
	fmt.Printf("[STAGE %s] Phase 1: Writing package.json with preinstall hook (node index.js)...\n", TECHNIQUE_ID)
	pkgJSON := generatePackageJSON()
	pkgPath := filepath.Join(pkgDir, "package.json")
	if err := os.WriteFile(pkgPath, []byte(pkgJSON), 0644); err != nil {
		return fmt.Errorf("failed to write package.json: %v", err)
	}
	LogFileDropped("package.json", pkgPath, int64(len(pkgJSON)), false)
	LogMessage("INFO", TECHNIQUE_ID, "package.json preinstall hook written: \"preinstall\": \"node index.js\"")

	// Phase 2: Write an obfuscated loader (index.js) that mirrors the campaign's
	// char-code-array + eval style. This is INERT TEXT — it is never executed.
	fmt.Printf("[STAGE %s] Phase 2: Writing obfuscated loader index.js (char-code map + eval pattern)...\n", TECHNIQUE_ID)
	loader := generateObfuscatedLoader()
	loaderPath := filepath.Join(pkgDir, "index.js")
	if err := os.WriteFile(loaderPath, []byte(loader), 0644); err != nil {
		return fmt.Errorf("failed to write obfuscated loader: %v", err)
	}
	LogFileDropped("index.js", loaderPath, int64(len(loader)), false)
	LogMessage("INFO", TECHNIQUE_ID, "Obfuscated loader written (inert text, never executed)")

	// Phase 3: Simulate the staged deobfuscation chain on a BENIGN marker.
	// Layer 1: char-code array -> string.
	fmt.Printf("[STAGE %s] Phase 3: Simulating staged deobfuscation of a benign embedded payload...\n", TECHNIQUE_ID)
	benignMarker := "F0RT1KA-SIMULATED-PAYLOAD::mini-shai-hulud::thebeautifulmarchoftime"
	layer1 := encodeCharCodes(benignMarker)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Layer 1 (char-code map): produced %d-element code array", len(layer1)))
	recovered := decodeCharCodes(layer1)
	if recovered != benignMarker {
		return fmt.Errorf("layer 1 deobfuscation self-check mismatch")
	}

	// Layer 2: AES-128-GCM encrypt/decrypt the benign marker (mirrors _b/_p blobs).
	key := make([]byte, 16) // AES-128
	iv := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate simulation key material: %v", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate simulation IV: %v", err)
	}
	ct, tag, err := aesGCMEncrypt(key, iv, []byte(recovered))
	if err != nil {
		return fmt.Errorf("simulated AES-GCM encrypt of benign payload failed: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Layer 2 (AES-128-GCM): blob _p = %d bytes ciphertext + %d-byte auth tag", len(ct), len(tag)))
	pt, err := aesGCMDecrypt(key, iv, ct, tag)
	if err != nil {
		return fmt.Errorf("simulated AES-GCM decrypt of benign payload failed: %v", err)
	}
	if string(pt) != benignMarker {
		return fmt.Errorf("layer 2 deobfuscation self-check mismatch")
	}

	// Phase 4: Write the "decrypted payload" to a randomized /tmp path then delete
	// it (mirrors the campaign's /tmp/p<random>.js write-then-unlink anti-forensics).
	fmt.Printf("[STAGE %s] Phase 4: Writing decrypted (benign) payload to /tmp/p<rand>.js then unlinking...\n", TECHNIQUE_ID)
	tmpPayload := filepath.Join("/tmp/F0", fmt.Sprintf("p%d.js", time.Now().UnixNano()%1000000))
	if err := os.WriteFile(tmpPayload, []byte("// "+string(pt)+"\n// inert benign marker — not executed\n"), 0600); err != nil {
		return fmt.Errorf("failed to write decrypted payload marker: %v", err)
	}
	LogFileDropped(filepath.Base(tmpPayload), tmpPayload, int64(len(pt)), false)
	_ = os.Remove(tmpPayload)
	LogMessage("INFO", TECHNIQUE_ID, "Decrypted payload written and immediately unlinked (anti-forensic pattern simulated)")

	fmt.Printf("[STAGE %s] Install-hook execution + staged deobfuscation complete (benign).\n", TECHNIQUE_ID)
	return nil
}

func generatePackageJSON() string {
	return `{
  "name": "@redhat-cloud-services/chrome",
  "version": "2.3.1",
  "description": "Frontend chroming for Red Hat cloud services (SIMULATED COMPROMISED VERSION)",
  "main": "index.js",
  "scripts": {
    "preinstall": "node index.js"
  },
  "license": "Apache-2.0",
  "_simulation_note": "F0RT1KA benign supply-chain test artifact - not a real package"
}
`
}

func generateObfuscatedLoader() string {
	// Mirrors the campaign's obfuscation *shape* without any working payload.
	var sb strings.Builder
	sb.WriteString("// SIMULATED obfuscated npm loader (mini Shai-Hulud shape) - INERT, never executed\n")
	sb.WriteString("// Original campaign: eval-wrapped char-code arrays + AES-128-GCM (_b runtime helper, _p payload)\n")
	sb.WriteString("const _f4abccab2=[70,48,82,84,49,75,65].map(c=>String.fromCharCode(c)).join('');\n")
	sb.WriteString("// const _d=(k,i,a,c)=>{/* createDecipheriv aes-128-gcm ... */};  // disabled in simulation\n")
	sb.WriteString("// const _b='<bun-helper-blob>'; const _p='<payload-blob>';        // benign placeholders\n")
	sb.WriteString("module.exports={ note: 'F0RT1KA simulation - " + "thebeautifulmarchoftime" + "' };\n")
	return sb.String()
}

func encodeCharCodes(s string) []int {
	codes := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		codes[i] = int(s[i])
	}
	return codes
}

func decodeCharCodes(codes []int) string {
	b := make([]byte, len(codes))
	for i, c := range codes {
		b[i] = byte(c)
	}
	return string(b)
}

func aesGCMEncrypt(key, iv, plaintext []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	ts := gcm.Overhead()
	return sealed[:len(sealed)-ts], sealed[len(sealed)-ts:], nil
}

func aesGCMDecrypt(key, iv, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, ciphertext...), tag...)
	return gcm.Open(nil, iv, sealed, nil)
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	// Only match EDR/AV-specific indicators, NOT standard POSIX errors. On Linux,
	// EDR blocks manifest as process kills, file quarantine, or policy enforcement
	// — never as plain EACCES/EPERM on mkdir/write.
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
