//go:build windows
// +build windows

/*
STAGE 3: Steganographic C2 Config Retrieval + Web Protocols (T1027.003, T1071.001)

Recreates the 3CX second-stage retrieval: the implant fetched icon files
(*.ico) from a GitHub repository (raw.githubusercontent.com/IconStorages/images)
and read an AES-encrypted C2 configuration appended AFTER the legitimate icon
data — steganography in plain sight, over trusted HTTPS to a trusted CDN.

Safety / realism split:
  - Egress is REAL but benign: a genuine DNS lookup of raw.githubusercontent.com
    plus a short HTTPS GET shaped like the IOC URL. The response body is
    discarded and never parsed or executed — no attacker payload is retrieved.
    This produces authentic DNS + TLS egress telemetry against the real IOC
    domain shape without pulling anything malicious.
  - The second stage is EMBEDDED, not downloaded: a benign ICO-with-appended-
    AES-config blob is materialized locally to LOG_DIR (a real on-disk .ico with
    ICO magic + trailing high-entropy ciphertext), then decoded and AES-decrypted
    in-process to a BENIGN C2 descriptor. This exercises the exact stego-decode
    behavior EDR should flag, with zero real C2 and zero real payload.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	TEST_UUID      = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TECHNIQUE_ID   = "T1027.003"
	TECHNIQUE_NAME = "Steganography"
	STAGE_ID       = 3

	// IOC-shaped host + path (benign GitHub CDN; real IOC domain shape for telemetry)
	icoHost = "raw.githubusercontent.com"
	icoURL  = "https://raw.githubusercontent.com/IconStorages/images/main/icon0.ico"
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Embedded AES-256 key + IV standing in for the key hard-coded in the 3CX
// second stage. Used only to encrypt/decrypt a BENIGN local config blob.
var aesKey = []byte("F0RT1KA-3cx-stego-demo-key-32byt") // 32 bytes → AES-256
var aesIV = []byte("F0RT1KA-iv-16byt")                  // 16 bytes

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting steganographic C2 config retrieval simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Real benign egress shaped like the raw.githubusercontent.com ICO IOC; config decoded locally")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "DNS + HTTPS GET (benign) + local ICO-stego AES config decode")

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

	fmt.Printf("[STAGE %s] Steganographic C2 config decode completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Steganographic C2 config decode completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "ICO-appended AES config decoded to benign descriptor; no real payload retrieved")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	// Step 1: REAL but benign DNS lookup of the IOC domain (telemetry, no payload)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Resolving IOC-shaped host: %s", icoHost))
	if addrs, err := net.LookupHost(icoHost); err == nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("DNS resolved %s -> %d address(es)", icoHost, len(addrs)))
	} else {
		// DNS failure is environmental (offline lab), NOT a protection block.
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("DNS lookup for %s failed (offline lab expected): %v", icoHost, err))
	}

	// Step 2: REAL but benign HTTPS GET shaped like the ICO IOC; body discarded.
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("HTTPS GET (benign, body discarded): %s", icoURL))
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("GET", icoURL, nil)
	if err == nil {
		// User-Agent shaped like a desktop app fetching an icon resource.
		req.Header.Set("User-Agent", "3CXDesktopApp/18.12.416")
		if resp, derr := client.Do(req); derr == nil {
			// Discard the body — we never use downloaded content as a payload.
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("HTTPS GET returned HTTP %d (content discarded, not used)", resp.StatusCode))
		} else {
			// Connection failure is expected/benign in an offline lab — NOT a block.
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("HTTPS GET failed (offline lab expected, not a block): %v", derr))
		}
	}

	// Step 3: Materialize the EMBEDDED second stage as a real on-disk ICO stego blob.
	//   Layout: [valid ICO header + icon image bytes][appended AES-256-CBC ciphertext]
	stagoDir := filepath.Join(LOG_DIR, "stego")
	if err := os.MkdirAll(stagoDir, 0755); err != nil {
		return fmt.Errorf("could not create stego working directory: %v", err)
	}
	icoPath := filepath.Join(stagoDir, "icon0.ico")

	benignConfig := map[string]interface{}{
		"campaign": "3cx-demo-benign",
		"sleep":    IntendedDormancyRef(),
		"c2": []string{
			"https://msstorageazure.azureedge.net/", // benign-shaped descriptor only; never contacted
			"https://azureonlinestorage.azurefd.net/",
			"https://officeaddons.azureedge.net/",
		},
		"note": "F0RT1KA benign C2 descriptor — no real callback is performed",
	}
	configJSON, err := json.Marshal(benignConfig)
	if err != nil {
		return fmt.Errorf("could not marshal benign config: %v", err)
	}

	icoBlob, iconLen, err := buildStegoIco(configJSON)
	if err != nil {
		return fmt.Errorf("could not build stego ICO blob: %v", err)
	}
	if err := os.WriteFile(icoPath, icoBlob, 0644); err != nil {
		return fmt.Errorf("could not write stego ICO artifact: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Materialized stego artifact: %s (%d bytes; %d icon bytes + %d appended cipher bytes)",
		icoPath, len(icoBlob), iconLen, len(icoBlob)-iconLen))

	// Detection window + quarantine check (Rule 3: os.Stat)
	time.Sleep(2 * time.Second)
	if _, statErr := os.Stat(icoPath); os.IsNotExist(statErr) {
		return fmt.Errorf("stego ICO artifact was quarantined after being written")
	}

	// Step 4: Decode — read ICO back, locate appended ciphertext, AES-decrypt, parse.
	onDisk, err := os.ReadFile(icoPath)
	if err != nil {
		return fmt.Errorf("could not read back stego ICO artifact: %v", err)
	}
	cipherBytes, err := extractAppendedPayload(onDisk)
	if err != nil {
		return fmt.Errorf("could not extract appended payload from ICO: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Extracted %d bytes of appended data after the legitimate icon image", len(cipherBytes)))

	plain, err := aesCBCDecrypt(cipherBytes)
	if err != nil {
		return fmt.Errorf("could not AES-decrypt appended config: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(plain, &decoded); err != nil {
		return fmt.Errorf("could not parse decrypted config JSON: %v", err)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Decoded benign C2 descriptor: campaign=%v, c2_count=%d",
		decoded["campaign"], len(toStringSlice(decoded["c2"]))))
	LogMessage("INFO", TECHNIQUE_ID, "Decode complete: ICO magic + appended ciphertext + AES-256-CBC — matches 3CX stego pattern")

	// Write decoded (benign) config to disk for forensic/telemetry value.
	decodedPath := filepath.Join(stagoDir, "decoded_config.json")
	if err := os.WriteFile(decodedPath, plain, 0644); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Could not write decoded config: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Decoded benign config written: %s", decodedPath))
	}

	return nil
}

// IntendedDormancyRef documents the descriptor's sleep field (7 days), mirroring stage 2.
func IntendedDormancyRef() int { return 604800 }

// buildStegoIco returns a byte blob: a minimal valid ICO (header + one image entry
// + icon image bytes) with AES-256-CBC ciphertext of `payload` appended after the
// legitimate icon data. Returns the blob and the length of the legitimate icon region.
func buildStegoIco(payload []byte) ([]byte, int, error) {
	// Minimal icon image bytes (opaque; represents the real icon pixels).
	iconPixels := make([]byte, 64)
	for i := range iconPixels {
		iconPixels[i] = byte(0x30 + (i % 16))
	}

	const iconDirLen = 6
	const iconEntryLen = 16
	imageOffset := iconDirLen + iconEntryLen // 22

	buf := make([]byte, 0, imageOffset+len(iconPixels)+len(payload)+aes.BlockSize)

	// ICONDIR: reserved=0, type=1 (icon), count=1
	dir := make([]byte, iconDirLen)
	binary.LittleEndian.PutUint16(dir[0:2], 0)
	binary.LittleEndian.PutUint16(dir[2:4], 1)
	binary.LittleEndian.PutUint16(dir[4:6], 1)
	buf = append(buf, dir...)

	// ICONDIRENTRY (16 bytes)
	entry := make([]byte, iconEntryLen)
	entry[0] = 16                                                       // width
	entry[1] = 16                                                       // height
	entry[2] = 0                                                        // color count
	entry[3] = 0                                                        // reserved
	binary.LittleEndian.PutUint16(entry[4:6], 1)                        // color planes
	binary.LittleEndian.PutUint16(entry[6:8], 32)                       // bits per pixel
	binary.LittleEndian.PutUint32(entry[8:12], uint32(len(iconPixels))) // bytes in resource
	binary.LittleEndian.PutUint32(entry[12:16], uint32(imageOffset))    // image offset
	buf = append(buf, entry...)

	// Legitimate icon image bytes
	buf = append(buf, iconPixels...)
	legitLen := len(buf) // end of the legitimate icon region

	// Append AES-256-CBC ciphertext of the benign config (the hidden "second stage")
	cipherBytes, err := aesCBCEncrypt(payload)
	if err != nil {
		return nil, 0, err
	}
	buf = append(buf, cipherBytes...)

	return buf, legitLen, nil
}

// extractAppendedPayload parses the ICO header to find where the legitimate icon
// image ends, and returns everything appended after it (the hidden ciphertext).
func extractAppendedPayload(data []byte) ([]byte, error) {
	if len(data) < 22 {
		return nil, fmt.Errorf("data too small to be an ICO")
	}
	// Validate ICO magic: reserved=0, type=1
	if binary.LittleEndian.Uint16(data[0:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return nil, fmt.Errorf("ICO magic header not present")
	}
	bytesInRes := binary.LittleEndian.Uint32(data[14:18])
	imageOffset := binary.LittleEndian.Uint32(data[18:22])
	legitEnd := int(imageOffset) + int(bytesInRes)
	if legitEnd > len(data) {
		return nil, fmt.Errorf("declared icon image extends past file bounds")
	}
	if legitEnd == len(data) {
		return nil, fmt.Errorf("no appended data after the legitimate icon")
	}
	return data[legitEnd:], nil
}

func aesCBCEncrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, aesIV)
	mode.CryptBlocks(out, padded)
	return out, nil
}

func aesCBCDecrypt(ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the AES block size")
	}
	out := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, aesIV)
	mode.CryptBlocks(out, ct)
	return pkcs7Unpad(out, aes.BlockSize)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	pad := make([]byte, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	return data[:len(data)-padLen], nil
}

func toStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ==============================================================================
// EXIT CODE DETERMINATION (Bug Prevention Rule 8: never default to a block code)
// ==============================================================================

func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	errStr := err.Error()
	if containsAny(errStr, []string{"quarantined", "virus", "threat"}) {
		return StageQuarantined
	}
	if containsAny(errStr, []string{"access is denied", "access denied", "permission denied", "operation not permitted"}) {
		return StageBlocked
	}
	// Network / decode / ambiguous failures → 999, never a block.
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
