//go:build darwin
// +build darwin

/*
STAGE 1: Gatekeeper Bypass & Payload Delivery (T1553.001)
Simulates curl-based payload download without quarantine attribute,
notarized malware delivery with fake developer ID signing, and
quarantine attribute removal techniques used by RustBucket/BlueNoroff.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
	TECHNIQUE_ID   = "T1553.001"
	TECHNIQUE_NAME = "Subvert Trust Controls: Gatekeeper Bypass"
	STAGE_ID       = 1
)

// Standardized stage exit codes
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	// Attach to shared log created by main orchestrator
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Simulate Gatekeeper bypass and payload delivery")

	fmt.Printf("[STAGE %s] Starting Gatekeeper Bypass & Payload Delivery\n", TECHNIQUE_ID)

	// Execute technique
	if err := performTechnique(); err != nil {
		// Determine if blocked or error
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

	// Technique succeeded
	fmt.Printf("[STAGE %s] Gatekeeper bypass simulation completed successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Gatekeeper bypass completed without prevention")
	os.Exit(StageSuccess)
}

// performTechnique simulates the Gatekeeper bypass and payload delivery
func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := ARTIFACT_DIR

	// Ensure directories exist
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		fmt.Printf("[STAGE %s]   ARTIFACT_DIR %s not writable, falling back to /tmp/F0/fortika-test\n", TECHNIQUE_ID, artifactDir)
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("ARTIFACT_DIR %s not writable, using fallback", artifactDir))
		artifactDir = filepath.Join(targetDir, "fortika-test")
		if err := os.MkdirAll(artifactDir, 0755); err != nil {
			return fmt.Errorf("failed to create artifact directory: %v", err)
		}
	}

	// --- Sub-technique 1: Simulate curl-based download (no quarantine attribute) ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 1: Simulating curl-based payload delivery (no quarantine attribute)")
	fmt.Printf("[STAGE %s] Phase 1: curl-based payload delivery simulation\n", TECHNIQUE_ID)

	// Create a simulated dropper disguised as a PDF viewer (RustBucket pattern)
	dropperContent := []byte(`#!/bin/bash
# Simulated RustBucket Stage 1 Dropper
# In real attack: AppleScript -> downloads Objective-C Stage 2 via cURL
# cURL downloads do NOT set com.apple.quarantine attribute
# This bypasses Gatekeeper verification

PAYLOAD_URL="https://cloud.dnx.capital/InternalPDFViewer.app.tar.gz"
# In simulation: no actual download, just logging
echo "[RustBucket] Stage 1 Dropper Active"
echo "[RustBucket] Payload URL: ${PAYLOAD_URL}"
echo "[RustBucket] Delivery method: cURL (bypasses quarantine xattr)"
echo "[RustBucket] Quarantine attribute: NOT SET (Gatekeeper bypass)"
echo "[RustBucket] Fake developer: Avantis Regtech Private Limited (2S8XHJ7948)"
`)

	dropperPath := filepath.Join(artifactDir, "InternalPDFViewer.sh")
	if err := os.WriteFile(dropperPath, dropperContent, 0755); err != nil {
		return fmt.Errorf("failed to write dropper: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created simulated dropper: %s (%d bytes)", dropperPath, len(dropperContent)))

	// Verify dropper survived (check for quarantine/AV removal)
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(dropperPath); os.IsNotExist(err) {
		return fmt.Errorf("dropper quarantined after creation: file removed by security controls")
	}

	// --- Sub-technique 2: Simulate notarized malware with fake developer ID ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 2: Simulating notarized malware with hijacked developer ID")
	fmt.Printf("[STAGE %s] Phase 2: Notarized malware simulation\n", TECHNIQUE_ID)

	// Create fake code signing metadata (Hidden Risk campaign used hijacked Apple Developer ID)
	codeSignMetadata := `{
  "simulation": true,
  "campaign": "Hidden Risk (Nov 2024, SentinelLabs)",
  "signing_identity": "Avantis Regtech Private Limited (2S8XHJ7948)",
  "notarization_status": "NOTARIZED",
  "notarization_ticket": "simulated-ticket-id-bluenoroff-2024",
  "gatekeeper_status": "ALLOWED",
  "note": "Real attack used hijacked Apple Developer ID for notarization",
  "technique": "T1553.001 - Subvert Trust Controls: Gatekeeper Bypass",
  "threat_actor": "BlueNoroff/Lazarus (DPRK)",
  "delivery_method": "Fake cryptocurrency application",
  "binary_type": "Universal Mach-O (x86_64 + arm64)",
  "entitlements": {
    "com.apple.security.cs.disable-library-validation": true,
    "com.apple.security.cs.allow-unsigned-executable-memory": true
  }
}`

	metadataPath := filepath.Join(targetDir, "codesign_metadata.json")
	if err := os.WriteFile(metadataPath, []byte(codeSignMetadata), 0644); err != nil {
		return fmt.Errorf("failed to write code signing metadata: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Created code signing metadata with hijacked developer ID details")

	// --- Sub-technique 3: Simulate quarantine attribute removal ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 3: Simulating quarantine attribute removal (xattr -d)")
	fmt.Printf("[STAGE %s] Phase 3: Quarantine attribute removal simulation\n", TECHNIQUE_ID)

	// Create a simulated xattr removal script
	xattrScript := `#!/bin/bash
# Simulated quarantine attribute removal
# In real macOS attack: xattr -d com.apple.quarantine <payload>
# This removes Gatekeeper's quarantine flag, allowing execution
# without the "downloaded from the internet" warning

TARGET_APP="$1"

# Check if quarantine attribute exists
echo "[*] Checking quarantine attribute on: ${TARGET_APP}"
# xattr -l "${TARGET_APP}" | grep com.apple.quarantine

# Remove quarantine attribute
echo "[*] Removing quarantine attribute..."
# xattr -d com.apple.quarantine "${TARGET_APP}"

echo "[+] Quarantine attribute removed - Gatekeeper will not verify this file"
echo "[+] File will execute without macOS security prompt"
echo ""
echo "Note: In macOS Sequoia (Sept 2024), Apple removed right-click bypass"
echo "but xattr -d and curl downloads still bypass Gatekeeper"
`

	xattrScriptPath := filepath.Join(targetDir, "remove_quarantine.sh")
	if err := os.WriteFile(xattrScriptPath, []byte(xattrScript), 0755); err != nil {
		return fmt.Errorf("failed to write xattr removal script: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Created quarantine attribute removal script")

	// --- Sub-technique 4: Create simulated Mach-O dropper payload ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 4: Creating simulated Mach-O payload (crypto tool disguise)")
	fmt.Printf("[STAGE %s] Phase 4: Creating simulated Mach-O payload\n", TECHNIQUE_ID)

	// Simulate the fake application that BlueNoroff uses (crypto exchange/DeFi tool)
	fakeAppManifest := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Crypto Exchange Pro</string>
    <key>CFBundleIdentifier</key>
    <string>com.cryptoexchange.pro</string>
    <key>CFBundleVersion</key>
    <string>2.4.1</string>
    <key>CFBundleExecutable</key>
    <string>CryptoExchangePro</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>NSAppleEventsUsageDescription</key>
    <string>This app needs to manage your crypto portfolio</string>
    <key>note</key>
    <string>SIMULATION - BlueNoroff targets blockchain engineers with fake crypto apps</string>
</dict>
</plist>`

	manifestPath := filepath.Join(artifactDir, "CryptoExchangePro_Info.plist")
	if err := os.WriteFile(manifestPath, []byte(fakeAppManifest), 0644); err != nil {
		return fmt.Errorf("failed to write app manifest: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, "Created simulated macOS application manifest (crypto tool disguise)")

	// Verify all artifacts survived AV scanning
	time.Sleep(2 * time.Second)

	artifacts := []string{dropperPath, metadataPath, xattrScriptPath, manifestPath}
	for _, artifact := range artifacts {
		if _, err := os.Stat(artifact); os.IsNotExist(err) {
			return fmt.Errorf("artifact quarantined: %s removed by security controls", filepath.Base(artifact))
		}
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "All Gatekeeper bypass artifacts created and survived AV scanning")
	fmt.Printf("[STAGE %s] All 4 phases completed - artifacts survived\n", TECHNIQUE_ID)
	return nil
}

func isBlockedError(err error) bool {
	errStr := strings.ToLower(err.Error())
	// Only match EDR/AV-specific indicators, NOT standard OS errors.
	// "permission denied" and "operation not permitted" are standard POSIX errors
	// from filesystem operations — not EDR blocks. On Linux/macOS, EDR blocks manifest
	// as process kills (SIGKILL), file quarantine (file disappears), or security
	// policy enforcement — never as simple EACCES/EPERM on mkdir/write.
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

// determineExitCode converts error to appropriate exit code
func determineExitCode(err error) int {
	if err == nil {
		return StageSuccess
	}
	if isBlockedError(err) {
		return StageBlocked
	}
	return StageError
}
