//go:build windows
// +build windows

/*
STAGE 4: Credentials from Web Browsers (T1555.003) + Browser Information Discovery (T1217)

Recreates the 3CX ICONIC stealer's final act: harvesting browser credential
stores and history from Chrome, Edge, Brave and Firefox. This is the behavior
an EDR must catch — a process walking every browser profile and reading Login
Data / Web Data / cookies / history in quick succession.

Safety: NO real browser data is ever touched. The stage pre-stages DECOY
artifacts (benign, clearly-marked fake content) under the sandboxed ARTIFACT_DIR
in the exact relative layout a real browser uses, then enumerates and reads
ONLY those decoys, copying them into a collection buffer under LOG_DIR. The
canonical real profile paths (under %LOCALAPPDATA% / %APPDATA%) are LOGGED as
discovery targets for telemetry realism but are never opened. Decoys and the
collection buffer are removed on completion.
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
	TEST_UUID      = "56475cb3-febc-45ac-a0af-39bc5ca1c15f"
	TECHNIQUE_ID   = "T1555.003"
	TECHNIQUE_NAME = "Credentials from Web Browsers"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// browserArtifact describes one browser credential/history store to collect.
type browserArtifact struct {
	browser string
	relPath string // path relative to a profile root (real layout)
	decoy   []byte // benign decoy content written under ARTIFACT_DIR
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting ICONIC-style browser credential collection simulation")
	LogMessage("INFO", TECHNIQUE_ID, "Collection runs against DECOYS in ARTIFACT_DIR — no real credentials are read")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Enumerate + read decoy Chrome/Edge/Brave/Firefox credential stores")

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

	fmt.Printf("[STAGE %s] Browser credential collection completed\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Browser credential collection simulation completed")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Decoy credential stores enumerated and collected; no prevention observed")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	artifacts := browserArtifacts()

	// Decoy profile root under the sandboxed ARTIFACT_DIR.
	decoyRoot := filepath.Join(ARTIFACT_DIR, "browser_profiles")

	// T1217 — log canonical real target locations for discovery telemetry (NEVER opened).
	LogMessage("INFO", TECHNIQUE_ID, "Discovery (T1217): canonical browser credential-store locations that a real stealer targets:")
	for _, canon := range canonicalTargets() {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("  target (not read): %s", canon))
	}

	// Step 1: pre-stage decoys in the real relative layout under ARTIFACT_DIR.
	staged := 0
	for _, a := range artifacts {
		decoyPath := filepath.Join(decoyRoot, a.browser, a.relPath)
		if err := os.MkdirAll(filepath.Dir(decoyPath), 0755); err != nil {
			// ARTIFACT_DIR not provisioned/writable → prerequisite failure (999), not a block.
			return fmt.Errorf("could not prepare decoy path %s (ARTIFACT_DIR prerequisite): %v", decoyPath, err)
		}
		if err := os.WriteFile(decoyPath, a.decoy, 0644); err != nil {
			return fmt.Errorf("could not stage decoy %s (ARTIFACT_DIR prerequisite): %v", decoyPath, err)
		}
		staged++
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Pre-staged %d decoy browser credential/history artifacts under %s", staged, decoyRoot))

	// Detection window for the freshly-staged decoy stores.
	time.Sleep(2 * time.Second)

	// Step 2: enumerate + read the decoys (the ICONIC access pattern) into a collection buffer.
	collectionDir := filepath.Join(LOG_DIR, "collection")
	if err := os.MkdirAll(collectionDir, 0755); err != nil {
		return fmt.Errorf("could not create collection buffer: %v", err)
	}

	collected := 0
	for _, a := range artifacts {
		decoyPath := filepath.Join(decoyRoot, a.browser, a.relPath)

		if _, err := os.Stat(decoyPath); os.IsNotExist(err) {
			// A decoy we just wrote is gone → positive quarantine evidence.
			return fmt.Errorf("decoy artifact %s was quarantined before collection", decoyPath)
		}

		data, err := os.ReadFile(decoyPath)
		if err != nil {
			// An OS denial reading a file we own and just created is affirmative block evidence.
			if isDenied(err) {
				return fmt.Errorf("read of decoy %s returned access is denied", filepath.Base(decoyPath))
			}
			return fmt.Errorf("could not read decoy %s: %v", filepath.Base(decoyPath), err)
		}

		outName := fmt.Sprintf("%s_%s", a.browser, strings.ReplaceAll(a.relPath, string(os.PathSeparator), "_"))
		outPath := filepath.Join(collectionDir, outName)
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return fmt.Errorf("could not write collected copy %s: %v", outName, err)
		}
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Collected %s / %s (%d bytes)", a.browser, a.relPath, len(data)))
		collected++
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Collection complete: %d/%d decoy stores copied to %s", collected, len(artifacts), collectionDir))
	LogMessage("INFO", TECHNIQUE_ID, "Access pattern exercised: rapid sequential reads of browser Login Data / Web Data / cookies / history")

	// Step 3: cleanup — remove decoys and the collection buffer (no lingering fake credential files).
	if err := os.RemoveAll(decoyRoot); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Cleanup of decoy profiles incomplete: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Removed decoy browser profiles from ARTIFACT_DIR")
	}
	if err := os.RemoveAll(collectionDir); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Cleanup of collection buffer incomplete: %v", err))
	} else {
		LogMessage("INFO", TECHNIQUE_ID, "Removed collection buffer from LOG_DIR")
	}

	return nil
}

// browserArtifacts returns the browser stores to stage as decoys and collect.
func browserArtifacts() []browserArtifact {
	// Benign, clearly-marked decoy content. NOT a real SQLite DB and NOT real creds.
	loginDecoy := []byte("SQLite format 3\x00F0RT1KA-DECOY-login-data:origin=https://example.test;user=decoy;blob=NOT-A-REAL-CREDENTIAL\x00")
	webDataDecoy := []byte("SQLite format 3\x00F0RT1KA-DECOY-web-data:autofill=decoy-name,decoy@example.test\x00")
	historyDecoy := []byte("SQLite format 3\x00F0RT1KA-DECOY-history:url=https://example.test/decoy;visits=1\x00")
	cookiesDecoy := []byte("SQLite format 3\x00F0RT1KA-DECOY-cookies:host=example.test;name=decoy;value=NOT-REAL\x00")
	ffLogins := []byte(`{"_comment":"F0RT1KA-DECOY","logins":[{"hostname":"https://example.test","encryptedUsername":"DECOY","encryptedPassword":"DECOY"}]}`)
	ffKey4 := []byte("SQLite format 3\x00F0RT1KA-DECOY-key4-nss-keystore\x00")

	return []browserArtifact{
		{"Chrome", `Google\Chrome\User Data\Default\Login Data`, loginDecoy},
		{"Chrome", `Google\Chrome\User Data\Default\Web Data`, webDataDecoy},
		{"Chrome", `Google\Chrome\User Data\Default\History`, historyDecoy},
		{"Chrome", `Google\Chrome\User Data\Default\Network\Cookies`, cookiesDecoy},
		{"Edge", `Microsoft\Edge\User Data\Default\Login Data`, loginDecoy},
		{"Edge", `Microsoft\Edge\User Data\Default\History`, historyDecoy},
		{"Brave", `BraveSoftware\Brave-Browser\User Data\Default\Login Data`, loginDecoy},
		{"Firefox", `Mozilla\Firefox\Profiles\abcd1234.default-release\logins.json`, ffLogins},
		{"Firefox", `Mozilla\Firefox\Profiles\abcd1234.default-release\key4.db`, ffKey4},
	}
}

// canonicalTargets lists the REAL locations a stealer targets (logged only, never read).
func canonicalTargets() []string {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	if local == "" {
		local = `%LOCALAPPDATA%`
	}
	if roaming == "" {
		roaming = `%APPDATA%`
	}
	return []string{
		filepath.Join(local, `Google\Chrome\User Data\Default\Login Data`),
		filepath.Join(local, `Microsoft\Edge\User Data\Default\Login Data`),
		filepath.Join(local, `BraveSoftware\Brave-Browser\User Data\Default\Login Data`),
		filepath.Join(roaming, `Mozilla\Firefox\Profiles`),
	}
}

func isDenied(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	return containsAny(err.Error(), []string{"access is denied", "access denied", "permission denied"})
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
	// Missing prerequisite / ambiguous / benign failure → 999, never a block.
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
