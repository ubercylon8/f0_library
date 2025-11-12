//go:build windows
// +build windows

/*
STAGE 2: Windows Service Installation (T1543.003)
Installs OpenSSH Server for remote access
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	TEST_UUID      = "eafce2fc-75fd-4c62-92dc-32cabe5cf206"
	TECHNIQUE_ID   = "T1543.003"
	TECHNIQUE_NAME = "Windows Service Installation"
	STAGE_ID       = 2
)

// Standardized stage exit codes
const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	OPENSSH_STATE_FILE = "c:\\F0\\original_openssh_state.json"
)

// OpenSSHState represents the original state of OpenSSH before test modifications
type OpenSSHState struct {
	WasInstalled      bool   `json:"was_installed"`
	ServiceStartup    string `json:"service_startup"`    // "disabled", "manual", "auto"
	ServiceRunning    bool   `json:"service_running"`
	FirewallRuleExist bool   `json:"firewall_rule_exist"`
}

func main() {
	// Attach to shared log
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))

	LogMessage("INFO", TECHNIQUE_ID, "Starting Windows Service Installation")
	LogStageStart(STAGE_ID, TECHNIQUE_ID, "Install OpenSSH Server capability")

	// Check if running with admin privileges
	if !isAdmin() {
		LogMessage("ERROR", TECHNIQUE_ID, "Administrator privileges required")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Not running as administrator")
		os.Exit(StageError)
	}

	// Capture original OpenSSH state for cleanup restoration
	if err := captureOpenSSHState(); err != nil {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("Failed to capture OpenSSH state: %v", err))
		// Continue anyway - cleanup will still work, just won't restore original state
	}

	// Attempt to install OpenSSH Server
	if err := installOpenSSH(); err != nil {
		// Check if installation was blocked
		if strings.Contains(err.Error(), "access denied") ||
			strings.Contains(err.Error(), "blocked") ||
			strings.Contains(err.Error(), "restricted") {

			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Installation blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Installation failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	// Configure OpenSSH for remote access
	if err := configureOpenSSH(); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Configuration failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	// Start service
	if err := startOpenSSH(); err != nil {
		if strings.Contains(err.Error(), "access denied") ||
			strings.Contains(err.Error(), "blocked") {

			LogMessage("BLOCKED", TECHNIQUE_ID, fmt.Sprintf("Service start blocked: %v", err))
			LogStageBlocked(STAGE_ID, TECHNIQUE_ID, err.Error())
			os.Exit(StageBlocked)
		}

		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Service start failed: %v", err))
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", err.Error())
		os.Exit(StageError)
	}

	// Verify service is running
	if !isServiceRunning("sshd") {
		LogMessage("ERROR", TECHNIQUE_ID, "OpenSSH service not running after start attempt")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Service verification failed")
		os.Exit(StageError)
	}

	LogMessage("SUCCESS", TECHNIQUE_ID, "OpenSSH Server installed and running")
	LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "OpenSSH Server successfully configured")
	os.Exit(StageSuccess)
}

func installOpenSSH() error {
	LogMessage("INFO", TECHNIQUE_ID, "Installing OpenSSH Server capability...")

	// Check if already installed
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("capability check failed: %v", err)
	}

	if strings.Contains(string(output), "State : Installed") {
		LogMessage("INFO", TECHNIQUE_ID, "OpenSSH Server already installed")
		return nil
	}

	// Install OpenSSH Server
	LogMessage("INFO", TECHNIQUE_ID, "Adding OpenSSH Server capability...")
	cmd = exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("installation failed: %v - %s", err, string(output))
	}

	// Wait for installation to complete
	time.Sleep(5 * time.Second)

	LogMessage("INFO", TECHNIQUE_ID, "OpenSSH Server capability installed")
	return nil
}

func configureOpenSSH() error {
	LogMessage("INFO", TECHNIQUE_ID, "Configuring OpenSSH Server for remote access...")

	// Set service to automatic startup
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		"Set-Service -Name sshd -StartupType 'Automatic'")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service configuration failed: %v - %s", err, string(output))
	}

	// Configure firewall rule
	LogMessage("INFO", TECHNIQUE_ID, "Configuring firewall rules...")
	cmd = exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		`New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue`)

	cmd.Run() // Ignore error if rule already exists

	LogMessage("INFO", TECHNIQUE_ID, "OpenSSH Server configured")
	return nil
}

func startOpenSSH() error {
	LogMessage("INFO", TECHNIQUE_ID, "Starting OpenSSH Server service...")

	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		"Start-Service sshd")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service start failed: %v - %s", err, string(output))
	}

	// Wait for service to initialize
	time.Sleep(3 * time.Second)

	LogMessage("INFO", TECHNIQUE_ID, "OpenSSH Server started")
	return nil
}

func captureOpenSSHState() error {
	LogMessage("INFO", TECHNIQUE_ID, "Capturing original OpenSSH state for restoration...")

	state := OpenSSHState{
		WasInstalled:      isOpenSSHInstalled(),
		ServiceStartup:    getSSHDStartupType(),
		ServiceRunning:    isServiceRunning("sshd"),
		FirewallRuleExist: firewallRuleExists("sshd"),
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("OpenSSH state: Installed=%v, Startup=%s, Running=%v, Firewall=%v",
		state.WasInstalled, state.ServiceStartup, state.ServiceRunning, state.FirewallRuleExist))

	// Save state to JSON file
	jsonData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal OpenSSH state: %v", err)
	}

	if err := os.WriteFile(OPENSSH_STATE_FILE, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write OpenSSH state file: %v", err)
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("OpenSSH state saved to %s", OPENSSH_STATE_FILE))
	return nil
}

func isOpenSSHInstalled() bool {
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "State : Installed")
}

func getSSHDStartupType() string {
	cmd := exec.Command("sc", "qc", "sshd")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "not_installed"
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "DISABLED") {
		return "disabled"
	} else if strings.Contains(outputStr, "DEMAND_START") {
		return "manual"
	} else if strings.Contains(outputStr, "AUTO_START") {
		return "auto"
	}

	return "unknown"
}

func firewallRuleExists(ruleName string) bool {
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("Get-NetFirewallRule -Name '%s' -ErrorAction SilentlyContinue", ruleName))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// If rule exists, output will contain rule details
	return len(strings.TrimSpace(string(output))) > 0
}

func isServiceRunning(serviceName string) bool {
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("(Get-Service -Name %s).Status", serviceName))

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "Running"
}

// isAdmin function is defined in test_logger.go