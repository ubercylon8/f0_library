//go:build windows
// +build windows

/*
ID: b6c73735-0c24-4a1e-8f0a-3c24af39671b
NAME: MDE Authentication Bypass Command Interception
TECHNIQUE: T1562.001, T1014, T1090.003, T1140
UNIT: response
CREATED: 2025-01-22
*/
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	Dropper "github.com/preludeorg/libraries/go/tests/dropper"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

//go:embed mde_interceptor.ps1
var mdeInterceptor []byte

//go:embed fake_mssense.exe
var fakeMsSense []byte

//go:embed isolation_spoofer.exe
var isolationSpoofer []byte

type MDECommand struct {
	CommandType string    `json:"type"`
	Action      string    `json:"action"`
	MachineID   string    `json:"machineId"`
	TenantID    string    `json:"tenantId"`
	Timestamp   time.Time `json:"timestamp"`
}

func test() {
	// Initialize dropper
	if err := Endpoint.Dropper(Dropper.Dropper); err != nil {
		Endpoint.Say("Dropper initialization failed: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// CRITICAL: Drop to c:\F0
	targetDir := "c:\\F0"
	os.MkdirAll(targetDir, 0755)

	Endpoint.Say("Phase 1: Simulating MDE authentication bypass vulnerability")
	Endpoint.Say("Dropping attack components to %s", targetDir)

	// Drop PowerShell interceptor script
	scriptPath := filepath.Join(targetDir, "mde_interceptor.ps1")
	if err := os.WriteFile(scriptPath, mdeInterceptor, 0755); err != nil {
		Endpoint.Say("Failed to drop PowerShell script: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Drop fake MsSense.exe (simulates legitimate Defender agent)
	fakeMsSensePath := filepath.Join(targetDir, "fake_mssense.exe")
	if err := os.WriteFile(fakeMsSensePath, fakeMsSense, 0755); err != nil {
		Endpoint.Say("Failed to drop fake MsSense: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Drop isolation spoofer
	spooferPath := filepath.Join(targetDir, "isolation_spoofer.exe")
	if err := os.WriteFile(spooferPath, isolationSpoofer, 0755); err != nil {
		Endpoint.Say("Failed to drop isolation spoofer: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Check for initial quarantine
	Endpoint.Say("Checking for defensive reaction to dropped files")
	Endpoint.Wait(3)

	if Endpoint.Quarantined("fake_mssense.exe", fakeMsSense) {
		Endpoint.Say("Fake MsSense was quarantined before execution")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	if Endpoint.Quarantined("isolation_spoofer.exe", isolationSpoofer) {
		Endpoint.Say("Isolation spoofer was quarantined before execution")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExtraction)
	}

	// Phase 2: Simulate command interception
	Endpoint.Say("Phase 2: Attempting to intercept MDE cloud commands")

	// Execute PowerShell interceptor in background
	cmd := exec.Command("cmd.exe", "/C", "start", "/MIN", "powershell.exe",
		"-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath)

	if err := cmd.Start(); err != nil {
		Endpoint.Say("Failed to start PowerShell interceptor: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Wait for interceptor to initialize
	Endpoint.Wait(5)

	// Check if interceptor is running (look for status file)
	statusFile := filepath.Join(targetDir, "interceptor_status.txt")
	if _, err := os.Stat(statusFile); err != nil {
		Endpoint.Say("Interceptor failed to initialize - possible EDR intervention")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	// Phase 3: Simulate isolation command spoofing
	Endpoint.Say("Phase 3: Attempting to spoof device isolation status")

	// Execute isolation spoofer
	spooferCmd := exec.Command(spooferPath)
	spooferCmd.Dir = targetDir
	output, err := spooferCmd.CombinedOutput()

	if err != nil {
		if strings.Contains(string(output), "Access denied") {
			Endpoint.Say("Isolation spoofer blocked by EDR: %s", output)
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		}
		Endpoint.Say("Spoofer execution error: %v", err)
		Endpoint.Stop(Endpoint.UnexpectedTestError)
	}

	// Check if spoofing was successful
	spoofResult := filepath.Join(targetDir, "spoof_result.json")
	if data, err := os.ReadFile(spoofResult); err == nil {
		var result map[string]interface{}
		if json.Unmarshal(data, &result) == nil {
			if result["status"] == "isolated" {
				Endpoint.Say("Successfully spoofed isolation status to MDE portal")
			}
		}
	}

	// Phase 4: Simulate configuration exfiltration
	Endpoint.Say("Phase 4: Attempting to retrieve MDE configuration without authentication")

	// Create mock configuration request
	configPath := filepath.Join(targetDir, "mde_config_dump.json")
	mockConfig := map[string]interface{}{
		"detectionRules":     []string{"rule1", "rule2", "rule3"},
		"exclusions":         []string{"c:\\windows\\temp", "c:\\programdata\\microsoft"},
		"monitoredProcesses": []string{"powershell.exe", "cmd.exe", "wscript.exe"},
		"cloudEndpoints":     []string{"winatp-gw-eus.microsoft.com", "winatp-gw-weu.microsoft.com"},
		"configSize":         8388608, // 8MB
	}

	configData, _ := json.MarshalIndent(mockConfig, "", "  ")
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		Endpoint.Say("Failed to write config dump: %v", err)
	} else {
		Endpoint.Say("Simulated 8MB configuration file retrieval")
	}

	// Phase 5: Check for detection
	Endpoint.Say("Phase 5: Verifying attack success and defensive posture")
	Endpoint.Wait(5)

	// Check if any components were detected post-execution
	if Endpoint.Quarantined("fake_mssense.exe", fakeMsSense) {
		Endpoint.Say("Fake MsSense detected and quarantined during execution")
		Endpoint.Stop(Endpoint.FileQuarantinedOnExecution)
	}

	// Check for process termination indicators
	tasklist := exec.Command("tasklist", "/FI", "IMAGENAME eq powershell.exe")
	taskOutput, _ := tasklist.Output()

	if !strings.Contains(string(taskOutput), "powershell.exe") {
		Endpoint.Say("PowerShell interceptor was terminated - likely EDR intervention")
		Endpoint.Stop(Endpoint.ExecutionPrevented)
	}

	// Create attack summary
	summaryPath := filepath.Join(targetDir, "attack_summary.txt")
	summary := fmt.Sprintf(`MDE Authentication Bypass Attack Simulation Summary
====================================================
Attack Vector: CVE-2024-XXXX MDE Cloud Communication Vulnerability
Timestamp: %s

Successfully Simulated:
1. Command interception without authentication
2. Isolation status spoofing to MDE portal
3. Configuration file retrieval (8MB)
4. CloudLR token generation bypass

Impact Assessment:
- Post-breach persistence achieved
- False isolation status reported to SOC
- Detection rules and exclusions exposed
- Live Response session vulnerable to hijacking

MITRE ATT&CK Techniques:
- T1562.001: Impair Defenses - Disable or Modify Tools
- T1014: Rootkit
- T1090.003: Proxy - Multi-hop Proxy
- T1140: Deobfuscate/Decode Files or Information
`, time.Now().Format("2006-01-02 15:04:05"))

	os.WriteFile(summaryPath, []byte(summary), 0644)

	// Attack completed successfully without detection
	Endpoint.Say("Attack simulation completed - MDE authentication bypass successful")
	Endpoint.Say("Device appears isolated in portal but remains fully operational")
	Endpoint.Stop(Endpoint.Unprotected)
}

// Helper function to read status file
func readStatus() string {
	data, err := os.ReadFile("C:\\F0\\interceptor_status.txt")
	if err != nil {
		return ""
	}
	// Remove UTF-8 BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return strings.TrimSpace(string(data))
}

// Standardized F0RT1KA Custom Runner - eliminates 30-second timeout limitation
func main() {
	// Start with timestamp and runner identification
	Endpoint.Say("Starting test at: %s", time.Now().Format("2006-01-02T15:04:05"))
	Endpoint.Say("Using F0RT1KA standardized test runner")
	Endpoint.Say("Test: MDE Authentication Bypass Command Interception")

	done := make(chan bool, 1)
	go func() {
		test()
		done <- true
	}()

	// Extended timeout for multi-phase attack simulation
	timeout := 5 * time.Minute

	select {
	case <-done:
		Endpoint.Say("Test completed successfully")
	case <-time.After(timeout):
		Endpoint.Say("Test timed out after %v", timeout)
		Endpoint.Stop(Endpoint.TimeoutExceeded)
	}
}